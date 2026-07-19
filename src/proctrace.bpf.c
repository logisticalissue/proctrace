// SPDX-License-Identifier: GPL-2.0
/*
 * proctrace.bpf.c - kernel-side tracer.
 *
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "proctrace.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif

/* dentry-walk depth cap for the in-kernel cwd resolution */
#define MAX_PATH_DEPTH 32

const volatile enum pt_scope_mode scope_mode = PT_SCOPE_CGROUP;
const volatile __u64 target_cgid = 0;      /* cgroup id in PT_SCOPE_CGROUP  */
const volatile char  anchor[64] = {};      /* sentinel path in PT_SCOPE_PIDTREE */
const volatile __u32 anchor_len = 0;

__u32 root_seeded = 0;   /* set once the pid-tree root has been discovered */
__u64 dropped     = 0;   /* events lost to ring-buffer back-pressure       */

/* ---- maps ---- */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 * 1024); /* 256 MiB */
} rb SEC(".maps");

/* pid subtree membership (PT_SCOPE_PIDTREE) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 20);
	__type(key, __u32);   /* tgid */
	__type(value, __u8);
} traced_pids SEC(".maps");

/* argv captured at execve entry, keyed by task, consumed at sched_process_exec */
struct argv_scratch {
	__u32 argv_len;
	__u32 arg_count;
	__u8  truncated;
	char  argv[ARGV_BUF_SZ];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct argv_scratch);
} execve_argv SEC(".maps");

/* dup() oldfd captured at syscall entry, consumed at syscall exit */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);   /* pid_tgid */
	__type(value, __s32); /* oldfd    */
} dup_enter SEC(".maps");

/* per-CPU scratch for the cwd dentry walk (kept off the BPF stack) */
struct cwd_scratch {
	struct dentry *stack[MAX_PATH_DEPTH];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cwd_scratch);
} cwd_heap SEC(".maps");

/* open() args captured at syscall entry, consumed at syscall exit */
struct open_scratch {
	__u64 ts;
	__s32 dfd;
	__u32 flags;
	__u32 mode;
	__u32 path_len;
	char  path[MAX_PATH_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);   /* pid_tgid */
	__type(value, struct open_scratch);
} open_enter SEC(".maps");

/* per-CPU heaps so we can assemble oversized events off the BPF stack */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pt_exec_event);
} exec_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct argv_scratch);
} argv_heap SEC(".maps");

/* per-CPU heap for building an open_scratch off the BPF stack */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct open_scratch);
} open_heap SEC(".maps");

static __always_inline __u64 mm_peak_rss_pages(struct mm_struct *mm)
{
	__u64 rss = 0;
	__s64 c;
	c = BPF_CORE_READ(mm, rss_stat[MM_FILEPAGES].count);  if (c > 0) rss += c;
	c = BPF_CORE_READ(mm, rss_stat[MM_ANONPAGES].count);  if (c > 0) rss += c;
	c = BPF_CORE_READ(mm, rss_stat[MM_SHMEMPAGES].count); if (c > 0) rss += c;
	__u64 hw = BPF_CORE_READ(mm, hiwater_rss);
	return rss > hw ? rss : hw;
}

static __always_inline __u32 cur_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

/* mount that embeds a given vfsmount (private kernel type, present in BTF) */
#define pt_container_of(ptr, type, member) \
	((type *)((char *)(ptr) - __builtin_offsetof(type, member)))

/*
 * Resolve the current process working directory into `dst`  by walking
 * task->fs->pwd dentry-by-dentry up to the root, crossing mount points.
 * Collecting the dentry chain bottom-up into `stack`, then emit "/seg"
 * top-down.
 */
static __always_inline __u32 build_cwd(struct task_struct *task, char *dst,
				       struct dentry **stack)
{
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	if (!fs)
		return 0;
	struct vfsmount *vfsmnt = BPF_CORE_READ(fs, pwd.mnt);
	struct dentry *dentry = BPF_CORE_READ(fs, pwd.dentry);
	if (!vfsmnt || !dentry)
		return 0;
	struct mount *mnt = pt_container_of(vfsmnt, struct mount, mnt);
	struct dentry *mnt_root = BPF_CORE_READ(mnt, mnt.mnt_root);

	int n = 0;
#pragma unroll
	for (int i = 0; i < MAX_PATH_DEPTH; i++) {
		if (dentry == mnt_root) {
			/* at this mount's root: hop to the parent mount, if any */
			struct mount *parent = BPF_CORE_READ(mnt, mnt_parent);
			if (mnt == parent)
				break; /* global root reached */
			dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
			mnt = parent;
			mnt_root = BPF_CORE_READ(mnt, mnt.mnt_root);
			continue; /* re-examine the mountpoint dentry */
		}
		struct dentry *up = BPF_CORE_READ(dentry, d_parent);
		if (dentry == up)
			break; /* filesystem root with no parent mount */
		stack[n++] = dentry;
		dentry = up;
	}

	if (n == 0) {
		dst[0] = '/';
		dst[1] = '\0';
		return 1;
	}

	__u32 off = 0;
#pragma unroll
	for (int i = MAX_PATH_DEPTH - 1; i >= 0; i--) {
		if (i >= n)
			continue;
		/* keep room for a full segment + NUL so writes stay in bounds */
		if (off >= MAX_PATH_LEN - MAX_ARG_LEN - 1)
			break;
		dst[off++] = '/';
		const char *name = (const char *)BPF_CORE_READ(stack[i], d_name.name);
		long r = bpf_probe_read_kernel_str(&dst[off], MAX_ARG_LEN, name);
		if (r > 1)
			off += (__u32)r - 1; /* drop the trailing NUL */
		else
			off--; /* empty name: undo the '/' */
	}
	dst[off & (MAX_PATH_LEN - 1)] = '\0';
	return off;
}

static __always_inline bool pt_traced(void)
{
	if (scope_mode == PT_SCOPE_CGROUP)
		return bpf_get_current_cgroup_id() == target_cgid;

	__u32 tgid = cur_tgid();
	return bpf_map_lookup_elem(&traced_pids, &tgid) != NULL;
}

static __always_inline void fill_hdr(struct pt_hdr *h, __u32 type)
{
	__u64 id = bpf_get_current_pid_tgid();
	h->type = type;
	h->cpu  = bpf_get_smp_processor_id();
	h->ts_ns = bpf_ktime_get_ns();
	h->pid  = id >> 32;
	h->tid  = (__u32)id;
}

static __always_inline bool is_anchor(const char *path, __u32 len)
{
	if (anchor_len == 0 || len < anchor_len)
		return false;
#pragma unroll
	for (int i = 0; i < 64 && i < anchor_len; i++) {
		if (path[i] != anchor[i])
			return false;
	}
	return true;
}

SEC("tp_btf/sched_process_exec")
int handle_exec(u64 *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx[0];
	struct linux_binprm *bprm = (struct linux_binprm *)ctx[2];

	if (!pt_traced())
		return 0;

	__u32 zero = 0;
	struct pt_exec_event *e = bpf_map_lookup_elem(&exec_heap, &zero);
	if (!e)
		return 0;

	fill_hdr(&e->hdr, PT_EXEC);
	e->ppid = BPF_CORE_READ(p, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	const char *fname = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);

	e->cwd_len = 0;
	e->cwd[0] = '\0';
	struct cwd_scratch *cs = bpf_map_lookup_elem(&cwd_heap, &zero);
	if (cs)
		e->cwd_len = build_cwd(p, e->cwd, cs->stack);

	/* pull argv captured at execve entry (if any) */
	e->argv_len = 0;
	e->arg_count = 0;
	e->truncated = 0;
	__u64 key = bpf_get_current_pid_tgid();
	struct argv_scratch *a = bpf_map_lookup_elem(&execve_argv, &key);
	if (a) {
		__u32 n = a->argv_len;
		if (n > ARGV_BUF_SZ)
			n = ARGV_BUF_SZ;
		bpf_probe_read_kernel(e->argv, n, a->argv);
		e->argv_len = n;
		e->arg_count = a->arg_count;
		e->truncated = a->truncated;
		bpf_map_delete_elem(&execve_argv, &key);
	}

	/* The syscall-entry tracepoint normally fills this, but in certain
	 * cases it might not habe been available, so use this as a fallback. */
	if (e->argv_len == 0) {
		struct mm_struct *mm = BPF_CORE_READ(p, mm);
		if (mm) {
			unsigned long start = BPF_CORE_READ(mm, arg_start);
			unsigned long end = BPF_CORE_READ(mm, arg_end);
			if (end > start) {
				unsigned long span = end - start;
				__u32 n = span > ARGV_BUF_SZ ? ARGV_BUF_SZ : (__u32)span;
				if (!bpf_probe_read_user(e->argv, n,
							 (const void *)start)) {
					e->argv_len = n;
					e->arg_count = BPF_CORE_READ(bprm, argc);
					e->truncated = span > ARGV_BUF_SZ;
				}
			}
		}
	}

	__u32 fixed = __builtin_offsetof(struct pt_exec_event, argv);
	__u32 len = e->argv_len;
	if (len > ARGV_BUF_SZ)
		len = ARGV_BUF_SZ;
	if (bpf_ringbuf_output(&rb, e, fixed + len, 0))
		__sync_fetch_and_add(&dropped, 1);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int handle_fork(u64 *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx[0];
	struct task_struct *child  = (struct task_struct *)ctx[1];

	__u32 parent_tgid = BPF_CORE_READ(parent, tgid);
	__u32 child_tgid  = BPF_CORE_READ(child, tgid);
	__u32 child_pid   = BPF_CORE_READ(child, pid);
	__u32 parent_pid  = BPF_CORE_READ(parent, pid);

	if (scope_mode == PT_SCOPE_PIDTREE) {
		/* only descend from parents we already track */
		if (!bpf_map_lookup_elem(&traced_pids, &parent_tgid))
			return 0;
		__u8 one = 1;
		bpf_map_update_elem(&traced_pids, &child_tgid, &one, BPF_ANY);
	} else {
		/* child inherits the cgroup, so parent-in-cgroup is sufficient */
		if (BPF_CORE_READ(parent, cgroups) == 0) /* unreachable guard */
			return 0;
		if (!pt_traced())
			return 0;
	}

	struct pt_fork_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		return 0;
	}
	e->hdr.type = PT_FORK;
	e->hdr.cpu  = bpf_get_smp_processor_id();
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.pid  = child_tgid;
	e->hdr.tid  = child_pid;
	e->parent_pid = parent_tgid;
	e->parent_tid = parent_pid;
	e->is_thread = (child_tgid == parent_tgid);
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm),
				  BPF_CORE_READ(child, comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int handle_exit(u64 *ctx)
{
	struct task_struct *p = (struct task_struct *)ctx[0];

	if (!pt_traced())
		return 0;

	__u32 tgid = BPF_CORE_READ(p, tgid);
	__u32 pid  = BPF_CORE_READ(p, pid);
	__u8  leader = (pid == tgid);

	struct pt_exit_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		goto cleanup;
	}
	e->hdr.type = PT_EXIT;
	e->hdr.cpu  = bpf_get_smp_processor_id();
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.pid  = tgid;
	e->hdr.tid  = pid;
	e->exit_code = BPF_CORE_READ(p, exit_code);
	e->is_group_leader = leader;
	e->has_stats = 0;
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), BPF_CORE_READ(p, comm));

	/* Per-process resource usage, for the whole thread group. utime/stime
	 * and the io-accounting counters are summed across already-reaped
	 * threads (held in signal_struct) plus this task; for the common
	 * single-threaded build step signal_struct's contribution is zero, so
	 * task->{utime,stime,ioac} alone is the exact process total. */
	if (leader) {
		struct signal_struct *sig = BPF_CORE_READ(p, signal);
		struct mm_struct *mm = BPF_CORE_READ(p, mm);

		__u64 ut = BPF_CORE_READ(p, utime);
		__u64 st = BPF_CORE_READ(p, stime);
		if (sig) {
			ut += BPF_CORE_READ(sig, utime);
			st += BPF_CORE_READ(sig, stime);
		}
		e->cpu_user_ns = ut;
		e->cpu_sys_ns  = st;

		e->hiwater_rss_pages = mm ? mm_peak_rss_pages(mm) : 0;
		if (mm) {
			__u64 vh = BPF_CORE_READ(mm, hiwater_vm);
			__u64 vt = BPF_CORE_READ(mm, total_vm);
			e->hiwater_vm_pages = vt > vh ? vt : vh;
		} else {
			e->hiwater_vm_pages = 0;
		}

		e->rchar = e->wchar = e->read_bytes = e->write_bytes = 0;
		if (bpf_core_field_exists(p->ioac)) {
			e->rchar       = BPF_CORE_READ(p, ioac.rchar);
			e->wchar       = BPF_CORE_READ(p, ioac.wchar);
			e->read_bytes  = BPF_CORE_READ(p, ioac.read_bytes);
			e->write_bytes = BPF_CORE_READ(p, ioac.write_bytes);
			if (sig && bpf_core_field_exists(sig->ioac)) {
				e->rchar       += BPF_CORE_READ(sig, ioac.rchar);
				e->wchar       += BPF_CORE_READ(sig, ioac.wchar);
				e->read_bytes  += BPF_CORE_READ(sig, ioac.read_bytes);
				e->write_bytes += BPF_CORE_READ(sig, ioac.write_bytes);
			}
		}
		e->has_stats = 1;
	}
	bpf_ringbuf_submit(e, 0);

cleanup:
	/* free any per-task scratch and, in pid mode, stop tracking the leader */
	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&execve_argv, &key);
	bpf_map_delete_elem(&open_enter, &key);
	bpf_map_delete_elem(&dup_enter, &key);
	if (leader && scope_mode == PT_SCOPE_PIDTREE)
		bpf_map_delete_elem(&traced_pids, &tgid);
	return 0;
}

static __always_inline int capture_argv(const char *const *argv)
{
	if (!pt_traced())
		return 0;

	__u32 zero = 0;
	struct argv_scratch *a = bpf_map_lookup_elem(&argv_heap, &zero);
	if (!a)
		return 0;
	a->argv_len = 0;
	a->arg_count = 0;
	a->truncated = 0;

	__u32 off = 0;
#pragma unroll
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) || !argp) {
			goto done; /* end of argv */
		}
		if (off > ARGV_BUF_SZ - MAX_ARG_LEN) {
			a->truncated = 1;
			goto done;
		}
		long n = bpf_probe_read_user_str(&a->argv[off], MAX_ARG_LEN, argp);
		if (n <= 0)
			goto done;
		off += n; /* n includes the trailing NUL -> natural separator */
		a->arg_count++;
	}
	a->truncated = 1; /* hit MAX_ARGS */
done:
	a->argv_len = off;
	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&execve_argv, &key, a, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	return capture_argv((const char *const *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
	return capture_argv((const char *const *)ctx->args[2]);
}

/* ---- open() family ----
 *
 * We record the path exactly as passed to the syscall, plus dfd. The loader
 * reconstructs absolute paths from a per-process fd->path table plus the cwd
 * captured in-kernel at exec (build_cwd), and dup/dup2/dup3 events keep that
 * fd table from going stale. Potential improved accuracy step: an
 * fexit/vfs_open (or LSM) hook with bpf_d_path to read the resolved dentry
 * path after symlink/mount resolution.
 */

static __always_inline int pt_open_enter(__s32 dfd, const char *filename,
				      __u32 flags, __u32 mode)
{
	__u32 zero = 0;
	struct open_scratch *s = bpf_map_lookup_elem(&open_heap, &zero);
	if (!s)
		return 0;

	/* read the path straight into the heap buffer (off-stack) */
	long n = bpf_probe_read_user_str(s->path, sizeof(s->path), filename);
	__u32 len = (n > 0) ? (__u32)n : 0;

	/* pid-tree seeding: the child opens the sentinel just before exec */
	if (scope_mode == PT_SCOPE_PIDTREE && !root_seeded) {
		if (is_anchor(s->path, len)) {
			__u32 tgid = cur_tgid();
			__u8 one = 1;
			bpf_map_update_elem(&traced_pids, &tgid, &one, BPF_ANY);
			root_seeded = 1;
			return 0; /* swallow the sentinel open */
		}
	}

	if (!pt_traced())
		return 0;

	s->ts = bpf_ktime_get_ns();
	s->dfd = dfd;
	s->flags = flags;
	s->mode = mode;
	s->path_len = len;
	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&open_enter, &key, s, BPF_ANY);
	return 0;
}

static __always_inline int pt_open_exit(long ret)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct open_scratch *s = bpf_map_lookup_elem(&open_enter, &key);
	if (!s)
		return 0;

	struct pt_open_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		goto out;
	}
	e->hdr.type = PT_OPEN;
	e->hdr.cpu  = bpf_get_smp_processor_id();
	e->hdr.ts_ns = s->ts;
	e->hdr.pid  = key >> 32;
	e->hdr.tid  = (__u32)key;
	e->ret = ret;
	e->dfd = s->dfd;
	e->flags = s->flags;
	e->mode = s->mode;
	e->path_len = s->path_len;
	__u32 plen = s->path_len;
	if (plen > sizeof(e->path))
		plen = sizeof(e->path);
	bpf_probe_read_kernel(e->path, plen, s->path);
	bpf_ringbuf_submit(e, 0);
out:
	bpf_map_delete_elem(&open_enter, &key);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	return pt_open_enter((__s32)ctx->args[0], (const char *)ctx->args[1],
			  (__u32)ctx->args[2], (__u32)ctx->args[3]);
}
SEC("tracepoint/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit *ctx)
{
	return pt_open_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_open")
int enter_open(struct trace_event_raw_sys_enter *ctx)
{
	return pt_open_enter(AT_FDCWD, (const char *)ctx->args[0],
			  (__u32)ctx->args[1], (__u32)ctx->args[2]);
}
SEC("tracepoint/syscalls/sys_exit_open")
int exit_open(struct trace_event_raw_sys_exit *ctx)
{
	return pt_open_exit(ctx->ret);
}

/* ---- dup() family ----
 *
 * We don't emit a trace event for dups; they exist only so the loader's
 * fd->path table doesn't go stale when an fd number is reused without an open
 * (the one way a resolved dirfd can silently start pointing at the wrong file).
 * oldfd is stashed at entry; the new fd is the return value at exit.
 */
static __always_inline int pt_dup_enter(__s32 oldfd)
{
	if (!pt_traced())
		return 0;
	__u64 key = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&dup_enter, &key, &oldfd, BPF_ANY);
	return 0;
}

static __always_inline int pt_dup_exit(long ret)
{
	__u64 key = bpf_get_current_pid_tgid();
	__s32 *oldfd = bpf_map_lookup_elem(&dup_enter, &key);
	if (!oldfd)
		return 0;
	if (ret < 0)
		goto out; /* failed dup: fd table unchanged */

	struct pt_dup_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		goto out;
	}
	e->hdr.type = PT_DUP;
	e->hdr.cpu  = bpf_get_smp_processor_id();
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.pid  = key >> 32;
	e->hdr.tid  = (__u32)key;
	e->oldfd = *oldfd;
	e->newfd = (__s32)ret;
	bpf_ringbuf_submit(e, 0);
out:
	bpf_map_delete_elem(&dup_enter, &key);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int enter_dup(struct trace_event_raw_sys_enter *ctx)
{
	return pt_dup_enter((__s32)ctx->args[0]);
}
SEC("tracepoint/syscalls/sys_exit_dup")
int exit_dup(struct trace_event_raw_sys_exit *ctx)
{
	return pt_dup_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int enter_dup2(struct trace_event_raw_sys_enter *ctx)
{
	return pt_dup_enter((__s32)ctx->args[0]);
}
SEC("tracepoint/syscalls/sys_exit_dup2")
int exit_dup2(struct trace_event_raw_sys_exit *ctx)
{
	return pt_dup_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int enter_dup3(struct trace_event_raw_sys_enter *ctx)
{
	return pt_dup_enter((__s32)ctx->args[0]);
}
SEC("tracepoint/syscalls/sys_exit_dup3")
int exit_dup3(struct trace_event_raw_sys_exit *ctx)
{
	return pt_dup_exit(ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
	/* args: dfd, filename, struct open_how *how, size_t size */
	struct open_how how = {};
	bpf_probe_read_user(&how, sizeof(how), (void *)ctx->args[2]);
	return pt_open_enter((__s32)ctx->args[0], (const char *)ctx->args[1],
			  (__u32)how.flags, (__u32)how.mode);
}
SEC("tracepoint/syscalls/sys_exit_openat2")
int exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
	return pt_open_exit(ctx->ret);
}
