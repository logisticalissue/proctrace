/* SPDX-License-Identifier: GPL-2.0 */
/*
 * proctrace.h - event ABI shared between the BPF program and the C++ loader.
 *
 * Keep this file free of libbpf/vmlinux/STL types: it is included verbatim by
 * both the restricted-C BPF object and the C++ userspace consumer, so it may
 * only use fixed-width integers and plain structs.
 */
#ifndef __PROCTRACE_H
#define __PROCTRACE_H

#define MAX_ARG_LEN   256   /* bytes captured per single argv[] entry      */
#define MAX_ARGS      64    /* argv[] entries captured before truncating   */
#define ARGV_BUF_SZ   4096  /* total packed-argv byte budget per exec      */
#define MAX_PATH_LEN  512   /* bytes captured for an open() path           */
#define MAX_COMM      16    /* kernel TASK_COMM_LEN                          */

enum pt_event_type {
	PT_EXEC = 1,  /* a process successfully exec()'d a new image  */
	PT_FORK,      /* a task was cloned (process or thread)        */
	PT_EXIT,      /* a task exited                                */
	PT_OPEN,      /* an open()/openat()/openat2() completed       */
	PT_DUP,       /* dup/dup2/dup3 duplicated an fd (fd-table upkeep) */
};

/*
 * All pids/tgids below are HOST-namespace ids. The loader never assumes they
 * match its own namespaced view; the tree is rebuilt purely from these ids and
 * the ppid links, so it is correct inside containers too.
 */

/* Fixed-size header at the front of every record. */
struct pt_hdr {
	__u32 type;        /* enum pt_event_type       */
	__u32 cpu;         /* cpu that produced it     */
	__u64 ts_ns;       /* CLOCK_MONOTONIC (ktime)  */
	__u32 pid;         /* tgid (thread-group id)   */
	__u32 tid;         /* task pid (thread id)     */
};

/* PT_EXEC: variable length. `argv` holds `argv_len` bytes of NUL-separated
 * arguments; `arg_count` is how many were captured; `truncated` is set if we
 * hit MAX_ARGS / ARGV_BUF_SZ / MAX_ARG_LEN and dropped data.
 *
 * `cwd` is the process working directory resolved in-kernel at exec (a dentry
 * walk of task->fs->pwd, so it is known even for processes that exit before the
 * loader can read /proc, and across a container PID namespace). `cwd_len` is 0
 * if the walk produced nothing (the loader then falls back to /proc/<pid>/cwd).
 * Keep `argv` last: the record is sent as offsetof(argv)+argv_len bytes, so any
 * fixed field must precede it. */
struct pt_exec_event {
	struct pt_hdr hdr;
	__u32 ppid;                 /* real parent tgid            */
	__u32 argv_len;             /* used bytes in argv[]        */
	__u32 arg_count;            /* number of args captured     */
	__u8  truncated;            /* 1 if argv was clipped       */
	__u8  _pad[3];
	char  comm[MAX_COMM];       /* post-exec comm              */
	char  filename[MAX_PATH_LEN]; /* bprm->filename            */
	__u32 cwd_len;              /* bytes in cwd[] (0 = unknown) */
	char  cwd[MAX_PATH_LEN];    /* cwd at exec, absolute       */
	char  argv[ARGV_BUF_SZ];    /* NUL-separated arguments     */
};

/* PT_FORK */
struct pt_fork_event {
	struct pt_hdr hdr;          /* hdr.pid/tid = child ids     */
	__u32 parent_pid;           /* parent tgid                 */
	__u32 parent_tid;           /* parent task pid             */
	__u8  is_thread;            /* 1 if clone shares the tgid  */
	__u8  _pad[3];
	char  comm[MAX_COMM];
};

/* PT_EXIT
 *
 * Resource stats are read straight off the exiting task at the exit tracepoint
 * (task_struct + its signal_struct aggregate) instead of via taskstats netlink:
 * the read is scoped to our subtree, rides this same event in-order, and needs
 * no extra privilege. `has_stats` is set only for group-leader exits (whole
 * process). CPU times are nanoseconds, hiwater_* are in pages (the loader
 * scales by the page size). */
struct pt_exit_event {
	struct pt_hdr hdr;
	__s32 exit_code;            /* raw task->exit_code         */
	__u8  is_group_leader;      /* 1 if pid == tid (process)   */
	__u8  has_stats;            /* 1 if the stats below are set */
	__u8  _pad[2];
	char  comm[MAX_COMM];
	__u64 cpu_user_ns;          /* task+signal utime           */
	__u64 cpu_sys_ns;           /* task+signal stime           */
	__u64 hiwater_rss_pages;    /* mm high-water RSS, pages     */
	__u64 hiwater_vm_pages;     /* mm high-water VM, pages      */
	__u64 rchar;                /* bytes returned by read()    */
	__u64 wchar;                /* bytes passed to write()     */
	__u64 read_bytes;           /* bytes read from storage     */
	__u64 write_bytes;          /* bytes written to storage    */
};

/* PT_DUP: dup/dup2/dup3 succeeded, so newfd now aliases oldfd. The loader
 * copies its fd->path entry oldfd -> newfd (or drops newfd if oldfd is unknown)
 * to keep relative-path resolution from going stale. */
struct pt_dup_event {
	struct pt_hdr hdr;
	__s32 oldfd;
	__s32 newfd;
};

/* PT_OPEN */
struct pt_open_event {
	struct pt_hdr hdr;
	__s64 ret;                  /* fd on success, -errno on fail */
	__s32 dfd;                  /* dirfd (AT_FDCWD = -100)       */
	__u32 flags;                /* open flags                    */
	__u32 mode;                 /* creation mode                 */
	__u32 path_len;
	char  path[MAX_PATH_LEN];   /* raw path as passed to syscall */
};

/* Scoping mode selected by the loader and baked into .rodata. */
enum pt_scope_mode {
	PT_SCOPE_CGROUP = 0,  /* filter by cgroup id (bare metal / privileged) */
	PT_SCOPE_PIDTREE = 1, /* seed via sentinel open, grow on fork (Docker) */
};

/* Magic prefix the child opens right before exec() so the BPF side can learn
 * the root's HOST tgid without the loader knowing it (namespace-safe). The
 * full sentinel path is PT_ANCHOR_PREFIX followed by a per-run nonce. */
#define PT_ANCHOR_PREFIX "/proctrace-anchor-"

#endif /* __PROCTRACE_H */
