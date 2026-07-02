// SPDX-License-Identifier: GPL-2.0
/*
 * proctrace - trace a command and all of its descendants via eBPF and emit a
 * Perfetto trace of the process tree (with argv, timing, exit codes) and every
 * open()/openat()/openat2() with its status.
 *
 * Usage: sudo proctrace [-o out.pftrace] [--scope auto|cgroup|pidtree]
 *                       [--no-opens] -- <command> [args...]
 */
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "proctrace.h"
#include "perfetto_trace.h"
#include "proctrace.skel.h"

/* ------------------------------------------------------------------ */
/* userspace-side model                                                */
/* ------------------------------------------------------------------ */

struct Proc {
	uint64_t proc_uuid = 0;   /* Perfetto ProcessDescriptor track   */
	uint64_t thread_uuid = 0; /* ThreadDescriptor track (holds slices) */
	uint64_t start_ts = 0;
	uint32_t pid = 0;
	uint32_t ppid = 0;
	bool slice_open = false;
	bool cwd_known = false;
	std::string cwd;
	std::string comm;         /* short name for the track label     */
	std::string label;        /* argv for the summary report        */
	std::unordered_map<int, std::string> fds; /* fd -> resolved path */
};

struct Stats {
	uint64_t execs = 0, forks = 0, exits = 0, opens = 0, open_fail = 0;
	uint64_t rstats = 0; /* processes annotated with resource stats */
};

class Model {
public:
	Model(pt::TraceWriter &w, const std::string &, bool trace_opens)
		: w_(w), trace_opens_(trace_opens),
		  page_kb_(sysconf(_SC_PAGESIZE) / 1024) {}

	void onFork(const pt_fork_event *e)
	{
		stats_.forks++;
		if (e->is_thread)
			return; /* threads share the process track */
		uint32_t tgid = e->hdr.pid;
		if (live_.count(tgid))
			return;
		Proc &p = ensure(tgid, e->hdr.ts_ns);
		p.ppid = e->parent_pid;
		relabel(p, e->comm);
	}

	void onExec(const pt_exec_event *e)
	{
		stats_.execs++;
		uint32_t tgid = e->hdr.pid;
		Proc &p = ensure(tgid, e->hdr.ts_ns);
		p.ppid = e->ppid;
		/* fresh image: previous fds are gone / CLOEXEC'd. cwd was resolved
		 * in-kernel at this exec (no /proc race, container-safe); fall back
		 * to a lazy /proc read only if the kernel walk produced nothing. */
		p.fds.clear();
		if (e->cwd_len > 0 && e->cwd[0]) {
			p.cwd.assign(e->cwd, strnlen_(e->cwd, sizeof(e->cwd)));
			p.cwd_known = true;
		} else {
			p.cwd.clear();
			p.cwd_known = false;
		}
		relabel(p, e->comm);

		std::string cmd = cmdline(e);
		p.label = cmd; /* remembered for the teardown summary */
		std::vector<pt::Annotation> a = {
			pt::Annotation::s("filename", e->filename),
			pt::Annotation::n("pid", tgid),
			pt::Annotation::n("ppid", e->ppid),
			pt::Annotation::n("arg_count", e->arg_count),
			pt::Annotation::n("argv_truncated", e->truncated),
		};

		if (p.slice_open) {
			/* re-exec: close the previous image, open a new slice */
			w_.sliceEnd(p.thread_uuid, e->hdr.ts_ns);
			p.start_ts = e->hdr.ts_ns;
		}
		w_.sliceBegin(p.thread_uuid, p.start_ts, cmd, a);
		p.slice_open = true;
	}

	void onOpen(const pt_open_event *e)
	{
		stats_.opens++;
		if (!trace_opens_)
			return;
		uint32_t tgid = e->hdr.pid;
		Proc &p = ensure(tgid, e->hdr.ts_ns);

		std::string raw(e->path, strnlen_(e->path, e->path_len));
		std::string path = resolve(p, e->dfd, raw);
		bool fail = e->ret < 0;
		if (fail)
			stats_.open_fail++;
		else
			p.fds[(int)e->ret] = path; /* for later dfd resolution */

		/* aggregate for the summary: opens per path + ENOENT storms */
		PathStat &pstat = paths_[path];
		pstat.opens++;
		if (e->ret == -ENOENT)
			pstat.enoent++;

		std::string status = fail ? std::string("-") + strerror((int)-e->ret)
					  : "fd " + std::to_string(e->ret);
		std::string name = (fail ? "open! " : "open ") + path;

		char flagbuf[16];
		std::snprintf(flagbuf, sizeof(flagbuf), "0x%x", e->flags);
		std::vector<pt::Annotation> a = {
			pt::Annotation::s("status", status),
			pt::Annotation::n("ret", e->ret),
			pt::Annotation::n("dfd", e->dfd),
			pt::Annotation::s("flags", flagbuf),
		};
		if (raw != path)
			a.push_back(pt::Annotation::s("raw", raw));
		w_.instant(p.thread_uuid, e->hdr.ts_ns, name, a);
	}

	/* dup/dup2/dup3: newfd now aliases oldfd. Mirror it in the fd->path
	 * table so a later openat(newfd, "rel") resolves against the right dir;
	 * if oldfd is unknown, drop any stale newfd entry rather than trust it. */
	void onDup(const pt_dup_event *e)
	{
		auto it = live_.find(e->hdr.pid);
		if (it == live_.end())
			return;
		Proc &p = it->second;
		auto f = p.fds.find(e->oldfd);
		if (f != p.fds.end())
			p.fds[e->newfd] = f->second;
		else
			p.fds.erase(e->newfd);
	}

	void onExit(const pt_exit_event *e)
	{
		if (!e->is_group_leader)
			return;
		stats_.exits++;
		uint32_t tgid = e->hdr.pid;
		Proc &p = ensure(tgid, e->hdr.ts_ns);
		if (!p.slice_open) {
			w_.sliceBegin(p.thread_uuid, p.start_ts,
				      p.comm.empty() ? std::string(e->comm) : p.comm);
			p.slice_open = true;
		}
		int code = (e->exit_code >> 8) & 0xff;
		int sig = e->exit_code & 0x7f;
		char buf[64];
		if (sig)
			std::snprintf(buf, sizeof(buf), "killed by signal %d", sig);
		else
			std::snprintf(buf, sizeof(buf), "exit code %d", code);
		w_.instant(p.thread_uuid, e->hdr.ts_ns, buf,
			   {pt::Annotation::n("exit_code", code),
			    pt::Annotation::n("term_signal", sig)});

		/* Resource stats ride this exit event (read off the task in the
		 * kernel), so they land on the slice with no correlation dance. */
		if (e->has_stats) {
			w_.sliceEnd(p.thread_uuid, e->hdr.ts_ns, statAnnots(e));
			stats_.rstats++;
		} else {
			w_.sliceEnd(p.thread_uuid, e->hdr.ts_ns);
		}
		recordProc(p, e->hdr.ts_ns);
		live_.erase(tgid);
	}

	/* close anything still running (early stop / SIGKILLed subtree) */
	void finalize(uint64_t ts)
	{
		for (auto &kv : live_) {
			if (kv.second.slice_open)
				w_.sliceEnd(kv.second.thread_uuid, ts);
			recordProc(kv.second, ts); /* count procs alive at teardown */
		}
		live_.clear();
	}

	const Stats &stats() const { return stats_; }

	/* ---- teardown summary: slowest procs, hottest files, and
	 * ENOENT storms — all aggregated from the event stream ---- */
	static constexpr size_t kTopN = 10;

	void printSummary(std::FILE *out, size_t topn = kTopN) const
	{
		auto slow = topSlowest(topn);
		auto hot = topPaths(topn, /*enoent=*/false);
		auto miss = topPaths(topn, /*enoent=*/true);
		if (slow.empty() && hot.empty() && miss.empty())
			return;

		std::fprintf(out, "[proctrace] summary\n");
		if (!slow.empty()) {
			std::fprintf(out, "  slowest processes (wall time):\n");
			for (const auto &p : slow)
				std::fprintf(out, "    %9.1f ms  pid %-7u %s\n",
					     p.dur_ns / 1e6, p.pid,
					     ellipsize(p.label, 80).c_str());
		}
		if (!hot.empty()) {
			std::fprintf(out, "  most-opened files:\n");
			for (const auto &pc : hot)
				std::fprintf(out, "    %6llu  %s\n",
					     (unsigned long long)pc.count,
					     ellipsize(pc.path, 90).c_str());
		}
		if (!miss.empty()) {
			std::fprintf(out, "  -ENOENT storms (missing paths, "
					  "most-searched):\n");
			for (const auto &pc : miss)
				std::fprintf(out, "    %6llu  %s\n",
					     (unsigned long long)pc.count,
					     ellipsize(pc.path, 90).c_str());
		}
	}

	bool writeJsonSummary(const std::string &path, const std::string &cmd,
			      uint64_t dropped, size_t topn = kTopN) const
	{
		std::FILE *f = std::fopen(path.c_str(), "w");
		if (!f)
			return false;
		std::fprintf(f, "{\n  \"command\": %s,\n", jsonStr(cmd).c_str());
		std::fprintf(f, "  \"counts\": {\"execs\": %llu, \"forks\": %llu, "
			     "\"exits\": %llu, \"opens\": %llu, "
			     "\"open_failed\": %llu, \"dropped\": %llu},\n",
			     (unsigned long long)stats_.execs,
			     (unsigned long long)stats_.forks,
			     (unsigned long long)stats_.exits,
			     (unsigned long long)stats_.opens,
			     (unsigned long long)stats_.open_fail,
			     (unsigned long long)dropped);

		std::fprintf(f, "  \"slowest_processes\": [\n");
		auto slow = topSlowest(topn);
		for (size_t i = 0; i < slow.size(); i++)
			std::fprintf(f, "    {\"pid\": %u, \"wall_ms\": %.3f, "
				     "\"cmd\": %s}%s\n", slow[i].pid,
				     slow[i].dur_ns / 1e6,
				     jsonStr(slow[i].label).c_str(),
				     i + 1 < slow.size() ? "," : "");
		std::fprintf(f, "  ],\n");

		jsonPathArray(f, "most_opened_files", topPaths(topn, false), ",");
		jsonPathArray(f, "enoent_storms", topPaths(topn, true), "");

		std::fprintf(f, "}\n");
		std::fclose(f);
		return true;
	}

private:
	/* ---- summary aggregation ---- */
	struct ProcSummary { uint64_t dur_ns; uint32_t pid; std::string label; };
	struct PathStat { uint64_t opens = 0; uint64_t enoent = 0; };
	struct PathCount { std::string path; uint64_t count; };

	void recordProc(const Proc &p, uint64_t end_ts)
	{
		uint64_t dur = end_ts > p.start_ts ? end_ts - p.start_ts : 0;
		const std::string &lbl = p.label.empty() ? p.comm : p.label;
		finished_.push_back({dur, p.pid, lbl.substr(0, 256)});
	}

	std::vector<ProcSummary> topSlowest(size_t n) const
	{
		std::vector<ProcSummary> v = finished_;
		size_t k = std::min(n, v.size());
		std::partial_sort(v.begin(), v.begin() + k, v.end(),
			[](const ProcSummary &a, const ProcSummary &b) {
				return a.dur_ns > b.dur_ns;
			});
		v.resize(k);
		return v;
	}

	std::vector<PathCount> topPaths(size_t n, bool enoent) const
	{
		std::vector<PathCount> v;
		v.reserve(paths_.size());
		for (const auto &kv : paths_) {
			uint64_t c = enoent ? kv.second.enoent : kv.second.opens;
			if (c)
				v.push_back({kv.first, c});
		}
		size_t k = std::min(n, v.size());
		std::partial_sort(v.begin(), v.begin() + k, v.end(),
			[](const PathCount &a, const PathCount &b) {
				return a.count > b.count;
			});
		v.resize(k);
		return v;
	}

	/* Truncate to a display width, marking cuts with an ellipsis. */
	static std::string ellipsize(const std::string &s, size_t max)
	{
		return s.size() <= max ? s : s.substr(0, max - 1) + "…";
	}

	/* Minimal JSON string: quote + escape control chars, quotes, backslash. */
	static std::string jsonStr(const std::string &s)
	{
		std::string o = "\"";
		for (char c : s) {
			switch (c) {
			case '"':  o += "\\\""; break;
			case '\\': o += "\\\\"; break;
			case '\n': o += "\\n";  break;
			case '\r': o += "\\r";  break;
			case '\t': o += "\\t";  break;
			default:
				if ((unsigned char)c < 0x20) {
					char b[8];
					std::snprintf(b, sizeof(b), "\\u%04x", c);
					o += b;
				} else {
					o += c;
				}
			}
		}
		o += "\"";
		return o;
	}

	static void jsonPathArray(std::FILE *f, const char *key,
				  const std::vector<PathCount> &v,
				  const char *trailer)
	{
		std::fprintf(f, "  \"%s\": [\n", key);
		for (size_t i = 0; i < v.size(); i++)
			std::fprintf(f, "    {\"path\": %s, \"count\": %llu}%s\n",
				     jsonStr(v[i].path).c_str(),
				     (unsigned long long)v[i].count,
				     i + 1 < v.size() ? "," : "");
		std::fprintf(f, "  ]%s\n", trailer);
	}

	static size_t strnlen_(const char *s, size_t max)
	{
		size_t n = 0;
		while (n < max && s[n])
			n++;
		return n;
	}

	static std::string cmdline(const pt_exec_event *e)
	{
		if (e->argv_len == 0)
			return e->filename[0] ? e->filename : "(exec)";
		std::string s;
		s.reserve(e->argv_len);
		for (uint32_t i = 0; i < e->argv_len; i++)
			s.push_back(e->argv[i] ? e->argv[i] : ' ');
		while (!s.empty() && s.back() == ' ')
			s.pop_back();
		if (e->truncated)
			s += " …";
		return s;
	}

	/* Lexically clean a path (resolve "." and "..", collapse slashes). */
	static std::string normalize(const std::string &in)
	{
		bool absolute = !in.empty() && in[0] == '/';
		std::vector<std::string> parts;
		size_t i = 0;
		while (i < in.size()) {
			size_t j = in.find('/', i);
			if (j == std::string::npos)
				j = in.size();
			std::string seg = in.substr(i, j - i);
			if (seg.empty() || seg == ".") {
				/* skip */
			} else if (seg == "..") {
				if (!parts.empty() && parts.back() != "..")
					parts.pop_back();
				else if (!absolute)
					parts.push_back("..");
			} else {
				parts.push_back(seg);
			}
			i = j + 1;
		}
		std::string out = absolute ? "/" : "";
		for (size_t k = 0; k < parts.size(); k++) {
			if (k)
				out += '/';
			out += parts[k];
		}
		if (out.empty())
			out = absolute ? "/" : ".";
		return out;
	}

	/* Fallback cwd source: the kernel resolves cwd at exec (see onExec), so
	 * this only runs for tasks with no exec event (a bare fork that never
	 * exec'd) or when the in-kernel walk came up empty. Read lazily from
	 * /proc; racy for an already-exited task, leaving relative paths as-is. */
	const std::string &cwdOf(Proc &p)
	{
		if (!p.cwd_known) {
			p.cwd_known = true;
			char buf[4096];
			std::string link = "/proc/" + std::to_string(p.pid) + "/cwd";
			ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
			if (n > 0) {
				buf[n] = '\0';
				p.cwd = buf;
			}
		}
		return p.cwd;
	}

	/* Turn a raw syscall path + dirfd into an absolute path when we can. */
	std::string resolve(Proc &p, int32_t dfd, const std::string &raw)
	{
		if (raw.empty() || raw[0] == '/')
			return raw.empty() ? raw : normalize(raw);
		std::string base;
		if (dfd == AT_FDCWD) {
			base = cwdOf(p);
		} else {
			auto it = p.fds.find(dfd);
			if (it != p.fds.end())
				base = it->second;
		}
		if (base.empty())
			return raw; /* unresolved: keep the relative path as-is */
		return normalize(base + "/" + raw);
	}

	/* Resource-usage annotations, converted to stable units (ns -> ms,
	 * pages -> KiB) from the raw values the BPF exit event carries. */
	std::vector<pt::Annotation> statAnnots(const pt_exit_event *e) const
	{
		return {
			pt::Annotation::n("cpu_user_ms", (int64_t)(e->cpu_user_ns / 1000000)),
			pt::Annotation::n("cpu_sys_ms", (int64_t)(e->cpu_sys_ns / 1000000)),
			pt::Annotation::n("peak_rss_kb", (int64_t)(e->hiwater_rss_pages * page_kb_)),
			pt::Annotation::n("peak_vm_kb", (int64_t)(e->hiwater_vm_pages * page_kb_)),
			pt::Annotation::n("read_bytes", (int64_t)e->read_bytes),
			pt::Annotation::n("write_bytes", (int64_t)e->write_bytes),
			pt::Annotation::n("read_chars", (int64_t)e->rchar),
			pt::Annotation::n("write_chars", (int64_t)e->wchar),
		};
	}

	void relabel(Proc &p, const char *comm)
	{
		if (p.comm == comm)
			return;
		p.comm = comm;
		w_.processTrack(p.proc_uuid, (int32_t)p.pid, p.comm);
		w_.threadTrack(p.thread_uuid, (int32_t)p.pid, (int32_t)p.pid,
			       p.comm);
	}

	Proc &ensure(uint32_t tgid, uint64_t ts)
	{
		auto it = live_.find(tgid);
		if (it != live_.end())
			return it->second;
		Proc p;
		p.pid = tgid;
		p.start_ts = ts;
		p.proc_uuid = next_uuid_++;
		p.thread_uuid = next_uuid_++;
		p.comm = "?";
		w_.processTrack(p.proc_uuid, (int32_t)tgid, "pid " + std::to_string(tgid));
		w_.threadTrack(p.thread_uuid, (int32_t)tgid, (int32_t)tgid,
			       "pid " + std::to_string(tgid));
		return live_.emplace(tgid, std::move(p)).first->second;
	}

	pt::TraceWriter &w_;
	bool trace_opens_;
	int64_t page_kb_;
	std::unordered_map<uint32_t, Proc> live_;
	uint64_t next_uuid_ = 0x100;
	Stats stats_;

	/* summary state: one record per finished process, one entry per unique
	 * resolved open path (O(procs) + O(unique paths), like the writer's
	 * intern table — far below O(total events)). */
	std::vector<ProcSummary> finished_;
	std::unordered_map<std::string, PathStat> paths_;
};

/* ------------------------------------------------------------------ */
/* globals for the ring-buffer callback and signal handling            */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int) { g_stop = 1; }

static int handle_event(void *ctx, void *data, size_t len)
{
	auto *model = static_cast<Model *>(ctx);
	if (len < sizeof(pt_hdr))
		return 0;
	auto *h = static_cast<const pt_hdr *>(data);
	switch (h->type) {
	case PT_EXEC:
		if (len >= offsetof(pt_exec_event, argv))
			model->onExec(static_cast<const pt_exec_event *>(data));
		break;
	case PT_FORK:
		if (len >= sizeof(pt_fork_event))
			model->onFork(static_cast<const pt_fork_event *>(data));
		break;
	case PT_EXIT:
		if (len >= sizeof(pt_exit_event))
			model->onExit(static_cast<const pt_exit_event *>(data));
		break;
	case PT_OPEN:
		if (len >= sizeof(pt_open_event))
			model->onOpen(static_cast<const pt_open_event *>(data));
		break;
	case PT_DUP:
		if (len >= sizeof(pt_dup_event))
			model->onDup(static_cast<const pt_dup_event *>(data));
		break;
	}
	return 0;
}

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

/* ------------------------------------------------------------------ */
/* cgroup helpers                                                      */
/* ------------------------------------------------------------------ */

static bool cgroup_writable()
{
	/* cgroup2 mounted rw and we can create a subdir under the root */
	return access("/sys/fs/cgroup/cgroup.procs", W_OK) == 0;
}

/* ------------------------------------------------------------------ */

struct Options {
	std::string output = "proctrace.pftrace";
	std::string scope = "auto";
	std::string user;         /* run the command as this user (else auto) */
	std::string summary_json; /* also write a JSON summary sidecar here    */
	bool trace_opens = true;
	bool summary = true;      /* print the teardown summary to stderr      */
	std::vector<char *> argv; /* command to run */
};

static void usage(const char *p)
{
	fprintf(stderr,
		"usage: %s [-o out.pftrace] [--scope auto|cgroup|pidtree] "
		"[--user NAME] [--no-opens] [--no-summary] "
		"[--summary-json FILE] -- <command> [args...]\n", p);
}

/*
 * proctrace itself must run privileged to load BPF, but the traced command
 * should run as the *invoking* user, not root. We resolve that user (an
 * explicit --user, else the sudo caller, else the real uid) and drop to it in
 * the child just before exec.
 */
struct TargetUser {
	bool drop = false;
	uid_t uid = 0;
	gid_t gid = 0;
	std::string name;
	std::string home;
	std::vector<gid_t> groups; /* supplementary groups, resolved in the parent */
};

static TargetUser resolve_target_user(const std::string &want)
{
	TargetUser t;
	struct passwd *pw = nullptr;

	if (!want.empty()) {
		pw = getpwnam(want.c_str());
		if (!pw) {
			fprintf(stderr, "unknown user '%s'\n", want.c_str());
			return t; /* drop=false; caller will error out */
		}
	} else if (const char *su = getenv("SUDO_UID")) {
		/* launched via sudo: fall back to the original caller */
		uid_t uid = (uid_t)strtoul(su, nullptr, 10);
		pw = getpwuid(uid);
		if (!pw) {
			t.drop = (uid != 0);
			t.uid = uid;
			const char *sg = getenv("SUDO_GID");
			t.gid = sg ? (gid_t)strtoul(sg, nullptr, 10) : uid;
			return t;
		}
	} else {
		/* not under sudo: if we hold privileges via getuid()!=0 (e.g.
		 * file capabilities) the child already runs as the user. */
		uid_t ruid = getuid();
		if (ruid != 0)
			return t; /* nothing to drop */
		pw = getpwuid(ruid); /* running as real root: no target user */
	}

	if (pw && pw->pw_uid != 0) {
		t.drop = true;
		t.uid = pw->pw_uid;
		t.gid = pw->pw_gid;
		t.name = pw->pw_name;
		t.home = pw->pw_dir ? pw->pw_dir : "";

		/* Resolve the supplementary group list here, in the parent,
		 * BEFORE the child is forked and joined to the traced scope.
		 * getgrouplist() goes through NSS (nss-systemd's userdb chase
		 * on some distros opens '/' and probes the userdb dirs dozens
		 * of times); doing it in the child after it joins the cgroup
		 * would attribute all of those opens to the traced command. The
		 * child then only needs setgroups() with this precomputed list,
		 * which touches no files. */
		int ng = 0;
		getgrouplist(t.name.c_str(), t.gid, nullptr, &ng);
		if (ng < 1)
			ng = 1;
		t.groups.resize(ng);
		if (getgrouplist(t.name.c_str(), t.gid, t.groups.data(), &ng) < 0) {
			/* group set changed under us / still too small: fall back
			 * to the primary group alone rather than risk a stale set */
			t.groups.assign(1, t.gid);
		} else {
			t.groups.resize(ng);
		}
	}
	return t;
}

/* Irreversibly drop to the target user. Returns false on failure. */
static bool drop_privileges(const TargetUser &t)
{
	if (!t.drop || geteuid() != 0)
		return true;
	/* Apply the supplementary groups resolved in the parent (see
	 * resolve_target_user). We deliberately avoid initgroups() here: it does
	 * an NSS lookup, and this code runs in the child after it has joined the
	 * traced scope, so those opens would pollute the trace. setgroups() is a
	 * pure syscall. */
	if (!t.groups.empty()) {
		if (setgroups(t.groups.size(), t.groups.data()) != 0)
			return false;
	} else if (setgroups(1, &t.gid) != 0) {
		return false;
	}
	if (setgid(t.gid) != 0)
		return false;
	if (setuid(t.uid) != 0)
		return false;
	if (setuid(0) == 0) /* must NOT be able to regain root */
		return false;
	if (!t.name.empty()) {
		setenv("USER", t.name.c_str(), 1);
		setenv("LOGNAME", t.name.c_str(), 1);
	}
	if (!t.home.empty())
		setenv("HOME", t.home.c_str(), 1);
	return true;
}

int main(int argc, char **argv)
{
	Options opt;
	int i = 1;
	for (; i < argc; i++) {
		std::string a = argv[i];
		if (a == "--")
			{ i++; break; }
		else if ((a == "-o" || a == "--output") && i + 1 < argc)
			opt.output = argv[++i];
		else if (a == "--scope" && i + 1 < argc)
			opt.scope = argv[++i];
		else if (a == "--user" && i + 1 < argc)
			opt.user = argv[++i];
		else if (a == "--no-opens")
			opt.trace_opens = false;
		else if (a == "--no-summary")
			opt.summary = false;
		else if (a == "--summary-json" && i + 1 < argc)
			opt.summary_json = argv[++i];
		else if (a == "-h" || a == "--help")
			{ usage(argv[0]); return 0; }
		else
			{ usage(argv[0]); return 2; }
	}
	for (; i < argc; i++)
		opt.argv.push_back(argv[i]);
	if (opt.argv.empty()) {
		usage(argv[0]);
		return 2;
	}
	opt.argv.push_back(nullptr);

	/* decide scope */
	bool use_cgroup;
	if (opt.scope == "cgroup") use_cgroup = true;
	else if (opt.scope == "pidtree") use_cgroup = false;
	else use_cgroup = cgroup_writable(); /* auto */
	fprintf(stderr, "[proctrace] scope = %s\n",
		use_cgroup ? "cgroup" : "pidtree");

	/* Who should the traced command run as? Resolve before we load BPF. */
	TargetUser target = resolve_target_user(opt.user);
	if (!opt.user.empty() && !target.drop) {
		fprintf(stderr, "cannot run as user '%s'\n", opt.user.c_str());
		return 1;
	}
	if (target.drop)
		fprintf(stderr, "[proctrace] command runs as %s (uid %u)\n",
			target.name.empty() ? "?" : target.name.c_str(),
			target.uid);
	else if (geteuid() == 0)
		fprintf(stderr, "[proctrace] warning: command will run as root "
			"(no SUDO_UID; pass --user to change)\n");

	libbpf_set_print(libbpf_print);

	struct proctrace_bpf *skel = proctrace_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton (need root?)\n");
		return 1;
	}

	/* ---- configure scoping via .rodata (must be set before load) ---- */
	std::string cgroup_dir;
	std::string anchor_path;
	if (use_cgroup) {
		cgroup_dir = "/sys/fs/cgroup/proctrace." + std::to_string(getpid());
		if (mkdir(cgroup_dir.c_str(), 0755) && errno != EEXIST) {
			fprintf(stderr, "mkdir %s: %s\n", cgroup_dir.c_str(),
				strerror(errno));
			return 1;
		}
		struct stat st;
		if (stat(cgroup_dir.c_str(), &st)) {
			fprintf(stderr, "stat cgroup: %s\n", strerror(errno));
			return 1;
		}
		skel->rodata->scope_mode = PT_SCOPE_CGROUP;
		skel->rodata->target_cgid = st.st_ino; /* == cgroup id */
	} else {
		unsigned long nonce = ((unsigned long)getpid() << 20) ^
				      (unsigned long)time(nullptr);
		anchor_path = std::string(PT_ANCHOR_PREFIX) + std::to_string(nonce);
		skel->rodata->scope_mode = PT_SCOPE_PIDTREE;
		size_t n = anchor_path.size();
		if (n >= sizeof(skel->rodata->anchor))
			n = sizeof(skel->rodata->anchor) - 1;
		memcpy((void *)skel->rodata->anchor, anchor_path.data(), n);
		skel->rodata->anchor_len = (uint32_t)n;
	}

	if (proctrace_bpf__load(skel)) {
		fprintf(stderr, "failed to load BPF (verifier?): %s\n",
			strerror(errno));
		return 1;
	}

	/* Not every syscall exists on every arch: arm64 has no legacy open(2),
	 * and openat2(2) is absent on pre-5.6 kernels. Disable auto-attach for
	 * any tracepoint the kernel doesn't expose so attach still succeeds. */
	auto tp_missing = [](const char *tp) {
		std::string a = std::string("/sys/kernel/tracing/events/") + tp;
		std::string b = std::string("/sys/kernel/debug/tracing/events/") + tp;
		return access(a.c_str(), F_OK) && access(b.c_str(), F_OK);
	};
	if (tp_missing("syscalls/sys_enter_open")) {
		bpf_program__set_autoattach(skel->progs.enter_open, false);
		bpf_program__set_autoattach(skel->progs.exit_open, false);
	}
	if (tp_missing("syscalls/sys_enter_openat2")) {
		bpf_program__set_autoattach(skel->progs.enter_openat2, false);
		bpf_program__set_autoattach(skel->progs.exit_openat2, false);
	}
	/* dup2(2) is absent on arm64 (glibc routes it through dup3) */
	if (tp_missing("syscalls/sys_enter_dup2")) {
		bpf_program__set_autoattach(skel->progs.enter_dup2, false);
		bpf_program__set_autoattach(skel->progs.exit_dup2, false);
	}

	if (proctrace_bpf__attach(skel)) {
		fprintf(stderr, "failed to attach BPF programs\n");
		return 1;
	}

	/* ---- trace writer + model ---- */
	pt::TraceWriter writer(opt.output);
	if (!writer.ok()) {
		fprintf(stderr, "cannot open output %s\n", opt.output.c_str());
		return 1;
	}
	/* the trace is created by root; hand it to the invoking user */
	if (target.drop && chown(opt.output.c_str(), target.uid, target.gid))
		fprintf(stderr, "warning: chown %s: %s\n", opt.output.c_str(),
			strerror(errno));
	{
		struct timespec mono, boot, real;
		clock_gettime(CLOCK_MONOTONIC, &mono);
		clock_gettime(CLOCK_BOOTTIME, &boot);
		clock_gettime(CLOCK_REALTIME, &real);
		auto ns = [](struct timespec &t) {
			return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
		};
		writer.clockSnapshot(ns(mono), ns(boot), ns(real));
	}
	std::string cmdstr;
	for (size_t k = 0; opt.argv[k]; k++) {
		if (k) cmdstr += ' ';
		cmdstr += opt.argv[k];
	}
	Model model(writer, cmdstr, opt.trace_opens);

	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event,
				 &model, nullptr);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		return 1;
	}

	/* ---- launch the target, synchronised so BPF sees it from t=0 ---- */
	int sync_pipe[2];
	if (pipe(sync_pipe)) { perror("pipe"); return 1; }

	pid_t child = fork();
	if (child < 0) { perror("fork"); return 1; }
	if (child == 0) {
		close(sync_pipe[1]);
		char c;
		while (read(sync_pipe[0], &c, 1) < 0 && errno == EINTR)
			; /* wait until the parent has us scoped + ready */
		close(sync_pipe[0]);
		/* We are now inside the cgroup (or pid-seeded). Shed root so the
		 * command runs as the invoking user; the tracer keeps its privs. */
		if (!drop_privileges(target)) {
			fprintf(stderr, "failed to drop privileges: %s\n",
				strerror(errno));
			_exit(126);
		}
		if (!use_cgroup) {
			/* seed the pid-tree root; BPF matches this exact path */
			int fd = open(anchor_path.c_str(), O_RDONLY);
			if (fd >= 0) close(fd);
		}
		execvp(opt.argv[0], opt.argv.data());
		fprintf(stderr, "execvp %s: %s\n", opt.argv[0], strerror(errno));
		_exit(127);
	}

	/* parent */
	close(sync_pipe[0]);
	if (use_cgroup) {
		std::string procs = cgroup_dir + "/cgroup.procs";
		FILE *f = fopen(procs.c_str(), "w");
		if (f) { fprintf(f, "%d\n", child); fclose(f); }
		else fprintf(stderr, "warning: cannot join cgroup: %s\n",
			     strerror(errno));
	}
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	char go = 1;
	while (write(sync_pipe[1], &go, 1) < 0 && errno == EINTR)
		; /* release the child */
	close(sync_pipe[1]);

	/* ---- consume events until the child exits and the buffer drains ---- */
	int child_status = 0;
	bool reaped = false;
	int idle_drains = 0;
	while (!g_stop) {
		int n = ring_buffer__poll(rb, 100 /*ms*/);
		if (n < 0 && n != -EINTR)
			break;
		if (!reaped) {
			pid_t r = waitpid(child, &child_status, WNOHANG);
			if (r == child)
				reaped = true;
		} else {
			/* child gone: drain remaining events, then stop */
			if (n <= 0 && ++idle_drains >= 3)
				break;
			if (n > 0)
				idle_drains = 0;
		}
	}
	if (!reaped)
		waitpid(child, &child_status, 0);

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	model.finalize((uint64_t)now.tv_sec * 1000000000ull + now.tv_nsec);

	/* ---- report ---- */
	uint64_t dropped = skel->bss ? skel->bss->dropped : 0;
	const Stats &s = model.stats();
	fprintf(stderr,
		"[proctrace] execs=%llu forks=%llu exits=%llu opens=%llu "
		"(failed=%llu) stats=%llu dropped=%llu\n",
		(unsigned long long)s.execs, (unsigned long long)s.forks,
		(unsigned long long)s.exits, (unsigned long long)s.opens,
		(unsigned long long)s.open_fail, (unsigned long long)s.rstats,
		(unsigned long long)dropped);
	if (dropped)
		fprintf(stderr, "[proctrace] WARNING: %llu events dropped "
			"(ring buffer overflow) - trace is incomplete\n",
			(unsigned long long)dropped);

	if (opt.summary)
		model.printSummary(stderr);
	if (!opt.summary_json.empty()) {
		if (model.writeJsonSummary(opt.summary_json, cmdstr, dropped)) {
			/* hand the sidecar to the invoking user, like the trace */
			if (target.drop && chown(opt.summary_json.c_str(),
						 target.uid, target.gid))
				fprintf(stderr, "warning: chown %s: %s\n",
					opt.summary_json.c_str(), strerror(errno));
			fprintf(stderr, "[proctrace] wrote summary JSON to %s\n",
				opt.summary_json.c_str());
		} else {
			fprintf(stderr, "warning: cannot write summary JSON %s: %s\n",
				opt.summary_json.c_str(), strerror(errno));
		}
	}

	fprintf(stderr, "[proctrace] wrote %s (open in https://ui.perfetto.dev)\n",
		opt.output.c_str());

	ring_buffer__free(rb);
	proctrace_bpf__destroy(skel);
	if (use_cgroup && !cgroup_dir.empty())
		rmdir(cgroup_dir.c_str()); /* best effort; empty now */

	if (WIFEXITED(child_status))
		return WEXITSTATUS(child_status);
	return 1;
}
