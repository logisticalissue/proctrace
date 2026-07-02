// SPDX-License-Identifier: GPL-2.0
/*
 * perfetto_trace.h - a tiny, dependency-free writer for the subset of the
 * Perfetto trace protobuf we need. Uses the *standard* process/thread track
 * descriptors so the Perfetto UI groups and shows every process natively, plus
 * TrackEvent slices/instants and a ClockSnapshot. Packets stream straight to a
 * file, so writer memory stays O(live processes), not O(total events).
 *
 * Wire format reference (perfetto trace protos):
 *   Trace.packet                         = 1  (repeated TracePacket)
 *   TracePacket.timestamp                = 8
 *   TracePacket.clock_snapshot           = 6
 *   TracePacket.trusted_packet_sequence_id = 10
 *   TracePacket.track_event              = 11
 *   TracePacket.interned_data            = 12
 *   TracePacket.sequence_flags           = 13
 *   TracePacket.track_descriptor         = 60
 *   TracePacket.timestamp_clock_id       = 58
 *   TrackDescriptor{uuid=1, name=2, process=3, thread=4}
 *   ProcessDescriptor{pid=1, process_name=6}
 *   ThreadDescriptor{pid=1, tid=2, thread_name=5}
 *
 * Interning (dedups strings that recur across millions of events — repeated
 * open paths, annotation names, repeated annotation string values). Interned
 * entries ride the same packet as their first use; packets that reference them
 * carry SEQ_NEEDS_INCREMENTAL_STATE, and the first packet SEQ_..._CLEARED:
 *   InternedData.event_names               = 2  (EventName{iid=1, name=2})
 *   InternedData.debug_annotation_names    = 3  (DebugAnnotationName{iid=1, name=2})
 *   InternedData.debug_annotation_string_values = 4 (InternedString{iid=1, str=2})
 *   TrackEvent.name_iid                    = 10
 *   DebugAnnotation.name_iid               = 1, .string_value_iid = 17
 */
#ifndef PERFETTO_TRACE_H
#define PERFETTO_TRACE_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdio>

namespace pt {

struct Annotation {
	std::string name;
	enum Kind { STR, INT } kind = STR;
	std::string str;
	int64_t i = 0;

	static Annotation s(std::string n, std::string v) {
		return {std::move(n), STR, std::move(v), 0};
	}
	static Annotation n(std::string nm, int64_t v) {
		return {std::move(nm), INT, {}, v};
	}
};

class TraceWriter {
public:
	explicit TraceWriter(const std::string &path);
	~TraceWriter();
	bool ok() const { return f_ != nullptr; }

	/* Standard descriptors: Perfetto groups thread tracks under the process
	 * with the matching pid, and lists every process in the UI. */
	void processTrack(uint64_t uuid, int32_t pid, const std::string &name);
	void threadTrack(uint64_t uuid, int32_t pid, int32_t tid,
			 const std::string &name);

	void sliceBegin(uint64_t track_uuid, uint64_t ts_ns,
			const std::string &name,
			const std::vector<Annotation> &annots = {});
	void sliceEnd(uint64_t track_uuid, uint64_t ts_ns);
	/* slice end carrying debug annotations; Perfetto merges them onto the
	 * slice, so exit-time facts (e.g. resource stats) show in its detail. */
	void sliceEnd(uint64_t track_uuid, uint64_t ts_ns,
		      const std::vector<Annotation> &annots);
	void instant(uint64_t track_uuid, uint64_t ts_ns,
		     const std::string &name,
		     const std::vector<Annotation> &annots = {});

	/* Correlate CLOCK_MONOTONIC (our event timestamps) with wall clock. */
	void clockSnapshot(uint64_t mono_ns, uint64_t boot_ns, uint64_t real_ns);

private:
	/* needs_incremental: packet references interned data (name_iid etc.),
	 * so it must carry SEQ_NEEDS_INCREMENTAL_STATE. */
	void writePacket(std::string &packet, bool needs_incremental = false);
	std::string trackEvent(int type, uint64_t track_uuid,
			       const std::string *name, bool intern_name,
			       const std::vector<Annotation> *annots);
	std::string debugAnnotation(const Annotation &a);

	/* Intern a string into one namespace; returns its iid and appends a new
	 * interned entry to pending_ (flushed on the next writePacket) if unseen.
	 * `field` is the InternedData field number for that namespace. */
	uint64_t intern(std::unordered_map<std::string, uint64_t> &table,
			uint64_t &next_iid, uint32_t field, const std::string &s);

	std::FILE *f_ = nullptr;
	bool first_ = true; /* first packet clears incremental state */
	static constexpr uint32_t kSeq = 1; /* single trusted sequence */

	/* Interning: one table + iid counter per namespace. iids are per-
	 * namespace and start at 1. pending_ accumulates InternedData entries
	 * created since the last packet, emitted with their first referencing
	 * packet. Tables are O(unique strings) — far fewer than total events. */
	std::unordered_map<std::string, uint64_t> event_names_;
	std::unordered_map<std::string, uint64_t> annot_names_;
	std::unordered_map<std::string, uint64_t> annot_strs_;
	uint64_t next_event_iid_ = 1;
	uint64_t next_annot_name_iid_ = 1;
	uint64_t next_annot_str_iid_ = 1;
	std::string pending_; /* InternedData body awaiting the next packet */
};

} // namespace pt

#endif
