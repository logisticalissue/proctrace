// SPDX-License-Identifier: GPL-2.0
#include "perfetto_trace.h"

namespace pt {

/* ---- protobuf primitives ---- */

static void putVarint(std::string &out, uint64_t v)
{
	while (v >= 0x80) {
		out.push_back((char)(v | 0x80));
		v >>= 7;
	}
	out.push_back((char)v);
}

static void putTag(std::string &out, uint32_t field, uint32_t wire)
{
	putVarint(out, (field << 3) | wire);
}

/* wire type 0: varint field (int32/int64 negatives are sign-extended to 64b,
 * which is exactly what protobuf expects for int32/int64 fields) */
static void putInt(std::string &out, uint32_t field, int64_t v)
{
	putTag(out, field, 0);
	putVarint(out, (uint64_t)v);
}

static void putUint(std::string &out, uint32_t field, uint64_t v)
{
	putTag(out, field, 0);
	putVarint(out, v);
}

static void putFixed64(std::string &out, uint32_t field, uint64_t v)
{
	putTag(out, field, 1);
	for (unsigned int i = 0; i < 8; i++) {
		out.push_back((char)(v & 0xff));
		v >>= 8;
	}
}

/* wire type 2: length-delimited (string or nested message) */
static void putBytes(std::string &out, uint32_t field, const std::string &b)
{
	putTag(out, field, 2);
	putVarint(out, b.size());
	out.append(b);
}

/* ---- Perfetto message builders ---- */

/*
 * Intern `s` into `table`. On first sight it gets the next iid and a new
 * InternedData entry (message {iid=1, name/str=2}, framed under `field`) is
 * appended to pending_ so it rides the next packet. Returns the iid.
 */
uint64_t TraceWriter::intern(std::unordered_map<std::string, uint64_t> &table,
			     uint64_t &next_iid, uint32_t field,
			     const std::string &s)
{
	auto it = table.find(s);
	if (it != table.end())
		return it->second;
	uint64_t iid = next_iid++;
	table.emplace(s, iid);
	std::string entry;
	putUint(entry, 1, iid);          /* iid */
	putBytes(entry, 2, s);           /* name / str */
	putBytes(pending_, field, entry);
	return iid;
}

/* DebugAnnotation: name_iid=1, string_value_iid=17, int_value=4. Both the
 * annotation name and (for string values) the value are interned. */
std::string TraceWriter::debugAnnotation(const Annotation &a)
{
	std::string m;
	putUint(m, 1, intern(annot_names_, next_annot_name_iid_, 3, a.name));
	if (a.kind == Annotation::STR)
		putUint(m, 17, intern(annot_strs_, next_annot_str_iid_, 4, a.str));
	else
		putInt(m, 4, a.i);
	return m;
}

/*
 * TrackEvent:
 *   type=9 (1=SLICE_BEGIN, 2=SLICE_END, 3=INSTANT)
 *   track_uuid=11, name=23, name_iid=10, debug_annotations=4
 * Slice names (argv) are mostly unique, so they stay inline (name=23);
 * instant names (open paths, "exit code N") recur, so they are interned. */
std::string TraceWriter::trackEvent(int type, uint64_t track_uuid,
				    const std::string *name, bool intern_name,
				    const std::vector<Annotation> *annots,
				    uint64_t flow_id, bool terminate_flow)
{
	std::string m;
	putUint(m, 9, (uint64_t)type);
	putUint(m, 11, track_uuid);
	if (name) {
		if (intern_name)
			putUint(m, 10,
				intern(event_names_, next_event_iid_, 2, *name));
		else
			putBytes(m, 23, *name);
	}
	if (annots)
		for (const auto &a : *annots)
			putBytes(m, 4, debugAnnotation(a));
	if (flow_id)
		putFixed64(m, terminate_flow ? 48 : 47, flow_id);
	return m;
}

/* ---- TraceWriter ---- */

TraceWriter::TraceWriter(const std::string &path)
{
	f_ = std::fopen(path.c_str(), "wb");
}

TraceWriter::~TraceWriter()
{
	if (f_)
		std::fclose(f_);
}

/*
 * Finalise a TracePacket: attach the trusted sequence id (and, on the very
 * first packet, SEQ_INCREMENTAL_STATE_CLEARED so the sequence is valid), then
 * frame it as Trace.packet (field 1, length-delimited) and write it out.
 */
void TraceWriter::writePacket(std::string &pkt, bool needs_incremental)
{
	if (!f_)
		return;
	putUint(pkt, 10, kSeq);          /* trusted_packet_sequence_id */

	/* Flush any interned entries created while building this packet; they
	 * must ship no later than the packet that first references them. */
	if (!pending_.empty()) {
		putBytes(pkt, 12, pending_); /* interned_data */
		pending_.clear();
		needs_incremental = true;
	}

	uint32_t flags = 0;
	if (first_) {
		flags |= 1;              /* SEQ_INCREMENTAL_STATE_CLEARED */
		first_ = false;
	}
	if (needs_incremental)
		flags |= 2;              /* SEQ_NEEDS_INCREMENTAL_STATE */
	if (flags)
		putUint(pkt, 13, flags); /* sequence_flags */

	std::string framed;
	putBytes(framed, 1, pkt);
	std::fwrite(framed.data(), 1, framed.size(), f_);
}

void TraceWriter::overviewRoot(uint64_t uuid, const std::string &name)
{
	std::string td;
	putUint(td, 1, uuid);            /* uuid */
	putBytes(td, 2, name);           /* name */
	putUint(td, 11, 2);              /* child_ordering = CHRONOLOGICAL */

	std::string pkt;
	putBytes(pkt, 60, td);
	writePacket(pkt);
}

void TraceWriter::overviewLane(uint64_t uuid, uint64_t parent_uuid,
			       const std::string &name)
{
	std::string td;
	putUint(td, 1, uuid);            /* uuid */
	putBytes(td, 2, name);           /* name */
	putUint(td, 5, parent_uuid);     /* parent_uuid */
	/* Do not merge same-named compiler lanes. This mode also makes the last
	 * descriptor name authoritative, allowing exec to replace the provisional
	 * fork-time label with its more useful argv-based label. */
	putUint(td, 15, 2);              /* SIBLING_MERGE_BEHAVIOR_NONE */

	std::string pkt;
	putBytes(pkt, 60, td);
	writePacket(pkt);
}

void TraceWriter::nativeProcess(uint64_t uuid, uint32_t pid,
				uint64_t start_ts_ns, const std::string &name)
{
	std::string process;
	putUint(process, 1, pid);          /* ProcessDescriptor.pid */
	putBytes(process, 6, name);        /* process_name */
	putUint(process, 7, start_ts_ns);  /* start_timestamp_ns */

	std::string td;
	putUint(td, 1, uuid);
	putBytes(td, 2, name);
	putBytes(td, 3, process);          /* TrackDescriptor.process */

	std::string pkt;
	putBytes(pkt, 60, td);
	writePacket(pkt);
}

void TraceWriter::counterTrack(uint64_t uuid, uint64_t parent_uuid,
			       const std::string &name, const std::string &unit)
{
	std::string counter;
	if (!unit.empty())
		putBytes(counter, 6, unit);     /* CounterDescriptor.unit_name */

	std::string td;
	putUint(td, 1, uuid);
	putBytes(td, 2, name);
	if (parent_uuid)
		putUint(td, 5, parent_uuid);
	putBytes(td, 8, counter);         /* counter descriptor */

	std::string pkt;
	putBytes(pkt, 60, td);
	writePacket(pkt);
}

void TraceWriter::sliceBegin(uint64_t track_uuid, uint64_t ts,
			     const std::string &name,
			     const std::vector<Annotation> &annots)
{
	std::string ev = trackEvent(1, track_uuid, &name, /*intern_name=*/false,
				    &annots);
	std::string pkt;
	putUint(pkt, 8, ts);             /* timestamp */
	putUint(pkt, 58, 3);             /* clock id = BUILTIN_MONOTONIC */
	putBytes(pkt, 11, ev);           /* track_event */
	writePacket(pkt, /*needs_incremental=*/true);
}

void TraceWriter::sliceEnd(uint64_t track_uuid, uint64_t ts)
{
	std::string ev = trackEvent(2, track_uuid, nullptr, false, nullptr);
	std::string pkt;
	putUint(pkt, 8, ts);
	putUint(pkt, 58, 3);
	putBytes(pkt, 11, ev);
	writePacket(pkt);
}

void TraceWriter::sliceEnd(uint64_t track_uuid, uint64_t ts,
			   const std::vector<Annotation> &annots)
{
	std::string ev = trackEvent(2, track_uuid, nullptr, false, &annots);
	std::string pkt;
	putUint(pkt, 8, ts);
	putUint(pkt, 58, 3);
	putBytes(pkt, 11, ev);
	writePacket(pkt, /*needs_incremental=*/true);
}

void TraceWriter::instant(uint64_t track_uuid, uint64_t ts,
			  const std::string &name,
			  const std::vector<Annotation> &annots)
{
	std::string ev = trackEvent(3, track_uuid, &name, /*intern_name=*/true,
				    &annots);
	std::string pkt;
	putUint(pkt, 8, ts);
	putUint(pkt, 58, 3);
	putBytes(pkt, 11, ev);
	writePacket(pkt, /*needs_incremental=*/true);
}

void TraceWriter::flowPoint(uint64_t track_uuid, uint64_t ts,
			    const std::string &name, uint64_t flow_id)
{
	std::string ev = trackEvent(3, track_uuid, &name, true, nullptr,
				    flow_id, false);
	std::string pkt;
	putUint(pkt, 8, ts);
	putUint(pkt, 58, 3);
	putBytes(pkt, 11, ev);
	writePacket(pkt, true);
}

void TraceWriter::flowEnd(uint64_t track_uuid, uint64_t ts,
			  const std::string &name, uint64_t flow_id)
{
	std::string ev = trackEvent(3, track_uuid, &name, true, nullptr,
				    flow_id, true);
	std::string pkt;
	putUint(pkt, 8, ts);
	putUint(pkt, 58, 3);
	putBytes(pkt, 11, ev);
	writePacket(pkt, true);
}

void TraceWriter::counter(uint64_t track_uuid, uint64_t ts, int64_t value)
{
	std::string ev = trackEvent(4, track_uuid, nullptr, false, nullptr);
	putInt(ev, 30, value);            /* TrackEvent.counter_value */
	std::string pkt;
	putUint(pkt, 8, ts);
	putUint(pkt, 58, 3);
	putBytes(pkt, 11, ev);
	writePacket(pkt);
}

void TraceWriter::clockSnapshot(uint64_t mono_ns, uint64_t boot_ns,
				uint64_t real_ns)
{
	/* ClockSnapshot.clocks=1 (repeated Clock{clock_id=1, timestamp=2}) */
	auto clock = [](uint32_t id, uint64_t ts) {
		std::string c;
		putUint(c, 1, id);
		putUint(c, 2, ts);
		return c;
	};
	std::string cs;
	putBytes(cs, 1, clock(3, mono_ns));  /* BUILTIN_CLOCK_MONOTONIC */
	putBytes(cs, 1, clock(6, boot_ns));  /* BUILTIN_CLOCK_BOOTTIME  */
	putBytes(cs, 1, clock(5, real_ns));  /* BUILTIN_CLOCK_REALTIME  */

	std::string pkt;
	putBytes(pkt, 6, cs);                /* clock_snapshot */
	writePacket(pkt);
}

} // namespace pt
