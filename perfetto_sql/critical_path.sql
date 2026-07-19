-- Likely critical-path starting points. This is deliberately a heuristic:
-- proctrace observes process dependency (ppid) but not build-system target
-- dependencies. Long-lived descendants ending near the trace end are the
-- most useful process chains to inspect first, aided by fork/exec flow arrows.
WITH lifetimes AS (
  SELECT
    CAST(EXTRACT_ARG(arg_set_id, 'debug.pid') AS INT) AS pid,
    CAST(EXTRACT_ARG(arg_set_id, 'debug.ppid') AS INT) AS ppid,
    name AS command,
    ts,
    dur,
    ts + dur AS end_ts
  FROM slice
  WHERE dur > 0 AND EXTRACT_ARG(arg_set_id, 'debug.pid') IS NOT NULL
), trace_end AS (
  SELECT MAX(end_ts) AS ts FROM lifetimes
)
SELECT
  pid,
  ppid,
  command,
  dur / 1e6 AS wall_ms,
  (trace_end.ts - end_ts) / 1e6 AS ms_before_trace_end
FROM lifetimes, trace_end
ORDER BY ms_before_trace_end ASC, wall_ms DESC
LIMIT 50;
