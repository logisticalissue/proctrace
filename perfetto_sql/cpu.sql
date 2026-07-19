-- Processes ranked by total CPU time. Lifetime fields are emitted as
-- debug annotations on the process slice.
SELECT
  CAST(EXTRACT_ARG(arg_set_id, 'debug.pid') AS INT) AS pid,
  name AS command,
  EXTRACT_ARG(arg_set_id, 'debug.cpu_user_ms') AS user_ms,
  EXTRACT_ARG(arg_set_id, 'debug.cpu_sys_ms') AS system_ms,
  COALESCE(EXTRACT_ARG(arg_set_id, 'debug.cpu_user_ms'), 0) +
    COALESCE(EXTRACT_ARG(arg_set_id, 'debug.cpu_sys_ms'), 0) AS cpu_ms,
  dur / 1e6 AS wall_ms
FROM slice
WHERE dur > 0 AND EXTRACT_ARG(arg_set_id, 'debug.pid') IS NOT NULL
ORDER BY cpu_ms DESC;
