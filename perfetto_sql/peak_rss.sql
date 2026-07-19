-- Processes ranked by peak resident memory.
SELECT
  CAST(EXTRACT_ARG(arg_set_id, 'debug.pid') AS INT) AS pid,
  name AS command,
  EXTRACT_ARG(arg_set_id, 'debug.peak_rss_kb') AS peak_rss_kb,
  EXTRACT_ARG(arg_set_id, 'debug.peak_vm_kb') AS peak_vm_kb,
  dur / 1e6 AS wall_ms
FROM slice
WHERE dur > 0 AND EXTRACT_ARG(arg_set_id, 'debug.peak_rss_kb') IS NOT NULL
ORDER BY peak_rss_kb DESC;
