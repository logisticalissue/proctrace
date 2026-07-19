-- Processes ranked by filesystem bytes accounted at process exit.
SELECT
  CAST(EXTRACT_ARG(arg_set_id, 'debug.pid') AS INT) AS pid,
  name AS command,
  EXTRACT_ARG(arg_set_id, 'debug.read_bytes') AS read_bytes,
  EXTRACT_ARG(arg_set_id, 'debug.write_bytes') AS write_bytes,
  COALESCE(EXTRACT_ARG(arg_set_id, 'debug.read_bytes'), 0) +
    COALESCE(EXTRACT_ARG(arg_set_id, 'debug.write_bytes'), 0) AS io_bytes
FROM slice
WHERE dur > 0 AND EXTRACT_ARG(arg_set_id, 'debug.read_bytes') IS NOT NULL
ORDER BY io_bytes DESC;
