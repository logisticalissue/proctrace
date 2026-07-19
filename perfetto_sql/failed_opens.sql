-- Failed paths aggregated across all process lanes.
SELECT
  EXTRACT_ARG(arg_set_id, 'debug.path') AS path,
  EXTRACT_ARG(arg_set_id, 'debug.status') AS status,
  COUNT(*) AS failures,
  COUNT(DISTINCT track_id) AS process_lanes
FROM slice
WHERE name GLOB 'open *'
  AND EXTRACT_ARG(arg_set_id, 'debug.ret') < 0
GROUP BY path, status
ORDER BY failures DESC;
