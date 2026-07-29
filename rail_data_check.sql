-- rail_data_check.sql — is the ground solid before we build the rail spine?
-- Read-only. Paste into the Neon SQL Editor. Three questions, three results.
-- The seam (transport.isWatchable) needs: a real departs_at (>= 2015, not epoch),
-- both endpoints (station_from/station_to OR origin/destination), and time that
-- doesn't run backwards. This checks whether ingested train legs actually have them.

-- ── 1. Health of train legs: how many exist, and how many are watchable? ──
SELECT
  count(*)                                                        AS train_legs_total,
  count(*) FILTER (WHERE departs_at > now())                      AS upcoming,
  count(*) FILTER (WHERE departs_at >= '2015-01-01')              AS real_departs_at,
  count(*) FILTER (WHERE departs_at < '2015-01-01' OR departs_at IS NULL) AS corrupt_or_missing_time,
  count(*) FILTER (WHERE COALESCE(NULLIF(TRIM(station_from),''), NULLIF(TRIM(origin),'')) IS NOT NULL
                     AND COALESCE(NULLIF(TRIM(station_to),''),   NULLIF(TRIM(destination),'')) IS NOT NULL)
                                                                  AS has_both_endpoints,
  -- the seam's isWatchable, expressed in SQL, restricted to upcoming:
  count(*) FILTER (
    WHERE departs_at > now()
      AND departs_at >= '2015-01-01'
      AND COALESCE(NULLIF(TRIM(station_from),''), NULLIF(TRIM(origin),'')) IS NOT NULL
      AND COALESCE(NULLIF(TRIM(station_to),''),   NULLIF(TRIM(destination),'')) IS NOT NULL
      AND (arrives_at IS NULL OR arrives_at >= departs_at)
  )                                                               AS watchable_upcoming
FROM trip_legs
WHERE type = 'train';

-- ── 2. Which networks show up? (decides UK-first vs where Amtrak etc. matter) ──
SELECT COALESCE(NULLIF(TRIM(carrier),''),'(no operator)') AS operator,
       count(*) AS legs,
       count(*) FILTER (WHERE departs_at > now()) AS upcoming
FROM trip_legs
WHERE type = 'train'
GROUP BY 1
ORDER BY legs DESC;

-- ── 3. Eyeball the fields on the most recent train legs ──
SELECT id, departs_at, arrives_at,
       station_from, station_to, origin, destination,
       carrier, flight_number, status, state
FROM trip_legs
WHERE type = 'train'
ORDER BY departs_at DESC NULLS LAST
LIMIT 20;
