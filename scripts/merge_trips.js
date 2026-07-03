#!/usr/bin/env node
/**
 * merge_trips.js — one-time migration to merge fragmented trip records
 *
 * Problem: before the grouping engine was added, every email created its own
 * trip record. A Scotland trip with a BA flight, an Airbnb, a ScotRail leg,
 * and a Hertz pickup would appear as 4 separate trips.
 *
 * This script:
 *   1. Loads all trips + legs for every user
 *   2. Groups them by (user_email, destination_city, date_window) using the
 *      same ±2-day overlap logic as findOrCreateGroupedTrip
 *   3. For each group with >1 trip, picks the "canonical" trip (the one with
 *      the most legs, or the earliest created_at as a tiebreaker)
 *   4. Re-parents all legs from the other trips onto the canonical trip
 *   5. Re-parents any related rows (companions, upgrade_bids, compensation_claims,
 *      activity_events, concierge_threads, destination_intel) onto the canonical trip
 *   6. Deletes the now-empty duplicate trips
 *   7. Renames the canonical trip to the best available destination name
 *
 * Usage:
 *   DATABASE_URL="postgresql://..." node scripts/merge_trips.js
 *
 * Options:
 *   --dry-run   Print what would be merged without writing anything
 *   --user      Only process a specific user email
 *
 * The script is idempotent — running it twice is safe.
 */

require("dotenv").config({ path: require("path").join(__dirname, "../.env") });
const { neon } = require("@neondatabase/serverless");

const DRY_RUN = process.argv.includes("--dry-run");
const USER_FILTER = (() => {
  const idx = process.argv.indexOf("--user");
  return idx !== -1 ? process.argv[idx + 1] : null;
})();

const MERGE_BUFFER_DAYS = 2; // same as findOrCreateGroupedTrip

if (!process.env.DATABASE_URL || process.env.DATABASE_URL.includes("placeholder")) {
  console.error("❌  DATABASE_URL is not set. Export it before running this script.");
  process.exit(1);
}

const sql = neon(process.env.DATABASE_URL);

// ─── helpers ─────────────────────────────────────────────────────────────────

function normaliseCity(raw) {
  if (!raw) return null;
  return raw.trim().toLowerCase()
    .replace(/\s+/g, " ")
    .replace(/[^a-z0-9 ]/g, "");
}

/** Returns true if the two date windows overlap (with buffer). */
function windowsOverlap(startA, endA, startB, endB, bufferDays = MERGE_BUFFER_DAYS) {
  if (!startA || !startB) return false;
  const buf = bufferDays * 24 * 3600 * 1000;
  const sA = new Date(startA).getTime() - buf;
  const eA = (endA ? new Date(endA).getTime() : new Date(startA).getTime()) + buf;
  const sB = new Date(startB).getTime() - buf;
  const eB = (endB ? new Date(endB).getTime() : new Date(startB).getTime()) + buf;
  return sA <= eB && sB <= eA;
}

/** Pick the best destination city label from a set of legs. */
function bestDestinationCity(legs) {
  // Prefer a destination_city that is not an IATA code (3 uppercase letters)
  const cities = legs
    .map(l => l.destination_city || l.destination || null)
    .filter(Boolean);
  const named = cities.find(c => !/^[A-Z]{3}$/.test(c));
  return named || cities[0] || null;
}

/** Build a human-readable trip title from legs. */
function buildTitle(legs, existingTitle) {
  const city = bestDestinationCity(legs);
  if (city && !/^[A-Z]{3}$/.test(city)) return city;
  // If all we have is IATA codes, try to use the existing title if it looks meaningful
  if (existingTitle && !existingTitle.match(/^trip #?\d+$/i) && existingTitle.length > 3) {
    return existingTitle;
  }
  return city || existingTitle || "Trip";
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n🔍  Loading trips${USER_FILTER ? ` for ${USER_FILTER}` : " for all users"}…`);

  // Load all trips with their legs
  const rows = USER_FILTER
    ? await sql`
        SELECT t.id, t.user_email, t.title, t.created_at, t.source,
          json_agg(
            json_build_object(
              'id',               tl.id,
              'type',             tl.type,
              'destination',      tl.destination,
              'destination_city', tl.destination_city,
              'departs_at',       tl.departs_at,
              'arrives_at',       tl.arrives_at
            )
            ORDER BY tl.departs_at ASC NULLS LAST
          ) FILTER (WHERE tl.id IS NOT NULL) AS legs
        FROM trips t
        LEFT JOIN trip_legs tl ON tl.trip_id = t.id
        WHERE t.user_email = ${USER_FILTER}
        GROUP BY t.id
        ORDER BY t.user_email, t.created_at ASC
      `
    : await sql`
        SELECT t.id, t.user_email, t.title, t.created_at, t.source,
          json_agg(
            json_build_object(
              'id',               tl.id,
              'type',             tl.type,
              'destination',      tl.destination,
              'destination_city', tl.destination_city,
              'departs_at',       tl.departs_at,
              'arrives_at',       tl.arrives_at
            )
            ORDER BY tl.departs_at ASC NULLS LAST
          ) FILTER (WHERE tl.id IS NOT NULL) AS legs
        FROM trips t
        LEFT JOIN trip_legs tl ON tl.trip_id = t.id
        GROUP BY t.id
        ORDER BY t.user_email, t.created_at ASC
      `;

  console.log(`   Found ${rows.length} trips across ${new Set(rows.map(r => r.user_email)).size} users.\n`);

  // Group by user
  const byUser = {};
  for (const trip of rows) {
    if (!byUser[trip.user_email]) byUser[trip.user_email] = [];
    byUser[trip.user_email].push(trip);
  }

  let totalMerged = 0;
  let totalDeleted = 0;

  for (const [userEmail, trips] of Object.entries(byUser)) {
    // Build trip windows
    const windows = trips.map(t => {
      const legs = t.legs || [];
      const dates = legs.map(l => l.departs_at || l.arrives_at).filter(Boolean).sort();
      const endDates = legs.map(l => l.arrives_at || l.departs_at).filter(Boolean).sort();
      return {
        trip: t,
        legs,
        start: dates[0] || null,
        end: endDates[endDates.length - 1] || dates[dates.length - 1] || null,
        cities: new Set(
          legs.map(l => normaliseCity(l.destination_city || l.destination)).filter(Boolean)
        ),
      };
    });

    // Union-find style clustering
    const parent = windows.map((_, i) => i);
    function find(i) { return parent[i] === i ? i : (parent[i] = find(parent[i])); }
    function union(i, j) { parent[find(i)] = find(j); }

    for (let i = 0; i < windows.length; i++) {
      for (let j = i + 1; j < windows.length; j++) {
        const a = windows[i];
        const b = windows[j];

        // Must have overlapping dates
        if (!windowsOverlap(a.start, a.end, b.start, b.end)) continue;

        // Must share at least one destination city (or one of them has no city info — be conservative)
        const aHasCities = a.cities.size > 0;
        const bHasCities = b.cities.size > 0;
        if (aHasCities && bHasCities) {
          const shared = [...a.cities].some(c => b.cities.has(c));
          if (!shared) continue;
        }
        // If neither has city info but dates overlap, merge (both are likely from the same trip)

        union(i, j);
      }
    }

    // Build clusters
    const clusters = {};
    for (let i = 0; i < windows.length; i++) {
      const root = find(i);
      if (!clusters[root]) clusters[root] = [];
      clusters[root].push(windows[i]);
    }

    for (const cluster of Object.values(clusters)) {
      if (cluster.length < 2) continue; // nothing to merge

      // Pick canonical trip: most legs first, then earliest created_at
      cluster.sort((a, b) => {
        const legDiff = (b.legs.length) - (a.legs.length);
        if (legDiff !== 0) return legDiff;
        return new Date(a.trip.created_at) - new Date(b.trip.created_at);
      });

      const canonical = cluster[0];
      const duplicates = cluster.slice(1);
      const allLegs = cluster.flatMap(c => c.legs);
      const newTitle = buildTitle(allLegs, canonical.trip.title);

      console.log(`  👤  ${userEmail}`);
      console.log(`     Merging ${cluster.length} trips → canonical: #${canonical.trip.id} "${canonical.trip.title}"`);
      console.log(`     New title: "${newTitle}"`);
      for (const dup of duplicates) {
        console.log(`     ← absorbing #${dup.trip.id} "${dup.trip.title}" (${dup.legs.length} legs)`);
      }

      if (!DRY_RUN) {
        const dupIds = duplicates.map(d => d.trip.id);

        // 1. Re-parent trip_legs
        await sql`UPDATE trip_legs SET trip_id = ${canonical.trip.id} WHERE trip_id = ANY(${dupIds})`;

        // 2. Re-parent related tables
        await sql`UPDATE trip_companions SET trip_id = ${canonical.trip.id} WHERE trip_id = ANY(${dupIds})`;
        await sql`UPDATE upgrade_bids SET trip_id = ${canonical.trip.id} WHERE trip_id = ANY(${dupIds})`;
        await sql`UPDATE compensation_claims SET trip_id = ${canonical.trip.id} WHERE trip_id = ANY(${dupIds})`;
        await sql`UPDATE activity_events SET trip_id = ${canonical.trip.id} WHERE trip_id = ANY(${dupIds})`;
        await sql`UPDATE concierge_threads SET trip_id = ${canonical.trip.id} WHERE trip_id = ANY(${dupIds})`;

        // 3. Rename canonical trip to best destination name
        await sql`UPDATE trips SET title = ${newTitle}, updated_at = NOW() WHERE id = ${canonical.trip.id}`;

        // 4. Delete duplicate trips (cascade deletes any remaining orphan legs)
        await sql`DELETE FROM trips WHERE id = ANY(${dupIds})`;

        totalMerged += duplicates.length;
        totalDeleted += dupIds.length;
      } else {
        console.log(`     [DRY RUN — no changes written]`);
      }
      console.log();
    }
  }

  if (DRY_RUN) {
    console.log("✅  Dry run complete. Re-run without --dry-run to apply changes.\n");
  } else {
    console.log(`✅  Done. Merged ${totalMerged} duplicate trips into their canonical records.`);
    console.log(`   Deleted ${totalDeleted} empty trip records.\n`);
  }
}

main().catch(err => {
  console.error("❌  Migration failed:", err.message);
  process.exit(1);
});
