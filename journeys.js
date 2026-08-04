// journeys.js — home-to-home journey grouping.
//
// The mega-trip splitter (unmergeMegaTrips) separates legs more than SPLIT_GAP_DAYS apart
// into different trips. On real data that over-shreds: a Nashville trip with a 10-day stay,
// or a there-and-back with a connection, becomes three or four "trips" — one of them named
// after the HOME airport (a flight home is the tail of a trip, not a new trip) and another
// after a layover. The splitter has no concept of "home."
//
// This module adds that concept. A journey is home → away → home. A new journey begins only
// after a leg ARRIVES at a home airport; until then, gaps don't matter — you're still away.
// Two uses:
//   • planTripMerges — repair: stitch already-fragmented trips back into journeys (preview-first)
//   • unionClustersByHome — prevention: re-join the splitter's date-gap clusters into journeys
//
// Deliberately conservative: with no home airports known, it does nothing. It never welds
// two trips separated by more than maxGapDays (guards against a missing return-home leg
// gluing a March trip to a July one).

const DAY = 86400000;
const AIRPORTy = new Set(["flight", "train", "ferry", "cruise"]); // legs that carry O/D codes

const toTime = (v) => {
  if (v == null || v === "") return null;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? null : t;
};

// Normalize a home-airports value (array, JSON string, or CSV) into an uppercase code Set.
function homeSetOf(homeAirports) {
  let arr = homeAirports;
  if (typeof arr === "string") {
    try { arr = JSON.parse(arr); } catch { arr = arr.split(/[,\s]+/); }
  }
  if (!Array.isArray(arr)) arr = arr ? [arr] : [];
  return new Set(
    arr.map((c) => String(c || "").toUpperCase().trim()).filter((c) => /^[A-Z]{3}$/.test(c))
  );
}

const isTransport = (l) => AIRPORTy.has(String((l && l.type) || "").toLowerCase());

// Does this leg land at a home airport?
function legArrivesHome(leg, homeSet) {
  if (!isTransport(leg)) return false;
  const d = String((leg && leg.destination) || "").toUpperCase().trim();
  return d.length === 3 && homeSet.has(d);
}

const legsOf = (trip) => (trip && trip.legs) || [];
const datedLegs = (trip) => legsOf(trip).filter((l) => toTime(l.departs_at) != null);

function tripEarliestDep(trip) {
  const ts = datedLegs(trip).map((l) => toTime(l.departs_at));
  return ts.length ? Math.min(...ts) : null;
}
function tripLastEnd(trip) {
  const ts = legsOf(trip).map((l) => toTime(l.arrives_at) ?? toTime(l.departs_at)).filter((t) => t != null);
  return ts.length ? Math.max(...ts) : null;
}
// Does the trip's LAST transport leg (by departure) arrive home? That closes a journey.
function tripEndsHome(trip, homeSet) {
  const flights = legsOf(trip)
    .filter((l) => isTransport(l) && toTime(l.departs_at) != null)
    .sort((a, b) => toTime(a.departs_at) - toTime(b.departs_at));
  if (!flights.length) return false;
  return legArrivesHome(flights[flights.length - 1], homeSet);
}

/**
 * REPAIR. Given the user's trips (each { id, title, legs:[...] }) and their home airports,
 * return the merges needed to reunite home-to-home journeys:
 *   [{ keepTripId, mergeTripIds:[...], titles:[...] }]
 * Only groups of 2+ trips are returned (a single trip needs no merge). The earliest trip in
 * a journey is the keeper; the caller moves the others' legs into it and retitles.
 */
function planTripMerges(trips, homeAirports, opts = {}) {
  const homeSet = homeAirports instanceof Set ? homeAirports : homeSetOf(homeAirports);
  if (homeSet.size === 0) return [];
  const maxGap = opts.maxGapDays != null ? opts.maxGapDays : 30;

  const sorted = (trips || [])
    .filter((t) => tripEarliestDep(t) != null)
    .sort((a, b) => tripEarliestDep(a) - tripEarliestDep(b));

  const groups = [];
  let cur = null;
  for (const t of sorted) {
    if (!cur) { cur = [t]; continue; }
    const prev = cur[cur.length - 1];
    const gapDays = (tripEarliestDep(t) - tripLastEnd(cur[cur.length - 1])) / DAY;
    // Boundary: the previous trip already returned home, OR the gap is too large to trust
    // (a missing return-home leg must not glue unrelated trips together).
    if (tripEndsHome(prev, homeSet) || gapDays > maxGap) {
      groups.push(cur);
      cur = [t];
    } else {
      cur.push(t);
    }
  }
  if (cur) groups.push(cur);

  return groups
    .filter((g) => g.length > 1)
    .map((g) => ({
      keepTripId: g[0].id,
      mergeTripIds: g.slice(1).map((t) => t.id),
      titles: g.map((t) => t.title),
    }));
}

/**
 * PREVENTION. The splitter builds date-gap clusters (each { legs:[...], end }). Re-join any
 * adjacent clusters that aren't actually separated by a return home, so a home-to-home
 * journey survives the split as one trip. Same rule as planTripMerges, at the cluster level.
 */
function unionClustersByHome(clusters, homeAirports, opts = {}) {
  const homeSet = homeAirports instanceof Set ? homeAirports : homeSetOf(homeAirports);
  if (homeSet.size === 0 || !Array.isArray(clusters) || clusters.length < 2) return clusters || [];
  const maxGap = opts.maxGapDays != null ? opts.maxGapDays : 30;

  const clusterEndsHome = (c) => {
    const flights = (c.legs || [])
      .filter((l) => isTransport(l) && toTime(l.departs_at) != null)
      .sort((a, b) => toTime(a.departs_at) - toTime(b.departs_at));
    return flights.length ? legArrivesHome(flights[flights.length - 1], homeSet) : false;
  };
  const clusterStart = (c) => {
    const ts = (c.legs || []).map((l) => toTime(l.departs_at)).filter((t) => t != null);
    return ts.length ? Math.min(...ts) : null;
  };

  const out = [];
  for (const c of clusters) {
    if (!out.length) { out.push({ legs: [...(c.legs || [])], end: c.end }); continue; }
    const prev = out[out.length - 1];
    const gapDays = (clusterStart(c) - prev.end) / DAY;
    if (clusterEndsHome(prev) || gapDays > maxGap) {
      out.push({ legs: [...(c.legs || [])], end: c.end });
    } else {
      prev.legs.push(...(c.legs || []));
      prev.end = Math.max(prev.end, c.end);
    }
  }
  return out;
}

/**
 * STANDING GUARD for invariant #3 (FOUNDATION.md). A well-formed trip is one home-to-home
 * journey. This flags the two pathologies — without changing anything — so they're visible
 * and can't silently recur:
 *   • welded:    a home ARRIVAL that isn't the trip's last transport leg → two journeys in one
 *   • tail-frag: the trip arrives home but never departed from home → a return leg orphaned
 *                into its own "trip" (the EWR→PIT-as-"Pittsburgh" over-split)
 * Returns [{ tripId, title, reason }]. Pure; needs home airports (empty → no opinion).
 */
function auditGrouping(trips, homeAirports) {
  const homeSet = homeAirports instanceof Set ? homeAirports : homeSetOf(homeAirports);
  if (homeSet.size === 0) return [];
  const out = [];
  for (const t of trips || []) {
    const flights = legsOf(t)
      .filter((l) => isTransport(l) && toTime(l.departs_at) != null)
      .sort((a, b) => toTime(a.departs_at) - toTime(b.departs_at));
    if (!flights.length) continue;

    // welded: a homecoming that the trip continues past
    for (let i = 0; i < flights.length - 1; i++) {
      if (legArrivesHome(flights[i], homeSet)) {
        out.push({ tripId: t.id, title: t.title, reason: "spans a return home — should be two trips" });
        break;
      }
    }
    // tail-fragment: arrives home but never left home (a lone return leg made its own trip)
    const first = flights[0];
    const last = flights[flights.length - 1];
    const departsFromHome = homeSet.has(String((first.origin) || "").toUpperCase().trim());
    if (legArrivesHome(last, homeSet) && !departsFromHome) {
      out.push({ tripId: t.id, title: t.title, reason: "arrives home but never departed home — a return-leg fragment" });
    }
  }
  return out;
}

module.exports = {
  homeSetOf, legArrivesHome, tripEndsHome, planTripMerges, unionClustersByHome, auditGrouping,
};
