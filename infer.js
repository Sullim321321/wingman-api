// infer.js — a meeting in a city you're not in means you have to get there.
//
// ─────────────────────────────────────────────────────────────────────────────
// This is the "it knows me" step: turn the calendar into travel. But the value is
// entirely in the RESTRAINT. The dangerous version proposes a trip for every
// meeting with a place in it; the trustworthy version proposes one only when the
// evidence is unambiguous, and asks when it isn't.
//
// The design that makes "handle changes so I don't have to" fall out for free:
// travel needs are a PURE FUNCTION of the current calendar + where you are. Nobody
// "handles" a cancellation. When a meeting moves, turns virtual, or you're already
// in the city, re-running this simply doesn't produce the need anymore. The change
// takes care of itself because nothing was ever stored that has to be undone.
// (Undoing a real BOOKING is different — that's a permissioned proposal, computed
// by diffing these needs against what's booked. It lives one layer up, not here.)
//
// The honesty rules, in order:
//   virtual / unknown-nature   → no travel. Ever. (A Zoom call is not a trip.)
//   in-person, city unknown    → ASK. We saw a place we couldn't turn into a city;
//                                 unknown never silently becomes a booked flight.
//   in-person, same city       → no travel. You're already there.
//   in-person, other city      → PROPOSE a trip.
//   ambiguous (link AND place) → ASK, even if it's out of town. We don't know it's
//                                 travel, so we don't assert it is.
//
// Pure and dependency-free. `resolveCity` is injected so the same logic runs on a
// tiny built-in gazetteer today and on real geocoding later, without changing a rule.
// ─────────────────────────────────────────────────────────────────────────────

// A pragmatic starter set — major business cities plus your bases. Not exhaustive;
// when a place doesn't resolve, we ASK rather than pretend. Real geocoding replaces
// this later by swapping the resolver, not the rules.
const DEFAULT_CITIES = [
  "New York", "London", "Nashville", "Chicago", "Dallas", "Austin", "Houston",
  "San Francisco", "Los Angeles", "Seattle", "Boston", "Washington", "Atlanta",
  "Miami", "Denver", "Toronto", "Paris", "Berlin", "Amsterdam", "Dublin",
  "N.Y.C.", "Manhattan",
];
// Aliases fold onto a canonical city so "NYC" and "Manhattan" are New York.
const ALIASES = {
  "nyc": "New York", "n.y.c.": "New York", "manhattan": "New York", "new york city": "New York",
  "sf": "San Francisco", "la": "Los Angeles", "d.c.": "Washington", "dc": "Washington",
};

function makeCityResolver(extraCities = []) {
  // Longest names first so "New York" wins over a stray "York".
  const cities = [...new Set([...DEFAULT_CITIES, ...extraCities])]
    .sort((a, b) => b.length - a.length);
  return (text) => {
    const t = " " + String(text || "").toLowerCase().replace(/[^a-z. ]/g, " ").replace(/\s+/g, " ") + " ";
    for (const alias of Object.keys(ALIASES)) {
      if (t.includes(" " + alias + " ")) return { city: ALIASES[alias], confidence: "matched" };
    }
    for (const c of cities) {
      if (t.includes(" " + c.toLowerCase() + " ")) return { city: c, confidence: "matched" };
    }
    return { city: null, confidence: "unknown" };
  };
}

const sameCity = (a, b) =>
  a && b && String(a).trim().toLowerCase() === String(b).trim().toLowerCase();

const ms = (v) => { const t = new Date(v).getTime(); return Number.isNaN(t) ? null : t; };

/**
 * Turn calendar commitments into travel needs, judged against where you are now.
 *
 * @param commitments  normalized events (gcal.js shape) enriched with { nature, place }
 * @param opts.now         epoch ms; only future meetings drive travel
 * @param opts.currentCity where you are right now (from geolocation, later)
 * @param opts.bases       your home cities (["New York","London"]) — resolvable + never "away"
 * @param opts.resolveCity injected place→city; defaults to the built-in gazetteer
 * @returns array of needs: { kind:"propose_trip"|"ask", destination, reason, question, driver, arrive_by, depart_after, certain:false, source }
 */
function inferTravelNeeds(commitments, opts = {}) {
  const now = opts.now != null ? opts.now : Date.now();
  const currentCity = opts.currentCity || null;
  const bases = opts.bases || [];
  const resolveCity = opts.resolveCity || makeCityResolver(bases);

  const needs = [];
  for (const c of commitments || []) {
    if (!c) continue;
    const startMs = ms(c.start);
    if (startMs == null || startMs <= now) continue;         // past / undated → not a live driver
    if (c.nature === "virtual" || c.nature === "unknown") continue; // never travel

    const driver = {
      calendar_id: c.calendar_id || null,
      title: c.title || "(no title)",
      start: c.start, end: c.end || c.start,
      account_email: c.account_email || null,
      nature: c.nature,
    };
    const { city } = resolveCity(c.place || c.location || "");

    if (c.nature === "ambiguous") {
      // Both a link and a place: could be a flight, could be a dial-in. A question,
      // never a booking — this is your Texas Rangers / Dallas meeting.
      if (city && sameCity(city, currentCity)) continue; // already there → no travel either way
      needs.push({
        kind: "ask", destination: city, driver,
        arrive_by: c.start, depart_after: c.end || c.start,
        reason: `"${driver.title}" has both a video link and a place${city ? ` (${city})` : ""}.`,
        question: `Are you attending "${driver.title}"${city ? ` in ${city}` : ""} in person, or remotely?`,
        certain: false, source: "inferred_from_calendar",
      });
      continue;
    }

    // in_person
    if (!city) {
      needs.push({
        kind: "ask", destination: null, driver,
        arrive_by: c.start, depart_after: c.end || c.start,
        reason: `"${driver.title}" looks in person but I couldn't tell what city.`,
        question: `Where is "${driver.title}"? I couldn't read a city from "${c.place || c.location || ""}".`,
        certain: false, source: "inferred_from_calendar",
      });
      continue;
    }
    if (sameCity(city, currentCity)) continue; // you're already in that city

    needs.push({
      kind: "propose_trip", destination: city, driver,
      arrive_by: c.start, depart_after: c.end || c.start,
      reason: `In-person meeting in ${city}${currentCity ? ` and you're in ${currentCity}` : ""}.`,
      question: null,
      certain: false, source: "inferred_from_calendar",
    });
  }
  return needs;
}

/**
 * Collapse per-meeting needs into trip proposals: several in-person meetings in the
 * same city on nearby days are ONE trip, not three. Only propose_trip needs group;
 * asks stay individual (each is a distinct open question). A trip spans from the
 * earliest arrive_by to the latest depart_after among its drivers.
 */
function groupTrips(needs) {
  const trips = [];
  const asks = [];
  const byCity = new Map();
  for (const n of needs || []) {
    if (n.kind !== "propose_trip") { asks.push(n); continue; }
    const key = String(n.destination).toLowerCase();
    if (!byCity.has(key)) byCity.set(key, []);
    byCity.get(key).push(n);
  }
  for (const [, group] of byCity) {
    group.sort((a, b) => ms(a.arrive_by) - ms(b.arrive_by));
    trips.push({
      kind: "propose_trip",
      destination: group[0].destination,
      arrive_by: group[0].arrive_by,
      depart_after: group.reduce((late, n) => (ms(n.depart_after) > ms(late) ? n.depart_after : late), group[0].depart_after),
      drivers: group.map((n) => n.driver),
      reason: group.length === 1
        ? group[0].reason
        : `${group.length} in-person meetings in ${group[0].destination}.`,
      certain: false, source: "inferred_from_calendar",
    });
  }
  return { trips, asks };
}

module.exports = { inferTravelNeeds, groupTrips, makeCityResolver, sameCity };
