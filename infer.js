// infer.js — a meeting in a place you're not near means you have to get there.
//
// ─────────────────────────────────────────────────────────────────────────────
// This is the "it knows me" step: turn the calendar into travel. The value is
// entirely in the RESTRAINT — propose a trip only when the evidence is clear, ask
// when it isn't, and stay silent for the Zoom calls.
//
// Now judged by DISTANCE, not string matching. Each commitment carries a resolved
// `geo` ({ city, lat, lng }); "out of town" means the meeting is farther than
// `radiusMiles` from where you currently are. That's why Evanston folds into a
// Chicago trip (12 miles) instead of becoming its own question — a thing no amount
// of city-name matching could ever get right.
//
// "Handle changes so I don't have to" falls out for free: travel needs are a pure
// function of the current calendar + where you are. Nobody "handles" a
// cancellation — when a meeting moves, turns virtual, or you're already there,
// re-running simply doesn't produce the need. Undoing a real BOOKING is the one
// thing that isn't automatic: that's a permissioned proposal, computed one layer up.
//
// Honesty rules, in order:
//   virtual / unknown-nature → no travel, ever.
//   we don't know where you are → ASK (can't judge distance without a "from").
//   in-person, unresolved place → ASK (never invent a location).
//   in-person, within radius → no travel (you're already there / it's local).
//   in-person, far → PROPOSE a trip.
//   ambiguous (link AND place) → ASK, even if far. We don't know it's travel.
//
// Pure and dependency-free (haversine is the only import, itself pure).
// ─────────────────────────────────────────────────────────────────────────────

const { haversineMiles } = require("./geo");

const DEFAULT_RADIUS_MI = 50; // same-metro / "you're basically there" threshold
const ms = (v) => { const t = new Date(v).getTime(); return Number.isNaN(t) ? null : t; };
const hasCoords = (g) => !!(g && g.lat != null && g.lng != null);
const near = (a, b, mi) => haversineMiles(a, b) <= mi;

/**
 * Turn calendar commitments into travel needs, judged against where you are now.
 *
 * @param commitments  normalized events enriched with { nature, place, geo:{city,lat,lng} }
 * @param opts.now         epoch ms; only future meetings drive travel
 * @param opts.current    { city, lat, lng } where you are now (geolocation, later)
 * @param opts.radiusMiles anything within this of `current` is "not travel"
 * @returns needs: { kind:"propose_trip"|"ask", destination, geo, reason, question, driver, arrive_by, depart_after, certain:false, source }
 */
function inferTravelNeeds(commitments, opts = {}) {
  const now = opts.now != null ? opts.now : Date.now();
  const current = opts.current || null;
  const radius = opts.radiusMiles != null ? opts.radiusMiles : DEFAULT_RADIUS_MI;

  const needs = [];
  for (const c of commitments || []) {
    if (!c) continue;
    const startMs = ms(c.start);
    if (startMs == null || startMs <= now) continue;                 // past / undated
    if (c.nature === "virtual" || c.nature === "unknown") continue;  // never travel

    const geo = c.geo || null;
    const driver = {
      calendar_id: c.calendar_id || null,
      title: c.title || "(no title)",
      start: c.start, end: c.end || c.start,
      account_email: c.account_email || null,
      nature: c.nature,
    };
    const base = {
      destination: geo && geo.city ? geo.city : null, geo,
      driver, arrive_by: c.start, depart_after: c.end || c.start,
      certain: false, source: "inferred_from_calendar",
    };
    const ask = (reason, question) => needs.push({ ...base, kind: "ask", reason, question });

    // Can't judge distance without knowing where you are.
    if (!current || !hasCoords(current)) {
      ask(`"${driver.title}" is in person${geo && geo.city ? ` in ${geo.city}` : ""}, but I don't know where you are right now.`,
          `Where are you right now? I can tell you if "${driver.title}" needs travel once I know.`);
      continue;
    }

    if (c.nature === "ambiguous") {
      // Both a link and a place — could be a flight, could be a dial-in. Never a
      // silent booking. (Your Texas Rangers / Dallas meeting.)
      if (hasCoords(geo) && near(geo, current, radius)) continue; // local anyway
      ask(`"${driver.title}" has both a video link and a place${geo && geo.city ? ` (${geo.city})` : ""}.`,
          `Are you attending "${driver.title}"${geo && geo.city ? ` in ${geo.city}` : ""} in person, or remotely?`);
      continue;
    }

    // in_person
    if (!hasCoords(geo)) {
      ask(`"${driver.title}" looks in person but I couldn't locate it.`,
          `Where is "${driver.title}"? I couldn't resolve "${c.place || c.location || ""}".`);
      continue;
    }
    if (near(geo, current, radius)) continue; // you're already there / it's local

    needs.push({
      ...base, kind: "propose_trip",
      reason: `In-person meeting in ${geo.city || "another city"}${current.city ? ` and you're in ${current.city}` : ""} (${Math.round(haversineMiles(geo, current))} mi away).`,
      question: null,
    });
  }
  return needs;
}

/**
 * Collapse per-meeting needs into trip proposals: in-person meetings within
 * `radiusMiles` of each other are ONE trip (Chicago + Evanston = one Chicago trip),
 * spanning the earliest arrive_by to the latest depart_after. Asks stay individual —
 * each is a distinct open question. A cluster is labeled by a `hubs` city if it
 * contains one (so the metro name wins over the suburb), else the most common city.
 */
function groupTrips(needs, opts = {}) {
  const radius = opts.radiusMiles != null ? opts.radiusMiles : DEFAULT_RADIUS_MI;
  const hubs = (opts.hubs || []).map((h) => String(h).toLowerCase());

  const proposals = [], asks = [];
  for (const n of needs || []) (n.kind === "propose_trip" ? proposals : asks).push(n);

  const clusters = [];
  for (const n of proposals) {
    let placed = false;
    for (const cl of clusters) {
      if (cl.some((m) => hasCoords(m.geo) && hasCoords(n.geo) && near(m.geo, n.geo, radius))) {
        cl.push(n); placed = true; break;
      }
    }
    if (!placed) clusters.push([n]);
  }

  const trips = clusters.map((cl) => {
    cl.sort((a, b) => ms(a.arrive_by) - ms(b.arrive_by));
    // Label: prefer a hub city in the cluster, else the most frequent city.
    const cities = cl.map((n) => n.destination).filter(Boolean);
    const hubCity = cities.find((c) => hubs.includes(String(c).toLowerCase()));
    const freq = {};
    cities.forEach((c) => (freq[c] = (freq[c] || 0) + 1));
    const topCity = Object.keys(freq).sort((a, b) => freq[b] - freq[a])[0] || null;
    return {
      kind: "propose_trip",
      destination: hubCity || topCity,
      arrive_by: cl[0].arrive_by,
      depart_after: cl.reduce((late, n) => (ms(n.depart_after) > ms(late) ? n.depart_after : late), cl[0].depart_after),
      drivers: cl.map((n) => n.driver),
      reason: cl.length === 1
        ? cl[0].reason
        : `${cl.length} in-person meetings around ${hubCity || topCity}.`,
      certain: false, source: "inferred_from_calendar",
    };
  });

  return { trips, asks };
}

module.exports = { inferTravelNeeds, groupTrips };
