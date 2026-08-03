// companions.js — model who is on a trip, and which legs belong to whom.
//
// The companion / multi-traveler leap (Roadmap v4, Epic E), Slice 1: the reasoning core.
// Pure + dependency-free and test-first, mirroring itinerary.js / regroup.js / holds.js —
// the DB columns, endpoints, and UI build on top of this in later slices.
//
// THE MODEL
//   A trip has travelers. A leg is SHARED by default — it applies to everyone on the trip
//   (the flight you all take together). A leg may instead name a SUBSET of travelers via
//   `leg.traveler_ids`: the "two rooms in Asia" case — two people, two hotel rooms, one
//   shared flight. Absent or empty `traveler_ids` = shared.
//
// HONESTY RULES (same discipline as the rest of the codebase)
//   - Never invent a traveler: an assignment referencing an unknown id is dropped, and
//     validateAssignment reports it rather than silently accepting garbage.
//   - A subset that resolves to nobody known falls back to SHARED, never to empty — a leg
//     that belongs to no one is a data error, not a real state.

const OWNER = "owner"; // role of the account holder; always a traveler on their own trips

// Canonical traveler list: dedupe by id (or email), ensure each has an id + a display name.
function normalizeTravelers(travelers = []) {
  const seen = new Set();
  const out = [];
  for (const t of travelers || []) {
    if (!t) continue;
    const id = String(t.id || t.email || "").trim().toLowerCase();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push({
      id,
      name: String(t.name || t.email || id).trim(),
      role: t.role || "companion",
    });
  }
  return out;
}

// A leg is shared when it names no specific travelers.
function isShared(leg) {
  return !Array.isArray(leg && leg.traveler_ids) || leg.traveler_ids.length === 0;
}

// The traveler ids a leg applies to. A named subset wins (unknown ids dropped); an empty
// or all-unknown subset falls back to SHARED = everyone on the trip.
function travelersForLeg(leg, travelers = []) {
  const norm = normalizeTravelers(travelers);
  const known = new Set(norm.map((t) => t.id));
  const ids = Array.isArray(leg && leg.traveler_ids)
    ? leg.traveler_ids.map((x) => String(x).toLowerCase())
    : [];
  const named = ids.filter((id) => known.has(id));
  return named.length === 0 ? [...known] : named;
}

// Every leg that applies to a given traveler — their personal itinerary within the trip.
function legsForTraveler(travelerId, legs = [], travelers = []) {
  const id = String(travelerId || "").toLowerCase();
  const norm = normalizeTravelers(travelers);
  return (legs || []).filter((l) => travelersForLeg(l, norm).includes(id));
}

// Per-traveler breakdown: { traveler, legs, sharedCount, soloCount }. `soloCount` is the
// legs named specifically to that traveler (their own room/seat), not the shared ones.
function perTravelerItinerary(travelers = [], legs = []) {
  const norm = normalizeTravelers(travelers);
  return norm.map((tr) => {
    const mine = legsForTraveler(tr.id, legs, norm);
    const shared = mine.filter(isShared).length;
    return { traveler: tr, legs: mine, sharedCount: shared, soloCount: mine.length - shared };
  });
}

// Validate an assignment update before it's written: split requested ids into the ones we
// recognize and the ones we don't (which the caller must reject, never invent).
function validateAssignment(travelerIds = [], travelers = []) {
  const known = new Set(normalizeTravelers(travelers).map((t) => t.id));
  const req = (travelerIds || []).map((x) => String(x).toLowerCase());
  return { valid: req.filter((id) => known.has(id)), unknown: req.filter((id) => !known.has(id)) };
}

module.exports = {
  OWNER,
  normalizeTravelers,
  isShared,
  travelersForLeg,
  legsForTraveler,
  perTravelerItinerary,
  validateAssignment,
};
