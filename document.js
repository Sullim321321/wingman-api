// document.js — the rules of the trip document, in one place.
//
// ─────────────────────────────────────────────────────────────────────────────
// A trip is one document. The Dossier reads all of it; Home reads today's page.
// Those are two windows onto the same thing, so they must agree about what a leg
// IS — which chapter it belongs to, whether it's a ride worth mentioning, what to
// call it.
//
// This module exists because of what happened with the trip title. That rule lived
// in two functions, one got fixed, the other didn't, and running the repair would
// have restored the exact bug the fix removed. Two implementations of one rule is
// not redundancy — it's a race between versions, and the loser ships.
//
// So before Home gets its own copy of "is this happening now": there is no copy.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Which chapter does this leg belong to?
 *
 * PLAN       a sketch — proposed, or undated. Still being decided.
 * PREPARE    booked, dated, ahead of you.
 * IN MOTION  happening right now.
 * AFTER      done.
 *
 * A LEG's chapter is decided by ITS OWN times, never by the trip's. The first
 * version of this asked whether the TRIP was in motion and, if so, shoved every leg
 * into "happening now" — so a flight three days out rendered as in progress. If
 * "happening now" doesn't mean happening now, the word is worthless on the one
 * screen where you'd act on it.
 */
function chapterOf(leg, nowMs) {
  if (!leg) return "plan";
  if (leg.state === "proposed" || !leg.departs_at) return "plan";
  const dep = new Date(leg.departs_at).getTime();
  if (Number.isNaN(dep)) return "plan";
  const arr = leg.arrives_at ? new Date(leg.arrives_at).getTime() : dep;
  if (nowMs > (Number.isNaN(arr) ? dep : arr)) return "after";
  if (nowMs >= dep && nowMs <= (Number.isNaN(arr) ? dep : arr)) return "in_motion";
  return "prepare";
}

/**
 * A property_name that is just the CITY is not a name — it's a label the importer
 * fell back to. Those four "Nashville" cards were address-to-address rides whose
 * property_name had been set to "Nashville", which made isRide think they had a name
 * and legName proudly print the city. A ride to 250 Rep John Lewis Way is not "the
 * Nashville". So a city-as-name counts as no name at all.
 */
function isCityLabel(leg) {
  const n = String(leg?.property_name || "").trim().toLowerCase();
  if (!n) return false;
  const city = String(leg.destination_city || leg.destination || "").trim().toLowerCase();
  return !!city && n === city;
}

// A real, specific name — not blank, not the city.
function hasRealName(leg) {
  return (!!leg.property_name && !isCityLabel(leg)) || !!leg.vehicle_class || !!leg.nights || !!leg.confirmation;
}

// Pull a specific place out of an address, when that's all we have. "2021 Broadway,
// Nashville, TN" → "2021 Broadway". A bare ZIP or the city itself doesn't count.
function venueFrom(leg) {
  const raw = leg.location || leg.address || leg.destination || "";
  const first = String(raw).split(/\s*(?:→|->|;|\n)\s*/)[0].split(",")[0].trim();
  const city = String(leg.destination_city || "").trim().toLowerCase();
  if (!first || /^\d{4,6}$/.test(first) || first.toLowerCase() === city) return "";
  return first;
}

/**
 * An Uber is an expense; a seaplane is an appointment.
 *
 * Address-to-address rides with the same weight as a hotel are noise. But pretending
 * they didn't happen is its own lie, so they're counted, not deleted. The distinction
 * is a real NAME — and the city is not one.
 */
function isRide(leg) {
  const t = String(leg?.type || "").toLowerCase();
  return (t === "car" || t === "transfer" || t === "ride" || t === "taxi") && !hasRealName(leg);
}

/** What a person should see on the card. `fid` is the flightid module. */
function legName(leg, fid) {
  if (!leg) return "";
  if (leg.type === "flight" && fid) return fid.displayName(leg);
  if (leg.property_name && !isCityLabel(leg)) return leg.property_name;
  // property_name is missing or just the city — reach for a specific place first.
  return venueFrom(leg) || leg.property_name || leg.destination_city || leg.destination || leg.type || "booking";
}

/**
 * Is this whole trip in the past? True only when there IS dated, real (non-proposed)
 * evidence and every bit of it has finished — so a finished trip stops calling itself
 * "in motion". A trip with any live or upcoming leg, or with nothing dated to judge,
 * is not "past".
 */
function tripIsPast(legs, nowMs) {
  const dated = (legs || []).filter((l) => l.state !== "proposed" && l.departs_at && !Number.isNaN(new Date(l.departs_at).getTime()));
  if (!dated.length) return false;
  return dated.every((l) => chapterOf(l, nowMs) === "after");
}

/**
 * Is any of this real?
 *
 * A trip built entirely from proposals is an IDEA, and a screen has to say so in its
 * own voice rather than leaving someone to infer it from four dashed borders. She
 * asked where she might go for three days; she should not have to audit border
 * styles to find out whether she's going.
 */
function certaintyOf(legs) {
  return (legs || []).some((l) => l.state !== "proposed") ? "real" : "idea";
}

/** Split legs into chapters, counting rides rather than listing them. */
function toChapters(legs, nowMs, fid, depBy = {}) {
  const chapters = { plan: [], prepare: [], in_motion: [], after: [] };
  const rides = { plan: 0, prepare: 0, in_motion: 0, after: 0 };
  for (const l of legs || []) {
    const ch = chapterOf(l, nowMs);
    if (isRide(l)) { rides[ch]++; continue; }
    chapters[ch].push({ ...l, display_name: legName(l, fid), depends_on: depBy[l.id] || [] });
  }
  return { chapters, rides };
}

module.exports = { chapterOf, isRide, legName, certaintyOf, toChapters, isCityLabel, tripIsPast, venueFrom };
