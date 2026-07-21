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
 * An Uber is an expense; a seaplane is an appointment.
 *
 * Four address-to-address "Nashville" rides sitting in an itinerary with the same
 * weight as a hotel is noise, and noise is what makes a briefing unreadable. But
 * pretending they didn't happen is its own lie, so they're counted, not deleted.
 *
 * The distinction is a NAME. An Uber doesn't have one. "Seaplane transfer" does, and
 * a named transfer stays visible — it's exactly the kind of thing the cascade defends.
 */
function isRide(leg) {
  return (leg?.type === "car" || leg?.type === "transfer") &&
    !leg.property_name && !leg.vehicle_class && !leg.nights && !leg.confirmation;
}

/** What a person should see on the card. `fid` is the flightid module. */
function legName(leg, fid) {
  if (!leg) return "";
  if (leg.type === "flight" && fid) return fid.displayName(leg);
  return leg.property_name || leg.destination_city || leg.destination || leg.type || "booking";
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

module.exports = { chapterOf, isRide, legName, certaintyOf, toChapters };
