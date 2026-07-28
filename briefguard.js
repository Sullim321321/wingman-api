// briefguard.js — a leg earns a briefing, or it stays silent.
//
// ─────────────────────────────────────────────────────────────────────────────
// The proactive spine (pre-departure push, arrival plan, day-of signal) speaks on
// a user's behalf. Two kinds of bad row have historically slipped through and made
// it lie:
//
// 1. A ROUTELESS leg. A flight with no origin or no destination produces the
//    "null → null departs in 24 hours" briefing we shipped once and never want
//    again. A leg with no route is malformed; it must never generate a briefing.
//
// 2. A leg with CORRUPT TIME. An epoch-0 / pre-2000 / unparseable departure is a
//    parser artefact, not a trip. It must never anchor a "departs in N hours"
//    message, a leave-by, or a signal.
//
// These invariants are currently enforced only inside SQL WHERE clauses, where
// they're untested and free to drift apart from each other and from the code that
// borrows them. This module states them once, in pure JS, so the crons and
// endpoints can share ONE predicate and a test can hold it. Persistence and
// queries stay the caller's job; the rule stays testable without a database.
// ─────────────────────────────────────────────────────────────────────────────

// A departure earlier than this is a parser artefact, not a trip. (Wingman did not
// exist before this; any leg claiming to depart before it is corrupt.)
const MIN_PLAUSIBLE_MS = Date.parse("2015-01-01T00:00:00Z");

// Statuses that mean "don't brief it": the flight is over or called off.
const DEAD_STATUSES = ["cancelled", "canceled", "landed", "completed", "archived"];

const nonEmpty = (v) => v != null && String(v).trim() !== "";

/** A real, forward-looking timestamp — not null, not NaN, not an epoch/pre-2015 artefact. */
function isRealTime(iso) {
  if (!nonEmpty(iso)) return false;
  const t = Date.parse(iso);
  return Number.isFinite(t) && t >= MIN_PLAUSIBLE_MS;
}

/** Does this leg name where it goes? Both endpoints must be present and non-empty. */
function hasRoute(leg) {
  return nonEmpty(leg?.origin) && nonEmpty(leg?.destination);
}

/**
 * Is this leg structurally broken — such that surfacing it anywhere would be a lie?
 *   • no route (would render "null → null"), or
 *   • a corrupt/epoch departure time, or
 *   • it arrives before it departs (time runs backwards).
 * A missing ARRIVAL alone is not malformed — plenty of honest legs lack one.
 */
function isMalformedLeg(leg) {
  if (!leg) return true;
  if (!hasRoute(leg)) return true;
  if (leg.departs_at != null && !isRealTime(leg.departs_at)) return true;
  const dep = Date.parse(leg?.departs_at);
  const arr = Date.parse(leg?.arrives_at);
  if (Number.isFinite(dep) && Number.isFinite(arr) && arr < dep) return true;
  return false;
}

/**
 * Should the proactive spine speak about this leg? It must be a flight, structurally
 * sound, still live (not cancelled/landed), and carry a real departure time. This is
 * the single "null → null" guard the pre-departure cron and the signal builder share.
 *   opts.types — leg types considered briefable (default: flights only).
 */
function isBriefableLeg(leg, opts = {}) {
  if (isMalformedLeg(leg)) return false;
  const types = opts.types || ["flight"];
  if (!types.includes(String(leg.type || "").toLowerCase())) return false;
  if (DEAD_STATUSES.includes(String(leg.status || "").toLowerCase())) return false;
  if (!isRealTime(leg.departs_at)) return false;
  return true;
}

/** Filter a set of legs down to those that may be briefed. Pure; order preserved. */
function briefableLegs(legs, opts = {}) {
  return (legs || []).filter((l) => isBriefableLeg(l, opts));
}

module.exports = {
  MIN_PLAUSIBLE_MS, DEAD_STATUSES,
  isRealTime, hasRoute, isMalformedLeg, isBriefableLeg, briefableLegs,
};
