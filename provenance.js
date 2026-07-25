// provenance.js — a suggestion must never become a fact.
//
// ─────────────────────────────────────────────────────────────────────────────
// Two failure modes turn a sketch into a lie, and this module names both so they
// can be tested and repaired instead of merely hoped-against.
//
// 1. A sketch WEARING A BOOKING'S CLOTHES. A proposed leg may be DATED — "fly in
//    around the 17th" is an honest suggestion — but it must never carry a booking's
//    IDENTITY: a confirmation code, a flight number, a seat, a gate. Those are the
//    exact fields that make a fiction indistinguishable from a fact to someone
//    standing in an airport. planner.stripShape() throws them away at creation; this
//    catches the ones that got in another way (import, rescan, an older code path)
//    so they can be stripped from rows that already exist.
//
// 2. A sketch THAT SHOULD HAVE EXPIRED. A proposal is a live idea, not a permanent
//    one. A suggested leg whose date has already passed, or that has sat unconfirmed
//    long past its shelf life, is no longer a suggestion — it's clutter that reads
//    like a plan. It expires.
//
// Pure and dependency-free: it takes plain leg rows and returns a verdict. The
// persistence (nulling columns, marking expired) is the caller's job, so the rule
// stays testable without a database.
// ─────────────────────────────────────────────────────────────────────────────

const DAY = 86400000;

// A proposal that isn't booked. These states are sketches; anything else is real.
const SKETCH_STATES = ["proposed", "considered", "held"];

// The fields that turn a sketch into an apparent booking. A DATE is allowed on a
// sketch (it's a suggestion about when); a booking's IDENTITY is not. Mirrors
// planner.FORBIDDEN_ON_A_PLAN minus departs_at/arrives_at, which a dated proposal
// legitimately carries.
const BOOKING_IDENTITY = [
  "confirmation", "flight_number", "pnr", "booking_reference",
  "record_locator", "seat", "gate", "terminal",
];

function isSketch(leg) {
  return SKETCH_STATES.includes(String(leg?.state || "").toLowerCase());
}

/**
 * Which booking-identity fields is this sketch wearing that it must not? Returns the
 * offending field names (empty array = clean). A real (booked) leg is never flagged —
 * it's entitled to its confirmation.
 */
function factClothes(leg) {
  if (!isSketch(leg)) return [];
  return BOOKING_IDENTITY.filter((k) => {
    const v = leg[k];
    return v != null && String(v).trim() !== "";
  });
}

/**
 * Is this sketch stale? A proposal has expired when:
 *   • its suggested date has already passed (a plan for last week is not a plan), or
 *   • it has aged past `ttlDays` since creation AND is not anchored to a future date.
 * A dated future proposal never expires by age — it's still a live idea about a real
 * upcoming window. Only sketches expire; booked legs never do.
 */
function isStaleSketch(leg, nowMs, ttlDays = 21) {
  if (!isSketch(leg)) return false;
  const dep = leg.departs_at ? Date.parse(leg.departs_at) : NaN;
  if (!Number.isNaN(dep) && dep < nowMs) return true;        // its date is in the past
  const created = leg.created_at ? Date.parse(leg.created_at) : NaN;
  if (!Number.isNaN(created) && nowMs - created > ttlDays * DAY) {
    if (Number.isNaN(dep)) return true;                      // undated + old = dead idea
  }
  return false;
}

/**
 * Audit a set of legs. Returns what a repair pass should do:
 *   strip:  [{ id, fields }]  — null these booking-identity columns on this row
 *   expire: [{ id }]          — mark this sketch expired (hide it; it's no longer live)
 * Pure: computes the verdict, performs nothing.
 */
function auditLegs(legs, nowMs = Date.now(), ttlDays = 21) {
  const strip = [], expire = [];
  for (const l of legs || []) {
    const fields = factClothes(l);
    if (fields.length) strip.push({ id: l.id, fields });
    if (isStaleSketch(l, nowMs, ttlDays)) expire.push({ id: l.id });
  }
  return { strip, expire };
}

/**
 * A read-time guard: return a COPY of the leg with any booking-identity blanked if it's
 * a sketch, so a proposal can never render as a booking even if a bad row slipped past
 * the repair. Real legs pass through untouched. Belt-and-braces for the display layer.
 */
function sanitize(leg) {
  if (!leg || !isSketch(leg)) return leg;
  const offending = factClothes(leg);
  if (!offending.length) return leg;
  const clean = { ...leg };
  for (const k of offending) clean[k] = null;
  return clean;
}

module.exports = {
  SKETCH_STATES, BOOKING_IDENTITY,
  isSketch, factClothes, isStaleSketch, auditLegs, sanitize,
};
