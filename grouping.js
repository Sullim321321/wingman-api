// grouping.js — the predicates that decide whether two bookings are one trip.
//
// These live outside server.js for one reason: they were WRONG in two places at
// once and nothing could see it. The grouper united legs on any shared
// confirmation string; the splitter refused to unite legs whose shared
// confirmation spanned more than a journey. Both were reasonable alone. Together
// they were an infinite loop — import, merge, repair, split, import, merge —
// which from the outside looks exactly like a grouping bug that won't stay fixed.
//
// One definition, imported by both sides, testable without a database.

// ── Is this string actually a booking reference? ────────────────────────────
//
// The confirmation number is the STRONGEST grouping signal in the system: two legs
// that share one are treated as one booking, and a leg that matches an existing
// confirmation is discarded as a duplicate. Both of those are destructive if the
// string isn't really a reference.
//
// Parsers put all sorts of things in this field: "N/A", "Confirmed", "Pending", a
// loyalty number, a fare class. Those collide across unrelated bookings — and the
// collision doesn't merely mis-file, it can DROP a leg as a duplicate of a trip a
// year away. So a reference has to look like one before it is allowed to speak.
const NOT_A_REFERENCE = new Set([
  "n/a", "na", "none", "null", "unknown", "tbd", "pending", "confirmed",
  "confirmation", "booked", "see email", "n a", "-", "--", "0", "00000",
]);

function usableConfirmation(raw) {
  const c = String(raw || "").trim();
  if (c.length < 5) return null;                       // too short to be unique
  const lc = c.toLowerCase();
  if (NOT_A_REFERENCE.has(lc)) return null;
  if (!/[a-z0-9]/i.test(c)) return null;
  if (/^\d{1,4}$/.test(c)) return null;                 // a bare small number
  return lc;
}

/**
 * May a shared confirmation number pull `whenISO` into a trip spanning s → e?
 *
 * Yes, unless the reference would reach further than a journey plausibly runs.
 * A confirmation shared across nine months is a recycled reference, a loyalty
 * number that landed in the wrong field, or a parse error — not one booking.
 *
 * Returns { ok, days }. `days` is how far the reference reached, so the caller
 * can say WHY it declined instead of just declining.
 */
function confirmationReachOk(whenISO, s, e, maxTripDays) {
  if (!whenISO || !s) return { ok: true, days: 0 };   // nothing to contradict
  const w = new Date(whenISO).getTime();
  const a = new Date(s).getTime();
  const b = new Date(e || s).getTime();
  if ([w, a, b].some(Number.isNaN)) return { ok: true, days: 0 };
  const days = Math.round(Math.max(Math.abs(w - a), Math.abs(w - b)) / 86400000);
  return { ok: days <= maxTripDays, days };
}

module.exports = { usableConfirmation, confirmationReachOk, NOT_A_REFERENCE };
