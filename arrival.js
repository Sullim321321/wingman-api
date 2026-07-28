// arrival.js — the arrival plan: land, clear the airport, make the meeting.
//
// ─────────────────────────────────────────────────────────────────────────────
// The day-of chain, as one computed answer: you land at X; your next real meeting
// is at Y; the drive is N minutes; so leave the curb by Z — and here's whether you
// actually make it. Pure and dependency-free: it takes the three facts (arrival,
// meeting, travel minutes) and returns the plan plus an honest verdict. The API glue
// (flight status, calendar, travelTime, the ride deep link) lives in server.js; the
// JUDGEMENT lives here so it can be tested without a network.
//
// Honesty: if a fact is missing — no arrival time, no meeting, no route — the plan
// says so in `verdict: "unknown"` and leaves the derived times null. It never guesses
// a leave-by it cannot defend, the same rule the "when to leave" card already follows.
// ─────────────────────────────────────────────────────────────────────────────

const MIN = 60000;
const ms = (v) => { if (v == null || v === "") return null; const t = new Date(v).getTime(); return Number.isNaN(t) ? null : t; };

/**
 * @param arrival      flight arrival time (ISO or ms)
 * @param meeting      { start, title?, venue?, address? } — the next in-person meeting, or null
 * @param travelMin    driving/transit minutes airport→venue, or null if no route
 * @param opts.deplaneMin  time from wheels-down to curb (default 20)
 * @param opts.bagsMin     add if a checked bag (default 0)
 * @param opts.arrivePadMin cushion before the meeting start (default 5)
 * @returns the plan (see fields below)
 */
function plan(arrival, meeting, travelMin, opts = {}) {
  const deplaneMin = opts.deplaneMin != null ? opts.deplaneMin : 20;
  const bagsMin = opts.bagsMin != null ? opts.bagsMin : 0;
  const arrivePadMin = opts.arrivePadMin != null ? opts.arrivePadMin : 5;

  const landMs = ms(arrival);
  const meetMs = meeting ? ms(meeting.start) : null;
  const hasTravel = travelMin != null && !Number.isNaN(Number(travelMin));

  const out = {
    land_at: landMs != null ? new Date(landMs).toISOString() : null,
    ready_to_leave_at: null,   // off the plane, past bags — at the curb
    meeting: meeting || null,
    travel_minutes: hasTravel ? Math.round(Number(travelMin)) : null,
    leave_airport_by: null,    // the latest you can pull away and still make it
    arrive_venue_by: meetMs != null ? new Date(meetMs).toISOString() : null,
    slack_minutes: null,
    verdict: "unknown",        // comfortable | tight | wont_make_it | no_meeting | unknown
  };

  if (landMs == null) return out;                       // can't plan without a landing
  const readyMs = landMs + (deplaneMin + bagsMin) * MIN;
  out.ready_to_leave_at = new Date(readyMs).toISOString();

  if (!meeting || meetMs == null) { out.verdict = "no_meeting"; return out; }
  if (!hasTravel) return out;                            // meeting known but no route → unknown

  const leaveByMs = meetMs - arrivePadMin * MIN - Math.round(Number(travelMin)) * MIN;
  out.leave_airport_by = new Date(leaveByMs).toISOString();
  const slack = Math.round((leaveByMs - readyMs) / MIN);
  out.slack_minutes = slack;
  out.verdict = slack < 0 ? "wont_make_it" : slack < 30 ? "tight" : "comfortable";
  return out;
}

// ── The active window (Roadmap v4, C) ────────────────────────────────────────
// The arrival surface must not light up for a flight 15 hours out — the exact bug that
// shipped. A flight is "active" only when it's genuinely happening: in the air, just
// landed, or inside the head-to-the-airport window. A malformed leg (arrives before it
// departs) is never active. Pure so the gate is unit-tested, not eyeballed on a device.
const ACTIVE = {
  boardingMs:   4 * 3600000,  // heading to the airport
  justLandedMs: 2 * 3600000,  // arrived recently
};

function isArrivalActive(flight, nowMs = Date.now()) {
  if (!flight) return false;
  const dep = flight.departs_at ? ms(flight.departs_at) : null;
  const arr = ms(flight.arrives_at);
  if (arr == null) return false;                         // no landing → nothing to plan
  if (dep != null && arr <= dep) return false;           // malformed leg — never active
  if (dep != null && dep <= nowMs && nowMs <= arr) return true;         // in the air
  if (arr < nowMs && nowMs - arr <= ACTIVE.justLandedMs) return true;   // landed <2h ago
  if (dep != null && dep > nowMs && dep - nowMs <= ACTIVE.boardingMs) return true; // boarding
  return false;
}

// From a set of flights (ordered soonest-departure first), the one to surface — the
// in-air leg if any, else the first that's active. Null when none qualify.
function pickActiveFlight(flights, nowMs = Date.now()) {
  const list = Array.isArray(flights) ? flights : [];
  const inAir = list.find((f) => {
    const dep = f.departs_at ? ms(f.departs_at) : null, arr = ms(f.arrives_at);
    return dep != null && arr != null && arr > dep && dep <= nowMs && nowMs <= arr;
  });
  if (inAir) return inAir;
  return list.find((f) => isArrivalActive(f, nowMs)) || null;
}

// ── Operator timing (Roadmap v4, C1) — pure bits pulled out of the poll loops ──

// O2 · the re-timed arrival after a delay. A slipped departure moves the landing, which
// moves the door time and the car. Returns a NEW iso string when the landing shifted by
// more than 5 minutes (worth re-pushing the leave-by); null when it didn't move enough or
// we can't tell. Prefers the live estimate; falls back to the old arrival + the delay.
function retimedArrival(currentArrivesAt, live = {}) {
  const cur = ms(currentArrivesAt);
  if (cur == null) return null;
  let next = live.estimatedArrival ? ms(live.estimatedArrival) : null;
  if (next == null && live.delayMinutes) next = cur + Math.round(live.delayMinutes) * MIN;
  if (next == null || Number.isNaN(next)) return null;
  if (Math.abs(next - cur) <= 5 * MIN) return null;      // not worth a re-push
  return new Date(next).toISOString();
}

// The "leave {airport} by …" nudge fires only when the door time is imminent — within the
// next 90 minutes and not more than 15 past. One window here so the poll and its tests
// can't disagree about "imminent".
const NUDGE = { leadMs: 90 * MIN, graceMs: 15 * MIN };
function shouldNudgeLeaveBy(leaveByMs, nowMs = Date.now()) {
  if (leaveByMs == null || Number.isNaN(leaveByMs)) return false;
  return (leaveByMs - nowMs) <= NUDGE.leadMs && (nowMs - leaveByMs) <= NUDGE.graceMs;
}

// O4 · the check-in nudge gate. The trigger is ARRIVAL, not the clock: on a trip with
// flights, wait until the inbound has landed (don't nudge check-in mid-flight); on a
// drive/other trip with no flight to key off, fire when check-in is imminent — within 4h
// before, up to 6h after. Pure so the poll loop and its tests share one definition.
const CHECKIN = { leadMs: 4 * 3600000, graceMs: 6 * 3600000 };
function shouldNudgeCheckin({ hasFlights, inboundLanded, checkInMs, nowMs = Date.now() } = {}) {
  if (hasFlights) return !!inboundLanded;
  if (checkInMs == null || Number.isNaN(checkInMs)) return false;
  return (checkInMs - nowMs) <= CHECKIN.leadMs && (nowMs - checkInMs) <= CHECKIN.graceMs;
}

module.exports = { plan, isArrivalActive, pickActiveFlight, ACTIVE, retimedArrival, shouldNudgeLeaveBy, NUDGE, shouldNudgeCheckin, CHECKIN };
