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

module.exports = { plan };
