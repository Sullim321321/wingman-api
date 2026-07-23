// itinerary.js — turn "you need to be in Chicago" into "fly in Wed morning, one night."
//
// ─────────────────────────────────────────────────────────────────────────────
// The chief-of-staff move that follows the trip proposal: don't just say you need
// to travel — say HOW. Arrive before the first meeting with room to breathe, leave
// after the last, book the nights in between. This proposes the SKELETON, not a
// booking:
//
//   • Times are TARGETS, not fares. We name no flight number and no price, because
//     we haven't priced anything — saying "$412 on United 1" when we didn't check
//     is the exact lie this project refuses. `priced: false` says so out loud.
//   • Arrival is conservative: for a morning meeting you fly in the evening BEFORE,
//     because a chief of staff doesn't gamble your 9am on a dawn flight.
//   • The hotel is only named if history says which one — otherwise "a hotel in
//     Chicago." A guess about where you like to stay is still a guess.
//
// Pure and dependency-free. airportOf / hotelOf are injected, so the same logic runs
// on the built-in map today and on richer data (your stay history) later.
// ─────────────────────────────────────────────────────────────────────────────

// City → primary airport + rough UTC offset. The offset only decides "morning vs
// afternoon," so a DST hour of slop doesn't matter for a proposal. Extend freely.
const AIRPORTS = {
  "new york":      { code: "JFK", tz: -4 },
  "london":        { code: "LHR", tz: 1 },
  "nashville":     { code: "BNA", tz: -5 },
  "chicago":       { code: "ORD", tz: -5 },
  "evanston":      { code: "ORD", tz: -5 },
  "dallas":        { code: "DFW", tz: -5 },
  "austin":        { code: "AUS", tz: -5 },
  "houston":       { code: "IAH", tz: -5 },
  "san francisco": { code: "SFO", tz: -7 },
  "los angeles":   { code: "LAX", tz: -7 },
  "seattle":       { code: "SEA", tz: -7 },
  "boston":        { code: "BOS", tz: -4 },
  "washington":    { code: "IAD", tz: -4 },
  "atlanta":       { code: "ATL", tz: -4 },
  "miami":         { code: "MIA", tz: -4 },
  "denver":        { code: "DEN", tz: -6 },
  "toronto":       { code: "YYZ", tz: -4 },
  "paris":         { code: "CDG", tz: 2 },
};

function makeAirportResolver() {
  return (city) => AIRPORTS[String(city || "").trim().toLowerCase()] || null;
}

const ms = (v) => { const t = new Date(v).getTime(); return Number.isNaN(t) ? null : t; };
const HOUR = 3600000, DAY = 86400000;

// Local wall-clock hour and calendar-day index for an instant at a UTC offset.
function localHour(iso, tz) { return (new Date(ms(iso) + tz * HOUR)).getUTCHours(); }
function localDayIndex(iso, tz) { return Math.floor((ms(iso) + tz * HOUR) / DAY); }
function atLocalHour(iso, tz, hour) {
  // Return the ISO instant for `hour`:00 local on the same local day as `iso`.
  const dayStartUtc = localDayIndex(iso, tz) * DAY - tz * HOUR;
  return new Date(dayStartUtc + hour * HOUR).toISOString();
}

/**
 * Propose the skeleton of a trip.
 *
 * @param trip    { destination, arrive_by, depart_after }  (a groupTrips() trip)
 * @param opts.current    { city }  where you'd fly from
 * @param opts.airportOf  city -> { code, tz } | null   (injected; default map)
 * @param opts.hotelOf    city -> hotelName | null       (injected; default none)
 * @returns { destination, flight_in, flight_out, nights, hotel, certain:false, priced:false, note, gaps:[] }
 */
function proposeItinerary(trip, opts = {}) {
  const airportOf = opts.airportOf || makeAirportResolver();
  const hotelOf = opts.hotelOf || (() => null);
  const current = opts.current || null;

  const gaps = [];
  const destAir = airportOf(trip.destination);
  const fromAir = current && current.city ? airportOf(current.city) : null;
  if (!fromAir) gaps.push(current && current.city
    ? `couldn't map "${current.city}" to an airport`
    : "I don't know your home airport (need where you are)");
  if (!destAir) gaps.push(`couldn't map "${trip.destination}" to an airport`);

  // ── flight in ──────────────────────────────────────────────────────────────
  // Aim to be settled ~3h before the first meeting. If that lands before 9am local
  // (a dawn flight), come in the evening before instead.
  let targetArrival = null, arrivalBasis = null;
  if (destAir) {
    const tz = destAir.tz;
    const meetHour = localHour(trip.arrive_by, tz);
    const settledBy = new Date(ms(trip.arrive_by) - 3 * HOUR).toISOString();
    if (localHour(settledBy, tz) < 9 || meetHour < 11) {
      targetArrival = atLocalHour(new Date(ms(trip.arrive_by) - DAY).toISOString(), tz, 19); // 7pm night before
      arrivalBasis = "evening before — your first meeting is too early to fly in same-day";
    } else {
      targetArrival = settledBy;
      arrivalBasis = "same day, a few hours before your first meeting";
    }
  }

  const flight_in = {
    from: fromAir ? fromAir.code : null,
    to: destAir ? destAir.code : null,
    target_arrival: targetArrival,
    basis: arrivalBasis,
  };

  // ── flight out ─────────────────────────────────────────────────────────────
  // Leave a couple hours after the last meeting ends.
  const targetDeparture = new Date(ms(trip.depart_after) + 2 * HOUR).toISOString();
  const flight_out = {
    from: destAir ? destAir.code : null,
    to: fromAir ? fromAir.code : null,
    target_departure: targetDeparture,
  };

  // ── nights ─────────────────────────────────────────────────────────────────
  // Hotel nights = local calendar days between arrival and departure.
  let nights = 0;
  if (destAir && targetArrival) {
    nights = Math.max(0, localDayIndex(targetDeparture, destAir.tz) - localDayIndex(targetArrival, destAir.tz));
  }
  const hotelName = hotelOf(trip.destination);
  const hotel = nights > 0
    ? { name: hotelName || null, city: trip.destination, nights }
    : null; // day trip — no hotel

  return {
    destination: trip.destination,
    flight_in,
    flight_out,
    nights,
    hotel,
    certain: false,   // a proposal, not a plan
    priced: false,    // no fare has been checked; don't imply one
    note: "Times are targets — I'll price real flights and hold the hotel the second you say go.",
    gaps,
  };
}

module.exports = { proposeItinerary, makeAirportResolver, AIRPORTS };
