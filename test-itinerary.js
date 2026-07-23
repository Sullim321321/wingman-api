#!/usr/bin/env node
// test-itinerary.js — propose the shape of the trip, and never imply a fare you didn't check.
//
//   node test-itinerary.js
//
// The load-bearing honesty: no flight number, no price (priced:false), a hotel named
// only if history knows it. Plus the judgement calls: a morning meeting means flying
// in the night before, and a same-day in-and-out books no hotel.

const assert = require("assert");
const { proposeItinerary } = require("./itinerary");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const fromNashville = { current: { city: "Nashville" } };

console.log(`\n${b}The Chicago trip, from Nashville${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// St Regis at 3pm Chicago (20:00Z), Evanston next day ending ~14:45Z 07-24.
const chicago = { destination: "Chicago", arrive_by: "2026-07-23T20:00:00Z", depart_after: "2026-07-24T14:45:00Z" };

t("routes BNA → ORD and back", () => {
  const it = proposeItinerary(chicago, fromNashville);
  assert.strictEqual(it.flight_in.from, "BNA");
  assert.strictEqual(it.flight_in.to, "ORD");
  assert.strictEqual(it.flight_out.from, "ORD");
  assert.strictEqual(it.flight_out.to, "BNA");
});

t("a 3pm meeting flies in the SAME day, not the night before", () => {
  const it = proposeItinerary(chicago, fromNashville);
  assert.ok(/same day/.test(it.flight_in.basis), it.flight_in.basis);
  assert.strictEqual(it.nights, 1, "Wed noon → Thu afternoon is one night");
});

t("it never implies a fare it didn't check", () => {
  const it = proposeItinerary(chicago, fromNashville);
  assert.strictEqual(it.priced, false);
  assert.strictEqual(it.certain, false);
  const blob = JSON.stringify(it);
  assert.ok(!/\$\d/.test(blob), "a dollar amount leaked into a proposal");
  assert.ok(!/(UA|AA|DL|JL|WN)\s?\d{1,4}/.test(blob), "a flight number was invented");
});

console.log(`\n${b}Judgement: when to fly in, when to book a hotel${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("an 8am meeting means flying in the EVENING BEFORE (+ a night)", () => {
  const early = { destination: "Chicago", arrive_by: "2026-07-23T13:00:00Z", depart_after: "2026-07-23T22:00:00Z" }; // 8am–5pm CDT
  const it = proposeItinerary(early, fromNashville);
  assert.ok(/evening before/.test(it.flight_in.basis), it.flight_in.basis);
  assert.strictEqual(it.nights, 1, "arrive Tue eve, leave Wed eve = one night");
});

t("a same-day in-and-out books NO hotel", () => {
  const dayTrip = { destination: "Chicago", arrive_by: "2026-07-23T20:00:00Z", depart_after: "2026-07-23T23:00:00Z" }; // 3pm–6pm, home that night
  const it = proposeItinerary(dayTrip, fromNashville);
  assert.strictEqual(it.nights, 0);
  assert.strictEqual(it.hotel, null, "a day trip booked a hotel");
});

t("the hotel is named only when history knows it", () => {
  const noHistory = proposeItinerary(chicago, fromNashville);
  assert.strictEqual(noHistory.hotel.name, null, "invented a hotel with no history");

  const withHistory = proposeItinerary(chicago, { ...fromNashville, hotelOf: (c) => c === "Chicago" ? "Kimpton Gray" : null });
  assert.strictEqual(withHistory.hotel.name, "Kimpton Gray");
});

console.log(`\n${b}Honest about what it can't resolve${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("unknown home location is a gap, not a guessed airport", () => {
  const it = proposeItinerary(chicago, { current: null });
  assert.strictEqual(it.flight_in.from, null);
  assert.ok(it.gaps.some((s) => /home airport/.test(s)));
});

t("an unmappable destination is a gap, not a fake code", () => {
  const it = proposeItinerary({ destination: "Timbuktu", arrive_by: "2026-07-23T20:00:00Z", depart_after: "2026-07-24T20:00:00Z" }, fromNashville);
  assert.strictEqual(it.flight_in.to, null);
  assert.ok(it.gaps.some((s) => /Timbuktu/.test(s)));
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
