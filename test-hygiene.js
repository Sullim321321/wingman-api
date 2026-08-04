#!/usr/bin/env node
// test-hygiene.js — the Nashville mess, cleaned by rule.
//
//   node test-hygiene.js
//
// Fixture is the real trip: three copies of the Kimpton (one a sketch, one branded
// "by IHG") and a Southwest flight from May sitting in a July trip. The load-bearing
// assertions: the three hotels become one (the booked one), the May flight is flagged
// stale, and — the safety side — a genuinely different stay is NOT collapsed and a
// small trip is never "cleaned" on a guess.

const assert = require("assert");
const { normalizeProperty, dedupeStays, staleLegs, dedupeCodeshares } = require("./hygiene");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

console.log(`\n${b}Same hotel, three ways → one${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("brand suffix and 'Hotel' normalize to the same identity", () => {
  assert.strictEqual(normalizeProperty("Kimpton Aertson Hotel"), normalizeProperty("Kimpton Aertson Hotel by IHG"));
  assert.strictEqual(normalizeProperty("Kimpton Aertson Hotel"), "kimpton aertson");
});

t("three Kimpton copies collapse to the booked one", () => {
  const legs = [
    { id: 1, type: "hotel", property_name: "Kimpton Aertson Hotel", state: "proposed", departs_at: "2026-07-19T16:00:00Z" },
    { id: 2, type: "hotel", property_name: "Kimpton Aertson Hotel", state: "booked", confirmation: "ABC123", departs_at: "2026-07-19T16:00:00Z" },
    { id: 3, type: "hotel", property_name: "Kimpton Aertson Hotel by IHG", state: "booked", departs_at: "2026-07-19T16:00:00Z" },
  ];
  const { kept, removed } = dedupeStays(legs);
  const hotels = kept.filter((l) => l.type === "hotel");
  assert.strictEqual(hotels.length, 1, "the Kimpton wasn't collapsed to one");
  assert.strictEqual(hotels[0].id, 2, "kept the wrong copy — should keep the booked one with a confirmation");
  assert.strictEqual(removed.length, 2);
});

t("two DIFFERENT hotels are left alone", () => {
  const legs = [
    { id: 1, type: "hotel", property_name: "Kimpton Aertson", departs_at: "2026-07-19T16:00:00Z" },
    { id: 2, type: "hotel", property_name: "Four Seasons", departs_at: "2026-07-19T16:00:00Z" },
  ];
  assert.strictEqual(dedupeStays(legs).kept.length, 2, "collapsed two different hotels");
});

// dedupeStays is always called on ONE trip's legs (WHERE trip_id = …), so "two different
// trips" never share a call. The real within-trip cases are: a genuine re-stay (keep both)
// vs a mis-dated duplicate (collapse). Both anchored to the trip's date cluster.

t("a genuine re-stay at the same hotel within a trip (both plausibly dated) is kept", () => {
  const legs = [
    { id: 1, type: "hotel", property_name: "Kimpton Aertson", departs_at: "2026-07-05T16:00:00Z", arrives_at: "2026-07-07T11:00:00Z" },
    { id: 2, type: "flight", departs_at: "2026-07-10T12:00:00Z" },  // anchors the cluster mid-July
    { id: 3, type: "hotel", property_name: "Kimpton Aertson Hotel", departs_at: "2026-07-20T16:00:00Z", arrives_at: "2026-07-22T11:00:00Z" },
  ];
  assert.strictEqual(dedupeStays(legs).kept.filter((l) => l.type === "hotel").length, 2, "collapsed a genuine re-stay");
});

t("the Dec-31 mis-dated Graduate collapses into the real July stay (#4 via #2)", () => {
  const legs = [
    { id: 1, type: "flight", origin: "LGA", destination: "BNA", departs_at: "2026-07-17T13:00:00Z" },
    { id: 2, type: "hotel", property_name: "Graduate by Hilton Nashville", departs_at: "2026-07-24T16:00:00Z", arrives_at: "2026-07-27T11:00:00Z" },
    { id: 3, type: "hotel", property_name: "Graduate by Hilton Nashville, TN", departs_at: "2026-12-31T16:00:00Z" }, // mis-parse
  ];
  const { kept, removed } = dedupeStays(legs);
  const hotels = kept.filter((l) => l.type === "hotel");
  assert.strictEqual(hotels.length, 1, "the mis-dated Graduate wasn't collapsed");
  assert.strictEqual(hotels[0].id, 2, "kept the wrong copy — should keep the real July stay");
  assert.ok(removed.some((l) => l.id === 3), "the Dec-31 copy should be the one removed");
});

t("non-lodging legs pass through untouched", () => {
  const legs = [
    { id: 1, type: "flight", carrier: "United", departs_at: "2026-07-17T12:00:00Z" },
    { id: 2, type: "hotel", property_name: "Kimpton Aertson", departs_at: "2026-07-17T20:00:00Z" },
    { id: 3, type: "hotel", property_name: "Kimpton Aertson Hotel", departs_at: "2026-07-17T20:00:00Z" },
  ];
  const { kept } = dedupeStays(legs);
  assert.ok(kept.some((l) => l.type === "flight"), "dropped a flight while deduping hotels");
  assert.strictEqual(kept.filter((l) => l.type === "hotel").length, 1);
});

console.log(`\n${b}The May flight doesn't belong in a July trip${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a flight two months off the cluster is stale", () => {
  const legs = [
    { id: 1, type: "flight", carrier: "Southwest", departs_at: "2026-05-16T07:55:00Z" }, // the outlier
    { id: 2, type: "flight", carrier: "American", departs_at: "2026-07-17T12:00:00Z" },
    { id: 3, type: "hotel", property_name: "Kimpton", departs_at: "2026-07-17T20:00:00Z" },
    { id: 4, type: "dining", departs_at: "2026-07-18T23:00:00Z" },
  ];
  const stale = staleLegs(legs);
  assert.strictEqual(stale.length, 1);
  assert.strictEqual(stale[0].id, 1, "the May flight wasn't flagged");
});

t("a tight July cluster flags nothing", () => {
  const legs = [
    { id: 1, type: "flight", departs_at: "2026-07-17T12:00:00Z" },
    { id: 2, type: "hotel", departs_at: "2026-07-17T20:00:00Z" },
    { id: 3, type: "dining", departs_at: "2026-07-18T23:00:00Z" },
    { id: 4, type: "flight", departs_at: "2026-07-19T18:00:00Z" },
  ];
  assert.strictEqual(staleLegs(legs).length, 0, "flagged a leg inside a normal 3-day trip");
});

t("a NULL-dated leg is never flagged stale (the 1970 trap)", () => {
  // Real case: a Kimpton with no departure date was read as 1970 and flagged as a
  // wild outlier from a 2026 trip. A leg with no date has nothing to judge.
  const legs = [
    { id: 1, type: "hotel", property_name: "Kimpton Aertson", departs_at: null },
    { id: 2, type: "flight", departs_at: "2026-07-17T12:00:00Z" },
    { id: 3, type: "hotel", departs_at: "2026-07-17T20:00:00Z" },
    { id: 4, type: "dining", departs_at: "2026-07-18T23:00:00Z" },
    { id: 5, type: "flight", departs_at: "2026-07-19T18:00:00Z" },
  ];
  const stale = staleLegs(legs);
  assert.ok(!stale.some((l) => l.id === 1), "an undated leg was flagged stale (1970 trap)");
});

t("too few dated legs = no guessing (never flags)", () => {
  const legs = [
    { id: 1, type: "flight", departs_at: "2026-05-16T07:55:00Z" },
    { id: 2, type: "hotel", departs_at: "2026-07-19T20:00:00Z" },
  ];
  assert.strictEqual(staleLegs(legs).length, 0, "flagged on too little evidence");
});

console.log(`\n${b}Codeshares → one physical flight (#228)${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("AA 4611 and UA 3403 — same route, same time — collapse to one", () => {
  const legs = [
    { id: 1, type: "flight", flight_number: "AA4611", carrier: "American", origin: "PIT", destination: "ORD", departs_at: "2026-08-10T14:30:00Z", arrives_at: "2026-08-10T15:45:00Z" },
    { id: 2, type: "flight", flight_number: "UA3403", carrier: "United",   origin: "PIT", destination: "ORD", departs_at: "2026-08-10T14:30:00Z", arrives_at: "2026-08-10T15:45:00Z", confirmation: "XYZ9" },
  ];
  const { kept, removed } = dedupeCodeshares(legs);
  assert.strictEqual(kept.filter((l) => l.type === "flight").length, 1, "the codeshare wasn't collapsed");
  assert.strictEqual(kept.find((l) => l.type === "flight").id, 2, "kept the wrong copy — should keep the one with a confirmation");
  assert.strictEqual(removed.length, 1);
});

t("codeshare with arrival on only one row still collapses", () => {
  const legs = [
    { id: 1, type: "flight", flight_number: "AA4611", origin: "PIT", destination: "ORD", departs_at: "2026-08-10T14:30:00Z" },
    { id: 2, type: "flight", flight_number: "UA3403", origin: "PIT", destination: "ORD", departs_at: "2026-08-10T14:30:00Z", arrives_at: "2026-08-10T15:45:00Z" },
  ];
  const { kept, removed } = dedupeCodeshares(legs);
  assert.strictEqual(kept.filter((l) => l.type === "flight").length, 1);
  assert.strictEqual(removed.length, 1);
});

t("SAFETY: two real flights, same route, DIFFERENT times — both kept", () => {
  const legs = [
    { id: 1, type: "flight", flight_number: "AA4611", origin: "PIT", destination: "ORD", departs_at: "2026-08-10T14:30:00Z" },
    { id: 2, type: "flight", flight_number: "UA3403", origin: "PIT", destination: "ORD", departs_at: "2026-08-10T18:05:00Z" },
  ];
  const { kept, removed } = dedupeCodeshares(legs);
  assert.strictEqual(kept.filter((l) => l.type === "flight").length, 2, "collapsed two genuinely different flights");
  assert.strictEqual(removed.length, 0);
});

t("SAFETY: same route + departure but CONFLICTING arrivals — both kept", () => {
  const legs = [
    { id: 1, type: "flight", flight_number: "AA4611", origin: "PIT", destination: "ORD", departs_at: "2026-08-10T14:30:00Z", arrives_at: "2026-08-10T15:45:00Z" },
    { id: 2, type: "flight", flight_number: "UA3403", origin: "PIT", destination: "ORD", departs_at: "2026-08-10T14:30:00Z", arrives_at: "2026-08-10T16:20:00Z" },
  ];
  const { kept, removed } = dedupeCodeshares(legs);
  assert.strictEqual(removed.length, 0, "merged despite different arrival times");
});

t("SAFETY: undated or routeless flights pass through untouched", () => {
  const legs = [
    { id: 1, type: "flight", flight_number: "AA4611", origin: "PIT", destination: "ORD" },              // no time
    { id: 2, type: "flight", flight_number: "UA3403", departs_at: "2026-08-10T14:30:00Z" },             // no route
  ];
  const { kept, removed } = dedupeCodeshares(legs);
  assert.strictEqual(kept.length, 2);
  assert.strictEqual(removed.length, 0);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
