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
const { normalizeProperty, dedupeStays, staleLegs } = require("./hygiene");

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

t("the same hotel on two different trips (months apart) is not merged", () => {
  const legs = [
    { id: 1, type: "hotel", property_name: "Kimpton Aertson", departs_at: "2026-07-19T16:00:00Z" },
    { id: 2, type: "hotel", property_name: "Kimpton Aertson Hotel", departs_at: "2026-11-02T16:00:00Z" },
  ];
  assert.strictEqual(dedupeStays(legs).kept.length, 2, "merged two separate stays at the same hotel");
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

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
