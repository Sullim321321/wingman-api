#!/usr/bin/env node
// test-regroup.js — legs cluster into trips by TIME, never by destination alone.
//
//   node test-regroup.js
//
// The bug this prevents: every leg that ever ended in New York collapsed into one
// "New York" trip — an Albany train from April and a JFK flight years later in the same
// card, a 17-year span rendered as "upcoming". Grouping must be temporal: a new trip
// begins wherever there's a real gap between legs. Destination is the title, not the
// membership key. And a corrupt date (epoch, absurd year) must never anchor anything.

const assert = require("assert");
const { clusterLegs, plausibleDate } = require("./regroup");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const NOW = Date.parse("2026-07-24T12:00:00Z");
const leg = (dep, origin, destination, extra = {}) => ({
  departs_at: dep, arrives_at: dep, origin, destination, type: "flight", state: "confirmed", ...extra,
});

console.log(`\n${b}plausibleDate${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);
t("rejects epoch 1970 and NaN", () => {
  assert.strictEqual(plausibleDate("1970-01-01T00:00:00Z", NOW), false);
  assert.strictEqual(plausibleDate(null, NOW), false);
  assert.strictEqual(plausibleDate("not-a-date", NOW), false);
});
t("rejects absurd years, accepts a normal near-term date", () => {
  assert.strictEqual(plausibleDate("1899-05-01T00:00:00Z", NOW), false);
  assert.strictEqual(plausibleDate("2099-01-01T00:00:00Z", NOW), false);
  assert.strictEqual(plausibleDate("2026-08-01T00:00:00Z", NOW), true);
  assert.strictEqual(plausibleDate("2025-11-01T00:00:00Z", NOW), true); // recent past is fine (past trips exist)
});

console.log(`\n${b}clusterLegs — temporal, not destination${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("two legs 2 days apart become ONE trip", () => {
  const out = clusterLegs([
    leg("2026-08-03T09:00:00Z", "BNA", "JFK"),
    leg("2026-08-05T18:00:00Z", "JFK", "BNA"),
  ], { nowMs: NOW });
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].legs.length, 2);
});

t("two legs 10 days apart become TWO trips", () => {
  const out = clusterLegs([
    leg("2026-08-03T09:00:00Z", "BNA", "JFK"),
    leg("2026-08-15T18:00:00Z", "BNA", "JFK"),
  ], { nowMs: NOW });
  assert.strictEqual(out.length, 2);
});

t("a 2009 leg never merges with a 2026 leg — the corrupt-old one is dropped", () => {
  const out = clusterLegs([
    leg("2009-04-09T07:00:00Z", "ALB", "New York"),
    leg("2026-07-27T08:00:00Z", "BNA", "New York"),
  ], { nowMs: NOW });
  // The 17-year-old leg is implausible for a 2026 user → dropped, never folded into the
  // current trip. What remains is one clean 2026 trip, not a 17-year span.
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].legs.length, 1);
  assert.strictEqual(Date.parse(out[0].legs[0].departs_at), Date.parse("2026-07-27T08:00:00Z"));
});

t("a multi-city week (legs within the gap) stays ONE trip", () => {
  const out = clusterLegs([
    leg("2026-09-10T09:00:00Z", "BNA", "LHR"),
    leg("2026-09-13T09:00:00Z", "LHR", "CDG"),
    leg("2026-09-16T09:00:00Z", "CDG", "BNA"),
  ], { nowMs: NOW, gapDays: 4 });
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].legs.length, 3);
});

t("a chain longer than maxTripDays is split even without a big gap", () => {
  // legs every 4 days for 40 days — no single gap > 4, but the span exceeds the cap
  const legs = [];
  for (let i = 0; i < 11; i++) legs.push(leg(new Date(NOW + i * 4 * 864e5).toISOString(), "BNA", "X"));
  const out = clusterLegs(legs, { nowMs: NOW, gapDays: 4, maxTripDays: 30 });
  assert.ok(out.length >= 2, "a 40-day chain must not be one trip");
});

t("title comes from the destination, not the origin", () => {
  const out = clusterLegs([
    leg("2026-08-03T09:00:00Z", "BNA", "Chicago"),
    leg("2026-08-05T18:00:00Z", "Chicago", "BNA"),
  ], { nowMs: NOW });
  assert.strictEqual(out[0].title, "Chicago");
});

t("legs with corrupt dates are dropped, not clustered", () => {
  const out = clusterLegs([
    leg("1970-01-01T00:00:00Z", "BNA", "Nowhere"),
    leg("2026-08-03T09:00:00Z", "BNA", "JFK"),
  ], { nowMs: NOW });
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].legs.length, 1);
});

t("proposed/sketch legs don't force or split a trip (committed only)", () => {
  const out = clusterLegs([
    leg("2026-08-03T09:00:00Z", "BNA", "JFK"),
    leg("2026-08-05T18:00:00Z", "JFK", "BNA"),
    leg("2026-08-04T09:00:00Z", "JFK", "BOS", { state: "proposed" }),
  ], { nowMs: NOW });
  assert.strictEqual(out.length, 1);
  assert.strictEqual(out[0].legs.length, 2); // the proposal isn't counted as membership
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
