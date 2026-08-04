#!/usr/bin/env node
// test-journeys.js — home-to-home journey grouping.
//
//   node test-journeys.js
//
// The load-bearing case is the real over-split: a Nashville trip that Tidy shredded into
// four — Nashville, Newark (a connection), Saratoga Springs (a stay), Pittsburgh (HOME) —
// must merge back into one. The safety cases matter as much: two genuinely separate trips
// (each returning home) stay apart, and a huge gap never welds trips together.

const assert = require("assert");
const { homeSetOf, tripEndsHome, planTripMerges, unionClustersByHome, auditGrouping, unresolvedHomeCities } = require("./journeys");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const F = (o, dst, dep, arr) => ({ type: "flight", origin: o, destination: dst, departs_at: dep, arrives_at: arr });

console.log(`\n${b}homeSetOf — parse the many shapes home_airports arrives in${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);
t("airport codes (array, JSON string, comma list) normalize to a code set", () => {
  assert.deepStrictEqual([...homeSetOf(["pit"])], ["PIT"]);
  assert.deepStrictEqual([...homeSetOf('["PIT","JFK"]')], ["PIT", "JFK"]);
  assert.deepStrictEqual([...homeSetOf("PIT, jfk")], ["PIT", "JFK"]);
  assert.strictEqual(homeSetOf(null).size, 0);
});

t("home CITIES expand to all their metro airports", () => {
  assert.deepStrictEqual([...homeSetOf(["New York"])].sort(), ["EWR", "JFK", "LGA"]);
  assert.ok(homeSetOf(["London"]).has("LHR") && homeSetOf(["London"]).has("LGW") && homeSetOf(["London"]).has("LCY"));
});

t("Maddie's real homes — New York + London — cover every home-area airport", () => {
  const s = homeSetOf(["New York", "London"]);
  for (const code of ["JFK", "LGA", "EWR", "LHR", "LGW", "LCY"]) assert.ok(s.has(code), `${code} missing from home set`);
});

t("cities and codes mix; aliases and case are handled", () => {
  const s = homeSetOf(["nyc", "LHR"]);
  assert.ok(s.has("JFK") && s.has("EWR") && s.has("LHR"));
});

t("an unknown home city resolves to nothing AND is reported honestly", () => {
  assert.strictEqual(homeSetOf(["Atlantis"]).size, 0);
  assert.deepStrictEqual(unresolvedHomeCities(["New York", "Atlantis"]), ["Atlantis"]);
});

t("EWR counts as home when New York is home — the Pittsburgh-split correction", () => {
  const home = homeSetOf(["New York", "London"]);
  // The Nashville journey ends BNA→EWR (arrives NY = home); the EWR→PIT leg is a SEPARATE trip.
  const nyTrip = { id: 1, title: "Nashville", legs: [
    F("LGA", "BNA", "2026-07-17T13:00:00Z", "2026-07-17T15:00:00Z"),
    F("BNA", "EWR", "2026-07-27T12:00:00Z", "2026-07-27T15:00:00Z"),   // home
  ] };
  const pitTrip = { id: 2, title: "Pittsburgh", legs: [
    F("EWR", "PIT", "2026-07-30T12:00:00Z", "2026-07-30T14:00:00Z"),
  ] };
  assert.strictEqual(tripEndsHome(nyTrip, home), true, "arriving EWR should count as home");
  assert.strictEqual(planTripMerges([nyTrip, pitTrip], home).length, 0, "Pittsburgh must NOT merge into the NY trip");
});

console.log(`\n${b}The Nashville over-split → one journey (repair)${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

const nashville = [
  { id: 1, title: "Nashville",        legs: [F("LGA", "BNA", "2026-07-17T13:00:00Z", "2026-07-17T15:00:00Z")] },
  { id: 2, title: "Newark",           legs: [F("BNA", "EWR", "2026-07-27T12:00:00Z", "2026-07-27T15:00:00Z")] },
  { id: 3, title: "Saratoga Springs", legs: [{ type: "hotel", property_name: "The Adelphi", departs_at: "2026-07-28T18:00:00Z", arrives_at: "2026-07-29T11:00:00Z" }] },
  { id: 4, title: "Pittsburgh",       legs: [F("EWR", "PIT", "2026-07-30T12:00:00Z", "2026-07-30T14:00:00Z")] },
];

t("home airport closes the journey (PIT arrival)", () => {
  assert.strictEqual(tripEndsHome(nashville[3], homeSetOf(["PIT"])), true);
  assert.strictEqual(tripEndsHome(nashville[0], homeSetOf(["PIT"])), false, "landing at BNA is not home");
});

t("all four fragments merge into the earliest trip", () => {
  const merges = planTripMerges(nashville, ["PIT"]);
  assert.strictEqual(merges.length, 1, "expected exactly one merge group");
  assert.strictEqual(merges[0].keepTripId, 1, "should keep the earliest (Nashville) as anchor");
  assert.deepStrictEqual(merges[0].mergeTripIds.sort(), [2, 3, 4]);
});

t("a stay with no airport in the middle still belongs to the journey", () => {
  const merges = planTripMerges(nashville, ["PIT"]);
  assert.ok(merges[0].mergeTripIds.includes(3), "Saratoga (hotel, no O/D) was dropped from the journey");
});

console.log(`\n${b}SAFETY — never merge what belongs apart${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("two complete trips, each returning home, stay separate", () => {
  const trips = [
    { id: 1, title: "Los Angeles", legs: [F("PIT", "LAX", "2026-03-01T12:00:00Z", "2026-03-01T15:00:00Z"), F("LAX", "PIT", "2026-03-05T12:00:00Z", "2026-03-05T19:00:00Z")] },
    { id: 2, title: "Miami",       legs: [F("PIT", "MIA", "2026-03-20T12:00:00Z", "2026-03-20T15:00:00Z"), F("MIA", "PIT", "2026-03-24T12:00:00Z", "2026-03-24T15:00:00Z")] },
  ];
  assert.strictEqual(planTripMerges(trips, ["PIT"]).length, 0, "merged two separate home-to-home trips");
});

t("a huge gap is never bridged, even with no detected home return", () => {
  const trips = [
    { id: 1, title: "Berlin", legs: [F("PIT", "BER", "2026-03-01T12:00:00Z", "2026-03-01T20:00:00Z")] },  // return leg missing
    { id: 2, title: "Tokyo",  legs: [F("PIT", "NRT", "2026-07-01T12:00:00Z", "2026-07-02T06:00:00Z")] },  // 4 months later
  ];
  assert.strictEqual(planTripMerges(trips, ["PIT"]).length, 0, "welded two trips across a 4-month gap");
});

t("no home airports known → do nothing", () => {
  assert.strictEqual(planTripMerges(nashville, []).length, 0);
  assert.strictEqual(planTripMerges(nashville, null).length, 0);
});

t("a new journey starts right after a home return", () => {
  const trips = [
    { id: 1, title: "Nashville",  legs: [F("PIT", "BNA", "2026-07-17T13:00:00Z", "2026-07-17T15:00:00Z"), F("BNA", "PIT", "2026-07-20T12:00:00Z", "2026-07-20T14:00:00Z")] },
    { id: 2, title: "Boston",     legs: [F("PIT", "BOS", "2026-07-22T12:00:00Z", "2026-07-22T14:00:00Z")] }, // 2 days later, new trip
  ];
  assert.strictEqual(planTripMerges(trips, ["PIT"]).length, 0, "trip after a home return should stand alone");
});

console.log(`\n${b}Prevention — union the splitter's clusters${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("clusters not separated by a home return re-join into one", () => {
  const DAY = 86400000;
  const clusters = [
    { legs: [F("LGA", "BNA", "2026-07-17T13:00:00Z", "2026-07-17T15:00:00Z")], end: new Date("2026-07-17T15:00:00Z").getTime() },
    { legs: [F("BNA", "EWR", "2026-07-27T12:00:00Z", "2026-07-27T15:00:00Z")], end: new Date("2026-07-27T15:00:00Z").getTime() },
    { legs: [F("EWR", "PIT", "2026-07-30T12:00:00Z", "2026-07-30T14:00:00Z")], end: new Date("2026-07-30T14:00:00Z").getTime() },
  ];
  const out = unionClustersByHome(clusters, ["PIT"]);
  assert.strictEqual(out.length, 1, "the journey's clusters didn't re-join");
  assert.strictEqual(out[0].legs.length, 3);
});

t("clusters split by a home return stay separate", () => {
  const clusters = [
    { legs: [F("PIT", "BNA", "2026-07-17T13:00:00Z", "2026-07-17T15:00:00Z"), F("BNA", "PIT", "2026-07-20T12:00:00Z", "2026-07-20T14:00:00Z")], end: new Date("2026-07-20T14:00:00Z").getTime() },
    { legs: [F("PIT", "BOS", "2026-07-25T12:00:00Z", "2026-07-25T14:00:00Z")], end: new Date("2026-07-25T14:00:00Z").getTime() },
  ];
  const out = unionClustersByHome(clusters, ["PIT"]);
  assert.strictEqual(out.length, 2, "merged across a home return");
});

console.log(`\n${b}auditGrouping — the standing guard for invariant #3${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a lone return leg (EWR→PIT as its own trip) is flagged as a tail fragment", () => {
  const trips = [{ id: 9, title: "Pittsburgh", legs: [F("EWR", "PIT", "2026-07-30T12:00:00Z", "2026-07-30T14:00:00Z")] }];
  const v = auditGrouping(trips, ["PIT"]);
  assert.strictEqual(v.length, 1);
  assert.match(v[0].reason, /never departed home/);
});

t("a trip that continues past a homecoming is flagged as welded", () => {
  const trips = [{ id: 10, title: "Two trips", legs: [
    F("PIT", "BNA", "2026-07-17T13:00:00Z", "2026-07-17T15:00:00Z"),
    F("BNA", "PIT", "2026-07-20T12:00:00Z", "2026-07-20T14:00:00Z"),   // home — should end here
    F("PIT", "BOS", "2026-07-25T12:00:00Z", "2026-07-25T14:00:00Z"),   // but it keeps going
  ] }];
  const v = auditGrouping(trips, ["PIT"]);
  assert.strictEqual(v.length, 1);
  assert.match(v[0].reason, /spans a return home/);
});

t("a clean round trip (home → away → home) is NOT flagged", () => {
  const trips = [{ id: 11, title: "Nashville", legs: [
    F("PIT", "BNA", "2026-07-17T13:00:00Z", "2026-07-17T15:00:00Z"),
    F("BNA", "PIT", "2026-07-20T12:00:00Z", "2026-07-20T14:00:00Z"),
  ] }];
  assert.strictEqual(auditGrouping(trips, ["PIT"]).length, 0);
});

t("no home airport → the guard holds no opinion", () => {
  const trips = [{ id: 9, title: "Pittsburgh", legs: [F("EWR", "PIT", "2026-07-30T12:00:00Z", "2026-07-30T14:00:00Z")] }];
  assert.strictEqual(auditGrouping(trips, []).length, 0);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
