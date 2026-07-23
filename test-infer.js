#!/usr/bin/env node
// test-infer.js — propose a trip only when distance says so, ask when it can't.
//
//   node test-infer.js
//
// Fixture: Maddie in Nashville, with virtual calls, an in-person Chicago meeting,
// the Dallas meeting that carries a link AND a place, and the Evanston coffee that
// a city-name matcher choked on. The load-bearing assertions: a Zoom call never
// becomes a flight, an ambiguous meeting is a question, Evanston folds into the
// Chicago trip because it's 12 miles away, and pushing a meeting makes its trip
// vanish with nothing to undo.

const assert = require("assert");
const { inferTravelNeeds, groupTrips } = require("./infer");
const { HUBS } = require("./geo");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const NOW = Date.parse("2026-07-23T12:00:00Z");
const soon = (h) => new Date(NOW + h * 3600000).toISOString();
const NASHVILLE = { city: "Nashville", lat: 36.1627, lng: -86.7816 };
const OPTS = { now: NOW, current: NASHVILLE };

const geo = {
  chicago:  { city: "Chicago",  lat: 41.8781, lng: -87.6298 },
  evanston: { city: "Evanston", lat: 42.0451, lng: -87.6877 }, // 12mi N of Chicago
  dallas:   { city: "Dallas",   lat: 32.7767, lng: -96.7970 },
  nashville:{ city: "Nashville",lat: 36.1670, lng: -86.7780 },
};

const WEEK = [
  { calendar_id: "1", title: "Covrly — Sales Daily", nature: "virtual", start: soon(2), end: soon(2.5) },
  { calendar_id: "3", title: "Miru Terrace — St. Regis Tower", nature: "in_person", geo: geo.chicago, start: soon(20), end: soon(22) },
  { calendar_id: "4", title: "Preston DeLong — Texas Rangers", nature: "ambiguous", geo: geo.dallas, start: soon(26), end: soon(27) },
  { calendar_id: "5", title: "Maddie/JR Meet up", nature: "in_person", geo: geo.evanston, start: soon(30), end: soon(31) },
];

console.log(`\n${b}From Nashville, what actually needs travel${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("the Zoom call produces nothing", () => {
  assert.strictEqual(inferTravelNeeds([WEEK[0]], OPTS).length, 0);
});

t("the Chicago meeting proposes a trip", () => {
  const n = inferTravelNeeds([WEEK[1]], OPTS);
  assert.strictEqual(n[0].kind, "propose_trip");
  assert.strictEqual(n[0].destination, "Chicago");
  assert.strictEqual(n[0].certain, false);
});

t("the Dallas meeting ASKS — never a silent booking", () => {
  const n = inferTravelNeeds([WEEK[2]], OPTS);
  assert.strictEqual(n[0].kind, "ask");
  assert.ok(/in person, or remotely/i.test(n[0].question));
});

t("a meeting near where you already are is not travel", () => {
  const local = [{ calendar_id: "9", title: "Coffee", nature: "in_person", geo: geo.nashville, start: soon(5), end: soon(6) }];
  assert.strictEqual(inferTravelNeeds(local, OPTS).length, 0);
});

t("an in-person meeting with an unresolved place ASKS", () => {
  const noGeo = [{ calendar_id: "z", title: "Mystery", nature: "in_person", place: "Some Cafe", geo: { city: null, lat: null, lng: null }, start: soon(8), end: soon(9) }];
  assert.strictEqual(inferTravelNeeds(noGeo, OPTS)[0].kind, "ask");
});

t("without a 'where are you', it ASKS instead of guessing travel", () => {
  const n = inferTravelNeeds([WEEK[1]], { now: NOW, current: null });
  assert.strictEqual(n[0].kind, "ask");
  assert.ok(/where are you/i.test(n[0].question));
});

t("a past meeting drives nothing", () => {
  const past = [{ calendar_id: "0", title: "Old", nature: "in_person", geo: geo.chicago, start: soon(-5), end: soon(-4) }];
  assert.strictEqual(inferTravelNeeds(past, OPTS).length, 0);
});

console.log(`\n${b}Distance beats string-matching${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("Evanston folds into the Chicago trip (12 miles), not its own question", () => {
  const needs = inferTravelNeeds([WEEK[1], WEEK[3]], OPTS);
  const { trips } = groupTrips(needs, { hubs: HUBS });
  assert.strictEqual(trips.length, 1, "Evanston and Chicago should be ONE trip");
  assert.strictEqual(trips[0].destination, "Chicago", "the metro should win over the suburb");
  assert.strictEqual(trips[0].drivers.length, 2, "the trip should remember both meetings");
});

t("the whole week: one Chicago trip + one Dallas question", () => {
  const { trips, asks } = groupTrips(inferTravelNeeds(WEEK, OPTS), { hubs: HUBS });
  assert.strictEqual(trips.length, 1);
  assert.strictEqual(trips[0].destination, "Chicago");
  assert.strictEqual(asks.length, 1);
  assert.strictEqual(asks[0].driver.title, "Preston DeLong — Texas Rangers");
});

console.log(`\n${b}Handle changes so I don't have to${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("push the meeting → the trip is gone, nothing to undo", () => {
  assert.strictEqual(groupTrips(inferTravelNeeds([WEEK[1]], OPTS)).trips.length, 1);
  assert.strictEqual(groupTrips(inferTravelNeeds([], OPTS)).trips.length, 0);
});

t("turn the meeting virtual → also no trip", () => {
  const nowVirtual = [{ ...WEEK[1], nature: "virtual", geo: null }];
  assert.strictEqual(inferTravelNeeds(nowVirtual, OPTS).length, 0);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
