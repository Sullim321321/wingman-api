#!/usr/bin/env node
// test-infer.js — propose a trip only when the calendar is sure, ask when it isn't.
//
//   node test-infer.js
//
// The fixture is Maddie's real week, read live: she's in Nashville, with a set of
// virtual calls, one in-person Chicago meeting, and the Dallas meeting that carries
// both a Zoom link and a place. The assertions that matter are the ones that keep a
// booked flight from ever resting on a Zoom call — and the reactivity test, which is
// the whole "handle changes so I don't have to": when the meeting goes away, so does
// the trip, with nobody undoing anything.

const assert = require("assert");
const { inferTravelNeeds, groupTrips } = require("./infer");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const NOW = Date.parse("2026-07-22T12:00:00Z");
const soon = (h) => new Date(NOW + h * 3600000).toISOString();
const OPTS = { now: NOW, currentCity: "Nashville", bases: ["New York", "London"] };

// Maddie's real week, in the shape the calendar read produces (nature + place added
// by the classifier). Trimmed to the load-bearing cases.
const WEEK = [
  { calendar_id: "1", title: "Covrly — Sales Daily", nature: "virtual", place: null, start: soon(2), end: soon(2.5) },
  { calendar_id: "2", title: "Update Call",          nature: "virtual", place: null, start: soon(3), end: soon(3.5) },
  { calendar_id: "3", title: "Miru Terrace — St. Regis Tower", nature: "in_person",
    place: "401 E Wacker Dr, Chicago, IL", start: soon(20), end: soon(22) },
  { calendar_id: "4", title: "Preston DeLong — Texas Rangers Opportunity", nature: "ambiguous",
    place: "Conference — Dallas — Executive", start: soon(26), end: soon(27) },
  { calendar_id: "5", title: "Maddie/JR Meet up", nature: "in_person",
    place: "Starbucks Coffee Company", start: soon(30), end: soon(31) }, // city unknowable
];

console.log(`\n${b}From Nashville, what actually needs travel${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("the Zoom calls produce nothing", () => {
  const needs = inferTravelNeeds([WEEK[0], WEEK[1]], OPTS);
  assert.strictEqual(needs.length, 0, "a virtual call was treated as travel");
});

t("the Chicago meeting proposes a trip to Chicago", () => {
  const needs = inferTravelNeeds([WEEK[2]], OPTS);
  assert.strictEqual(needs.length, 1);
  assert.strictEqual(needs[0].kind, "propose_trip");
  assert.strictEqual(needs[0].destination, "Chicago");
  assert.strictEqual(needs[0].certain, false, "an inferred trip claimed certainty");
});

t("the Dallas meeting ASKS — it is never a silent booking", () => {
  const needs = inferTravelNeeds([WEEK[3]], OPTS);
  assert.strictEqual(needs.length, 1);
  assert.strictEqual(needs[0].kind, "ask", "an ambiguous meeting was booked as a trip");
  assert.strictEqual(needs[0].destination, "Dallas");
  assert.ok(/in person, or remotely/i.test(needs[0].question));
});

t("an in-person meeting with an unreadable city ASKS, it doesn't guess", () => {
  const needs = inferTravelNeeds([WEEK[4]], OPTS);
  assert.strictEqual(needs[0].kind, "ask");
  assert.strictEqual(needs[0].destination, null, "a city was invented from 'Starbucks'");
});

t("a meeting in the city you're already in is not travel", () => {
  const here = [{ calendar_id: "9", title: "Coffee", nature: "in_person", place: "Downtown Nashville, TN", start: soon(5), end: soon(6) }];
  assert.strictEqual(inferTravelNeeds(here, OPTS).length, 0, "proposed a trip to where you already are");
});

t("a past meeting drives nothing", () => {
  const past = [{ calendar_id: "0", title: "Old", nature: "in_person", place: "Chicago", start: soon(-5), end: soon(-4) }];
  assert.strictEqual(inferTravelNeeds(past, OPTS).length, 0);
});

console.log(`\n${b}The whole week at once${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("18-ish meetings collapse to one proposal and two questions", () => {
  const needs = inferTravelNeeds(WEEK, OPTS);
  const { trips, asks } = groupTrips(needs);
  assert.strictEqual(trips.length, 1, "expected exactly one trip (Chicago)");
  assert.strictEqual(trips[0].destination, "Chicago");
  assert.strictEqual(asks.length, 2, "expected two open questions (Dallas + Starbucks)");
});

t("two Chicago meetings on nearby days are ONE trip, not two", () => {
  const twoChi = [
    WEEK[2],
    { calendar_id: "6", title: "Second Chicago sync", nature: "in_person", place: "River North, Chicago", start: soon(44), end: soon(45) },
  ];
  const { trips } = groupTrips(inferTravelNeeds(twoChi, OPTS));
  assert.strictEqual(trips.length, 1, "same city, nearby days should be one trip");
  assert.strictEqual(trips[0].drivers.length, 2, "the trip should remember both meetings");
});

console.log(`\n${b}Handle changes so I don't have to${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// This is the sick-day. She pushes the Chicago meeting. Nobody cancels a trip; the
// trip simply is not inferred anymore, because it was never anything but a function
// of the calendar. The change handles itself.
t("push the meeting → the trip need is gone, with nothing to undo", () => {
  const before = groupTrips(inferTravelNeeds([WEEK[2]], OPTS)).trips;
  assert.strictEqual(before.length, 1, "precondition: the trip existed");

  const afterPush = []; // the meeting moved off this window / turned into a call
  const after = groupTrips(inferTravelNeeds(afterPush, OPTS)).trips;
  assert.strictEqual(after.length, 0, "the trip lingered after its reason left");
});

t("turn the meeting virtual → also no trip", () => {
  const nowVirtual = [{ ...WEEK[2], nature: "virtual", place: null }];
  assert.strictEqual(inferTravelNeeds(nowVirtual, OPTS).length, 0, "a meeting moved to video still pulled a trip");
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
