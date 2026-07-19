#!/usr/bin/env node
// test-sketches.js — expiry must delete ideas, and must NEVER delete arrangements.
//
//   node test-sketches.js
//
// Expiry is the most dangerous thing in this codebase, because it destroys rows on a
// schedule with nobody watching. Every other bug this project has hunted made the app
// SAY something false. This one can make the app LOSE something true.
//
// So the interesting assertions here are not the ones where it expires. They're the
// refusals — the cases where a leg looks stale by the rule and must survive anyway.

const assert = require("assert");
const { shouldExpire, classifyTrip, MAX_IDLE_DAYS } = require("./sketches");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const DAY = 86400000;
const NOW = Date.parse("2026-07-19T12:00:00Z");
const iso = (ms) => new Date(ms).toISOString();

console.log(`\n${b}What must survive${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// The Kimpton. Booked, in the past, and expiry must not go near it.
t("a BOOKED leg in the past is untouchable", () => {
  const res = shouldExpire(
    { state: "booked", departs_at: iso(NOW - 40 * DAY), confirmation: "H3K9QP" }, NOW);
  assert.strictEqual(res.expire, false, "expiry deleted a real booking — this is data loss");
});

t("a leg with no state at all is untouchable", () => {
  // Legs imported from email don't always carry a state. Absence of 'booked' is
  // NOT presence of 'proposed', and treating it as such would delete the inbox.
  assert.strictEqual(shouldExpire({ departs_at: iso(NOW - 5 * DAY) }, NOW).expire, false);
  assert.strictEqual(shouldExpire({ state: null, departs_at: iso(NOW - 5 * DAY) }, NOW).expire, false);
  assert.strictEqual(shouldExpire({ state: "", departs_at: iso(NOW - 5 * DAY) }, NOW).expire, false);
});

// The trapdoor: a leg still marked 'proposed' that has acquired a real reference.
// Booking flows update state and confirmation separately; between those two writes,
// a crash leaves exactly this row. Deleting it loses the only record of a purchase.
t("a 'proposed' leg carrying a confirmation is untouchable", () => {
  const res = shouldExpire(
    { state: "proposed", departs_at: iso(NOW - 10 * DAY), confirmation: "ABC123" }, NOW);
  assert.strictEqual(res.expire, false,
    "a sketch with a booking reference was deleted — that reference was the only proof it happened");
});

t("a future proposal is left alone", () => {
  assert.strictEqual(
    shouldExpire({ state: "proposed", departs_at: iso(NOW + 3 * DAY) }, NOW).expire, false);
});

t("a young undated proposal is left alone", () => {
  assert.strictEqual(
    shouldExpire({ state: "proposed", created_at: iso(NOW - 2 * DAY) }, NOW).expire, false);
});

// A malformed date is the MOST likely thing to appear on a model-written proposal,
// and NaN comparisons are false in a way that quietly reads as "long ago".
t("a garbage date does not read as 'long past'", () => {
  assert.strictEqual(shouldExpire({ state: "proposed", departs_at: "sometime?" }, NOW).expire, false,
    "an unparseable date became NaN and the leg was expired for being in the past");
  assert.strictEqual(shouldExpire({ state: "proposed", created_at: "???" }, NOW).expire, false);
});

t("a proposal with nothing to judge it by stays", () => {
  assert.strictEqual(shouldExpire({ state: "proposed" }, NOW).expire, false);
});

console.log(`\n${b}What must go${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// The Smoky Mountains, one week later.
t("a proposal whose date has passed, unbooked, expires", () => {
  const res = shouldExpire({ state: "proposed", departs_at: iso(NOW - DAY) }, NOW);
  assert.strictEqual(res.expire, true);
  assert.match(res.why, /passed/);
});

t("an undated proposal older than the idle window expires", () => {
  const res = shouldExpire(
    { state: "proposed", created_at: iso(NOW - (MAX_IDLE_DAYS + 1) * DAY) }, NOW);
  assert.strictEqual(res.expire, true);
  assert.match(res.why, /never dated or booked/);
});

t("the idle boundary is a real boundary", () => {
  const at   = { state: "proposed", created_at: iso(NOW - MAX_IDLE_DAYS * DAY) };
  const just = { state: "proposed", created_at: iso(NOW - (MAX_IDLE_DAYS - 1) * DAY) };
  assert.strictEqual(shouldExpire(at, NOW).expire, true);
  assert.strictEqual(shouldExpire(just, NOW).expire, false);
});

t("every expiry states a reason a person can read", () => {
  const res = shouldExpire({ state: "proposed", departs_at: iso(NOW - DAY) }, NOW);
  assert.ok(res.why && res.why.length > 15, "no readable reason — this goes in the ledger");
  assert.ok(!/undefined|null|NaN/.test(res.why), `unreadable reason: ${res.why}`);
});

console.log(`\n${b}Is this trip real? — one definition${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// The actual trip from the screenshot: one booked hotel, three sketches.
t("the Nashville trip is MIXED, not an idea", () => {
  const res = classifyTrip({
    title: "Nashville",
    legs: [
      { state: "booked",   property_name: "Kimpton Aertson Hotel" },
      { state: "proposed", destination: "Nashville" },
      { state: "proposed", destination: "Chicago" },
      { state: "proposed", destination: "Smoky Mountains area" },
    ],
  });
  assert.strictEqual(res.verdict, "mixed");
  assert.match(res.note, /1 booked, 3 still proposed/);
});

t("a trip that is only proposals is an IDEA", () => {
  const res = classifyTrip({ title: "Smoky Mountains area", source: "planner",
    legs: [{ state: "proposed" }, { state: "proposed" }] });
  assert.strictEqual(res.verdict, "idea");
  assert.match(res.note, /planning conversation/);
});

t("a fully booked trip is REAL", () => {
  assert.strictEqual(classifyTrip({ title: "Tokyo", legs: [{ state: "booked" }] }).verdict, "real");
});

t("holders are named as holders, not judged as trips", () => {
  assert.strictEqual(classifyTrip({ title: "Needs review", legs: [] }).verdict, "holder");
  assert.strictEqual(classifyTrip({ title: "Reservations", legs: [{ state: "booked" }] }).verdict, "holder");
});

t("an empty trip is empty", () => {
  assert.strictEqual(classifyTrip({ title: "Paris", legs: [] }).verdict, "empty");
});

// The Dossier derives its 'idea' banner from the same rule. If these two ever
// disagree, the screen and the audit will tell the user different things about the
// same trip — which is how you lose trust in both.
t("classifyTrip agrees with the Dossier's certainty flag", () => {
  const legs = [{ state: "proposed" }, { state: "proposed" }];
  const dossierCertainty = legs.filter((l) => l.state !== "proposed").length === 0 ? "idea" : "real";
  assert.strictEqual(classifyTrip({ title: "X", legs }).verdict, dossierCertainty);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
