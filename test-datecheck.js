#!/usr/bin/env node
// test-datecheck.js — the weekday and the date must agree.
//
//   node test-datecheck.js
//
// Third occurrence of one bug. v1 asked the model to do arithmetic; v2 handed it a
// lookup table and a capitalised instruction; v3 is today, where it had the table,
// was told twice not to compute, and still wrote "Arrive Thursday, July 24" on a
// Sunday-July-19 conversation. July 24 is a Friday.
//
// So this file tests the only version that can actually hold: checking the output
// against a calendar we computed ourselves.

const assert = require("assert");
const { buildCalendar, verifyDateClaims, correctDateClaims } = require("./datecheck");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

// 6:39 PM EDT on Sunday 19 July 2026 — the moment from the screenshot.
const NOW = "2026-07-19T23:39:00Z";
const TZ  = "America/New_York";
const cal = buildCalendar(NOW, TZ, 21);

console.log(`\n${b}The calendar itself${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("today is Sunday 2026-07-19 in the user's timezone, not the server's", () => {
  assert.strictEqual(cal[0].iso, "2026-07-19");
  assert.strictEqual(cal[0].weekday, "Sunday");
});

t("Thursday is the 23rd; Friday is the 24th", () => {
  assert.strictEqual(cal.find((c) => c.weekday === "Thursday").iso, "2026-07-23");
  assert.strictEqual(cal.find((c) => c.iso === "2026-07-24").weekday, "Friday");
});

console.log(`\n${b}The sentence that shipped${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

const SAID = "Going to Chicago Thurs - where should I stay? What should I do?";

t("catches 'Thursday, July 24' as a contradiction", () => {
  const [c] = verifyDateClaims("Arrive Thursday, July 24.", cal, SAID);
  assert.strictEqual(c.ok, false, "the contradiction went undetected");
});

t("corrects it to Thursday, July 23 — she said Thursday, so the DATE was invented", () => {
  const out = correctDateClaims("Noted — Traveling to Chicago; Arrive Thursday, July 24.", cal, SAID);
  assert.match(out.text, /Thursday, July 23/);
  assert.doesNotMatch(out.text, /July 24/);
  assert.match(out.fixed[0].basis, /you said the weekday/);
});

// The other direction. If SHE gave the date and the model decorated it with a
// weekday, the date is the reliable half. Trusting the weekday here would move her
// trip — a correction worse than the error.
t("when SHE gave the date, the weekday is the invention", () => {
  const out = correctDateClaims("Arrive Thursday, July 24.", cal, "I land July 24");
  assert.match(out.text, /Friday, July 24/);
  assert.match(out.fixed[0].basis, /the date is fixed/);
});

console.log(`\n${b}What it must NOT do${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("leaves a correct claim completely alone", () => {
  const out = correctDateClaims("Arrive Thursday, July 23 at 4pm.", cal, SAID);
  assert.strictEqual(out.fixed.length, 0, "it 'corrected' something that was already right");
  assert.strictEqual(out.text, "Arrive Thursday, July 23 at 4pm.");
});

// The hardest restraint. A date outside the 21-day window cannot be checked against
// a 21-day calendar. Guessing here would be the exact sin the file exists to prevent:
// asserting on evidence we do not have.
t("refuses to judge a date outside the window", () => {
  const [c] = verifyDateClaims("Arrive Tuesday, December 14.", cal, "");
  assert.strictEqual(c.ok, null, "it judged a date it could not see");
  const out = correctDateClaims("Arrive Tuesday, December 14.", cal, "");
  assert.strictEqual(out.fixed.length, 0);
});

t("ignores text with no date claim at all", () => {
  assert.strictEqual(correctDateClaims("Where would you like to stay?", cal, "").fixed.length, 0);
  assert.strictEqual(correctDateClaims("", cal, "").fixed.length, 0);
  assert.strictEqual(correctDateClaims(null, cal, "").fixed.length, 0);
});

t("handles abbreviations the model actually emits", () => {
  const out = correctDateClaims("Arrive Thu, Jul 24.", cal, SAID);
  assert.match(out.text, /July 23/);
});

t("corrects every occurrence, not just the first", () => {
  const out = correctDateClaims(
    "Arrive Thursday, July 24. Dinner Thursday, July 24 at 8.", cal, SAID);
  assert.strictEqual((out.text.match(/July 23/g) || []).length, 2);
  assert.doesNotMatch(out.text, /July 24/);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
