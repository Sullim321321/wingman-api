#!/usr/bin/env node
// test-gaps.js — find the free windows, never over a meeting, and only what fits.
//
//   node test-gaps.js
//
// The load-bearing promises of the Curator's alive moment: a pocket is never
// carved over a commitment, never in the past, never below the minimum worth
// surfacing — and "back by X" is a real calculation, not a wish.

const assert = require("assert");
const { findFreePockets, fits } = require("./gaps");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

// 1:00pm CDT (offset -5). Chicago day.
const NOW = Date.parse("2026-08-19T18:00:00Z");
const OPTS = { now: NOW, offsetH: -5, dayStart: 8, dayEnd: 22, minMinutes: 60, horizonDays: 0 };

console.log(`\n${b}Free pockets between the meetings${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// A 3–4pm meeting (20:00–21:00Z). It's 1pm now.
const day = [
  { start: "2026-08-19T15:00:00Z", end: "2026-08-19T16:00:00Z" }, // 10–11am, already past
  { start: "2026-08-19T20:00:00Z", end: "2026-08-19T21:00:00Z" }, // 3–4pm
];

t("today gives two pockets: before the 3pm and the evening after the 4pm", () => {
  const p = findFreePockets(day, OPTS);
  assert.strictEqual(p.length, 2, `expected 2, got ${p.length}`);
  assert.strictEqual(p[0].minutes, 120, "1pm→3pm should be 120 min");   // now → 3pm
  assert.strictEqual(p[1].minutes, 360, "4pm→10pm should be 360 min");  // 4pm → wind-down
});

t("a pocket never overlaps a commitment", () => {
  const p = findFreePockets(day, OPTS);
  const meetingStart = Date.parse("2026-08-19T20:00:00Z");
  const meetingEnd = Date.parse("2026-08-19T21:00:00Z");
  for (const w of p) {
    const s = Date.parse(w.start), e = Date.parse(w.end);
    assert.ok(e <= meetingStart || s >= meetingEnd, "a pocket ran over the 3pm meeting");
  }
});

t("nothing in the past — the morning is gone by 1pm", () => {
  const p = findFreePockets(day, OPTS);
  for (const w of p) assert.ok(Date.parse(w.start) >= NOW, "surfaced a pocket that already passed");
});

t("a day packed to the edges yields no pocket", () => {
  const packed = [{ start: "2026-08-19T13:00:00Z", end: "2026-08-20T03:00:00Z" }]; // 8am–10pm solid
  assert.strictEqual(findFreePockets(packed, OPTS).length, 0);
});

t("a gap smaller than the minimum is not surfaced", () => {
  // meetings at 1–1:30 and 2–4: leaves only 30 min (1:30–2:00) → below 60.
  const tight = [
    { start: "2026-08-19T18:00:00Z", end: "2026-08-19T18:30:00Z" },
    { start: "2026-08-19T19:00:00Z", end: "2026-08-20T03:00:00Z" },
  ];
  const p = findFreePockets(tight, OPTS);
  assert.ok(!p.some((w) => w.minutes < 60), "surfaced a sub-minimum gap");
});

t("no commitments → the whole waking day is free", () => {
  const p = findFreePockets([], OPTS);
  assert.strictEqual(p.length, 1);
  assert.strictEqual(p[0].minutes, 540); // 1pm → 10pm = 9h
});

console.log(`\n${b}Does it fit? "back by X" is real math${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a 2h pocket fits a 1h museum + 6 min each way", () => {
  const pocket = { start: "2026-08-19T18:00:00Z", minutes: 120 };
  const f = fits(pocket, 60, 6);
  assert.strictEqual(f.ok, true);
  assert.strictEqual(f.need_minutes, 72);
  assert.strictEqual(f.back, "2026-08-19T19:12:00.000Z"); // 1pm + 72 min = 2:12pm
});

t("a 3h dinner does NOT fit a 2h pocket", () => {
  assert.strictEqual(fits({ start: "2026-08-19T18:00:00Z", minutes: 120 }, 180, 10).ok, false);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
