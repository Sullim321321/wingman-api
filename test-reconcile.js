#!/usr/bin/env node
// test-reconcile.js — a text can flag the calendar, but a wrong match can't delete it.
//
//   node test-reconcile.js
//
// The real case: the Chicago meetings were cancelled by text and the calendar never
// updated. The load-bearing assertions are the two failure modes — a confident
// cancellation must suppress the dead meeting, and an UNRELATED cancellation must
// NOT touch it. Silently dropping the wrong meeting is worse than doing nothing.

const assert = require("assert");
const { reconcileMessage, reconcile } = require("./reconcile");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const chicago = {
  calendar_id: "c1",
  title: "3 or 330 — Miru Terrace — St. Regis Tower",
  start: "2026-07-23T20:00:00Z",
  geo: { city: "Chicago" },
};
const evanston = {
  calendar_id: "c2",
  title: "Maddie/JR Meet up",
  start: "2026-07-24T14:00:00Z",
  geo: { city: "Evanston" },
};

console.log(`\n${b}A text that cancels the meeting${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("cancel + topic + date is a HIGH-confidence contradiction", () => {
  const sig = { intent: "cancel", topic: "St Regis", date: "2026-07-23T09:00:00Z", quote: "let's cancel the St Regis thing today" };
  const rr = reconcileMessage(chicago, sig);
  assert.strictEqual(rr.effect, "contradicts");
  assert.strictEqual(rr.confidence, "high");
});

t("a HIGH cancellation suppresses the meeting so no trip is proposed", () => {
  const sig = { intent: "cancel", topic: "St Regis", date: "2026-07-23T09:00:00Z" };
  const { commitments } = reconcile([chicago], [sig]);
  assert.strictEqual(commitments[0].suppressed, true, "the dead meeting stayed live");
});

console.log(`\n${b}The refusals — a wrong match must not delete a real meeting${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a cancellation about something ELSE does not touch Chicago", () => {
  const sig = { intent: "cancel", topic: "dentist", date: "2026-07-23T09:00:00Z" };
  const rr = reconcileMessage(chicago, sig);
  // date coincides, but topic doesn't — one weak signal, never a silent drop.
  assert.notStrictEqual(rr.effect === "contradicts" && rr.confidence === "high", true);
});

t("an unrelated cancel never suppresses", () => {
  const sig = { intent: "cancel", topic: "dentist appointment", date: "2026-07-23T09:00:00Z" };
  const { commitments, asks } = reconcile([chicago], [sig]);
  // Same-day only = medium at most → a question, not a suppression.
  assert.notStrictEqual(commitments[0].suppressed, true, "a dentist text deleted the Chicago meeting");
  if (asks.length) assert.strictEqual(asks[0].confidence, "medium");
});

t("no overlap at all = none, no ask", () => {
  const sig = { intent: "cancel", topic: "book club", date: "2026-08-01T00:00:00Z" };
  assert.strictEqual(reconcileMessage(chicago, sig).effect, "none");
});

t("a cancel that only shares the DAY does not query unrelated meetings", () => {
  // The real bug: a St-Regis cancel mis-dated to the 24th matched "Covrly Sales
  // Daily" and "Maddie/JR Meet up" purely because they fell on the 24th too.
  const covrly = { calendar_id: "z", title: "Covrly — Sales Daily", start: "2026-07-24T13:00:00Z" };
  const sig = { intent: "cancel", topic: "St. Regis / Miru Terrace", date: "2026-07-24T09:00:00Z" };
  assert.strictEqual(reconcileMessage(covrly, sig).effect, "none", "a same-day, unrelated meeting was flagged");
  const { asks } = reconcile([covrly], [sig]);
  assert.strictEqual(asks.length, 0, "produced a false 'was this cancelled?' question");
});

t("topic + date is confident enough to suppress", () => {
  const sig = { intent: "cancel", topic: "St Regis", date: "2026-07-23T09:00:00Z" };
  assert.strictEqual(reconcileMessage(chicago, sig).confidence, "high");
});

console.log(`\n${b}Medium matches ask; moves and confirms don't silently act${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("topic-only cancel is MEDIUM → a question, not a suppression", () => {
  const sig = { intent: "cancel", topic: "Miru Terrace" }; // no date
  const rr = reconcileMessage(chicago, sig);
  assert.strictEqual(rr.confidence, "medium");
  const { commitments, asks } = reconcile([chicago], [sig]);
  assert.notStrictEqual(commitments[0].suppressed, true);
  assert.strictEqual(asks.length, 1);
  assert.ok(/was cancelled/.test(asks[0].question));
});

t("a MOVE is a question about the trip, never a silent drop", () => {
  const sig = { intent: "move", topic: "St Regis", date: "2026-07-23T09:00:00Z" };
  const { commitments, asks } = reconcile([chicago], [sig]);
  assert.notStrictEqual(commitments[0].suppressed, true);
  assert.strictEqual(asks[0].effect, "reschedules");
});

t("the right meeting is matched when several are on the calendar", () => {
  const sig = { intent: "cancel", topic: "St Regis", date: "2026-07-23T09:00:00Z" };
  const { commitments } = reconcile([chicago, evanston], [sig]);
  assert.strictEqual(commitments[0].suppressed, true, "Chicago should be suppressed");
  assert.notStrictEqual(commitments[1].suppressed, true, "Evanston must be untouched");
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
