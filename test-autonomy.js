#!/usr/bin/env node
// test-autonomy.js — the dial may widen what Wingman does, never what you said.
//
//   node test-autonomy.js
//
// The dangerous cases are the ones where autonomy could overreach: booking over the
// ceiling, or buying something a standing order forbids. Those must be impossible at
// EVERY level. The rest is making sure each level does what it says.

const assert = require("assert");
const { decideAction, qualifies, normalizeOffer, isRedEye } = require("./autonomy");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

// A few normalized offers on the BNA→ORD trip.
const cheap   = { id: "a", price: 210, currency: "USD", cabin: "economy",  airports: ["BNA", "ORD"], departs_at: "2026-08-15T09:00:00-05:00", red_eye: false, refundable: false };
const mid     = { id: "b", price: 340, currency: "USD", cabin: "business", airports: ["BNA", "ORD"], departs_at: "2026-08-15T10:00:00-05:00", red_eye: false, refundable: true };
const redeye  = { id: "c", price: 150, currency: "USD", cabin: "economy",  airports: ["BNA", "MDW"], departs_at: "2026-08-15T23:30:00-05:00", red_eye: true,  refundable: false };
const dear    = { id: "d", price: 900, currency: "USD", cabin: "first",    airports: ["BNA", "ORD"], departs_at: "2026-08-15T12:00:00-05:00", red_eye: false, refundable: true };

console.log(`\n${b}Each level does what it says${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("watch acts on nothing", () => {
  assert.strictEqual(decideAction({ level: "watch", offers: [cheap, mid] }).action, "watch");
});
t("suggest proposes the best, never books", () => {
  const dcn = decideAction({ level: "suggest", offers: [mid, cheap] });
  assert.strictEqual(dcn.action, "suggest");
  assert.strictEqual(dcn.offer.id, "a"); // cheapest qualifying
});
t("hold holds the best, asks before buying", () => {
  assert.strictEqual(decideAction({ level: "hold", offers: [cheap, mid] }).action, "hold");
});
t("full books the best that fits", () => {
  const dcn = decideAction({ level: "full", offers: [mid, cheap] });
  assert.strictEqual(dcn.action, "book");
  assert.strictEqual(dcn.offer.id, "a");
});

console.log(`\n${b}Money has a ceiling${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("book_under BUYS at/under the ceiling", () => {
  const dcn = decideAction({ level: "book_under", threshold: 250, offers: [cheap] });
  assert.strictEqual(dcn.action, "book");
});
t("book_under HOLDS (never buys) over the ceiling", () => {
  const dcn = decideAction({ level: "book_under", threshold: 250, offers: [mid] }); // 340 > 250
  assert.strictEqual(dcn.action, "hold", "it bought over the ceiling");
  assert.ok(/ceiling/.test(dcn.reason));
});

console.log(`\n${b}A standing order is a hard wall — at every level${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("no_red_eyes rules out the red-eye even though it's cheapest", () => {
  const dcn = decideAction({ level: "full", standingOrders: { no_red_eyes: true }, offers: [redeye, cheap] });
  assert.strictEqual(dcn.offer.id, "a", "booked the red-eye you forbade");
  assert.ok(dcn.excluded.some((e) => e.id === "c" && e.reasons.includes("red-eye")));
});
t("min_cabin business excludes economy", () => {
  const dcn = decideAction({ level: "full", standingOrders: { min_cabin: "business" }, offers: [cheap, mid] });
  assert.strictEqual(dcn.offer.id, "b", "booked below your cabin floor");
});
t("avoid_airports excludes offers routing through them", () => {
  const dcn = decideAction({ level: "full", standingOrders: { avoid_airports: ["MDW"] }, offers: [redeye] });
  assert.strictEqual(dcn.action, "suggest", "should not book — MDW is avoided and it's the only offer");
  assert.strictEqual(dcn.offer, null);
});
t("even FULL won't buy when nothing clears your rules", () => {
  const dcn = decideAction({ level: "full", standingOrders: { min_cabin: "first", max_price: 500 }, offers: [cheap, mid, redeye] });
  assert.strictEqual(dcn.action, "suggest");
  assert.strictEqual(dcn.offer, null, "bought something that broke a standing order");
});
t("a standing order can't be widened by autonomy: max_price holds under full", () => {
  const dcn = decideAction({ level: "full", standingOrders: { max_price: 400 }, offers: [dear] }); // 900 > 400
  assert.strictEqual(dcn.action, "suggest", "full mode bought over your own price cap");
});

console.log(`\n${b}Legacy mode maps, red-eye detection${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("always_ask maps to suggest", () => {
  assert.strictEqual(decideAction({ mode: "always_ask", offers: [cheap] }).action, "suggest");
});
t("fully_auto + threshold maps to book_under", () => {
  assert.strictEqual(decideAction({ mode: "fully_auto", threshold: 250, offers: [cheap] }).action, "book");
  assert.strictEqual(decideAction({ mode: "fully_auto", threshold: 150, offers: [cheap] }).action, "hold"); // 210 > 150
});
t("red-eye detection reads the departure hour", () => {
  assert.strictEqual(isRedEye("2026-08-15T23:30:00-05:00"), true);
  assert.strictEqual(isRedEye("2026-08-15T09:00:00-05:00"), false);
  assert.strictEqual(isRedEye(null), false);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
