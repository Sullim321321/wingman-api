#!/usr/bin/env node
// test-holds.js — hold-then-confirm is the whole safety story of C6.
//
//   node test-holds.js
//
// The one rule this module exists to enforce: a REFUNDABLE HOLD may be placed on
// Wingman's own judgement, but a CHARGE never happens without an explicit confirm
// that names the exact hold and price being bought. Every dangerous case below is a
// way that rule could be circumvented — a stale hold, a price that moved, a missing
// token, a hold that isn't actually free to release. All must be impossible.

const assert = require("assert");
const {
  decideBooking, assertChargeable, holdState, normalizeHold, summarizeForConfirm,
} = require("./holds");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const NOW = Date.parse("2026-08-01T12:00:00Z");

// A refundable stay offer that clears the rules.
const stay = {
  id: "stay_1", kind: "stay", price: 420, currency: "USD",
  refundable: true, refundable_until: "2026-08-10T00:00:00Z",
  name: "Kimpton Aertson", area: "Midtown",
};
// A non-refundable offer — cannot be auto-held on our judgement.
const nonRef = { id: "stay_2", kind: "stay", price: 260, currency: "USD", refundable: false };

console.log(`\n${b}decideBooking never auto-charges${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("watch level does nothing", () => {
  assert.strictEqual(decideBooking({ level: "watch", offer: stay }).step, "watch");
});
t("a refundable offer that clears rules → auto-hold (not charge)", () => {
  const dcn = decideBooking({ level: "full", offer: stay });
  assert.strictEqual(dcn.step, "hold");
});
t("NO level ever returns an auto-charge step", () => {
  for (const level of ["watch", "suggest", "hold", "book_under", "full"]) {
    const step = decideBooking({ level, offer: stay, threshold: 100000 }).step;
    assert.notStrictEqual(step, "charge", `level ${level} tried to auto-charge`);
    assert.notStrictEqual(step, "book", `level ${level} tried to auto-book`);
  }
});
t("a non-refundable offer is never auto-held — only suggested", () => {
  const dcn = decideBooking({ level: "full", offer: nonRef });
  assert.strictEqual(dcn.step, "suggest");
  assert.match(dcn.reason, /refund/i);
});
t("an offer breaking a standing order is suggested, not held", () => {
  const dcn = decideBooking({ level: "full", offer: stay, standingOrders: { max_price: 300 } });
  assert.strictEqual(dcn.step, "suggest");
  assert.match(dcn.reason, /cap|300|over/i);
});

console.log(`\n${b}assertChargeable — the confirm gate${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

const activeHold = normalizeHold({
  id: "hold_1", offer_id: "stay_1", amount: 420, currency: "USD",
  expires_at: "2026-08-01T13:00:00Z", refundable: true, state: "held",
});

t("charge proceeds only with a matching confirm token", () => {
  const res = assertChargeable(activeHold, { confirm: true, offer_id: "stay_1", amount: 420 }, NOW);
  assert.strictEqual(res.ok, true);
});
t("NO confirm flag → refused", () => {
  const res = assertChargeable(activeHold, { offer_id: "stay_1", amount: 420 }, NOW);
  assert.strictEqual(res.ok, false);
  assert.match(res.reason, /confirm/i);
});
t("confirm for a different hold/offer → refused", () => {
  const res = assertChargeable(activeHold, { confirm: true, offer_id: "stay_9", amount: 420 }, NOW);
  assert.strictEqual(res.ok, false);
  assert.match(res.reason, /match|offer/i);
});
t("price moved since the hold → refused (no silent overpay)", () => {
  const res = assertChargeable(activeHold, { confirm: true, offer_id: "stay_1", amount: 470 }, NOW);
  assert.strictEqual(res.ok, false);
  assert.match(res.reason, /price|amount|changed/i);
});
t("expired hold → refused even with a perfect confirm", () => {
  const later = Date.parse("2026-08-01T14:00:00Z"); // past 13:00 expiry
  const res = assertChargeable(activeHold, { confirm: true, offer_id: "stay_1", amount: 420 }, later);
  assert.strictEqual(res.ok, false);
  assert.match(res.reason, /expir/i);
});

console.log(`\n${b}holdState + normalize + summary${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("holdState reads active vs expired from real time", () => {
  assert.strictEqual(holdState(activeHold, NOW), "active");
  assert.strictEqual(holdState(activeHold, Date.parse("2026-08-01T13:00:01Z")), "expired");
});
t("a confirmed hold stays confirmed regardless of clock", () => {
  const confirmed = { ...activeHold, state: "confirmed" };
  assert.strictEqual(holdState(confirmed, Date.parse("2026-09-01T00:00:00Z")), "confirmed");
});
t("normalizeHold coerces provider fields + flags missing expiry honestly", () => {
  const h = normalizeHold({ id: "h", offer_id: "o", total_amount: "199.00", total_currency: "USD", state: "held" });
  assert.strictEqual(h.amount, 199);
  assert.strictEqual(h.currency, "USD");
  assert.strictEqual(h.expires_at, null); // unknown, not invented
});
t("summarizeForConfirm states amount, destination of charge, and expiry", () => {
  const line = summarizeForConfirm(activeHold);
  assert.match(line, /420/);
  assert.match(line, /USD/);
});
t("summary never claims a refund window it doesn't have", () => {
  const noRef = normalizeHold({ id: "h", offer_id: "o", amount: 100, currency: "USD", refundable: false, state: "held" });
  const line = summarizeForConfirm(noRef);
  assert.doesNotMatch(line, /refundable until/i);
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
