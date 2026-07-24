#!/usr/bin/env node
// test-flightbook.js — flights on the same hold-then-confirm safety rail as stays.
//
//   node test-flightbook.js
//
// Two shapes of offer: HOLDABLE (Duffel lets you reserve the fare without paying) and
// INSTANT-only (creating the order IS the payment). Both must obey one rule: no money
// moves without an explicit, matching, live confirm. The load-bearing tests are the ones
// that assert payments.create / the instant orders.create are NEVER reached when the gate
// fails — a charge past a failed gate is an unauthorised spend.

const assert = require("assert");
const fb = require("./flightbook");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  const done = (e) => e ? (console.log(`  ${r}✗${x} ${name}\n      ${e.message}`), fail++) : (console.log(`  ${g}✓${x} ${name}`), pass++);
  try { const p = fn(); if (p && p.then) return p.then(() => done(), done); done(); }
  catch (e) { done(e); }
};

function mockDuffel() {
  const calls = [];
  return {
    calls,
    orders: {
      create: async (data) => { calls.push(["orders.create", data]); return {
        data: {
          id: "ord_1", total_amount: "210.00", total_currency: "USD",
          booking_reference: "ABC123",
          payment_status: { awaiting_payment: data.type === "hold", payment_required_by: "2026-08-01T18:00:00Z" },
          slices: [],
        },
      }; },
    },
    payments: {
      create: async (data) => { calls.push(["payments.create", data]); return { data: { id: "pay_1", ...data } }; },
    },
  };
}

const NOW = Date.parse("2026-08-01T12:00:00Z");
const holdableOffer  = { id: "off_h", total_amount: "210.00", total_currency: "USD", payment_requirements: { requires_instant_payment: false } };
const instantOffer   = { id: "off_i", total_amount: "185.00", total_currency: "USD", payment_requirements: { requires_instant_payment: true } };
const passengers = [{ id: "pas_1", given_name: "Madeline", family_name: "Sullivan", born_on: "1990-01-01", gender: "f", email: "m@x.com", phone_number: "+16155551212" }];

console.log(`\n${b}holdable offers — hold then pay${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("offerHoldable reads requires_instant_payment", () => {
  assert.strictEqual(fb.offerHoldable(holdableOffer), true);
  assert.strictEqual(fb.offerHoldable(instantOffer), false);
});
t("placeFlightHold creates a type:hold order and returns a hold with expiry", async () => {
  const dfl = mockDuffel();
  const hold = await fb.placeFlightHold(dfl, { offer: holdableOffer, passengers });
  const call = dfl.calls.find(c => c[0] === "orders.create");
  assert.strictEqual(call[1].type, "hold");
  assert.deepStrictEqual(call[1].selected_offers, ["off_h"]);
  assert.strictEqual(hold.id, "ord_1");
  assert.strictEqual(hold.offer_id, "off_h");
  assert.strictEqual(hold.amount, 210);
  assert.strictEqual(hold.expires_at, "2026-08-01T18:00:00.000Z");
});

const goodHold = { id: "ord_1", offer_id: "off_h", amount: 210, currency: "USD", expires_at: "2026-08-01T18:00:00Z", state: "held" };

t("confirmFlightHold WITHOUT confirm never calls payments.create", async () => {
  const dfl = mockDuffel();
  const res = await fb.confirmFlightHold(dfl, { hold: goodHold, confirm: {} }, NOW);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "payments.create"), false);
});
t("confirmFlightHold price mismatch never pays", async () => {
  const dfl = mockDuffel();
  const res = await fb.confirmFlightHold(dfl, { hold: goodHold, confirm: { confirm: true, offer_id: "off_h", amount: 260 } }, NOW);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "payments.create"), false);
});
t("confirmFlightHold expired hold never pays", async () => {
  const dfl = mockDuffel();
  const later = Date.parse("2026-08-01T19:00:00Z");
  const res = await fb.confirmFlightHold(dfl, { hold: goodHold, confirm: { confirm: true, offer_id: "off_h", amount: 210 } }, later);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "payments.create"), false);
});
t("confirmFlightHold valid confirm pays the held order", async () => {
  const dfl = mockDuffel();
  const res = await fb.confirmFlightHold(dfl, { hold: goodHold, confirm: { confirm: true, offer_id: "off_h", amount: 210 } }, NOW);
  assert.strictEqual(res.ok, true);
  const call = dfl.calls.find(c => c[0] === "payments.create");
  assert.strictEqual(call[1].order_id, "ord_1");
  assert.strictEqual(call[1].payment.amount, "210"); // Duffel wants a string; no raw on this hand-built hold
});

console.log(`\n${b}instant-only offers — no free hold, still gated${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("bookInstant WITHOUT confirm never creates the order", async () => {
  const dfl = mockDuffel();
  const res = await fb.bookInstant(dfl, { offer: instantOffer, passengers, confirm: {} }, NOW);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "orders.create"), false);
});
t("bookInstant price mismatch never creates the order", async () => {
  const dfl = mockDuffel();
  const res = await fb.bookInstant(dfl, { offer: instantOffer, passengers, confirm: { confirm: true, offer_id: "off_i", amount: 999 } }, NOW);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "orders.create"), false);
});
t("bookInstant valid confirm creates a type:instant order with payment", async () => {
  const dfl = mockDuffel();
  const res = await fb.bookInstant(dfl, { offer: instantOffer, passengers, confirm: { confirm: true, offer_id: "off_i", amount: 185 } }, NOW);
  assert.strictEqual(res.ok, true);
  const call = dfl.calls.find(c => c[0] === "orders.create");
  assert.strictEqual(call[1].type, "instant");
  assert.strictEqual(call[1].payments[0].amount, "185.00");
});

Promise.resolve().then(async () => {
  await new Promise(r => setTimeout(r, 50));
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
