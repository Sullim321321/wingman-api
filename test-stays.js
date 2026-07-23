#!/usr/bin/env node
// test-stays.js — the Duffel Stays adapter, with a MOCK Duffel client (no network).
//
//   node test-stays.js
//
// The adapter's job is to turn Duffel's shapes into ours and to route every money
// step through holds.js. The load-bearing test is the last one: when the confirm gate
// refuses, bookings.create must NEVER be called. A booking that slips past a failed
// gate is a real charge with no authorisation — the exact thing C6 must make impossible.

const assert = require("assert");
const stays = require("./stays");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  const run = (e) => e ? (console.log(`  ${r}✗${x} ${name}\n      ${e.message}`), fail++) : (console.log(`  ${g}✓${x} ${name}`), pass++);
  try { const p = fn(); if (p && p.then) return p.then(() => run(), run); run(); }
  catch (e) { run(e); }
};

// ── A mock Duffel client that records calls and returns canned data ────────────
function mockDuffel(overrides = {}) {
  const calls = [];
  return {
    calls,
    stays: {
      search: async (data) => { calls.push(["search", data]); return {
        data: { results: [
          { id: "sr_2", accommodation: { name: "The Hoxton", rating: 4, location: { address: { city_name: "Nashville" } } }, cheapest_rate_total_amount: "512.00", cheapest_rate_currency: "USD" },
          { id: "sr_1", accommodation: { name: "Kimpton Aertson", rating: 5, location: { address: { city_name: "Nashville" } } }, cheapest_rate_total_amount: "420.00", cheapest_rate_currency: "USD" },
        ] },
      }; },
      searchResults: {
        fetchAllRates: async (id) => { calls.push(["fetchAllRates", id]); return {
          data: { id, accommodation: { name: "Kimpton Aertson", rooms: [
            { rates: [
              { id: "rate_ref", total_amount: "420.00", total_currency: "USD", payment_type: "card",
                cancellation_timeline: [{ before: "2026-08-10T00:00:00Z", refund_amount: "420.00", currency: "USD" }] },
              { id: "rate_nonref", total_amount: "380.00", total_currency: "USD", payment_type: "card",
                cancellation_timeline: [] },
            ] },
          ] } },
        }; },
      },
      quotes: {
        create: async (rateId) => { calls.push(["quotes.create", rateId]); return {
          data: { id: "quote_1", total_amount: "420.00", total_currency: "USD", expires_at: "2026-08-01T13:00:00Z" },
        }; },
      },
      bookings: {
        create: async (data) => { calls.push(["bookings.create", data]); return { data: { id: "booking_1", ...data } }; },
        cancel: async (id) => { calls.push(["bookings.cancel", id]); return { data: { id, status: "cancelled" } }; },
      },
    },
    ...overrides,
  };
}

const NOW = Date.parse("2026-08-01T12:00:00Z");

console.log(`\n${b}search + normalize${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("searchStays builds a geographic location body and sorts by price", async () => {
  const dfl = mockDuffel();
  const out = await stays.searchStays(dfl, { latitude: 36.15, longitude: -86.79, check_in_date: "2026-08-05", check_out_date: "2026-08-07" });
  const body = dfl.calls.find(c => c[0] === "search")[1];
  assert.deepStrictEqual(body.location.geographic_coordinates, { longitude: -86.79, latitude: 36.15 });
  assert.strictEqual(out[0].name, "Kimpton Aertson"); // cheapest first
  assert.strictEqual(out[0].price, 420);
  assert.strictEqual(out[0].search_result_id, "sr_1");
});

t("refundabilityOf reads a full-refund timeline", () => {
  const rf = stays.refundabilityOf({ total_amount: "420.00", cancellation_timeline: [{ before: "2026-08-10T00:00:00Z", refund_amount: "420.00" }] });
  assert.strictEqual(rf.refundable, true);
  assert.strictEqual(rf.refundable_until, "2026-08-10T00:00:00.000Z");
});
t("refundabilityOf treats an empty timeline as non-refundable", () => {
  assert.strictEqual(stays.refundabilityOf({ total_amount: "380.00", cancellation_timeline: [] }).refundable, false);
});
t("refundabilityOf treats pay-at-property as freely cancellable", () => {
  assert.strictEqual(stays.refundabilityOf({ total_amount: "300.00", payment_type: "pay_at_property", cancellation_timeline: [] }).refundable, true);
});

t("ratesFor normalizes rates + derives refundability", async () => {
  const dfl = mockDuffel();
  const { rates } = await stays.ratesFor(dfl, "sr_1");
  const ref = rates.find(r => r.id === "rate_ref");
  const non = rates.find(r => r.id === "rate_nonref");
  assert.strictEqual(ref.refundable, true);
  assert.strictEqual(ref.kind, "stay");
  assert.strictEqual(non.refundable, false);
});

console.log(`\n${b}hold (quote) — no money moves${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("placeHold quotes the rate and returns a hold carrying offer_id + refundability", async () => {
  const dfl = mockDuffel();
  const rate = { id: "rate_ref", price: 420, currency: "USD", refundable: true, refundable_until: "2026-08-10T00:00:00Z" };
  const hold = await stays.placeHold(dfl, rate);
  assert.deepStrictEqual(dfl.calls.find(c => c[0] === "quotes.create"), ["quotes.create", "rate_ref"]);
  assert.strictEqual(hold.id, "quote_1");
  assert.strictEqual(hold.offer_id, "rate_ref");
  assert.strictEqual(hold.amount, 420);
  assert.strictEqual(hold.refundable, true);
  assert.strictEqual(hold.expires_at, "2026-08-01T13:00:00.000Z");
});

console.log(`\n${b}confirm (booking) — gated on holds.assertChargeable${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

const goodHold = { id: "quote_1", offer_id: "rate_ref", amount: 420, currency: "USD", refundable: true, expires_at: "2026-08-01T13:00:00Z", state: "held" };
const guests = [{ given_name: "Madeline", family_name: "Sullivan" }];

t("confirmBooking WITHOUT confirm never calls bookings.create", async () => {
  const dfl = mockDuffel();
  const res = await stays.confirmBooking(dfl, { hold: goodHold, confirm: {}, guests, email: "m@x.com", phone_number: "+16155551212" }, NOW);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "bookings.create"), false, "bookings.create was reached without confirm");
});
t("confirmBooking with a price mismatch never calls bookings.create", async () => {
  const dfl = mockDuffel();
  const res = await stays.confirmBooking(dfl, { hold: goodHold, confirm: { confirm: true, offer_id: "rate_ref", amount: 470 }, guests, email: "m@x.com", phone_number: "+1" }, NOW);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "bookings.create"), false);
});
t("confirmBooking with a valid confirm charges via quote_id", async () => {
  const dfl = mockDuffel();
  const res = await stays.confirmBooking(dfl, { hold: goodHold, confirm: { confirm: true, offer_id: "rate_ref", amount: 420 }, guests, email: "m@x.com", phone_number: "+16155551212" }, NOW);
  assert.strictEqual(res.ok, true);
  const call = dfl.calls.find(c => c[0] === "bookings.create");
  assert.ok(call, "bookings.create should have been called");
  assert.strictEqual(call[1].quote_id, "quote_1");
  assert.deepStrictEqual(call[1].guests, guests);
});
t("an expired hold cannot be booked even with a perfect confirm", async () => {
  const dfl = mockDuffel();
  const later = Date.parse("2026-08-01T14:00:00Z");
  const res = await stays.confirmBooking(dfl, { hold: goodHold, confirm: { confirm: true, offer_id: "rate_ref", amount: 420 }, guests, email: "m@x.com", phone_number: "+1" }, later);
  assert.strictEqual(res.ok, false);
  assert.strictEqual(dfl.calls.some(c => c[0] === "bookings.create"), false);
});

Promise.resolve().then(async () => {
  // allow async tests to flush
  await new Promise(r => setTimeout(r, 50));
  console.log(`\n${pass} passed, ${fail} failed\n`);
  process.exit(fail ? 1 : 0);
});
