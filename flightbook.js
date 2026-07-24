/**
 * flightbook.js — C6b: flights on the same hold-then-confirm rail as stays.
 *
 * Duffel offers come in two shapes:
 *   HOLDABLE  (payment_requirements.requires_instant_payment === false) — you can create
 *             a `type:"hold"` order that reserves the fare and moves NO money, then pay
 *             later. This maps directly onto holds.js: the hold order is the hold, the
 *             payment is the confirm.
 *   INSTANT   (requires_instant_payment === true) — creating the order IS the payment,
 *             so there is no free hold. We therefore do NOT create the order until an
 *             explicit confirm arrives; confirm creates + pays atomically, still gated.
 *
 * Either way, the invariant from holds.js holds: no money moves without an explicit,
 * matching, live confirm. The Duffel client is injected so this is unit-tested with a
 * mock and no network.
 */

const holds = require("./holds");

function num(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }

/** Can this offer be reserved without paying? */
function offerHoldable(offer = {}) {
  return offer?.payment_requirements?.requires_instant_payment === false;
}

/**
 * placeFlightHold — create a `type:"hold"` order (no money). Returns a normalized hold
 * whose id is the Duffel order id; a hold order is unwound simply by not paying, so it's
 * treated as refundable, and its expiry is Duffel's payment_required_by / guarantee.
 */
async function placeFlightHold(duffel, { offer, passengers }) {
  const resp = await duffel.orders.create({
    type: "hold",
    selected_offers: [offer.id],
    passengers,
  });
  const o = resp?.data || {};
  const ps = o.payment_status || {};
  return holds.normalizeHold({
    id: o.id,
    offer_id: offer.id,
    kind: "flight",
    amount: o.total_amount,
    currency: o.total_currency,
    refundable: true, // abandoning a hold costs nothing
    expires_at: ps.payment_required_by || ps.price_guarantee_expires_at || null,
    state: "held",
    provider: "duffel_air",
    booking_reference: o.booking_reference || null,
  });
}

/**
 * confirmFlightHold — pay for a held order. The ONLY path that spends money on a held
 * flight. Refuses (never calling payments.create) unless holds.assertChargeable passes.
 */
async function confirmFlightHold(duffel, { hold, confirm }, now = Date.now()) {
  const gate = holds.assertChargeable(hold, confirm, now);
  if (!gate.ok) return { ok: false, reason: gate.reason };
  // Pay the EXACT string Duffel quoted (raw.amount, e.g. "210.00") when we have it, so
  // there's no format drift ("210" vs "210.00") that a strict provider could reject.
  const payAmount = hold.raw?.amount != null ? String(hold.raw.amount) : String(hold.amount);
  const resp = await duffel.payments.create({
    order_id: hold.id,
    payment: { type: "balance", amount: payAmount, currency: hold.currency },
  });
  return { ok: true, payment: resp?.data || null, order_id: hold.id, booking_reference: hold.raw?.booking_reference || null };
}

/**
 * bookInstant — for offers that can't be held. There is no free reservation, so we do not
 * touch Duffel until confirm. We build a pseudo-hold from the offer purely to run the same
 * confirm gate (explicit flag + matching offer + matching amount), then create a
 * `type:"instant"` order WITH payment in one step. No confirm → no order, ever.
 */
async function bookInstant(duffel, { offer, passengers, confirm }, now = Date.now()) {
  const amount = num(offer.total_amount ?? offer.price);
  const currency = offer.total_currency || offer.currency || "USD";
  const pseudoHold = holds.normalizeHold({
    id: offer.id, offer_id: offer.id, kind: "flight",
    amount, currency, state: "held",
  });
  const gate = holds.assertChargeable(pseudoHold, confirm, now);
  if (!gate.ok) return { ok: false, reason: gate.reason };

  const resp = await duffel.orders.create({
    type: "instant",
    selected_offers: [offer.id],
    passengers,
    payments: [{ type: "balance", amount: (offer.total_amount ?? String(amount)), currency }],
  });
  const o = resp?.data || {};
  return { ok: true, order: o, order_id: o.id, booking_reference: o.booking_reference || null };
}

module.exports = { offerHoldable, placeFlightHold, confirmFlightHold, bookInstant };
