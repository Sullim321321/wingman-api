/**
 * stays.js — the Duffel Stays adapter for C6a (real, bookable hotels).
 *
 * Wingman's Curator shows a stay slate; this turns a chosen room into a real booking,
 * safely. The safety model is hold-then-confirm from holds.js:
 *
 *   HOLD    = duffel.stays.quotes.create(rate_id)   — confirms price + availability,
 *             moves NO money, and is short-lived. Wingman may do this on its own for a
 *             refundable rate.
 *   CONFIRM = duffel.stays.bookings.create({ quote_id, guests, … })  — the charge. This
 *             is gated on holds.assertChargeable, which refuses without an explicit,
 *             matching, still-live confirm. There is no path here to an unattended charge.
 *
 * The Duffel client is injected (never imported) so this module is unit-tested against a
 * mock with no network. Every function normalises Duffel's shapes into ours and never
 * invents a field it wasn't given (a fabricated price or refund window is a lie with a
 * booking reference attached).
 */

const holds = require("./holds");

// ── normalisation ─────────────────────────────────────────────────────────────

function num(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }

function normalizeStayResult(r = {}) {
  const acc = r.accommodation || {};
  const addr = acc.location?.address || {};
  const photo = (acc.photos && acc.photos[0] && (acc.photos[0].url || acc.photos[0])) || null;
  return {
    search_result_id: r.id || null,
    name: acc.name || null,
    area: addr.city_name || addr.region || null,
    rating: acc.rating ?? null,
    price: num(r.cheapest_rate_total_amount),
    currency: r.cheapest_rate_currency || "USD",
    photo,
    lat: acc.location?.geographic_coordinates?.latitude ?? null,
    lng: acc.location?.geographic_coordinates?.longitude ?? null,
  };
}

/**
 * refundabilityOf — derive { refundable, refundable_until } from a Duffel rate.
 * A rate is auto-holdable only if it can be unwound at no cost: either it's payable at
 * the property (nothing charged now) or its cancellation timeline offers a FULL refund
 * up to some date. Partial-refund-only rates are treated as non-refundable — we won't
 * auto-hold something Wingman can't fully reverse.
 */
function refundabilityOf(rate = {}) {
  if (rate.payment_type === "pay_at_property") {
    return { refundable: true, refundable_until: null };
  }
  const total = num(rate.total_amount);
  const timeline = Array.isArray(rate.cancellation_timeline) ? rate.cancellation_timeline : [];
  const full = timeline
    .filter((e) => e && e.before && total != null && num(e.refund_amount) != null && num(e.refund_amount) >= total)
    .map((e) => Date.parse(e.before))
    .filter((ms) => !Number.isNaN(ms));
  if (full.length) {
    return { refundable: true, refundable_until: new Date(Math.max(...full)).toISOString() };
  }
  return { refundable: false, refundable_until: null };
}

function normalizeRate(rate = {}) {
  const rf = refundabilityOf(rate);
  return {
    id: rate.id || null,
    kind: "stay",
    price: num(rate.total_amount),
    currency: rate.total_currency || "USD",
    board_type: rate.board_type || null,
    payment_type: rate.payment_type || null,
    refundable: rf.refundable,
    refundable_until: rf.refundable_until,
    cancellation_timeline: rate.cancellation_timeline || [],
  };
}

// ── search ────────────────────────────────────────────────────────────────────

/**
 * searchStays — real availability around a point.
 * @param opts.latitude/longitude  the search centre (from the Curator's city/geo)
 * @param opts.radius              km (default 5)
 * @param opts.check_in_date/check_out_date  YYYY-MM-DD
 * @param opts.rooms               integer (default 1)
 * @param opts.guests              e.g. [{ type:"adult" }]
 * Returns normalized results, cheapest first, capped.
 */
async function searchStays(duffel, opts = {}) {
  const {
    latitude, longitude, radius = 5, check_in_date, check_out_date,
    rooms = 1, guests = [{ type: "adult" }], limit = 20,
  } = opts;
  const resp = await duffel.stays.search({
    location: { radius, geographic_coordinates: { longitude, latitude } },
    check_in_date, check_out_date, rooms, guests,
  });
  const results = (resp?.data?.results || []).map(normalizeStayResult);
  results.sort((a, b) => (a.price ?? Infinity) - (b.price ?? Infinity));
  return results.slice(0, limit);
}

/** ratesFor — bookable rates for a chosen search result, refundability derived. */
async function ratesFor(duffel, searchResultId) {
  const resp = await duffel.stays.searchResults.fetchAllRates(searchResultId);
  const acc = resp?.data?.accommodation || {};
  const rates = [];
  for (const room of acc.rooms || []) {
    for (const rate of room.rates || []) rates.push(normalizeRate(rate));
  }
  rates.sort((a, b) => (a.price ?? Infinity) - (b.price ?? Infinity));
  return { accommodation: { name: acc.name || null }, rates };
}

// ── hold (no money) ─────────────────────────────────────────────────────────────

/**
 * placeHold — create a Duffel Stays QUOTE for a rate. This confirms current price and
 * availability and moves no money. Returns a normalized hold (holds.normalizeHold) that
 * carries the rate id as offer_id and the rate's refundability, so the confirm step can
 * verify it's charging exactly what was held.
 *
 * Caller must have decided this is holdable (holds.decideBooking → "hold"); we also carry
 * refundable through so assertChargeable/summaries stay honest.
 */
async function placeHold(duffel, rate = {}) {
  const resp = await duffel.stays.quotes.create(rate.id);
  const q = resp?.data || {};
  return holds.normalizeHold({
    id: q.id,
    offer_id: rate.id,
    kind: "stay",
    amount: q.total_amount,
    currency: q.total_currency || rate.currency,
    refundable: rate.refundable ?? false,
    refundable_until: rate.refundable_until ?? null,
    expires_at: q.expires_at || null,
    state: "held",
    provider: "duffel_stays",
  });
}

// ── confirm (the charge) ─────────────────────────────────────────────────────────

/**
 * confirmBooking — the ONLY path that spends money on a stay.
 * @param opts.hold     normalized hold from placeHold (its id is the quote_id)
 * @param opts.confirm  { confirm:true, offer_id, amount } — must match the hold, live
 * @param opts.guests   [{ given_name, family_name }, …]
 * @param opts.email / opts.phone_number
 * Refuses (without ever calling bookings.create) unless the confirm gate passes.
 */
async function confirmBooking(duffel, opts = {}, now = Date.now()) {
  const { hold, confirm, guests, email, phone_number, accommodation_special_requests } = opts;
  const gate = holds.assertChargeable(hold, confirm, now);
  if (!gate.ok) return { ok: false, reason: gate.reason };

  const resp = await duffel.stays.bookings.create({
    quote_id: hold.id,
    guests,
    email,
    phone_number,
    ...(accommodation_special_requests ? { accommodation_special_requests } : {}),
  });
  return { ok: true, booking: resp?.data || null };
}

/** releaseHold — cancel a quote-backed booking (used if a hold is abandoned). */
async function releaseBooking(duffel, bookingId) {
  const resp = await duffel.stays.bookings.cancel(bookingId);
  return resp?.data || null;
}

module.exports = {
  searchStays, ratesFor, placeHold, confirmBooking, releaseBooking,
  normalizeStayResult, normalizeRate, refundabilityOf,
};
