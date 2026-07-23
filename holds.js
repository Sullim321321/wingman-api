/**
 * holds.js — hold-then-confirm: the safety core of C6 (real booking actions).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE ONE RULE THIS FILE EXISTS TO ENFORCE:
 *
 *   Wingman may place a REFUNDABLE HOLD on its own judgement.
 *   Wingman may NEVER charge money without an explicit confirm that names the
 *   exact hold, offer, and price being bought — and only while the hold is live.
 *
 * A hold costs nothing and can be released; it is reversible, so autonomy is safe
 * there. A charge is irreversible spend, so it stays behind a human yes. This module
 * is pure and dependency-free: it decides which step is allowed and refuses a charge
 * that isn't fully, currently, and specifically authorised. The provider adapters
 * (Duffel Stays, Duffel flights) call these before touching money.
 *
 * This mirrors the autonomy dial (autonomy.js): 'hold' is the furthest an unattended
 * run may go for live money; the confirm is a separate, explicit act.
 * ────────────────────────────────────────────────────────────────────────────── */

const LEVELS = ["watch", "suggest", "hold", "book_under", "full"];

// A hold may be placed automatically only when it is genuinely free to unwind — i.e.
// the offer is refundable (or the provider hold itself is a no-cost reservation). If
// it isn't, holding it is really a soft purchase, and that must be a human decision.
function holdable(offer = {}) {
  return offer.refundable === true;
}

/**
 * decideBooking — the furthest Wingman may go on its own for a single offer.
 *
 * Returns { step, offer, reason } where step is one of:
 *   "watch"    — do nothing, don't even surface (watch level)
 *   "suggest"  — surface it for the user; do not touch money or place a hold
 *   "hold"     — place a refundable, no-cost hold now; ask before charging
 *
 * It NEVER returns "book"/"charge". Charging is assertChargeable + the adapter,
 * gated on an explicit confirm. This is deliberate: there is no code path here that
 * yields an autonomous charge.
 */
function decideBooking(opts = {}) {
  const level = LEVELS.includes(opts.level) ? opts.level : "suggest";
  const offer = opts.offer || null;
  const orders = opts.standingOrders || {};

  if (level === "watch") {
    return { step: "watch", offer: null, reason: "Watching only — I won't surface or act." };
  }
  if (!offer) {
    return { step: "suggest", offer: null, reason: "No offer to act on." };
  }

  // Hard walls first — a standing order is a wall, not a preference.
  const wall = brokenOrder(offer, orders);
  if (wall) {
    return { step: "suggest", offer, reason: `Leaving it for you — ${wall}.` };
  }

  // suggest level never places a hold, even for a perfect offer.
  if (level === "suggest") {
    return { step: "suggest", offer, reason: `Best that fits your rules: ${money(offer)}.` };
  }

  // hold / book_under / full: the most we ever do unattended is a refundable hold.
  if (!holdable(offer)) {
    return {
      step: "suggest", offer,
      reason: `${money(offer)} is non-refundable — I won't hold that on my own; it's yours to decide.`,
    };
  }
  return {
    step: "hold", offer,
    reason: `Holding ${money(offer)} — refundable, and I'll ask before I buy.`,
  };
}

function brokenOrder(offer = {}, orders = {}) {
  if (orders.max_price != null && Number.isFinite(offer.price) && offer.price > orders.max_price) {
    return `${money(offer)} is over your ${offer.currency || "USD"} ${orders.max_price} cap`;
  }
  if (orders.require_refundable && offer.refundable !== true) return "it's non-refundable";
  return null;
}

/**
 * assertChargeable — the confirm gate. The ONLY approved path to spending money.
 *
 * @param hold     a normalized hold (see normalizeHold)
 * @param confirm  { confirm:true, offer_id, amount }  — must be present and match
 * @param now      ms epoch (injectable for tests)
 * @returns { ok:boolean, reason?:string }
 *
 * Refuses unless: confirm.confirm is truthy; the offer_id matches the hold; the
 * amount matches the held amount exactly (no silent price drift); and the hold is
 * still active (not expired, not already resolved).
 */
function assertChargeable(hold, confirm = {}, now = Date.now()) {
  if (!hold) return { ok: false, reason: "No hold to charge against." };
  if (!confirm || confirm.confirm !== true) {
    return { ok: false, reason: "A charge needs your explicit confirm." };
  }
  if (confirm.offer_id != null && hold.offer_id != null && String(confirm.offer_id) !== String(hold.offer_id)) {
    return { ok: false, reason: "That confirm doesn't match this offer — refusing to charge the wrong thing." };
  }
  if (confirm.amount != null && Number.isFinite(hold.amount) && Number(confirm.amount) !== hold.amount) {
    return { ok: false, reason: `The price changed since the hold (held ${hold.currency} ${hold.amount}, confirm was ${hold.currency} ${confirm.amount}) — reconfirm the new price.` };
  }
  const state = holdState(hold, now);
  if (state === "expired") return { ok: false, reason: "That hold has expired — I'll need to place a fresh one." };
  if (state === "confirmed") return { ok: false, reason: "That hold is already confirmed." };
  if (state === "released") return { ok: false, reason: "That hold was released." };
  return { ok: true };
}

/** holdState — active | expired | confirmed | released, from real time. */
function holdState(hold = {}, now = Date.now()) {
  if (hold.state === "confirmed") return "confirmed";
  if (hold.state === "released" || hold.state === "cancelled") return "released";
  const exp = hold.expires_at ? Date.parse(hold.expires_at) : null;
  if (exp != null && !Number.isNaN(exp) && now > exp) return "expired";
  return "active";
}

/** normalizeHold — coerce a provider hold into the uniform shape; never invent fields. */
function normalizeHold(raw = {}) {
  const amount = Number(raw.amount ?? raw.total_amount ?? NaN);
  const expRaw = raw.expires_at ?? raw.expires ?? raw.hold_expires_at ?? null;
  return {
    id: raw.id || raw.hold_id || null,
    offer_id: raw.offer_id ?? raw.offerId ?? null,
    kind: raw.kind || null,                 // "stay" | "flight"
    amount: Number.isFinite(amount) ? amount : null,
    currency: raw.currency || raw.total_currency || "USD",
    refundable: raw.refundable ?? false,
    refundable_until: raw.refundable_until ?? null,
    expires_at: expRaw && !Number.isNaN(Date.parse(expRaw)) ? new Date(expRaw).toISOString() : null,
    state: raw.state || "held",
    provider: raw.provider || null,
    raw,
  };
}

/** summarizeForConfirm — the exact line the user confirms. Says what, how much, and
 *  the two clocks that matter (refund window, hold expiry) — and claims neither if
 *  they're unknown. */
function summarizeForConfirm(hold = {}) {
  const h = hold.amount != null ? `${hold.currency} ${hold.amount}` : "an amount I don't yet have";
  const what = hold.raw?.name ? ` for ${hold.raw.name}` : "";
  let line = `Confirm to charge ${h}${what}.`;
  if (hold.refundable && hold.refundable_until) {
    line += ` Refundable until ${fmtDay(hold.refundable_until)}.`;
  }
  if (hold.expires_at) line += ` This hold expires ${fmtDay(hold.expires_at, true)}.`;
  return line;
}

// ── small helpers ────────────────────────────────────────────────────────────
function money(o = {}) {
  return o.price != null ? `${o.currency || "USD"} ${o.price}` : "this option";
}
function fmtDay(iso, withTime = false) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const day = d.toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
  if (!withTime) return day;
  const time = d.toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", timeZone: "UTC" });
  return `${day} at ${time} UTC`;
}

module.exports = {
  decideBooking, assertChargeable, holdState, normalizeHold, summarizeForConfirm,
  holdable, LEVELS,
};
