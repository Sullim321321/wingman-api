// autonomy.js — the dial that decides how far Wingman may act, on its own.
//
// ─────────────────────────────────────────────────────────────────────────────
// Pillar 5. Everything up to here PROPOSES; this decides when Wingman may ACT
// without another tap — the thing that makes it stop being manual labor. That power
// is exactly why the rules must be strict and legible:
//
//   • A standing order is a HARD wall. "Never a red-eye", "business or better",
//     "not O'Hare" — an offer that breaks one is never chosen, at ANY level, not
//     even Full. Autonomy widens what Wingman may do; it never widens what YOU said.
//   • Money has a ceiling. Book-under-$X books only at or under the number. Over it,
//     it holds and asks — it does not "round up because it was close".
//   • Every decision carries its REASON and what it ruled out, so the ledger can
//     show why, and a green light can always be shown to have been earned.
//   • Missing data fails DOWN. Unsure → the safer, lower action. Never book on a guess.
//
// The levels, least to most autonomous:
//   watch       observe only; surface nothing new.
//   suggest     propose the best option; never act.
//   hold        place a hold on the best qualifying option; ask before buying.
//   book_under  buy the best qualifying option IF it's at/under the ceiling; else hold.
//   full        buy the best qualifying option (still bounded by standing orders).
//
// Pure and dependency-free. Offers arrive already normalized (see normalizeOffer),
// so the decision is exact and testable without a network or a supplier.
// ─────────────────────────────────────────────────────────────────────────────

const LEVELS = ["watch", "suggest", "hold", "book_under", "full"];
const CABIN_RANK = { economy: 0, premium_economy: 1, business: 2, first: 3 };

// Legacy autonomy_mode ("always_ask" / "fully_auto") → a dial level.
function levelFromMode(mode, threshold) {
  if (mode === "fully_auto") return threshold != null ? "book_under" : "full";
  return "suggest"; // always_ask and anything unknown → propose only
}

const cabinRank = (c) => CABIN_RANK[String(c || "").toLowerCase()] ?? 0;

/**
 * Normalize a raw offer (Duffel/booking shape) into what the decision needs.
 * Kept small on purpose — the decision reasons over these fields only.
 */
function normalizeOffer(raw = {}) {
  const seg0 = raw.slices?.[0]?.segments?.[0] || {};
  const airports = new Set();
  (raw.slices || []).forEach((s) => (s.segments || []).forEach((g) => {
    if (g.origin) airports.add(g.origin);
    if (g.destination) airports.add(g.destination);
  }));
  return {
    id: raw.id || raw.offer_id || null,
    price: Number(raw.price ?? raw.total_amount ?? NaN),
    currency: raw.currency || raw.total_currency || "USD",
    cabin: raw.cabin || raw.cabin_class || "economy",
    airports: raw.airports || [...airports],
    departs_at: raw.departs_at || seg0.departing_at || null,
    red_eye: raw.red_eye != null ? !!raw.red_eye : isRedEye(raw.departs_at || seg0.departing_at),
    refundable: raw.refundable ?? raw.conditions?.refundable ?? false,
    changeable: raw.changeable ?? raw.conditions?.changeable ?? false,
  };
}

// A departure between 21:00 and 05:00 (its own local wall clock, as carried in the
// ISO offset) is a red-eye. Unknown time → not flagged (we don't guess a red-eye).
function isRedEye(iso) {
  if (!iso) return false;
  const m = String(iso).match(/T(\d{2}):/);
  if (!m) return false;
  const h = Number(m[1]);
  return h >= 21 || h < 5;
}

/**
 * Does an offer satisfy the standing orders? Returns { ok, reasons } — reasons lists
 * every wall it hit, so the ledger can say precisely why it was ruled out.
 */
function qualifies(offer, orders = {}) {
  const reasons = [];
  if (orders.max_price != null && Number.isFinite(offer.price) && offer.price > orders.max_price) {
    reasons.push(`over your ${offer.currency} ${orders.max_price} cap`);
  }
  if (orders.min_cabin && cabinRank(offer.cabin) < cabinRank(orders.min_cabin)) {
    reasons.push(`below ${orders.min_cabin}`);
  }
  if (orders.no_red_eyes && offer.red_eye) reasons.push("red-eye");
  if (orders.require_refundable && !offer.refundable) reasons.push("non-refundable");
  const avoid = (orders.avoid_airports || []).map((a) => String(a).toUpperCase());
  if (avoid.length && (offer.airports || []).some((a) => avoid.includes(String(a).toUpperCase()))) {
    reasons.push(`uses an airport you avoid (${(offer.airports || []).filter((a) => avoid.includes(String(a).toUpperCase())).join(", ")})`);
  }
  return { ok: reasons.length === 0, reasons };
}

/**
 * Decide the action Wingman may take on its own.
 *
 * @param opts.level     one of LEVELS (or omit and pass mode/threshold to map)
 * @param opts.mode      legacy autonomy_mode, mapped when level is absent
 * @param opts.threshold the Book-under ceiling (money)
 * @param opts.standingOrders { max_price, min_cabin, avoid_airports, no_red_eyes, require_refundable }
 * @param opts.offers    array of raw or normalized offers (cheapest-best chosen)
 * @returns { action:"watch"|"suggest"|"hold"|"book", offer, level, reason, qualifying_count, excluded:[{id,reasons}] }
 */
function decideAction(opts = {}) {
  const level = LEVELS.includes(opts.level) ? opts.level : levelFromMode(opts.mode, opts.threshold);
  const orders = opts.standingOrders || {};
  const offers = (opts.offers || []).map((o) => (o && o.airports && o.price != null && o.cabin ? o : normalizeOffer(o)));

  if (level === "watch") {
    return { action: "watch", offer: null, level, reason: "Watching only — I won't surface or act.", qualifying_count: 0, excluded: [] };
  }

  // Apply the hard walls. Anything that breaks a standing order is out — recorded.
  const excluded = [];
  const qualifying = [];
  for (const o of offers) {
    const q = qualifies(o, orders);
    if (q.ok) qualifying.push(o);
    else excluded.push({ id: o.id, reasons: q.reasons });
  }
  qualifying.sort((a, b) => a.price - b.price);
  const best = qualifying[0] || null;

  // Nothing clears your rules → do not act. Surface it as a suggestion/question,
  // never a booking of something you told me not to book.
  if (!best) {
    return {
      action: "suggest", offer: null, level,
      reason: offers.length
        ? "Nothing on offer clears your standing orders — leaving it for you."
        : "No offers to act on.",
      qualifying_count: 0, excluded,
    };
  }

  if (level === "suggest") {
    return { action: "suggest", offer: best, level, reason: `Best that fits your rules: ${best.currency} ${best.price}.`, qualifying_count: qualifying.length, excluded };
  }
  if (level === "hold") {
    return { action: "hold", offer: best, level, reason: `Holding the best that fits (${best.currency} ${best.price}); I'll ask before buying.`, qualifying_count: qualifying.length, excluded };
  }
  if (level === "book_under") {
    const cap = opts.threshold;
    if (cap != null && best.price > cap) {
      return { action: "hold", offer: best, level, reason: `Best fit is ${best.currency} ${best.price}, over your ${best.currency} ${cap} auto-book ceiling — holding, not buying.`, qualifying_count: qualifying.length, excluded };
    }
    return { action: "book", offer: best, level, reason: `Booking ${best.currency} ${best.price} — within your ${best.currency} ${cap} ceiling and your rules.`, qualifying_count: qualifying.length, excluded };
  }
  // full
  return { action: "book", offer: best, level, reason: `Booking the best that fits your rules: ${best.currency} ${best.price}.`, qualifying_count: qualifying.length, excluded };
}

module.exports = { decideAction, qualifies, normalizeOffer, levelFromMode, isRedEye, LEVELS };
