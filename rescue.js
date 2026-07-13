// ═══════════════════════════════════════════════════════════════════════════════
// rescue.js — "Ranked by what they protect, not by price."
//
// That is a line on a slide. This file is that line, made literal.
//
// The existing rebooking code asks Duffel for offers with `sort: "total_amount"` and
// takes the first one. Cheapest wins. Which means: on the Asia trip, it would happily
// rebook Maddie onto a flight that lands after the seaplane has gone, cancelling a
// night at Aman to save $80 — and report it as a success.
//
// A rescue engine that doesn't know WHY you booked something cannot protect it. It can
// only replace it. The difference between a concierge and a booking engine with an
// alarm clock is exactly this scoring function.
//
// ── What we rank on ──────────────────────────────────────────────────────────
//   1. DOWNSTREAM SURVIVAL. Does this option still get you to the things that hang
//      off this flight — with their measured slack respected?
//   2. CONSTRAINT SATISFACTION. Weighted by hardness: a 'must' is worth 100, a
//      'strong' 10, a 'nice' 1. Breaking a must is not compensable by cheapness.
//   3. Price — last, as a tiebreak. Never first.
//
// ── The honesty rules ────────────────────────────────────────────────────────
//   · Every option is a REAL Duffel offer with a real offer_id. We never invent a
//     flight. (See stripShape() in planner.js — same disease, same discipline.)
//   · Every option NAMES what it costs you. "Loses the cold plunge" is the whole
//     product. An option whose losses we can't name is not offered as recommended.
//   · A constraint we cannot evaluate against an offer scores UNKNOWN, never PASS.
//     Unknown blocks the auto-book path; it never blocks a human.
// ═══════════════════════════════════════════════════════════════════════════════

const graph = require("./constraints");

const WEIGHT = { must: 100, strong: 10, nice: 1 };

// ── "I don't know" vs "that isn't a question about flights" ──────────────────
// The first version of this file conflated the two, and the result was that Wingman
// would never recommend anything: it saw "cold plunge — the 5K is 8 weeks out",
// correctly noted that a flight offer cannot answer it, filed that as an unassessed
// consequence, and refused to stand behind any option. Paralysed by its own honesty.
//
// But a flight cannot EVER answer a question about a hotel's spa, and it doesn't need
// to — the way a flight affects that hotel is by arriving late, which the downstream
// slack calculation already models exactly.
//
// So: only constraints that a flight offer could plausibly answer count as unknown
// when it can't. Everything else is out of scope, not unresolved. Being scrupulous
// about the difference is what keeps the honesty from becoming useless.
const APPLIES_TO_FLIGHT = new Set([
  "cabin_at_least", "exclude_carrier_class", "alliance_is", "credits_to",
  "budget_max_cents", "arrive_before", "depart_after",
]);

/**
 * Can this offer satisfy this constraint?  → true | false | null (unknown)
 *
 * null is a first-class answer and the most important one. A Duffel offer does not
 * tell us whether the destination hotel has a cold plunge, so any lodging constraint
 * is simply unanswerable here — and pretending otherwise is how you end up confidently
 * rebooking someone away from the only pool in Tokyo.
 */
function evaluate(constraint, offer) {
  const p = constraint.predicate || {};
  const seg = offer.slices?.[0]?.segments?.[0] || {};
  const carrier = (seg.marketing_carrier?.name || seg.operating_carrier?.name || "").toLowerCase();
  const iata = (seg.marketing_carrier?.iata_code || "").toUpperCase();
  const cabin = (offer.slices?.[0]?.segments?.[0]?.passengers?.[0]?.cabin_class || "").toLowerCase();

  switch (p.op) {
    case "cabin_at_least": {
      if (!cabin) return null;
      const rank = { economy: 0, premium_economy: 1, business: 2, first: 3 };
      const want = rank[String(p.value).toLowerCase()];
      const got  = rank[cabin];
      if (want == null || got == null) return null;
      return got >= want;
    }
    case "exclude_carrier_class": {
      if (!carrier) return null;
      // A deliberately small, explicit list. Guessing which carriers are "budget"
      // from the name is how you exclude the wrong airline.
      const LOW_COST = ["ryanair", "easyjet", "spirit", "frontier", "wizz", "vueling",
                        "jetstar", "scoot", "airasia", "norwegian", "wow"];
      return !LOW_COST.some((c) => carrier.includes(c));
    }
    case "alliance_is": {
      const STAR = ["LH","UA","AC","SQ","NH","OZ","TG","SK","LX","OS","BR","CA","TK","ET","SA","AV","CM","ZH","MS","A3"];
      const ONEWORLD = ["AA","BA","CX","QF","JL","QR","AY","IB","MH","RJ","UL","AT"];
      const SKYTEAM  = ["DL","AF","KL","KE","AZ","AM","MU","CZ","SU","VN","GA","KQ","RO"];
      if (!iata) return null;
      const want = String(p.value).toLowerCase();
      if (want === "star")     return STAR.includes(iata);
      if (want === "oneworld") return ONEWORLD.includes(iata);
      if (want === "skyteam")  return SKYTEAM.includes(iata);
      return null;
    }
    case "budget_max_cents": {
      const cents = Math.round(parseFloat(offer.total_amount || "0") * 100);
      return cents <= Number(p.value);
    }
    // These two were listed in APPLIES_TO_FLIGHT and then never implemented, so they
    // fell through to `default: return null` — permanently "unknown". Which meant that
    // for any trip carrying an "I have to land before the rehearsal" constraint, Wingman
    // would show "I can't assess this", and refuse to act alone, FOREVER — about a
    // question it can answer from the offer's own timestamps.
    //
    // An honest "unknown" is the most valuable thing this system says. That is exactly
    // why it has to be scarce: a system that says "I don't know" about things it plainly
    // does know teaches you to stop believing it when it doesn't.
    case "arrive_before": {
      const arr = offer.slices?.[0]?.segments?.slice(-1)[0]?.arriving_at;
      if (!arr || !p.value) return null;
      const limit = new Date(p.value);
      if (isNaN(limit)) return null;
      return new Date(arr) <= limit;
    }
    case "depart_after": {
      const dep = seg.departing_at;
      if (!dep || !p.value) return null;
      const limit = new Date(p.value);
      if (isNaN(limit)) return null;
      return new Date(dep) >= limit;
    }
    // Lodging, facilities, climate, entry rules — a flight offer says nothing about
    // any of them. UNKNOWN, and we say so, rather than scoring them as satisfied.
    default:
      return null;
  }
}

/**
 * Which downstream bookings survive if we take this offer?
 *
 * The slack on each edge was MEASURED (arrival-to-departure gap). An option arriving
 * later than the original eats into that slack. This is the calculation the old
 * price-sorted rebooking never did — and it is the reason it would happily strand you.
 */
function survives(nodes, extraDelayMin) {
  const kept = [], lost = [], unknown = [];
  for (const n of nodes) {
    if (n.verdict === "unknown") { unknown.push(n); continue; }
    if (n.slack_minutes == null) { unknown.push(n); continue; }
    (extraDelayMin <= n.slack_minutes ? kept : lost).push(n);
  }
  return { kept, lost, unknown };
}

/**
 * Score and rank real Duffel offers.
 *
 * `offers` must come from Duffel. Never synthesise one — a fabricated flight rendered
 * beside real ones, to someone standing in an airport, is the worst thing this system
 * could produce.
 */
function rank({ offers, constraints, nodes, originalArrival }) {
  const ranked = offers.map((offer) => {
    // How much later than planned does this option land?
    const arr = offer.slices?.[0]?.segments?.slice(-1)[0]?.arriving_at;
    const extraDelay = (arr && originalArrival)
      ? Math.max(0, (new Date(arr) - new Date(originalArrival)) / 60000)
      : null;

    const surv = extraDelay == null
      ? { kept: [], lost: [], unknown: nodes }         // no arrival time → we don't know
      : survives(nodes, extraDelay);

    // ── 1. What does it protect? ──
    // Weighted by the hardness of the constraints each surviving booking serves.
    let protectScore = 0;
    for (const n of surv.kept) {
      const rs = n.reasons || [];
      protectScore += rs.length
        ? rs.reduce((a, r) => a + (WEIGHT[r.hardness] || 1) * (r.strength ?? 1), 0)
        : 5;   // a booking with no recorded reason is still worth keeping — just less
    }

    // ── 2. What constraints does the OPTION itself satisfy? ──
    const satisfied = [], broken = [], unknowable = [];
    let constraintScore = 0;
    for (const c of constraints) {
      const v = evaluate(c, offer);
      if (v === true)  { satisfied.push(c); constraintScore += WEIGHT[c.hardness] || 1; }
      else if (v === false) { broken.push(c); }
      // UNKNOWN — never counted as a pass. But see APPLIES_TO_FLIGHT below: there is
      // a difference between "I don't know" and "that question isn't about flights."
      else if (APPLIES_TO_FLIGHT.has(c.predicate?.op)) { unknowable.push(c); }
    }

    const price = parseFloat(offer.total_amount || "0");

    // ── 3. Price is a TIEBREAK, not a ranking. ──
    // A tiny nudge — enough to separate two options that protect identically, far too
    // small to buy its way past a broken 'must'.
    const priceNudge = -price / 100000;

    // Two ways to fail her, and the first version only checked one.
    //
    //   brokeMust  — the option itself violates a hard rule (a budget carrier).
    //   losesMust  — the option is fine, and it DESTROYS something that was.
    //
    // The seaplane is the only transfer to the island that day: a 'must'. An option
    // that lands 90 minutes late doesn't break any rule about flights — it's business
    // class, full-service, perfectly respectable — it just quietly strands her
    // overnight. Checking only what an option *breaks*, and not what it *costs*, is
    // exactly how you end up recommending that with a straight face.
    const brokeMust = broken.some((c) => c.hardness === "must");
    const losesMust = surv.lost.some((n) => (n.reasons || []).some((r) => r.hardness === "must"));

    return {
      offer_id: offer.id,                                    // REAL. always.
      carrier: offer.slices?.[0]?.segments?.[0]?.marketing_carrier?.name || null,
      flight: offer.slices?.[0]?.segments?.[0]?.marketing_carrier_flight_number || null,
      departs_at: offer.slices?.[0]?.segments?.[0]?.departing_at || null,
      arrives_at: arr || null,
      price,
      currency: offer.total_currency || "USD",
      cabin: offer.slices?.[0]?.segments?.[0]?.passengers?.[0]?.cabin_class || null,

      // The raw Duffel offer, passed through untouched. The booking screens need the
      // real object — and it must be the ACTUAL offer, not a reconstruction. Rebuilding
      // a flight from fields we chose to keep is how you book someone onto something
      // subtly different from what they were shown.
      offer,

      score: (brokeMust ? -1e6 : 0) + protectScore + constraintScore + priceNudge,
      brokeMust, losesMust,

      // ── What this option COSTS you, in plain words. The whole product. ──
      protects: surv.kept.map((n) => n.label),
      loses:    surv.lost.map((n) => ({
        what: n.label,
        why: (n.reasons || [])[0]?.rationale || null,
        hardness: (n.reasons || []).some((r) => r.hardness === "must") ? "must"
                : (n.reasons || []).some((r) => r.hardness === "strong") ? "strong" : "nice",
      })),
      breaks:   broken.map((c) => ({ rationale: c.rationale, hardness: c.hardness })),
      // The system stating the limits of its own knowledge, per option — but only
      // about things it could actually have known. See APPLIES_TO_FLIGHT.
      cannot_assess: [
        ...surv.unknown.map((n) => n.label),
        ...unknowable.filter((c) => c.hardness !== "nice").map((c) => c.rationale),
      ],
    };
  });

  ranked.sort((a, b) => b.score - a.score);

  // Only recommend something we can actually stand behind. An option that breaks a
  // 'must', or whose consequences we can't fully assess, is offered — but never as
  // "here, tap this."
  const best = ranked[0];
  const recommendable = best && !best.brokeMust && !best.losesMust && best.cannot_assess.length === 0;

  return {
    options: ranked,
    recommended_id: recommendable ? best.offer_id : null,
    // If we can't recommend, SAY WHY. Silence is how a user assumes we approve.
    // "One tap and I fix the rest" is a promise Wingman may only make when it can
    // actually keep it. The rest of the time it hands the decision back, with the
    // trade-off spelled out — which is what a chief of staff does, and what a booking
    // engine sorted by price never will.
    no_recommendation_because: recommendable ? null
      : !best ? "I found no alternatives."
      : best.brokeMust
        ? `Every option breaks something you told me was non-negotiable: ${best.breaks.filter((b) => b.hardness === "must").map((b) => b.rationale).join("; ")}. You should choose.`
      : best.losesMust
        ? `Even the best option costs you something you can't get back: ${best.loses.filter((l) => l.hardness === "must").map((l) => `${l.what}${l.why ? ` — ${l.why}` : ""}`).join("; ")}. I won't make that call for you.`
      : `I can't fully assess the consequences: ${best.cannot_assess.slice(0, 2).join("; ")}. You should choose.`,
  };
}

module.exports = { rank, evaluate, survives, WEIGHT };
