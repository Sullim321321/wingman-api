// transport.js — a leg is a MOVEMENT with a MODE, not just "a flight".
//
// ─────────────────────────────────────────────────────────────────────────────
// The whole proactive spine — the pollers, the arrival plan, the cascade, the
// pre-departure briefing — was written against the literal string `type='flight'`.
// A train imports and renders, but the spine can't see it: no delay watch, no
// leave-by, no "your train is cancelled". Generalizing that spine safely needs ONE
// place that answers three questions the same way everywhere:
//
//   1. Is this leg a movement, and by what MODE?  (air / rail; sea/road reserved)
//   2. Is it WATCHABLE — sound enough for the spine to speak about?
//   3. How do we SAY it — gate or platform, airport or station, flight or train?
//
// This module is that place: pure, dependency-light, tested. It borrows the time /
// route sanity rules from `briefguard` (so a routeless or epoch-timed leg is no more
// watchable as a train than as a flight) and the human name from `flightid` for air.
// It introduces NO behaviour on its own — R1 is vocabulary; R2/R3 wire it in.
// ─────────────────────────────────────────────────────────────────────────────

const flightid = require("./flightid");
const briefguard = require("./briefguard");

// A leg's `type` → its transport MODE. Anything not here is not a movement leg
// (hotel, dining, ride are handled elsewhere). Sea/road are reserved, not yet wired.
const MODE_OF_TYPE = {
  flight: "air",
  train: "rail",
  // ferry: "sea", coach: "road", bus: "road",  // reserved — do not watch yet
};

// The modes the proactive spine is allowed to watch today. Rail is live (Darwin);
// broadening this is a deliberate, tested step, not a default.
const WATCHABLE_MODES = ["air", "rail"];

// How each mode is spoken. The single dictionary the UI and copy read from, so
// "platform" vs "gate" is decided once, not re-guessed per screen.
const VOCAB = {
  air: {
    mode: "air", vehicle: "flight", verb: "fly",
    hub: "airport", node: "gate", terminal: "terminal",
    depart_hub_label: "Departure airport", board_word: "Boarding",
  },
  rail: {
    mode: "rail", vehicle: "train", verb: "take the train",
    hub: "station", node: "platform", terminal: null,
    depart_hub_label: "Departure station", board_word: "Boarding",
  },
};

const nonEmpty = (v) => v != null && String(v).trim() !== "";

/** This leg's transport mode ("air"/"rail"), or null if it isn't a movement leg. */
function modeOf(leg) {
  return MODE_OF_TYPE[String(leg?.type || "").toLowerCase()] || null;
}

/** Is this leg a movement at all (something the spine could, in principle, watch)? */
function isTransportLeg(leg) {
  return modeOf(leg) != null;
}

/**
 * Where this leg starts / ends, whichever field the producer used. Rail legs may
 * carry station_from/station_to; air legs carry origin/destination. Prefer the
 * mode-native pair, fall back to the other so a mixed row still resolves.
 */
function endpointsOf(leg) {
  if (!leg) return { from: null, to: null };
  const mode = modeOf(leg);
  const air = { from: leg.origin, to: leg.destination };
  const rail = { from: leg.station_from, to: leg.station_to };
  const pick = mode === "rail" ? [rail, air] : [air, rail];
  const from = nonEmpty(pick[0].from) ? pick[0].from : (nonEmpty(pick[1].from) ? pick[1].from : null);
  const to = nonEmpty(pick[0].to) ? pick[0].to : (nonEmpty(pick[1].to) ? pick[1].to : null);
  return { from, to };
}

/** Does this leg name both ends of the journey, in either field pair? */
function hasEndpoints(leg) {
  const { from, to } = endpointsOf(leg);
  return nonEmpty(from) && nonEmpty(to);
}

/**
 * Should the proactive spine watch this leg? It must be a watchable mode, name both
 * endpoints, carry a real (non-epoch) departure time, and not run backwards. This is
 * the mode-generalized sibling of briefguard.isBriefableLeg — same sanity, any mode.
 * Status (cancelled/landed) is intentionally NOT checked here: "watchable" is about
 * whether the leg is sound; liveness is the caller's separate concern.
 */
function isWatchable(leg) {
  const mode = modeOf(leg);
  if (!WATCHABLE_MODES.includes(mode)) return false;
  if (!hasEndpoints(leg)) return false;
  if (!briefguard.isRealTime(leg.departs_at)) return false;
  const dep = Date.parse(leg.departs_at);
  const arr = Date.parse(leg?.arrives_at);
  if (Number.isFinite(dep) && Number.isFinite(arr) && arr < dep) return false;
  return true;
}

/** The mode's word-dictionary. Unknown/absent mode → the air dictionary (safe default). */
function vocab(mode) {
  return VOCAB[mode] || VOCAB.air;
}

/**
 * A human-readable name for the leg. Air delegates to flightid (the airline + number
 * logic already lives there). Rail names the operator + service if present, else the
 * route "Edinburgh → London". Returns null only when there's genuinely nothing to say.
 */
function displayName(leg = {}) {
  const mode = modeOf(leg);
  if (mode === "air") return flightid.displayName(leg);
  const { from, to } = endpointsOf(leg);
  const route = nonEmpty(from) && nonEmpty(to) ? `${from} → ${to}` : (nonEmpty(to) ? String(to) : null);
  if (mode === "rail") {
    const operator = nonEmpty(leg.carrier) ? String(leg.carrier).trim() : null;
    const service = nonEmpty(leg.flight_number) ? String(leg.flight_number).trim() : null;
    const named = [operator, service].filter(Boolean).join(" ");
    return named || route || null;
  }
  return route || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Which live-status network a rail leg belongs to. This decides who we ask about a
// delay — and, honestly, whether we can ask at all. UK National Rail has a wired
// feed (Darwin); Amtrak's slot exists but only answers if a feed is configured.
// An unrecognised operator returns null: we watch nothing rather than guess.
// ─────────────────────────────────────────────────────────────────────────────
const AMTRAK_KEYWORDS = ["amtrak", "acela"];
const UK_OPERATORS = [
  "lner", "avanti", "scotrail", "gwr", "great western", "southern", "southeastern",
  "thameslink", "northern", "transpennine", "crosscountry", "cross country",
  "greater anglia", "c2c", "chiltern", "east midlands", "merseyrail", "south western",
  "southwestern", "trainline", "national rail", "elizabeth line", "gatwick express",
  "grand central", "hull trains", "lumo", "heathrow express", "caledonian sleeper",
];

function networkOf(leg) {
  if (modeOf(leg) !== "rail") return null;
  const hay = `${leg?.carrier || ""} ${leg?.operator || ""}`.toLowerCase();
  if (AMTRAK_KEYWORDS.some((k) => hay.includes(k))) return "amtrak";
  if (UK_OPERATORS.some((k) => hay.includes(k))) return "uk_nr";
  return null;
}

/**
 * Turn a live rail-status reading into the message + decision the disruption poll
 * should act on — the rail sibling of the flight branch, spoken in rail vocab
 * (platform, station, train). Pure: given the leg, the live reading, and the prior
 * status, it returns what to say and whether to cascade; it performs nothing.
 *   returns null when there's nothing to act on (no reading, or unchanged status).
 *   shape: { newStatus, push:{title,body}|null, activity:{title,body,type},
 *            cascade:{kind,delayMins}|null, reTimeArrival:bool }
 */
function railNarrative(leg, live, prevStatus) {
  if (!live || !live.status) return null;
  const newStatus = live.status;
  const prev = prevStatus || "Scheduled";
  if (newStatus === prev) return null;
  const name = displayName(leg) || "Your train";
  const { from, to } = endpointsOf(leg);
  const route = from && to ? `${from} → ${to}` : (to || "your route");
  const plat = live.platform ? ` Platform ${live.platform}.` : "";

  if (newStatus === "Cancelled") {
    return {
      newStatus,
      push: { title: `${name} is cancelled`, body: `${route} cancelled. I'm already looking at alternatives — tap to replan.` },
      activity: { title: `${name} cancelled`, body: `Your ${route} train was cancelled. Wingman is finding alternatives.`, type: "disruption" },
      cascade: { kind: "cancelled", delayMins: 0 },
      reTimeArrival: false,
    };
  }
  if (newStatus === "Delayed") {
    const dm = Number.isFinite(live.delayMins) ? live.delayMins : null;
    const ds = dm ? ` by ${dm}m` : "";
    return {
      newStatus,
      push: { title: `${name} is delayed${ds}`, body: `${route} delayed${ds}.${plat}` },
      activity: { title: `${name} delayed${ds}`, body: `Your ${route} train is delayed${ds}.${plat}`, type: "delay" },
      cascade: dm && dm >= 60 ? { kind: "delayed", delayMins: dm } : null,
      reTimeArrival: true,
    };
  }
  if (newStatus === "On Time" && ["Delayed", "Watching"].includes(prev)) {
    return {
      newStatus,
      push: { title: `✅ ${name} back on time`, body: `Your ${route} train is now showing on time.` },
      activity: { title: `${name} back on time`, body: `Your ${route} train recovered to on-time.`, type: "recovery" },
      cascade: null,
      reTimeArrival: false,
    };
  }
  // A reading we don't turn into a push (e.g. "No services", "Unknown"): log only,
  // never fabricate reassurance.
  return {
    newStatus,
    push: null,
    activity: { title: `${name} status: ${newStatus}`, body: route, type: "status" },
    cascade: null,
    reTimeArrival: false,
  };
}

module.exports = {
  MODE_OF_TYPE, WATCHABLE_MODES, VOCAB, AMTRAK_KEYWORDS, UK_OPERATORS,
  modeOf, isTransportLeg, endpointsOf, hasEndpoints, isWatchable, vocab, displayName,
  networkOf, railNarrative,
};
