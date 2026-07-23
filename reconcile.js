// reconcile.js — when a text contradicts the calendar, the calendar isn't gospel.
//
// ─────────────────────────────────────────────────────────────────────────────
// The Chicago phantom: the meetings were cancelled in a text thread, but the
// calendar never heard, so Wingman proposed a trip for dead meetings. The calendar
// is the spine, but the spine can be stale — decisions get made in messages.
//
// This reconciles a MESSAGE SIGNAL (a parsed intent: cancel / move / confirm, with
// whatever people/topic/date it named) against a calendar commitment, and decides:
//   contradicts  — this message says that meeting is off.
//   reschedules  — this message moves it.
//   confirms     — this message reaffirms it.
//   none         — this message isn't about this meeting.
//
// The honesty rule that matters: matching a message to an event is ITSELF a guess.
// A wrong match would drop a real meeting. So we return a CONFIDENCE, and the caller
// only acts silently on `high`; anything less becomes a question. A text never gets
// to quietly delete a commitment — it flags, and you confirm.
//
// Pure and dependency-free. The message PARSING (free text → intent) is an LLM step
// upstream; this module only does the matching, so it can be tested exactly.
// ─────────────────────────────────────────────────────────────────────────────

const STOP = new Set([
  "the", "and", "for", "with", "our", "your", "you", "min", "mins", "review",
  "meeting", "meet", "call", "sync", "catch", "up", "re", "about", "please",
  "can", "we", "let", "lets", "will", "tomorrow", "today", "this", "next",
]);

function tokens(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 2 && !STOP.has(w));
}

const sameDay = (a, b) => {
  const x = new Date(a), y = new Date(b);
  return !isNaN(x) && !isNaN(y) && x.toDateString() === y.toDateString();
};

/**
 * Match one message signal against one calendar commitment.
 *
 * @param commitment { title, start, geo:{city}, ... }
 * @param signal     { intent:"cancel"|"move"|"confirm", names?:[], topic?, date?, quote?, said_at? }
 * @returns { effect:"contradicts"|"reschedules"|"confirms"|"none", confidence:"high"|"medium"|"low", reason, provenance }
 */
function reconcileMessage(commitment, signal) {
  if (!commitment || !signal || !signal.intent) {
    return { effect: "none", confidence: "low", reason: "nothing to match" };
  }

  const titleTokens = new Set([
    ...tokens(commitment.title),
    ...tokens(commitment.geo && commitment.geo.city),
  ]);

  // ── the three independent signals ──
  const dateMatch = signal.date ? sameDay(signal.date, commitment.start) : false;

  const nameTokens = (signal.names || []).flatMap(tokens);
  const personMatch = nameTokens.some((t) => titleTokens.has(t));

  const topicTokens = tokens(signal.topic);
  const topicMatch = topicTokens.some((t) => titleTokens.has(t));

  const strength = (dateMatch ? 1 : 0) + (personMatch ? 1 : 0) + (topicMatch ? 1 : 0);

  // No overlap at all → this message is about something else. Refusing here is what
  // stops a "cancel the dentist" text from deleting your Chicago trip.
  if (strength === 0) {
    return { effect: "none", confidence: "low", reason: "message doesn't match this meeting" };
  }

  // Confidence: two independent signals (e.g. date + topic) is a confident match;
  // one is plausible but a question.
  const confidence = strength >= 2 ? "high" : "medium";

  const effect = signal.intent === "cancel" ? "contradicts"
               : signal.intent === "move" ? "reschedules"
               : signal.intent === "confirm" ? "confirms"
               : "none";

  const matched = [dateMatch && "date", personMatch && "person", topicMatch && "topic"]
    .filter(Boolean).join(" + ");

  return {
    effect,
    confidence,
    reason: `message (${signal.intent}) matches "${commitment.title}" on ${matched}`,
    provenance: {
      source: "message",
      quote: signal.quote || null,
      said_at: signal.said_at || null,
      matched_on: matched,
    },
  };
}

/**
 * Reconcile a set of message signals against a set of commitments. Returns the
 * commitments annotated with any reconciliation that applies, plus the list of
 * "asks" where the match was only medium-confidence (surface, don't act).
 *
 * A commitment is only marked `suppressed` when a cancellation matched with HIGH
 * confidence. Medium matches become questions; the commitment stays live until you
 * answer. Nothing here deletes a calendar event — that's the user's to do — it only
 * decides whether Wingman should keep treating it as a live commitment.
 */
function reconcile(commitments, signals) {
  const asks = [];
  const annotated = (commitments || []).map((c) => {
    let best = null;
    for (const s of signals || []) {
      const r = reconcileMessage(c, s);
      if (r.effect === "none") continue;
      if (!best || (r.confidence === "high" && best.confidence !== "high")) best = r;
    }
    if (!best) return c;

    if (best.effect === "contradicts" && best.confidence === "high") {
      return { ...c, reconciliation: best, suppressed: true };
    }
    // Medium confidence, or a move/confirm — surface it, don't silently act.
    asks.push({
      kind: "reconcile_ask",
      commitment: { calendar_id: c.calendar_id || null, title: c.title, start: c.start },
      effect: best.effect,
      confidence: best.confidence,
      question: best.effect === "contradicts"
        ? `A message suggests "${c.title}" was cancelled — drop it and any trip for it?`
        : best.effect === "reschedules"
        ? `A message suggests "${c.title}" is moving — should I hold off on the trip?`
        : `A message mentions "${c.title}" — anything to change?`,
      provenance: best.provenance,
    });
    return { ...c, reconciliation: best };
  });
  return { commitments: annotated, asks };
}

module.exports = { reconcileMessage, reconcile, tokens };
