// sketches.js — when an idea Wingman had stops being an idea you're having.
//
// ─────────────────────────────────────────────────────────────────────────────
// The user asked where she might go for three days. Wingman suggested the Smoky
// Mountains. Days later the app was still showing her a Smoky Mountains trip — not
// because she'd agreed, but because nothing in the system ever asked whether she had.
//
// A proposal is a question. Questions expire. If you never answer "shall we look at
// the Smokies?", the honest state a week later is silence, not a trip.
//
// THE RISK THIS CREATES, stated plainly because it's real: expiry can bin an idea
// you were still weighing. So two rules constrain it.
//
//   1. It only ever touches `proposed` legs. Anything booked, confirmed, or carrying
//      a reference number is untouchable, whatever its dates say.
//   2. It is never silent. Every expiry is written to the ledger with its reason.
//      "Wingman quietly deleted your plans" is a worse failure than a stale sketch,
//      and the only defence against it is a record you can read afterwards.
//
// The decision is pure and lives here so it can be tested without a database —
// including the cases where it must REFUSE, which are the ones that matter.
// ─────────────────────────────────────────────────────────────────────────────

const DAY = 86400000;

// How long an undated proposal may sit untouched before it's treated as abandoned.
// Deliberately generous: a fortnight of not mentioning a trip idea is weak evidence
// you dropped it, and this is the direction where being wrong costs the user work.
const MAX_IDLE_DAYS = 14;

/**
 * Should this leg stop being shown?
 *
 * Returns { expire, why }. `why` is written to the ledger verbatim, so it is
 * phrased for a person: it has to survive being read back in three weeks.
 */
function shouldExpire(leg, nowMs, { maxIdleDays = MAX_IDLE_DAYS } = {}) {
  const keep = (why) => ({ expire: false, why });

  // ── The two refusals. Order matters: check what makes a leg REAL first. ──
  if (!leg || leg.state !== "proposed") {
    return keep("not a proposal — only sketches expire");
  }
  // A reference number means something outside Wingman knows about this. Whatever
  // the state column says, that is not a sketch, and deleting it would destroy the
  // only record of a real arrangement.
  if (String(leg.confirmation || "").trim()) {
    return keep("carries a confirmation — something real is attached to it");
  }

  const dep = leg.departs_at ? new Date(leg.departs_at).getTime() : null;

  // An unparseable date is NOT a date in the past. Treating NaN as "long ago" would
  // expire everything with a malformed date — the single most likely thing to be
  // malformed in a proposal the model wrote.
  if (dep != null && !Number.isNaN(dep)) {
    if (dep < nowMs) {
      return { expire: true, why: "the date it proposed has passed and it was never booked" };
    }
    return keep("still ahead of you");
  }

  // Undated: fall back to age. Same NaN caution.
  const born = leg.created_at ? new Date(leg.created_at).getTime() : null;
  if (born == null || Number.isNaN(born)) {
    return keep("no date and no age — nothing to judge it by, so it stays");
  }
  const idleDays = Math.floor((nowMs - born) / DAY);
  if (idleDays >= maxIdleDays) {
    return { expire: true, why: `suggested ${idleDays} days ago, never dated or booked` };
  }
  return keep(`only ${idleDays} days old`);
}

/**
 * Classify a trip by what's actually IN it.
 *
 * This is what the provenance audit reports and what the Dossier's `certainty`
 * flag is derived from. One definition, so the audit and the screen can never
 * disagree about whether a trip is real.
 */
function classifyTrip({ legs = [], title = "", source = "" } = {}) {
  if (title === "Needs review" || title === "Reservations") {
    return { verdict: "holder", note: "a parking bucket, not a trip" };
  }
  if (!legs.length) {
    return { verdict: "empty", note: "no legs at all — nothing to show" };
  }
  const real = legs.filter((l) => l.state !== "proposed");
  if (!real.length) {
    return {
      verdict: "idea",
      note: source === "planner"
        ? "entirely proposals from a planning conversation — nothing was booked"
        : "entirely proposals — nothing was booked",
    };
  }
  if (real.length < legs.length) {
    return { verdict: "mixed", note: `${real.length} booked, ${legs.length - real.length} still proposed` };
  }
  return { verdict: "real", note: `${real.length} booked` };
}

module.exports = { shouldExpire, classifyTrip, MAX_IDLE_DAYS };
