// watcher.js — the hands, kept on a short leash.
//
// ─────────────────────────────────────────────────────────────────────────────
// Pillar 5d. This is the part that finally removes the manual labor: a scheduled
// pass that turns each trip's autonomy decision into an action taken WITHOUT a tap.
// Precisely because it runs unattended, it has hard backstops that the interactive
// path doesn't need:
//
//   • NEVER auto-spend real money. If the supplier books real tickets (live mode),
//     a "book" decision is downgraded to a HOLD and a question. A real charge always
//     gets a human yes — even at Full. Test mode (no charge, no seat) may auto-book.
//   • Idempotent. An item already acted on this cycle is skipped. No double-booking.
//   • Capped. At most `maxActions` side effects per run, so a bug or a bad feed can't
//     cascade into a dozen bookings while you sleep.
//   • watch / suggest touch nothing. Ever.
//
// This module is the DECISION about what to execute — pure and testable. The actual
// hold/book call, the ledger write, and the notification live in the runner that
// consumes this. Keeping the leash logic pure is how we can prove the leash holds.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Decide which actions a single autonomy run should actually execute.
 *
 * @param opts.items      [{ key, decision }]  decision is autonomy.decideAction output
 * @param opts.liveMoney  true if the supplier books real tickets (charges real money)
 * @param opts.maxActions per-run ceiling on side effects (default 3)
 * @param opts.actedKeys  keys already acted on (idempotency)
 * @returns { actions:[{key,action,offer,downgraded,reason}], skipped:[{key,why}] }
 */
function planRun({ items = [], liveMoney = false, maxActions = 3, actedKeys = [] } = {}) {
  const acted = new Set(actedKeys);
  const actions = [];
  const skipped = [];

  for (const it of items) {
    const d = (it && it.decision) || {};
    const key = it && it.key;

    if (acted.has(key)) { skipped.push({ key, why: "already acted" }); continue; }

    // Only hold/book are side effects. watch/suggest (and any decision without a
    // concrete offer) are surfaced elsewhere; the watcher does not touch them.
    if ((d.action !== "hold" && d.action !== "book") || !d.offer) {
      skipped.push({ key, why: d.action || "no action" });
      continue;
    }

    let action = d.action;
    let downgraded = false;
    // The money backstop: real charges never happen unattended.
    if (action === "book" && liveMoney) { action = "hold"; downgraded = true; }

    if (actions.length >= maxActions) { skipped.push({ key, why: "run cap reached" }); continue; }

    actions.push({
      key,
      action,
      offer: d.offer,
      downgraded,
      reason: downgraded
        ? `Would auto-book, but real-money mode requires your confirmation — holding instead. (${d.reason || ""})`.trim()
        : d.reason || null,
    });
  }

  return { actions, skipped };
}

module.exports = { planRun };
