#!/usr/bin/env node
// test-paste.js — can the planner turn a mess of real texts into a schedule?
//
//   node --env-file=.env test-paste.js
//
// This is the "paste your messages" path, tested on the thing it will actually receive:
// a WhatsApp/iMessage thread from friends and business partners. Not a tidy itinerary —
// fragments, contradictions, ambiguity, and social noise.
//
// WHAT THIS IS CHECKING, and why each matters:
//
//   1. Does it EXTRACT the timed commitments at all? ("office at 2", "dinner at 8")
//      If those don't become constraints, transport reasoning is impossible — the graph
//      can't say "leave by 1:20" if it doesn't know about the 2pm.
//
//   2. Does it INVENT anything? This is the failure this project exists to prevent. A
//      thread that says "maybe drinks Friday?" must NOT become a confirmed commitment,
//      and a restaurant nobody named must not acquire a name.
//
//   3. Does it mark uncertainty honestly? "Maybe", "I'll confirm", "either Thursday or
//      Friday" are NOT musts. Hardness inflation here is what makes the rescue engine
//      useless later — if everything is a must, nothing is.
//
// This costs real Anthropic credits (it calls the live planner), so it runs only when
// invoked directly, never as part of the fast test suite.

const assert = require("assert");

if (!process.env.ANTHROPIC_API_KEY) {
  console.log("\n  SKIPPED — no ANTHROPIC_API_KEY. Run with: node --env-file=.env test-paste.js\n");
  process.exit(0);
}

const planner = require("./planner");

// A realistic thread. Deliberately messy: no dates on some items, a maybe, a
// contradiction (two different dinner times), a nickname, and social chatter.
const THREAD = `
Here are messages about my trip — build the schedule from them:

Dave (business): landing Thursday night, can you swing by the office Friday at 2?
we're on the 4th floor now, not the 12th

Me: yes should work

Priya: DINNER FRIDAY!! 8pm at Rolf and Daughters, booked under my name
also can you bring the thing

Dave: actually make it 2:30 Friday, got a call before

Sam: are you around Saturday? thinking drinks but might have to bail, will confirm Thurs

Priya: oh and Marcus said he'd drive you from the airport if you need
`.trim();

(async () => {
  console.log("\n\x1b[1mPaste → graph: a real thread of texts\x1b[0m");
  console.log("\x1b[2m──────────────────────────────────────────────────────────\x1b[0m");

  let out;
  try {
    out = await planner.converse({
      message: THREAD,
      known: [],
      history: [],
      now: new Date().toISOString(),
      timezone: "America/New_York",
    });
  } catch (e) {
    console.log(`\n  \x1b[31m✗ the planner threw:\x1b[0m ${e.message}`);
    console.log("    (credits? rate limit? see the message above — this is not a test failure per se)\n");
    process.exit(1);
  }

  const cs = Array.isArray(out.constraints) ? out.constraints : [];
  const text = (out.reply || "").toLowerCase();
  const all = cs.map((c) => (c.rationale || "").toLowerCase()).join(" | ");

  let pass = 0, fail = 0;
  // `needsData: true` marks an assertion that is only meaningful when something was
  // actually extracted. With an empty result it reports UNPROVEN and counts as a
  // failure — never a silent pass.
  const t = (name, cond, detail, needsData = false) => {
    if (needsData && cs.length === 0) {
      console.log(`  \x1b[31m? UNPROVEN\x1b[0m ${name}\n      nothing was extracted, so this check proved nothing`);
      fail++; return;
    }
    if (cond) { console.log(`  \x1b[32m✓\x1b[0m ${name}`); pass++; }
    else { console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? `\n      ${detail}` : ""}`); fail++; }
  };

  console.log(`\n  (extracted ${cs.length} constraints)\n`);
  cs.forEach((c) => console.log(`    · [${c.hardness}/${c.source}] ${c.rationale}`));
  console.log(`\n  \x1b[2mreply:\x1b[0m ${(out.reply || "(none)").slice(0, 400)}\n`);

  // ── THE GUARD AGAINST VACUOUS PASSES ────────────────────────────────────────
  // The first run of this file printed "6 held" while the planner extracted ZERO
  // constraints. Four of those six passed only because there was nothing to check:
  // "didn't inflate everything to MUST" is trivially true of an empty list, and
  // "Sam's drinks is not a must" is trivially true when no drinks constraint exists.
  //
  // That is the exact failure this whole project hunts — a green light that cannot
  // go red — and I wrote it into the test meant to catch it. So: if nothing was
  // extracted, every downstream assertion is UNPROVEN, and unproven is not passed.
  const vacuous = cs.length === 0;
  if (vacuous) {
    console.log("  \x1b[31m! NOTHING WAS EXTRACTED — every check below is unproven, not passed.\x1b[0m\n");
  }

  // ── 1. Did it catch the commitments that drive scheduling? ──
  t("caught the Friday office meeting", /office|dave|4th floor|meeting/.test(all),
    `nothing about the office in: ${all.slice(0, 200)}`);
  t("caught the Friday dinner", /dinner|rolf/.test(all),
    `nothing about dinner in: ${all.slice(0, 200)}`);

  // ── 2. The CORRECTION. Dave moved the meeting 2:00 → 2:30. Both must not survive. ──
  //
  // The first version of this assertion computed both flags over the WHOLE joined string,
  // so if "2:30" appeared anywhere the "2:00" flag went false and the test passed no
  // matter what. A check that cannot fail is worse than no check — it manufactures
  // confidence. So: look at the meeting constraints SPECIFICALLY, and fail if the graph
  // is carrying two different times for the same commitment.
  const meetingCs = cs.filter((c) => /office|meeting|dave|4th floor/i.test(c.rationale || ""));
  const timesFound = new Set();
  for (const c of meetingCs) {
    const r = (c.rationale || "") + " " + JSON.stringify(c.predicate || {});
    if (/2:30/.test(r)) timesFound.add("2:30");
    // a bare 2 / 2:00 / 2pm that is NOT part of 2:30
    if (/(?<!:)\b2(:00)?\s?(pm|PM)?\b(?!:?3)/.test(r.replace(/2:30/g, ""))) timesFound.add("2:00");
  }
  t("took the CORRECTED meeting time, not both",
    timesFound.size <= 1,
    `graph holds ${[...timesFound].join(" AND ")} for the same meeting — a correction must supersede, not accumulate`, true);

  // ── 3. Uncertainty stays uncertain. This is the whole ethic. ──
  const drinks = cs.find((c) => /drinks|sam/i.test(c.rationale || ""));
  t("Sam's 'might bail' drinks is NOT a must",
    !drinks || drinks.hardness !== "must",
    drinks ? `recorded as ${drinks.hardness}` : "", true);

  // ── 4. It must not invent. Nobody gave an airport pickup TIME. ──
  t("did not invent a pickup time nobody stated",
    !/pickup at \d|drive.*at \d{1,2}(:\d\d)?\s?(am|pm)/i.test(all),
    "a time appeared that no message contained", true);

  // ── 5. Musts must be real musts, not everything. ──
  const musts = cs.filter((c) => c.hardness === "must");
  t("didn't inflate everything to MUST",
    musts.length <= Math.max(2, Math.ceil(cs.length / 2)),
    `${musts.length} of ${cs.length} are 'must' — if everything is a must, nothing is`, true);

  // ── 6. It has to SAY something, not just file. ──
  t("replied in text rather than silently filing", (out.reply || "").trim().length > 0);

  // ── 7. And it should surface what's still unresolved rather than paper over it. ──
  t("named a gap or asked something (didn't pretend it's complete)",
    (out.gaps || []).length > 0 || /\?/.test(out.reply || ""),
    "no gaps, no questions — a thread this ambiguous should leave open questions");

  console.log(`\n\x1b[2m──────────────────────────────────────────────────────────\x1b[0m`);
  console.log(`${fail === 0 ? "\x1b[32mall " + pass + " held" : "\x1b[31m" + fail + " FAILED, " + pass + " held"}\x1b[0m\n`);
  process.exit(fail ? 1 : 0);
})();
