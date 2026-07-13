#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// simulate-delay.js — fire a delay at a real leg and watch the cascade decide.
//
//   node --env-file=.env simulate-delay.js you@email.com <legId> <minutes>
//   node --env-file=.env simulate-delay.js you@email.com <legId> <minutes> --push
//
// This walks the SAME graph.cascadeFrom() the production cascade walks. It is not a
// mock of the logic — it is the logic. A test harness that reimplements the thing it
// is testing proves only that you can write the same bug twice.
//
// What to watch for, on the seeded trip:
//
//   +30   nothing breaks. Everything has more slack than that.
//   +75   the seaplane dies (40 min slack). The dinner (95) and hotel (180) hold.
//   +200  all three go.
//
// If a 75-minute delay flags all three, the cascade is asserting impacts it hasn't
// computed — which is exactly what the old one did, and exactly what we replaced.
// ═══════════════════════════════════════════════════════════════════════════════

const { neon } = require("@neondatabase/serverless");
const sql = neon(process.env.DATABASE_URL);
const graph = require("./constraints").bind(sql);

const [, , email, legIdArg, minsArg] = process.argv;
const PUSH = process.argv.includes("--push");
const legId = parseInt(legIdArg, 10);
const mins  = parseInt(minsArg, 10);

if (!email || !legId || Number.isNaN(mins)) {
  console.error("usage: node simulate-delay.js you@email.com <legId> <minutes> [--push]");
  process.exit(1);
}

const c = { d:"\x1b[2m", g:"\x1b[32m", y:"\x1b[33m", r:"\x1b[31m", b:"\x1b[1m", cy:"\x1b[36m", x:"\x1b[0m" };
const say = (s = "") => console.log(s);

const MARK = {
  broken:  `${c.r}✗ BROKEN ${c.x}`,
  at_risk: `${c.y}~ AT RISK${c.x}`,
  unknown: `${c.d}? UNKNOWN${c.x}`,
};

(async () => {
  const [leg] = await sql`
    SELECT tl.*, t.title, t.user_email
    FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE tl.id = ${legId} AND t.user_email = ${email}`;
  if (!leg) { console.error(`${c.r}No such leg on that account.${c.x}`); process.exit(1); }

  const label = [leg.carrier, leg.flight_number].filter(Boolean).join(" ") || leg.property_name || leg.type;

  say();
  say(`${c.b}${label} is ${mins} minutes late${c.x}   ${c.d}${leg.title}${c.x}`);
  say(`${c.d}──────────────────────────────────────────────────────────────${c.x}`);

  const nodes = await graph.cascadeFrom(sql, legId, { delayMinutes: mins });

  if (!nodes.length) {
    say(`  ${c.g}Nothing downstream depends on it.${c.x}`);
    say(`  ${c.d}Either it's genuinely contained — or no dependency edges exist yet.${c.x}`);
    say();
    return;
  }

  for (const n of nodes) {
    const reasons = await graph.reasonsFor(sql, n.leg_id);
    const slack = n.slack_minutes != null ? `${String(n.slack_minutes).padStart(3)} min slack` : "  no slack known";
    say(`  ${MARK[n.verdict]}  ${n.label.padEnd(22)} ${c.d}${slack}${c.x}`);
    say(`             ${c.d}${n.why}${c.x}`);
    for (const r of reasons.slice(0, 2)) {
      say(`             ${c.cy}·${c.x} ${c.d}${r.rationale}${c.x}`);
    }
    say();
  }

  const broken  = nodes.filter((n) => n.verdict === "broken");
  const atRisk  = nodes.filter((n) => n.verdict === "at_risk");
  const unknown = nodes.filter((n) => n.verdict === "unknown");

  say(`${c.d}──────────────────────────────────────────────────────────────${c.x}`);
  say(`  ${broken.length} broken · ${atRisk.length} at risk · ${unknown.length} unknown`);

  // The claim the whole rewrite rests on. If a delay smaller than every slack value
  // still breaks something, the cascade is guessing.
  const minSlack = Math.min(...nodes.filter((n) => n.slack_minutes != null).map((n) => n.slack_minutes));
  if (broken.length && mins <= minSlack) {
    say(`  ${c.r}BUG: something broke on a ${mins}-minute delay, but the tightest slack is ${minSlack}.${c.x}`);
    process.exitCode = 1;
  } else if (!broken.length && !atRisk.length && !unknown.length) {
    say(`  ${c.g}Everything holds.${c.x}`);
  }

  if (PUSH) {
    say();
    say(`  ${c.d}Sending the real push…${c.x}`);
    // Deliberately NOT reimplemented here — hitting the live endpoint means we test
    // the code that actually runs in production, notification and all.
    const base = process.env.API_BASE || "https://wingman-api-y39a.onrender.com";
    say(`  ${c.y}Push requires the server. Trigger it from the app, or hit:${c.x}`);
    say(`  ${c.cy}POST ${base}/admin/simulate-delay${c.x} ${c.d}{ legId: ${legId}, minutes: ${mins} }${c.x}`);
  }

  say();
})().catch((e) => { console.error(`${c.r}${e.message}${c.x}`); process.exit(1); });
