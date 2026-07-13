#!/usr/bin/env node
// check-brief.js — is "nothing needs you" actually true?
//
//   node --env-file=.env check-brief.js you@email.com
//
// The Brief's one line is the most load-bearing sentence in the product. Every travel
// app writes something like it. Almost none of them have computed it — it's a greeting
// with a timestamp attached.
//
// This runs the same query the /brief endpoint runs, so we can look at the sentence
// before any pixel depends on it. If it says "nothing needs you" while the seeded trip
// has a 10-minute connection, the Brief is a liar and we find out here rather than on
// somebody's home screen.

const { neon } = require("@neondatabase/serverless");
const sql = neon(process.env.DATABASE_URL);
const graph = require("./constraints").bind(sql);

const email = process.argv[2];
if (!email) { console.error("usage: node check-brief.js you@email.com"); process.exit(1); }

const c = { d:"\x1b[2m", g:"\x1b[32m", y:"\x1b[33m", r:"\x1b[31m", b:"\x1b[1m", cy:"\x1b[36m", x:"\x1b[0m" };
const say = (s = "") => console.log(s);

(async () => {
  const trips = await sql`
    SELECT DISTINCT t.id, t.title FROM trips t JOIN trip_legs tl ON tl.trip_id = t.id
    WHERE t.user_email = ${email} AND tl.state = 'booked' AND tl.departs_at > NOW()
      AND COALESCE(t.archived, false) = false`;

  const needs = [];

  for (const t of trips) {
    const legs = await sql`
      SELECT id, carrier, flight_number FROM trip_legs
      WHERE trip_id = ${t.id} AND type = 'flight' AND departs_at > NOW()`;
    for (const leg of legs) {
      const nodes = await graph.cascadeFrom(sql, leg.id, { delayMinutes: 0 });
      for (const n of nodes) {
        if (n.verdict === "broken" || n.verdict === "at_risk") {
          needs.push({ sev: n.verdict === "broken" ? "high" : "medium",
            what: n.label, why: n.why, from: t.title });
        }
      }
    }
  }

  const proposed = await sql`
    SELECT id, rationale, hardness FROM constraints
    WHERE user_email = ${email} AND status = 'proposed' AND superseded_by IS NULL`;
  for (const p of proposed) {
    needs.push({ sev: p.hardness === "must" ? "high" : "low",
      what: p.rationale, why: "Waiting on your word — I inferred it.", from: "memory" });
  }

  const decisions = await sql`
    SELECT id, headline FROM decisions
    WHERE user_email = ${email} AND status = 'pending'
      AND (expires_at IS NULL OR expires_at > NOW())`;
  for (const d of decisions) {
    needs.push({ sev: "high", what: d.headline, why: "Waiting on you.", from: "decisions" });
  }

  const high = needs.filter((n) => n.sev === "high").length;
  const headline = needs.length === 0
    ? (trips.length ? "Nothing needs you." : "Nothing on the horizon.")
    : high ? `${high} ${high === 1 ? "thing needs" : "things need"} you.`
           : `${needs.length} ${needs.length === 1 ? "thing" : "things"} worth a look.`;

  say();
  say(`${c.b}The Brief${c.x}  ${c.d}${email}${c.x}`);
  say(`${c.d}──────────────────────────────────────────────────────────${c.x}`);
  say();
  say(`  ${c.b}${headline}${c.x}`);
  say();

  for (const n of needs) {
    const mark = n.sev === "high" ? `${c.r}●${c.x}` : n.sev === "medium" ? `${c.y}●${c.x}` : `${c.d}●${c.x}`;
    say(`  ${mark} ${n.what}`);
    say(`    ${c.d}${n.why}  ·  ${n.from}${c.x}`);
  }
  if (!needs.length) {
    say(`  ${c.d}No broken or tight dependency. No unresolved must. Nothing awaiting${c.x}`);
    say(`  ${c.d}your word. No pending decision.${c.x}`);
  }

  say();
  say(`${c.d}──────────────────────────────────────────────────────────${c.x}`);
  say(`  ${c.d}${trips.length} upcoming ${trips.length === 1 ? "trip" : "trips"} · ${needs.length} ${needs.length === 1 ? "item" : "items"}${c.x}`);

  // The guard that matters. An empty forward book is NOT an all-clear — 0 of 0 is 100%
  // and it means nothing. We have shipped that particular lie before, more than once.
  if (!trips.length) {
    say();
    say(`  ${c.y}No upcoming travel at all.${c.x}`);
    say(`  ${c.d}"Nothing needs you" would be technically true and completely useless.${c.x}`);
    say(`  ${c.d}The Brief says "Nothing on the horizon" instead, which is the honest line.${c.x}`);
  }
  say();
})().catch((e) => { console.error(`${c.r}${e.message}${c.x}`); process.exit(1); });
