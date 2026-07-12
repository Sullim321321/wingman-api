#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// backfill-graph.js — Phase 0, step 2.  Populate the constraint graph from what
// we already know, and then tell the truth about how little that is.
//
//   node backfill-graph.js you@email.com            # dry run  (default)
//   node backfill-graph.js you@email.com --apply    # write
//
// What it does, in order:
//   1. STANDING CONSTRAINTS  ← users.taste_profile, users.preferences, standing_orders
//   2. DEPENDENCY EDGES      ← inferred from times/places between existing legs
//   3. THE HONEST REPORT     ← how many bookings have no reason attached
//
// Step 3 is the point. Everything else is scaffolding.
//
// What it deliberately does NOT do: invent reasons. There is no LLM in this file.
// We could ask a model to guess why Maddie booked the Ett Hem in Stockholm and it
// would produce something plausible and unfalsifiable, and it would poison the graph
// forever. A booking with no reason must READ as a booking with no reason, so that
// the planner can go and ask.
// ═══════════════════════════════════════════════════════════════════════════════

const { neon } = require("@neondatabase/serverless");
const sql = neon(process.env.DATABASE_URL);
const graph = require("./constraints").bind(sql);

const email = process.argv[2];
const APPLY = process.argv.includes("--apply");

if (!email) {
  console.error("usage: node backfill-graph.js you@email.com [--apply]");
  process.exit(1);
}

const c = { d: "\x1b[2m", g: "\x1b[32m", y: "\x1b[33m", r: "\x1b[31m", b: "\x1b[1m", x: "\x1b[0m" };
const planned = [];
const say = (s = "") => console.log(s);

function plan(what, fn) { planned.push({ what, fn }); }

// ── 1. Standing constraints from what the user has already told us ────────────
// Every one of these is source='stated' — the user set it in Settings, which is a
// statement. None of them is inferred. We are moving facts, not manufacturing them.
async function fromProfile() {
  const [u] = await sql`SELECT taste_profile, preferences FROM users WHERE email = ${email}`;
  if (!u) { console.error(`${c.r}no such user${c.x}`); process.exit(1); }

  const taste = u.taste_profile || {};
  const prefs = u.preferences || {};

  const map = [
    [prefs.cabin_class || taste.cabin_class, "cabin", (v) => ({
      predicate: { op: "cabin_at_least", subject: "flight", value: String(v).toLowerCase(), when: "duration_h > 6" },
      rationale: `Business or better on long-haul — you've said so.`,
      hardness: "strong",
    })],
    [prefs.avoid_low_cost ?? taste.avoid_low_cost, "routing", () => ({
      predicate: { op: "exclude_carrier_class", value: "low_cost" },
      rationale: "No budget carriers.",
      hardness: "strong",
    })],
    [prefs.seat || taste.seat, "cabin", (v) => ({
      predicate: { op: "free_text", subject: "flight", value: `seat: ${v}` },
      rationale: `Always ask for a ${v} seat.`,
      hardness: "nice",
    })],
    [taste.dietary, "free_text", (v) => ({
      predicate: { op: "free_text", subject: "dining", value: `dietary: ${JSON.stringify(v)}` },
      rationale: `Dietary: ${Array.isArray(v) ? v.join(", ") : v}.`,
      hardness: "strong",
    })],
  ];

  for (const [val, kind, build] of map) {
    if (val == null || val === false || val === "") continue;
    const spec = build(val);
    plan(`standing · ${spec.rationale}`, () =>
      graph.addConstraint(sql, {
        user_email: email, trip_id: null, kind,
        source: "stated", confidence: 1.0,
        evidence: { from: "users.taste_profile/preferences" },
        ...spec,
      }));
  }

  // Loyalty programs are OBSERVED — we hold the account, we can see it.
  //
  // The FIRST version of this loop wrote "credit FLIGHTS to marriott" — because it
  // took every loyalty account and assumed it was an airline. Marriott is a hotel
  // programme. server.js has known that all along (LOYALTY_PROGRAMS[].kind), and I
  // didn't read it.
  //
  // That is the disease, exactly: a plausible-looking assertion, confidently made,
  // about something the system never checked. It would have sat in the graph as a
  // 'nice' constraint forever and quietly skewed every flight Wingman ever picked.
  // The dry run caught it. That is what the dry run is for.
  const PROGRAM_KIND = {
    marriott: "hotel", hilton: "hotel", hhonors: "hotel", hyatt: "hotel", ihg: "hotel",
    united: "airline", delta: "airline", american: "airline", aa: "airline",
    british: "airline", ba: "airline", emirates: "airline", jetblue: "airline",
    aeroplan: "airline", star: "airline",
    amex_mr: "credit_card", amex: "credit_card",
  };

  const loy = await sql`SELECT program, provider_code FROM loyalty_accounts WHERE user_email = ${email}`;
  for (const l of loy) {
    const key  = String(l.program || "").toLowerCase();
    const kind = PROGRAM_KIND[key] || PROGRAM_KIND[String(l.provider_code || "").toLowerCase()];

    if (kind === "airline") {
      plan(`standing · credit FLIGHTS to ${l.program}`, () =>
        graph.addConstraint(sql, {
          user_email: email, trip_id: null, kind: "loyalty",
          predicate: { op: "credits_to", subject: "flight", value: key },
          rationale: `Credit flights to ${l.program} where the carrier allows it.`,
          hardness: "nice", source: "observed", confidence: 1.0,
          evidence: { from: "loyalty_accounts", provider_code: l.provider_code },
        }));
    } else if (kind === "hotel") {
      plan(`standing · prefer ${l.program} PROPERTIES`, () =>
        graph.addConstraint(sql, {
          user_email: email, trip_id: null, kind: "lodging",
          predicate: { op: "credits_to", subject: "lodging", value: key },
          rationale: `Prefer ${l.program} properties, where they suit the trip.`,
          hardness: "nice", source: "observed", confidence: 1.0,
          evidence: { from: "loyalty_accounts", provider_code: l.provider_code },
        }));
    } else {
      // Unknown programme, or a credit card. We do NOT guess what it applies to.
      say(`  ${c.y}skipped${c.x} loyalty '${l.program}' — I don't know if that's a flight or a hotel programme, so I won't assert either.`);
    }
  }

  // Standing orders → per-trip budget ceilings. Already explicit; already the user's.
  const so = await sql`SELECT * FROM standing_orders WHERE user_email = ${email} AND enabled = TRUE`;
  for (const s of so) {
    if (s.max_price != null) {
      plan(`trip ${s.trip_id} · rebook ceiling $${s.max_price}`, () =>
        graph.addConstraint(sql, {
          user_email: email, trip_id: s.trip_id, kind: "budget",
          predicate: { op: "budget_max_cents", value: s.max_price * 100 },
          rationale: `Rebook without asking under $${s.max_price}.`,
          hardness: "must", source: "stated", confidence: 1.0,
          evidence: { from: "standing_orders" },
        }));
    }
  }
}

// ── 2. Dependency edges, inferred — and honestly labelled as inferred ─────────
// A hotel check-in on the day a flight lands depends on that flight. That is a real
// inference and a useful one. It is ALSO a guess, so it lands at confidence 0.6 and
// source 'inferred', which means cascadeFrom() will render it as `unknown` and
// refuse to tell anyone their hotel is gone. Correct. It gets promoted to 0.9 only
// when a human or a live data source confirms it.
async function edges() {
  const legs = await sql`
    SELECT tl.id, tl.trip_id, tl.type, tl.departs_at, tl.arrives_at,
           tl.origin, tl.destination, tl.destination_city, tl.property_name
    FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${email} AND tl.departs_at IS NOT NULL
    ORDER BY tl.trip_id, tl.departs_at`;

  const byTrip = {};
  for (const l of legs) (byTrip[l.trip_id] ||= []).push(l);

  let n = 0;
  for (const [tripId, ls] of Object.entries(byTrip)) {
    for (const a of ls) {
      if (a.type !== "flight" || !a.arrives_at) continue;
      const landed = new Date(a.arrives_at);
      for (const b of ls) {
        if (b.id === a.id || !b.departs_at) continue;
        const starts = new Date(b.departs_at);
        const gapMin = (starts - landed) / 60000;
        if (gapMin < 0 || gapMin > 14 * 60) continue;   // same-arrival-day only

        // A flight ten hours after another flight is not a connection — it is just
        // Tuesday. The first pass emitted "flight depends on PIT→LGA (611 min slack)"
        // and that edge is a fiction: nothing about the second flight actually
        // requires the first to have landed.
        //
        // A downstream FLIGHT only depends on an upstream one if it is a genuine
        // connection. Six hours is generous; beyond that, they are two separate
        // journeys that happen to share a date.
        if (b.type === "flight" && gapMin > 6 * 60) continue;

        // Slack is what the gap ALREADY gives you. A 90-minute gap tolerates 90
        // minutes of delay and not a minute more. This is the number the whole
        // cascade turns on, so it is measured, never assumed.
        n++;
        plan(
          `edge · ${b.property_name || b.type} depends on ${a.origin}→${a.destination} (${Math.round(gapMin)} min slack)`,
          () => graph.depend(sql, a.id, b.id, {
            kind: "requires_by",
            slack_minutes: Math.round(gapMin),
            source: "inferred",     // ← and therefore: never asserts an impact
            confidence: 0.6,
          })
        );
      }
    }
  }
  return n;
}

// ── 3. The honest report ──────────────────────────────────────────────────────
async function report() {
  const [{ total }] = await sql`
    SELECT COUNT(*)::int AS total FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${email} AND tl.departs_at > NOW()`;
  const [{ withreason }] = await sql`
    SELECT COUNT(DISTINCT s.commitment_id)::int AS withreason
    FROM satisfies s JOIN trip_legs tl ON tl.id = s.commitment_id
    JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${email} AND tl.departs_at > NOW()`;

  const [{ everything }] = await sql`
    SELECT COUNT(*)::int AS everything FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${email}`;

  say();
  say(`${c.b}The finding${c.x}`);
  say(`${c.d}────────────────────────────────────────────────────────${c.x}`);
  say(`  Bookings on this account:     ${everything}`);
  say(`  Upcoming (departs_at > now):  ${total}`);
  say(`  ...with a reason attached:    ${withreason}`);

  // ── The zero guard ──────────────────────────────────────────────────────────
  // The first run of this script printed "0 upcoming / 0 with reasons" and moved on
  // as though that were a clean bill of health. 0 out of 0 is 100%. It is also
  // completely meaningless, and printing it in calm grey text is precisely the false
  // all-clear that this whole project exists to stamp out.
  //
  // A denominator of zero is never a pass. It is a question.
  if (everything === 0) {
    say();
    say(`  ${c.r}This account has NO bookings at all.${c.x}`);
    say(`  ${c.d}Not "nothing to do" — something is wrong. Wrong email, or the${c.x}`);
    say(`  ${c.d}import never ran. Do not read the zeroes above as a pass.${c.x}`);
    process.exitCode = 1;
    return;
  }
  if (total === 0) {
    say();
    say(`  ${c.y}No UPCOMING travel — every booking on this account is in the past.${c.x}`);
    say(`  ${c.d}So the "0 with a reason" line above proves nothing either way: there${c.x}`);
    say(`  ${c.d}is nothing to protect right now. The graph can't be judged on an${c.x}`);
    say(`  ${c.d}empty forward book — plan a trip, then re-run this.${c.x}`);
    say();
    say(`  ${c.d}(${everything} past bookings are still here, and the ${planned.length} planned writes${c.x}`);
    say(`  ${c.d}above are real — the standing constraints and the dependency edges${c.x}`);
    say(`  ${c.d}apply to them. They just don't tell us anything about readiness.)${c.x}`);
    return;
  }

  const orphan = total - withreason;
  if (orphan > 0) {
    say();
    say(`  ${c.y}${orphan} of ${total} upcoming bookings Wingman cannot explain.${c.x}`);
    say(`  ${c.d}Each one is a booking it cannot defend during a disruption —${c.x}`);
    say(`  ${c.d}it can only rebook it. This is the gap the planner exists to close,${c.x}`);
    say(`  ${c.d}and it is measured, not guessed.${c.x}`);
  } else {
    say(`  ${c.g}Every upcoming booking knows why it exists.${c.x}`);
  }
}

(async () => {
  say();
  say(`${c.b}Wingman — constraint graph backfill${c.x}  ${c.d}${email}${c.x}`);
  say(`${c.d}${APPLY ? "APPLY — writing to the database" : "DRY RUN — nothing will be written"}${c.x}`);
  say();

  await graph.ensureConstraintSchema(sql);
  await fromProfile();
  const nEdges = await edges();

  say(`${c.b}Planned${c.x}  ${c.d}${planned.length} writes (${planned.length - nEdges} constraints, ${nEdges} edges)${c.x}`);
  say(`${c.d}────────────────────────────────────────────────────────${c.x}`);
  for (const p of planned) say(`  ${c.d}·${c.x} ${p.what}`);

  if (!APPLY) {
    say();
    say(`${c.y}Dry run. Re-run with --apply to write.${c.x}`);
    await report();
    return;
  }

  say();
  let ok = 0, failed = 0;
  for (const p of planned) {
    try { await p.fn(); ok++; }
    catch (e) {
      failed++;
      // A refusal here is the model working, not breaking. addConstraint() throws
      // when asked to store something it cannot stand behind — an inferred 'must',
      // a researched fact with no URL. Print it; do not swallow it.
      say(`  ${c.r}refused${c.x} ${p.what}\n    ${c.d}${e.message}${c.x}`);
    }
  }
  say(`${c.g}wrote ${ok}${c.x}${failed ? `  ${c.r}refused ${failed}${c.x}` : ""}`);
  await report();
})().catch((e) => { console.error(`${c.r}${e.message}${c.x}`); process.exit(1); });
