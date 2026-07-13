#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// seed-trip.js — a real upcoming trip, so the rest of the system has something to do.
//
//   node --env-file=.env seed-trip.js you@email.com            (dry run)
//   node --env-file=.env seed-trip.js you@email.com --apply
//   node --env-file=.env seed-trip.js you@email.com --remove   (delete it all)
//
// Everything built today — the cascade, the Situation screen, the ranked rescue, the
// Live Activity — has nothing to chew on, because there are 264 past bookings and zero
// upcoming ones. This creates one trip, three weeks out, with the shape of the real
// Asia itinerary: a long-haul, a tight connection, a hotel chosen for a reason, and a
// dinner that dies if the flight slips.
//
// ── This writes FAKE BOOKINGS into a production account ──────────────────────
// I don't love it, and it earns some rules:
//
//   · Every trip and leg is titled "TEST —" and carries raw_data.seeded = true.
//     No fabricated booking is allowed to look real. That is the whole discipline
//     behind stripShape() and invariant #9, and it applies to me too.
//   · --remove deletes exactly what this created, matched on the seeded flag. It
//     cannot touch a real booking, because it never looks at one.
//   · Confirmations are obvious fakes ("TEST-XXXX"), never plausible PNRs.
//
// The dependency edges are what make this worth doing. The seaplane has 40 minutes of
// slack. The dinner has 95. A 75-minute delay kills one and not the other — which is
// exactly the distinction the old cascade could not make, and the new one must.
// ═══════════════════════════════════════════════════════════════════════════════

const { neon } = require("@neondatabase/serverless");
const sql = neon(process.env.DATABASE_URL);
const graph = require("./constraints").bind(sql);

const email  = process.argv[2];
const APPLY  = process.argv.includes("--apply");
const REMOVE = process.argv.includes("--remove");

if (!email) {
  console.error("usage: node seed-trip.js you@email.com [--apply|--remove]");
  process.exit(1);
}

const c = { d:"\x1b[2m", g:"\x1b[32m", y:"\x1b[33m", r:"\x1b[31m", b:"\x1b[1m", cy:"\x1b[36m", x:"\x1b[0m" };
const say = (s = "") => console.log(s);

// Three weeks out — far enough to be plausible, close enough that the Live Activity
// and day-of logic will engage soon.
const D = (days, hhmm) => {
  const t = new Date();
  t.setDate(t.getDate() + days);
  const [h, m] = hhmm.split(":").map(Number);
  t.setHours(h, m, 0, 0);
  return t.toISOString();
};

const TRIP_TITLE = "TEST — Tokyo & Bali";

async function remove() {
  const trips = await sql`
    SELECT id, title FROM trips
    WHERE user_email = ${email} AND title LIKE 'TEST —%'`;
  if (!trips.length) { say(`  ${c.g}Nothing seeded to remove.${c.x}`); return; }

  for (const t of trips) {
    const [{ n }] = await sql`SELECT COUNT(*)::int AS n FROM trip_legs WHERE trip_id = ${t.id}`;
    say(`  ${c.y}removing${c.x} "${t.title}" ${c.d}(${n} legs)${c.x}`);
    if (APPLY || REMOVE) {
      // depends_on / satisfies / constraints all cascade from trips + trip_legs.
      await sql`DELETE FROM constraints WHERE trip_id = ${t.id}`;
      await sql`DELETE FROM trips WHERE id = ${t.id} AND user_email = ${email}`;
    }
  }
  say(`  ${c.g}Removed.${c.x}`);
}

async function seed() {
  // Idempotent: running twice must not give you two Tokyos.
  const [existing] = await sql`
    SELECT id FROM trips WHERE user_email = ${email} AND title = ${TRIP_TITLE} LIMIT 1`;
  if (existing) {
    say(`  ${c.y}Already seeded (trip ${existing.id}). Use --remove first to reseed.${c.x}`);
    return existing.id;
  }

  const [trip] = await sql`
    INSERT INTO trips (user_email, title, status, source, destination_city, destination_country)
    VALUES (${email}, ${TRIP_TITLE}, 'upcoming', 'seed', 'Tokyo', 'Japan')
    RETURNING id`;
  const tripId = trip.id;

  // ── the legs ───────────────────────────────────────────────────────────────
  // departs_at / arrives_at are what the cascade measures slack from. Fake, but
  // internally consistent — an inconsistent fixture teaches you nothing.
  const legs = {};
  const mk = async (key, row) => {
    const [r] = await sql`
      INSERT INTO trip_legs
        (trip_id, type, carrier, flight_number, origin, destination, destination_city,
         property_name, departs_at, arrives_at, confirmation, state, booked_by, raw_data)
      VALUES
        (${tripId}, ${row.type}, ${row.carrier || null}, ${row.flight || null},
         ${row.origin || null}, ${row.destination || null}, ${row.city || null},
         ${row.property || null}, ${row.departs}::TIMESTAMPTZ, ${row.arrives || null}::TIMESTAMPTZ,
         ${row.conf || null}, 'booked', 'imported',
         ${JSON.stringify({ seeded: true })}::jsonb)
      RETURNING id`;
    legs[key] = r.id;
    return r.id;
  };

  await mk("flight", {
    type: "flight", carrier: "Japan Airlines", flight: "JL 623",
    origin: "SFO", destination: "NRT", city: "Tokyo",
    departs: D(21, "11:40"), arrives: D(21, "15:00"), conf: "TEST-JL623",
  });
  // Seaplane: 40 minutes after the flight lands. Tight, and the point of the exercise.
  await mk("seaplane", {
    type: "transfer", property: "Seaplane transfer", city: "Tokyo",
    departs: D(21, "15:40"), conf: "TEST-SEA",
  });
  // Hotel: 3 hours of slack. Survives a 75-minute delay.
  await mk("hotel", {
    type: "hotel", property: "Palace Hotel Tokyo", city: "Tokyo",
    departs: D(21, "18:00"), arrives: D(25, "11:00"), conf: "TEST-PALACE",
  });
  // Dinner: 95 minutes of slack. Survives 75, dies at 100.
  await mk("dinner", {
    type: "dining", property: "Kikunoi", city: "Tokyo",
    departs: D(21, "16:35"), conf: "TEST-KIKU",
  });

  // ── the reasons ────────────────────────────────────────────────────────────
  const cs = {};
  const addC = async (key, spec) => {
    cs[key] = await graph.addConstraint(sql, { user_email: email, trip_id: tripId, ...spec });
  };

  await addC("plunge", {
    kind: "lodging", predicate: { op: "facility_present", subject: "lodging", value: "cold_plunge" },
    rationale: "Cold plunge for recovery — the 5K is eight weeks out",
    hardness: "strong", source: "stated", evidence: { from: "seed" },
  });
  await addC("loop", {
    kind: "lodging", predicate: { op: "within_distance", subject: "lodging", of: "imperial_palace_loop", km: 1 },
    rationale: "On the Imperial Palace 5km loop",
    hardness: "strong", source: "stated", evidence: { from: "seed" },
  });
  await addC("seaplane", {
    kind: "timing", predicate: { op: "free_text", value: "only transfer that day" },
    rationale: "The only transfer to the island that day",
    hardness: "must", source: "stated", evidence: { from: "seed" },
  });
  await addC("nolowcost", {
    kind: "routing", predicate: { op: "exclude_carrier_class", value: "low_cost" },
    rationale: "No budget carriers",
    hardness: "must", source: "stated", evidence: { from: "seed" },
  });
  await addC("business", {
    kind: "cabin", predicate: { op: "cabin_at_least", subject: "flight", value: "business", when: "duration_h > 6" },
    rationale: "Business on the long-hauls",
    hardness: "strong", source: "stated", evidence: { from: "seed" },
  });

  // ── satisfies: WHY each booking exists ─────────────────────────────────────
  // This is the edge no other travel app stores, and the reason a rescue can defend
  // the trip rather than merely rebook it.
  await graph.link(sql, legs.hotel,    cs.plunge.id,   1.0, "Palace has the cold plunge; Aman does not");
  await graph.link(sql, legs.hotel,    cs.loop.id,     1.0, "On the Imperial Palace loop");
  await graph.link(sql, legs.seaplane, cs.seaplane.id, 1.0, "Only transfer to the island that day");
  await graph.link(sql, legs.flight,   cs.business.id, 1.0, "JL 623 in business");
  await graph.link(sql, legs.flight,   cs.nolowcost.id,1.0, "Full-service carrier");

  // ── depends_on: MEASURED slack ─────────────────────────────────────────────
  // 'observed' at 0.95, because we set these times ourselves — the cascade is entitled
  // to assert an impact on them. An inferred edge would render as UNKNOWN, which is
  // correct in production and useless in a fixture.
  await graph.depend(sql, legs.flight, legs.seaplane, {
    kind: "requires_by", slack_minutes: 40, source: "observed", confidence: 0.95 });
  await graph.depend(sql, legs.flight, legs.dinner, {
    kind: "requires_by", slack_minutes: 95, source: "observed", confidence: 0.95 });
  await graph.depend(sql, legs.flight, legs.hotel, {
    kind: "requires_by", slack_minutes: 180, source: "observed", confidence: 0.95 });

  return tripId;
}

(async () => {
  say();
  say(`${c.b}Seed a trip${c.x}  ${c.d}${email}${c.x}`);
  say(`${c.d}${REMOVE ? "REMOVE" : APPLY ? "APPLY" : "DRY RUN — nothing will be written"}${c.x}`);
  say(`${c.d}──────────────────────────────────────────────────────────${c.x}`);

  if (REMOVE) { await remove(); say(); return; }

  if (!APPLY) {
    say(`  Would create ${c.cy}"${TRIP_TITLE}"${c.x} ${c.d}(3 weeks out)${c.x}`);
    say();
    say(`  ${c.d}JL 623   SFO → NRT      lands 15:00${c.x}`);
    say(`  ${c.d}Seaplane 15:40          ${c.y}40 min slack${c.x}  ${c.d}← dies at +41${c.x}`);
    say(`  ${c.d}Kikunoi  16:35          ${c.y}95 min slack${c.x}  ${c.d}← dies at +96${c.x}`);
    say(`  ${c.d}Palace   18:00          ${c.y}180 min slack${c.x} ${c.d}← survives${c.x}`);
    say();
    say(`  ${c.d}+ 5 constraints with their reasons, and the satisfies edges that link${c.x}`);
    say(`  ${c.d}  the Palace to the cold plunge — so a rescue can DEFEND it.${c.x}`);
    say();
    say(`  ${c.y}Dry run. Re-run with --apply.${c.x}`);
    say();
    return;
  }

  const tripId = await seed();
  say(`  ${c.g}Created trip ${tripId}.${c.x}`);
  say();
  say(`${c.b}Now fire a delay at it${c.x}`);
  say(`${c.d}──────────────────────────────────────────────────────────${c.x}`);
  const [f] = await sql`
    SELECT id FROM trip_legs WHERE trip_id = ${tripId} AND type = 'flight' LIMIT 1`;
  say(`  ${c.d}A 75-minute delay should kill the seaplane (40 min slack) and spare${c.x}`);
  say(`  ${c.d}the dinner (95) and the hotel (180). If it flags all three, the cascade${c.x}`);
  say(`  ${c.d}is lying again.${c.x}`);
  say();
  say(`  ${c.cy}node --env-file=.env simulate-delay.js ${email} ${f.id} 75${c.x}`);
  say();
  say(`  ${c.d}Then open the app: the push should land you straight in Situation.${c.x}`);
  say(`  ${c.d}When you're done:  ${c.cy}node --env-file=.env seed-trip.js ${email} --remove${c.x}`);
  say();
})().catch((e) => { console.error(`${c.r}${e.message}${c.x}`); process.exit(1); });
