#!/usr/bin/env node
// test-graph.js — exercises the constraint graph's REFUSALS.
//
//   node test-graph.js
//
// A syntax check is structurally incapable of catching a bad call at runtime; we
// learned that the expensive way when `g(C.gold, 0.35)` white-screened the app and
// a Babel compile had cheerfully approved it. So this file does not check that the
// code parses. It checks that the code SAYS NO.
//
// Every test below is a lie the system must refuse to tell.
// No database required — the guards fire before sql is ever touched.

const graph = require("./constraints");

// A sql stub that EXPLODES if reached. If a refusal test somehow gets past the
// guard and tries to write, we find out here instead of in production.
const boom = () => { throw new Error("REACHED THE DATABASE — the guard did not fire"); };

let pass = 0, fail = 0;
const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";

async function refuses(what, fn) {
  try {
    await fn();
    console.log(`  ${r}✗ ALLOWED${x} ${what}`);
    fail++;
  } catch (e) {
    if (/REACHED THE DATABASE/.test(e.message)) {
      console.log(`  ${r}✗ WROTE ANYWAY${x} ${what}`);
      fail++;
    } else {
      console.log(`  ${g}✓ refused${x} ${what}\n      ${d}${e.message}${x}`);
      pass++;
    }
  }
}

async function is(what, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(ok ? `  ${g}✓${x} ${what}` : `  ${r}✗${x} ${what}\n      ${d}got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}${x}`);
  ok ? pass++ : fail++;
}

(async () => {
  console.log(`\n${b}Things Wingman must refuse to believe${x}`);
  console.log(`${d}──────────────────────────────────────────────────────────${x}`);

  await refuses("citing research with no source link", () =>
    graph.addConstraint(boom, {
      user_email: "t@t.com", kind: "entry",
      predicate: { op: "entry_document", country: "CN", passport: "US", value: "visa_L" },
      hardness: "must", source: "researched", evidence: {},
    }));

  await refuses("a predicate nothing can evaluate", () =>
    graph.addConstraint(boom, {
      user_email: "t@t.com", kind: "lodging",
      predicate: { op: "vibes_immaculate", value: true },
      source: "stated",
    }));

  await refuses("acting alone without naming what it protected", () =>
    graph.deliberate(boom, {
      user_email: "t@t.com", trip_id: 1, question: "Rebook?",
      because: "seemed right", by: "wingman", protecting: [],
    }));

  console.log(`\n${b}It says the true weight, and then it ASKS${x}`);
  console.log(`${d}──────────────────────────────────────────────────────────${x}`);

  // This test used to assert that an inferred 'must' was REFUSED. Running the eval
  // on the real transcript showed what that rule actually bought: the planner kept
  // the inference and quietly downgraded the hardness to slip past. "US passports
  // need an L visa for China" was filed as a *nice-to-have*. Zero refusals all run —
  // not compliance, evasion.
  //
  // A rule that punishes honesty gets dishonesty. So the constraint is now stored at
  // its TRUE weight, as 'proposed', gating nothing until a human confirms it.
  // The stub must answer only the query it was ASKED. The first version returned a
  // row for everything, so addConstraint's new idempotence SELECT got a hit and
  // concluded the constraint already existed — five tests failed on a stub that was
  // lying, not on code that was wrong. A test double that answers questions it wasn't
  // asked is just another confident system reporting on evidence it never checked.
  let cap = null;
  const grab = (strings, ...vals) => {
    const q = strings.join("?");
    if (/SELECT \* FROM constraints/i.test(q)) return [];   // nothing exists yet
    cap = vals;
    return [{ id: 1, hardness: vals[6], source: vals[7], status: vals[12] }];
  };

  const visa = await graph.addConstraint(grab, {
    user_email: "t@t.com", kind: "entry",
    predicate: { op: "entry_document", country: "CN", passport: "US", value: "visa_L" },
    rationale: "US passports need an L visa for China",
    hardness: "must", source: "inferred",
  });
  await is("an inferred visa keeps its 'must' — no laundering", visa.hardness, "must");
  await is("...and is held as 'proposed' until you confirm it", visa.status, "proposed");

  // A RESEARCHED must is not ground truth either, and "sourced" reads like "verified".
  // The planner looked up the LANY Asia tour, got four dates right, invented Beijing
  // and Guangzhou, dropped Osaka and Tokyo — and filed all six as MUST, active,
  // anchoring the trip. Worse than the inference case, because the badge invited trust.
  //
  // And the deeper point is categorical: a tour SCHEDULE is not the fact "which shows
  // am I attending". No search can establish the second. Only she can.
  const researched = await graph.addConstraint(grab, {
    user_email: "t@t.com", kind: "timing",
    predicate: { op: "arrive_before", place: "Beijing", at: "2026-09-20T19:00:00Z" },
    rationale: "LANY concert in Beijing on September 20",
    hardness: "must", source: "researched",
    evidence: { url: "https://example.com/tour", retrieved_at: "2026-07-13" },
  });
  await is("a RESEARCHED must also waits for your word", researched.status, "proposed");

  const told = await graph.addConstraint(grab, {
    user_email: "t@t.com", kind: "party",
    predicate: { op: "rooms", value: 2 }, rationale: "Two rooms",
    hardness: "must", source: "stated",
  });
  await is("something you SAID is active at once", told.status, "active");

  console.log(`\n${b}Supersession must earn it${x}`);
  console.log(`${d}──────────────────────────────────────────────────────────${x}`);

  // The eval caught the planner deleting "two rooms with a friend" because you later
  // mentioned a boyfriend in Sydney. Both are true; they are different legs. It also
  // let a duration overwrite a hotel, and Raffles vanished. Supersession is the most
  // destructive operation in the system and it now has to prove a real contradiction.
  const rooms   = { kind: "party",   predicate: { op: "rooms", value: 2 }, rationale: "Two rooms, friend", hardness: "must", source: "stated", scope: "asia" };
  const sydney  = { kind: "party",   predicate: { op: "rooms", value: 1 }, rationale: "One room, boyfriend", hardness: "must", source: "stated", scope: "sydney" };
  const raffles = { kind: "lodging", predicate: { op: "free_text", value: "Raffles" }, rationale: "Stay at Raffles", hardness: "strong", source: "stated" };
  const nights  = { kind: "timing",  predicate: { op: "free_text", value: "2 nights" }, rationale: "2 nights", hardness: "strong", source: "stated" };
  const d17     = { kind: "timing",  predicate: { op: "depart_after", value: "2026-10-17" }, rationale: "Leave 10/17", hardness: "strong", source: "stated" };
  const d16     = { kind: "timing",  predicate: { op: "depart_after", value: "2026-10-16" }, rationale: "Leave 10/16", hardness: "strong", source: "stated" };

  await is("a different leg does NOT delete 'two rooms'",     graph.canSupersede(rooms, sydney).ok,  false);
  await is("a duration does NOT overwrite the hotel",         graph.canSupersede(raffles, nights).ok, false);
  await is("a real contradiction still supersedes",           graph.canSupersede(d17, d16).ok,        true);

  console.log(`\n${b}Confidence cannot exceed the evidence${x}`);
  console.log(`${d}──────────────────────────────────────────────────────────${x}`);

  // The clamp: an inferred constraint claiming 0.99 is the 266-night stay in a suit.
  let captured = null;
  const capture = (strings, ...vals) => {
    const q = strings.join("?");
    if (/SELECT \* FROM constraints/i.test(q)) return [];   // answer only what's asked
    captured = vals;
    return [{ id: 1 }];
  };

  await graph.addConstraint(capture, {
    user_email: "t@t.com", kind: "lodging",
    predicate: { op: "facility_present", subject: "lodging", value: "technogym_treadmill" },
    hardness: "strong", source: "inferred", confidence: 0.99,
  });
  const storedConf = captured[9];
  await is("inferred @0.99 is clamped to the 0.7 ceiling", storedConf, 0.7);

  await graph.addConstraint(capture, {
    user_email: "t@t.com", kind: "lodging",
    predicate: { op: "facility_present", subject: "lodging", value: "cold_plunge" },
    hardness: "must", source: "stated", confidence: 1.0,
  });
  await is("stated @1.0 is allowed to stand", captured[9], 1.0);

  console.log(`\n${b}The cascade tells the truth or says "I don't know"${x}`);
  console.log(`${d}──────────────────────────────────────────────────────────${x}`);

  // Three downstream bookings. Only ONE is confidently linked with a known time.
  const rows = [
    { from_commitment: 1, to_commitment: 2, kind: "requires_by", slack_minutes: 40,
      source: "observed", confidence: 0.95, leg_id: 2, property_name: "Seaplane transfer",
      departs_at: "2026-08-14T16:20:00Z" },
    { from_commitment: 1, to_commitment: 3, kind: "requires_by", slack_minutes: 200,
      source: "inferred", confidence: 0.6, leg_id: 3, property_name: "Aman Villas",
      departs_at: "2026-08-14T18:00:00Z" },
    { from_commitment: 1, to_commitment: 4, kind: "requires_by", slack_minutes: 30,
      source: "observed", confidence: 0.95, leg_id: 4, property_name: "Kikunoi",
      departs_at: null },   // ← we have no time for this one
  ];
  let served = false;
  const stub = () => { if (served) return []; served = true; return rows; };

  const out = await graph.cascadeFrom(stub, 1, { delayMinutes: 75 });
  const by = Object.fromEntries(out.map((o) => [o.label, o.verdict]));

  await is("confident edge + 75min delay vs 40min slack → broken", by["Seaplane transfer"], "broken");

  // ── "at risk" has to MEAN something ─────────────────────────────────────────
  // The seeded trip exposed this: a 30-minute delay against a hotel with 180 minutes
  // of buffer came back "AT RISK — 150 min of slack left", and Wingman would push
  // about it. That is not a risk, it is a non-event. An assistant that cries wolf
  // whenever a flight slips gets muted — and then it is muted on the day it matters.
  const roomy = [{
    from_commitment: 1, to_commitment: 5, kind: "requires_by", slack_minutes: 180,
    source: "observed", confidence: 0.95, leg_id: 5, property_name: "Palace Hotel",
    departs_at: "2026-08-14T18:00:00Z",
  }];
  let served2 = false;
  const stub2 = () => { if (served2) return []; served2 = true; return roomy; };
  const calm = await graph.cascadeFrom(stub2, 1, { delayMinutes: 30 });
  await is("30min delay vs 180min slack → NOT at risk", calm[0].verdict, "safe");
  console.log(`      ${d}"${calm[0].why}" — and Wingman stays quiet.${x}`);
  await is("INFERRED edge refuses to assert an impact → unknown", by["Aman Villas"], "unknown");
  await is("no departure time → unknown, never a guess", by["Kikunoi"], "unknown");

  const aman = out.find((o) => o.label === "Aman Villas");
  console.log(`      ${d}Aman: "${aman.why}"${x}`);

  console.log(`\n${b}Rescue ranks by what survives, not by price${x}`);
  console.log(`${d}──────────────────────────────────────────────────────────${x}`);

  // The Tokyo hotel, as the transcript actually reasoned it.
  const cs = [
    { id: 10, hardness: "must",   rationale: "Technogym treadmills — the 5K is 8 weeks out" },
    { id: 11, hardness: "must",   rationale: "Cold plunge for recovery" },
    { id: 12, hardness: "strong", rationale: "On the Imperial Palace 5km loop" },
  ];
  const palace = graph.scoreOption(cs, [10, 11, 12], { 10: 1.0, 11: 1.0, 12: 1.0 });
  const aman2  = graph.scoreOption(cs, [10, 11, 12], { 10: 1.0, 11: 0.2, 12: 1.0 });  // onsen ≠ cold plunge

  await is("Palace Hotel scores full marks", palace.score, 210);
  await is("Aman loses the cold plunge and drops below it", aman2.score < palace.score, true);
  await is("...and Wingman can NAME what Aman costs you", aman2.lost.map((l) => l.id), [11]);
  console.log(`      ${d}"${aman2.lost[0].rationale}" — the exact reason the transcript chose Palace.${x}`);

  console.log(`\n${b}A plan may never impersonate a booking${x}`);
  console.log(`${d}──────────────────────────────────────────────────────────${x}`);

  // The single most dangerous thing this system can produce: a flight that does not
  // exist, stored in the same table as flights that do, rendered by the same
  // components, shown to someone standing in an airport.
  //
  // A model asked to sketch a trip WILL volunteer a flight number — it is trying to be
  // helpful. The tool schema doesn't offer the field; stripShape throws it away if the
  // model invents it anyway; and invariant #9 fails loudly if one ever reaches the
  // table. Three layers, because being wrong here means a person misses a flight they
  // were told they had.
  const planner = require("./planner");
  const eager = {
    kind: "move", city: "Shanghai", from: "London", why: "The 9/24 show",
    flight_number: "LH 726", carrier: "Lufthansa", confirmation: "XK4P2Q",
    departs_at: "2026-09-22T11:40:00Z", seat: "2A", gate: "C14",
  };
  const clean = planner.stripShape(eager);

  await is("a sketched leg keeps its city",           clean.city, "Shanghai");
  await is("...and keeps the REASON it exists",       clean.why, "The 9/24 show");
  await is("...but the flight number is stripped",    clean.flight_number, undefined);
  await is("...and the confirmation is stripped",     clean.confirmation, undefined);
  await is("...and the departure time is stripped",   clean.departs_at, undefined);
  await is("...and the seat and gate are stripped",   [clean.seat, clean.gate].join(","), ",");
  await is("...and the smuggling is REPORTED, loudly", clean._stripped.length > 0, true);
  console.log(`      ${d}stripped: ${clean._stripped.join(", ")}${x}`);

  console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
  console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
  process.exit(fail === 0 ? 0 : 1);
})();
