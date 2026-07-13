/**
 * test-booking.js — does the plan survive becoming a booking?
 *
 * Run: node test-booking.js
 *
 * The tests that matter are not "did it book." They are:
 *   - did it refuse to guess anything it didn't know
 *   - did the leg keep its reasons
 *   - did it refuse to book a second copy of itself
 */

const assert  = require("assert");
const booking = require("./booking");

let pass = 0, fail = 0, declared = 0;
const pending = [];

const t = (name, fn) => {
  declared++;
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; }
};

// An async test that never settles used to just... not appear. It wouldn't fail; it
// would be ABSENT, and the run would still print "0 failed" and exit green. A tally
// that only counts the tests that finished is a report on evidence it never checked.
// So: count what was declared, await all of it, and refuse to call it a pass unless
// every declared test actually reported back.
const ta = (name, fn) => {
  declared++;
  pending.push(
    Promise.resolve()
      .then(fn)
      .then(() => { console.log(`  ✓ ${name}`); pass++; })
      .catch((e) => { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; })
  );
};

const PROPOSED = {
  id: 1, trip_id: 9, type: "flight", state: "proposed",
  destination: "Tokyo → Kyoto", destination_city: "Kyoto",
  departs_at: "2026-09-28T00:00:00Z",
  raw_data: { planned: true, from_city: "Tokyo", to_city: "Kyoto", why: "LANY plays Kyoto" },
};
const PAX = { given_name: "Maddie", family_name: "Sullivan", born_on: "1990-01-01" };

console.log("\nREADINESS — a gap is a question, never a default\n");

t("ready when the plan knows the route, the date, and the traveller", () => {
  const r = booking.readiness({ leg: PROPOSED, trip: { id: 9 }, passenger: PAX });
  assert.strictEqual(r.ready, true, JSON.stringify(r.missing));
  assert.strictEqual(r.from_city, "Tokyo");
});

t("no date → asks for the date, does not invent one", () => {
  const r = booking.readiness({ leg: { ...PROPOSED, departs_at: null }, trip: {}, passenger: PAX });
  assert.strictEqual(r.ready, false);
  const m = r.missing.find((x) => x.field === "departs_at");
  assert.ok(m, "should ask for the date");
  // The planner refused to guess a date. Booking must not undo that refusal.
  assert.ok(/guess/i.test(m.why), "should say it isn't going to start guessing now");
});

t("no origin → asks; the plan recorded where she was going, not where from", () => {
  const r = booking.readiness({
    leg: { ...PROPOSED, raw_data: { ...PROPOSED.raw_data, from_city: null } },
    trip: {}, passenger: PAX,
  });
  assert.strictEqual(r.ready, false);
  assert.ok(r.missing.some((x) => x.field === "from_city"));
});

t("no passenger profile → asks, and routes her somewhere she can answer", () => {
  const r = booking.readiness({ leg: PROPOSED, trip: {}, passenger: null });
  assert.strictEqual(r.ready, false);
  const m = r.missing.find((x) => x.field === "passenger");
  assert.ok(m && m.route === "PassengerProfile");
});

t("a half-filled passenger profile is not a passenger profile", () => {
  const r = booking.readiness({ leg: PROPOSED, trip: {}, passenger: { given_name: "Maddie" } });
  assert.ok(r.missing.some((x) => x.field === "passenger"));
});

t("refuses to book something that is already booked", () => {
  const r = booking.readiness({ leg: { ...PROPOSED, state: "booked" }, trip: {}, passenger: PAX });
  assert.strictEqual(r.ready, false);
  assert.strictEqual(r.already, "booked");
});

t("says plainly that it cannot book a hotel yet, rather than half-trying", () => {
  const r = booking.readiness({ leg: { ...PROPOSED, type: "hotel" }, trip: {}, passenger: PAX });
  assert.strictEqual(r.ready, false);
  assert.ok(/only book flights/i.test(r.missing[0].ask));
});

console.log("\nAIRPORTS — a city is not an airport\n");

const fakeDuffel = (places) => ({ suggestions: { list: async () => ({ data: places }) } });

ta("prefers the city node, so 'Tokyo' means HND *and* NRT", async () => {
  const d = fakeDuffel([
    { type: "airport", iata_code: "NRT", name: "Narita" },
    { type: "city", iata_code: "TYO", name: "Tokyo", airports: [{ iata_code: "HND" }, { iata_code: "NRT" }] },
  ]);
  const r = await booking.resolveAirport(d, "Tokyo");
  assert.strictEqual(r.iata, "TYO");
  assert.deepStrictEqual(r.covers, ["HND", "NRT"]);
});

ta("returns null for a city it cannot resolve — never the nearest big runway", async () => {
  const r = await booking.resolveAirport(fakeDuffel([]), "Nowheresville");
  assert.strictEqual(r, null);
});

console.log("\nPROMOTE — the plan becomes the booking, and keeps its reasons\n");

// A tiny fake `sql` tag that records what it was asked and answers plausibly.
function fakeSql({ updatedRow, edges = [] }) {
  const calls = [];
  const tag = async (strings, ...vals) => {
    const q = strings.join("?");
    calls.push({ q, vals });
    if (/INSERT INTO trip_legs/i.test(q)) throw new Error("promote INSERTed a leg — it must UPDATE the proposal");
    if (/UPDATE trip_legs/i.test(q))      return updatedRow ? [updatedRow] : [];
    if (/FROM satisfies/i.test(q))        return edges;
    return [];
  };
  tag.calls = calls;
  return tag;
}

const ORDER = {
  id: "ord_1", booking_reference: "ABC123",
  slices: [{ segments: [{
    id: "seg_1",
    marketing_carrier: { name: "Japan Airlines", iata_code: "JL" },
    marketing_carrier_flight_number: "623",
    origin: { iata_code: "HND" }, destination: { iata_code: "ITM" },
    departing_at: "2026-09-28T09:00:00Z", arriving_at: "2026-09-28T10:15:00Z",
  }] }],
};
const OFFER = { total_amount: "412.30", total_currency: "USD", conditions: {}, slices: ORDER.slices };

ta("UPDATEs the proposed leg — the same row, therefore the same edges", async () => {
  const sql = fakeSql({
    updatedRow: { id: 1, state: "booked", carrier: "Japan Airlines", flight_number: "JL 623" },
    edges: [{ constraint_id: 7 }, { constraint_id: 8 }],
  });
  const r = await booking.promote(sql, { leg: PROPOSED, order: ORDER, offer: OFFER });
  assert.strictEqual(r.leg.state, "booked");
  // The whole thesis of booking.js in one assertion.
  assert.strictEqual(r.reasons_kept, 2, "the booking must inherit the proposal's reasons");
  assert.ok(sql.calls.some((c) => /UPDATE trip_legs/i.test(c.q)), "must UPDATE");
  assert.ok(!sql.calls.some((c) => /INSERT INTO trips/i.test(c.q)), "must NOT create a second trip");
});

ta("puts a SPACE in the flight number — it is a name, and a person reads it", async () => {
  let captured;
  const sql = fakeSql({ updatedRow: { id: 1, state: "booked" }, edges: [] });
  const orig = sql;
  const spy = async (strings, ...vals) => { if (/UPDATE trip_legs/i.test(strings.join("?"))) captured = vals; return orig(strings, ...vals); };
  spy.calls = orig.calls;
  await booking.promote(spy, { leg: PROPOSED, order: ORDER, offer: OFFER });
  assert.ok(captured.includes("JL 623"), `expected "JL 623", got: ${JSON.stringify(captured)}`);
});

ta("refuses to double-book: if the row is no longer 'proposed', it shouts", async () => {
  // The UPDATE ... WHERE state='proposed' returns nothing. Duffel has ALREADY been paid.
  // The only safe move is a loud failure — never a silent success.
  const sql = fakeSql({ updatedRow: null });
  await assert.rejects(
    () => booking.promote(sql, { leg: PROPOSED, order: ORDER, offer: OFFER }),
    /no longer 'proposed'|double-book/i
  );
});

ta("refuses to mark a leg booked on an order with no segments", async () => {
  const sql = fakeSql({ updatedRow: { id: 1 } });
  await assert.rejects(
    () => booking.promote(sql, { leg: PROPOSED, order: { id: "x", slices: [] }, offer: {} }),
    /no segments/i
  );
});

console.log("\nPERMISSION — unknown blocks Wingman, never her\n");

const graph  = require("./constraints");
const rescue = require("./rescue");

// ── The test that would have caught the bug I actually shipped. ──
//
// The first version of these tests fed `permission()` a hand-written `choice` object
// with fields I INVENTED (`broken`, `unknowable`, `offer.total_amount`). Every test
// passed. Meanwhile rescue.rank() returns `{ options, recommended_id, ... }` — an
// object, not an array — and its options carry `breaks`, `cannot_assess`, `price`.
//
// So the tests validated my imagination against my imagination, and the real call
// would have thrown `.slice is not a function` on the first live search. A mock of the
// thing you are integrating with cannot fail the way the integration fails.
//
// Fix: build the `choice` with the REAL ranker, from a REAL Duffel-shaped offer.
const realChoice = (offer, constraints = []) =>
  rescue.rank({ offers: [offer], constraints, nodes: [], originalArrival: null }).options[0];

t("rank() returns an OBJECT with .options — not an array", () => {
  const r = rescue.rank({ offers: [OFFER], constraints: [], nodes: [], originalArrival: null });
  assert.ok(Array.isArray(r.options), "rank().options must be the array");
  assert.ok(!Array.isArray(r), "rank() itself is not an array — booking.js relied on this");
  assert.ok("recommended_id" in r);
});

t("the fields the booking screen renders are the fields rank() actually emits", () => {
  const c = realChoice(OFFER);
  for (const f of ["offer_id", "carrier", "flight", "departs_at", "arrives_at",
                   "price", "currency", "protects", "loses", "breaks", "cannot_assess"]) {
    assert.ok(f in c, `rank() options are missing '${f}', which BookLegScreen renders`);
  }
});

ta("an option it could not fully evaluate is not one it may book alone", async () => {
  const sql = async () => [];
  graph.bind(sql);
  // A constraint that IS about flights (so the system can't excuse itself) but which
  // this offer genuinely cannot answer: the offer carries no cabin class.
  const choice = realChoice(OFFER, [{
    id: 3, hardness: "must", rationale: "Business class on anything over 6 hours",
    predicate: { op: "cabin_at_least", value: "business" },
  }]);
  assert.ok(choice.cannot_assess.length, "expected the cabin question to be unanswerable here");
  const may = await booking.permission(sql, { user_email: "m@x.com", trip_id: 9, choice });
  assert.strictEqual(may.ok, false, JSON.stringify(may));
  assert.strictEqual(may.reason, "unevaluable");
  assert.ok(/won't book past a question I can't answer/i.test(may.detail));
});

// A constraint that is answerable must actually be ANSWERED. "Unknown" is the most
// valuable thing this system says, and that's exactly why it has to be scarce.
ta("'arrive before' is checked, not shrugged at — it lands at 10:15", async () => {
  const early = realChoice(OFFER, [{
    id: 4, hardness: "must", rationale: "Land before the 14:00 rehearsal",
    predicate: { op: "arrive_before", value: "2026-09-28T14:00:00Z" },
  }]);
  assert.strictEqual(early.cannot_assess.length, 0, "it can assess this");
  assert.strictEqual(early.breaks.length, 0, "10:15 is before 14:00");

  const late = realChoice(OFFER, [{
    id: 5, hardness: "must", rationale: "Land before the 09:00 call time",
    predicate: { op: "arrive_before", value: "2026-09-28T09:00:00Z" },
  }]);
  assert.strictEqual(late.brokeMust, true, "10:15 is not before 09:00 — say so");
});

ta("with nothing unknown and nothing broken, it may act", async () => {
  const sql = async () => [];
  graph.bind(sql);
  const may = await booking.permission(sql, {
    user_email: "m@x.com", trip_id: 9, choice: realChoice(OFFER),
  });
  assert.strictEqual(may.ok, true, JSON.stringify(may));
});

ta("no options at all is a refusal, not a crash", async () => {
  const sql = async () => [];
  graph.bind(sql);
  const may = await booking.permission(sql, { user_email: "m@x.com", trip_id: 9, choice: undefined });
  assert.strictEqual(may.ok, false);
  assert.strictEqual(may.reason, "no_options");
});

(async () => {
  await Promise.all(pending);
  const missing = declared - (pass + fail);
  console.log(`\n${pass} passed, ${fail} failed of ${declared} declared`);
  if (missing) console.log(`  ✗ ${missing} test(s) never reported. That is a failure, not a rounding error.`);
  console.log("");
  process.exit(fail || missing ? 1 : 0);
})();
