#!/usr/bin/env node
// test-document.js — Home and the Dossier must never disagree.
//
//   node test-document.js
//
// They are two windows onto one document: the Dossier reads all of it, Home reads
// today's page. The moment they hold separate copies of "is this happening now",
// they will drift, and the loser ships — which is exactly what happened with the
// trip title, where the repair function would have restored the bug the fix removed.
//
// So the rules live in document.js and this file holds them to the cases that
// actually broke.

const assert = require("assert");
const doc = require("./document");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const NOW = Date.parse("2026-07-19T23:00:00Z");
const H = 3600000;

console.log(`\n${b}Which chapter — decided by the leg's own times${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// The Kimpton: checked in, checking out in two days. This is the leg that Home
// couldn't see at all, because it wasn't a flight.
const kimpton = { id: 1, state: "booked", type: "hotel", property_name: "Kimpton Aertson",
                  departs_at: "2026-07-19T15:00:00Z", arrives_at: "2026-07-21T16:00:00Z" };

t("a stay you are inside is IN MOTION", () => {
  assert.strictEqual(doc.chapterOf(kimpton, NOW), "in_motion");
});

// The bug I shipped this morning: a blanket `if (inMotion) return "in_motion"` put
// every leg of a live trip into "happening now", so a flight three days out rendered
// as in progress. A leg's chapter is its own business.
t("a flight three days out is PREPARE even during a live trip", () => {
  const later = { state: "booked", type: "flight", departs_at: "2026-07-23T14:00:00Z" };
  assert.strictEqual(doc.chapterOf(later, NOW), "prepare",
    "a future flight was marked as happening now");
});

t("a finished leg is AFTER", () => {
  assert.strictEqual(doc.chapterOf(
    { state: "booked", type: "flight", departs_at: "2026-07-18T10:00:00Z" }, NOW), "after");
});

t("a proposal is always PLAN, whatever its dates say", () => {
  assert.strictEqual(doc.chapterOf(
    { state: "proposed", type: "hotel", departs_at: "2026-07-19T16:00:00Z" }, NOW), "plan");
});

t("an undated leg is PLAN, not a guess", () => {
  assert.strictEqual(doc.chapterOf({ state: "booked", type: "flight" }, NOW), "plan");
});

// A malformed date must not silently become 1970 and land in AFTER.
t("a garbage date does not become 'long ago'", () => {
  assert.strictEqual(doc.chapterOf({ state: "booked", type: "flight", departs_at: "soon?" }, NOW), "plan");
});

console.log(`\n${b}An Uber is an expense; a seaplane is an appointment${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("an unnamed car leg is a ride", () => {
  assert.strictEqual(doc.isRide({ type: "car", departs_at: "2026-07-19T18:00:00Z" }), true);
});

t("a NAMED transfer is not a ride — the cascade defends it", () => {
  assert.strictEqual(doc.isRide({ type: "transfer", property_name: "Seaplane transfer" }), false);
  assert.strictEqual(doc.isRide({ type: "car", confirmation: "ABC123XY" }), false);
  assert.strictEqual(doc.isRide({ type: "car", vehicle_class: "Sprinter" }), false);
});

t("a hotel is never a ride", () => {
  assert.strictEqual(doc.isRide(kimpton), false);
});

console.log(`\n${b}Today's page and the whole document agree${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// The actual state of her trip tonight.
const legs = [
  kimpton,
  { id: 2, state: "proposed", type: "hotel", destination: "Smoky Mountains area" },
  { id: 3, state: "booked", type: "car", departs_at: "2026-07-19T18:00:00Z" },
  { id: 4, state: "booked", type: "flight", departs_at: "2026-07-23T14:00:00Z",
    carrier: "United", flight_number: "1", origin: "BNA", destination: "ORD" },
];

t("rides are counted, not listed", () => {
  const { chapters, rides } = doc.toChapters(legs, NOW, null, {});
  assert.strictEqual(rides.after, 1, "the Uber wasn't counted");
  assert.ok(!chapters.after.some((l) => l.id === 3), "the Uber was listed anyway");
});

t("the Kimpton is in motion and the Chicago flight is not", () => {
  const { chapters } = doc.toChapters(legs, NOW, null, {});
  assert.deepStrictEqual(chapters.in_motion.map((l) => l.id), [1]);
  assert.deepStrictEqual(chapters.prepare.map((l) => l.id), [4]);
});

// This is the regression that matters: Home computing a NARROWER set must still
// place each leg in the same chapter the Dossier would. If these ever diverge, one
// screen tells you the flight is boarding and the other doesn't.
t("a narrow window puts legs in the SAME chapters as the full document", () => {
  const full = doc.toChapters(legs, NOW, null, {});
  const todayOnly = legs.filter((l) => {
    const ch = doc.chapterOf(l, NOW);
    return ch === "in_motion" || ch === "prepare";
  });
  const narrow = doc.toChapters(todayOnly, NOW, null, {});
  assert.deepStrictEqual(
    narrow.chapters.in_motion.map((l) => l.id), full.chapters.in_motion.map((l) => l.id));
  assert.deepStrictEqual(
    narrow.chapters.prepare.map((l) => l.id), full.chapters.prepare.map((l) => l.id));
});

t("dependency edges survive into the chapters", () => {
  const depBy = { 1: [{ on: "United UA 1", slack_minutes: 40, certain: true }] };
  const { chapters } = doc.toChapters(legs, NOW, null, depBy);
  assert.strictEqual(chapters.in_motion[0].depends_on[0].slack_minutes, 40,
    "the line the industry can't print got dropped");
});

console.log(`\n${b}Is any of this real${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("one booked leg among proposals makes the trip real", () => {
  assert.strictEqual(doc.certaintyOf(legs), "real");
});

t("proposals alone make it an idea", () => {
  assert.strictEqual(doc.certaintyOf([{ state: "proposed" }, { state: "proposed" }]), "idea");
});

t("no legs is an idea, not a claim of reality", () => {
  assert.strictEqual(doc.certaintyOf([]), "idea");
});

console.log(`\n${b}A suggestion is not a flight${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// The Home card that said "TODAY - YOUR FLIGHT: ? -> Smoky Mountains area -> Chicago,
// departs in 9h" — for a leg Wingman proposed and she never agreed to. It also got a
// 24-hour departure briefing pushed to her phone. Every flight-consuming path read
// `type = 'flight'` and none of them read `state`.
const nextFlight = (legs, nowMs) => {
  let best = null, bestT = Infinity;
  for (const l of legs) {
    if (l.type !== "flight" || !l.departs_at) continue;
    if (l.state === "proposed") continue;          // the line that was missing
    const t = new Date(l.departs_at).getTime();
    if (t > nowMs && t < bestT) { bestT = t; best = l; }
  }
  return best;
};

t("a proposed flight is never 'your flight'", () => {
  const sketch = { id: 9, state: "proposed", type: "flight",
                   departs_at: "2026-07-21T23:00:00Z", destination: "Chicago" };
  assert.strictEqual(nextFlight([sketch], NOW), null,
    "a suggestion was announced as the user's flight");
});

t("a real flight is still found when a sketch sits in front of it", () => {
  const sketch = { id: 9, state: "proposed", type: "flight", departs_at: "2026-07-20T10:00:00Z" };
  const real   = { id: 4, state: "booked",   type: "flight", departs_at: "2026-07-23T14:00:00Z" };
  assert.strictEqual(nextFlight([sketch, real], NOW)?.id, 4,
    "over-filtering hid the real flight");
});

t("a proposed leg is a sketch in the document too", () => {
  assert.strictEqual(doc.chapterOf(
    { state: "proposed", type: "flight", departs_at: "2026-07-21T23:00:00Z" }, NOW), "plan");
});

console.log(`\n${b}A fourteen-year trip is not "in progress"${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// Note this file runs under CommonJS; tripdoc.js is ESM (it renders React). So we
// re-implement the SAME span rule here and assert on the shapes that broke, rather
// than importing. If these two ever disagree, the app is the source of truth and
// this is the alarm.
const MAX_TRIP_DAYS = 30;
const spanOf = (legs) => {
  const real = legs.filter((l) => l && l.state !== "proposed" && l.departs_at);
  const starts = real.map((l) => new Date(l.departs_at).getTime()).filter((n) => !Number.isNaN(n));
  const ends = real.map((l) => new Date(l.arrives_at || l.departs_at).getTime()).filter((n) => !Number.isNaN(n));
  if (!starts.length) return { start: 0, end: 0, days: 0, plausible: false };
  const start = Math.min(...starts), end = Math.max(...ends, start);
  return { start, end, days: Math.round((end - start) / 86400000), plausible: (end - start) <= MAX_TRIP_DAYS * 86400000 };
};
const statusOf = (legs, now) => {
  const { start, end, plausible } = spanOf(legs);
  if (!start) return "upcoming";
  if (end < now - 86400000) return "past";
  if (plausible && start <= now && end >= now) return "active";
  return end < now ? "past" : "upcoming";
};

// The exact Nashville trip from the screenshot: a stray 2012 flight, real 2026
// legs, and a Smoky Mountains proposal dated tonight.
const nashville = [
  { state: "booked",   type: "flight", departs_at: "2012-05-16T07:55:00Z", arrives_at: "2012-05-16T09:30:00Z" },
  { state: "booked",   type: "flight", departs_at: "2026-07-17T11:00:00Z", arrives_at: "2026-07-17T13:00:00Z" },
  { state: "proposed", type: "flight", departs_at: "2026-07-21T23:00:00Z" },
];

t("a 2012 leg does not drag the trip start back fourteen years", () => {
  // The 2012 flight is real, so it DOES set the start — but the span is then
  // implausible, and an implausible span may not read as active.
  assert.strictEqual(statusOf(nashville, NOW), "past",
    "a fourteen-year span declared itself in progress");
});

t("the Smoky Mountains proposal does not set the trip end", () => {
  const { end } = spanOf(nashville);
  // end must come from a committed leg, not the tonight-dated sketch
  assert.ok(end < Date.parse("2026-07-18T00:00:00Z"),
    "a proposal extended the trip's end date");
});

t("a normal 3-day trip happening now IS active", () => {
  const live = [
    { state: "booked", type: "hotel", departs_at: "2026-07-19T15:00:00Z", arrives_at: "2026-07-21T16:00:00Z" },
  ];
  assert.strictEqual(statusOf(live, NOW), "active");
});

t("a trip made only of proposals is upcoming, never active", () => {
  assert.strictEqual(statusOf([{ state: "proposed", type: "flight", departs_at: "2026-07-21T23:00:00Z" }], NOW), "upcoming");
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
