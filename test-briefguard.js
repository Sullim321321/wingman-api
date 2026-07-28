// test-briefguard.js — the briefing guard never lets a routeless or corrupt leg speak.
const assert = require("assert");
const { isRealTime, hasRoute, isMalformedLeg, isBriefableLeg, briefableLegs } = require("./briefguard");

let pass = 0, fail = 0;
const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", x = "\x1b[0m";
const t = (n, fn) => { try { fn(); console.log(`  ${g}✓${x} ${n}`); pass++; } catch (e) { console.log(`  ${r}✗ ${n}${x}\n    ${e.message}`); fail++; } };

const soon = "2026-08-01T15:00:00Z";
const later = "2026-08-01T18:00:00Z";
const flight = (over = {}) => ({ type: "flight", status: "scheduled", origin: "SFO", destination: "JFK", departs_at: soon, arrives_at: later, ...over });

// ── isRealTime ──
t("isRealTime: a normal future ISO → true", () => assert.strictEqual(isRealTime(soon), true));
t("isRealTime: null → false", () => assert.strictEqual(isRealTime(null), false));
t("isRealTime: empty string → false", () => assert.strictEqual(isRealTime("  "), false));
t("isRealTime: garbage → false", () => assert.strictEqual(isRealTime("not a date"), false));
t("isRealTime: epoch 0 → false (parser artefact)", () => assert.strictEqual(isRealTime("1970-01-01T00:00:00Z"), false));
t("isRealTime: pre-2015 → false", () => assert.strictEqual(isRealTime("2009-06-01T00:00:00Z"), false));

// ── hasRoute ──
t("hasRoute: both endpoints → true", () => assert.strictEqual(hasRoute(flight()), true));
t("hasRoute: missing destination → false", () => assert.strictEqual(hasRoute(flight({ destination: null })), false));
t("hasRoute: empty origin → false", () => assert.strictEqual(hasRoute(flight({ origin: "" })), false));
t("hasRoute: whitespace origin → false", () => assert.strictEqual(hasRoute(flight({ origin: "   " })), false));

// ── isMalformedLeg ──
t("malformed: a clean flight → not malformed", () => assert.strictEqual(isMalformedLeg(flight()), false));
t("malformed: null leg → malformed", () => assert.strictEqual(isMalformedLeg(null), true));
t("malformed: no route → malformed (the null→null bug)", () => assert.strictEqual(isMalformedLeg(flight({ origin: null, destination: null })), true));
t("malformed: epoch departure → malformed", () => assert.strictEqual(isMalformedLeg(flight({ departs_at: "1970-01-01T00:00:00Z" })), true));
t("malformed: arrives before departs → malformed", () => assert.strictEqual(isMalformedLeg(flight({ arrives_at: "2026-08-01T12:00:00Z" })), true));
t("malformed: missing arrival only → NOT malformed (honest legs lack one)", () => assert.strictEqual(isMalformedLeg(flight({ arrives_at: null })), false));

// ── isBriefableLeg (the shared null→null guard) ──
t("briefable: a clean upcoming flight → yes", () => assert.strictEqual(isBriefableLeg(flight()), true));
t("briefable: routeless flight → no (never 'null → null departs in 24h')", () => assert.strictEqual(isBriefableLeg(flight({ origin: "", destination: "" })), false));
t("briefable: cancelled flight → no", () => assert.strictEqual(isBriefableLeg(flight({ status: "cancelled" })), false));
t("briefable: already landed → no", () => assert.strictEqual(isBriefableLeg(flight({ status: "landed" })), false));
t("briefable: no departure time → no", () => assert.strictEqual(isBriefableLeg(flight({ departs_at: null })), false));
t("briefable: a hotel leg → no (flights only by default)", () => assert.strictEqual(isBriefableLeg(flight({ type: "hotel" })), false));
t("briefable: a train, when types include rail → yes", () => assert.strictEqual(isBriefableLeg(flight({ type: "train" }), { types: ["flight", "train"] }), true));

// ── briefableLegs filter ──
t("briefableLegs: keeps only the sound, live flights; order preserved", () => {
  const legs = [
    flight({ id: 1 }),
    flight({ id: 2, destination: null }),   // routeless
    flight({ id: 3, status: "cancelled" }),  // dead
    flight({ id: 4 }),
    flight({ id: 5, departs_at: "1970-01-01T00:00:00Z" }), // corrupt
  ];
  assert.deepStrictEqual(briefableLegs(legs).map((l) => l.id), [1, 4]);
});
t("briefableLegs: null input → empty array", () => assert.deepStrictEqual(briefableLegs(null), []));

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
