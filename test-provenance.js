// test-provenance.js — the discipline that keeps a suggestion from becoming a fact.
const assert = require("assert");
const p = require("./provenance");

let pass = 0, fail = 0;
const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", x = "\x1b[0m";
function t(name, fn) { try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; } catch (e) { console.log(`  ${r}✗ ${name}${x}\n    ${e.message}`); fail++; } }

const NOW = Date.parse("2026-07-25T12:00:00Z");
const soon = "2026-08-10T09:00:00Z";     // future
const past = "2026-07-01T09:00:00Z";     // gone

// ── factClothes — a sketch wearing a booking's identity ──────────────────────
t("a proposed leg carrying a confirmation is flagged", () => {
  assert.deepStrictEqual(p.factClothes({ state: "proposed", confirmation: "ABC123" }), ["confirmation"]);
});
t("a proposed leg carrying a flight number is flagged", () => {
  assert.deepStrictEqual(p.factClothes({ state: "proposed", flight_number: "AA2302" }), ["flight_number"]);
});
t("multiple offending fields are all reported", () => {
  assert.deepStrictEqual(
    p.factClothes({ state: "considered", confirmation: "X", seat: "4A", gate: "B12" }).sort(),
    ["confirmation", "gate", "seat"]
  );
});
t("a DATE on a sketch is honest — never flagged", () => {
  assert.deepStrictEqual(p.factClothes({ state: "proposed", departs_at: soon, arrives_at: soon }), []);
});
t("a BOOKED leg is entitled to its confirmation — never flagged", () => {
  assert.deepStrictEqual(p.factClothes({ state: "booked", confirmation: "ABC123", flight_number: "AA2302" }), []);
});
t("empty-string identity is not 'wearing' anything", () => {
  assert.deepStrictEqual(p.factClothes({ state: "proposed", confirmation: "  ", flight_number: "" }), []);
});

// ── isStaleSketch — a suggestion past its shelf life ─────────────────────────
t("a proposed leg whose date already passed is stale", () => {
  assert.strictEqual(p.isStaleSketch({ state: "proposed", departs_at: past }, NOW), true);
});
t("a proposed leg dated in the future is NOT stale", () => {
  assert.strictEqual(p.isStaleSketch({ state: "proposed", departs_at: soon }, NOW), false);
});
t("an undated proposal older than the TTL is stale", () => {
  assert.strictEqual(p.isStaleSketch({ state: "proposed", created_at: "2026-06-01T00:00:00Z" }, NOW, 21), true);
});
t("an undated proposal within the TTL is NOT stale", () => {
  assert.strictEqual(p.isStaleSketch({ state: "proposed", created_at: "2026-07-20T00:00:00Z" }, NOW, 21), false);
});
t("a BOOKED leg with a past date is NOT a stale sketch (it happened)", () => {
  assert.strictEqual(p.isStaleSketch({ state: "booked", departs_at: past }, NOW), false);
});

// ── auditLegs — the full verdict over a mixed set ────────────────────────────
t("auditLegs separates strips from expiries and leaves real legs alone", () => {
  const legs = [
    { id: 1, state: "booked", confirmation: "OK" },                 // real → untouched
    { id: 2, state: "proposed", flight_number: "AA1", departs_at: soon }, // wears clothes
    { id: 3, state: "proposed", departs_at: past },                 // stale (past date)
    { id: 4, state: "proposed", departs_at: soon },                 // healthy sketch
  ];
  const out = p.auditLegs(legs, NOW, 21);
  assert.deepStrictEqual(out.strip, [{ id: 2, fields: ["flight_number"] }]);
  assert.deepStrictEqual(out.expire, [{ id: 3 }]);
});
t("empty input is safe", () => {
  assert.deepStrictEqual(p.auditLegs([], NOW), { strip: [], expire: [] });
  assert.deepStrictEqual(p.auditLegs(null, NOW), { strip: [], expire: [] });
});

// ── sanitize — read-time guard ───────────────────────────────────────────────
t("sanitize blanks a sketch's booking-identity but keeps its date", () => {
  const out = p.sanitize({ id: 9, state: "proposed", flight_number: "AA1", confirmation: "X", departs_at: soon });
  assert.strictEqual(out.flight_number, null);
  assert.strictEqual(out.confirmation, null);
  assert.strictEqual(out.departs_at, soon);
});
t("sanitize leaves a real booking untouched (same reference)", () => {
  const real = { id: 1, state: "booked", flight_number: "AA1", confirmation: "X" };
  assert.strictEqual(p.sanitize(real), real);
});
t("sanitize leaves a clean sketch untouched (same reference)", () => {
  const clean = { id: 2, state: "proposed", departs_at: soon };
  assert.strictEqual(p.sanitize(clean), clean);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
