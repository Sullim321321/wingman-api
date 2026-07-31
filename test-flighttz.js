// test-flighttz.js — a naive flight time is a wall clock at the airport, converted to true UTC.
const assert = require("assert");
const { toUTC, IANA_OF, hasExplicitZone, correctNaiveInstant } = require("./flighttz");

let pass = 0, fail = 0;
const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", x = "\x1b[0m";
const t = (n, fn) => { try { fn(); console.log(`  ${g}✓${x} ${n}`); pass++; } catch (e) { console.log(`  ${r}✗ ${n}${x}\n    ${e.message}`); fail++; } };

// ── The exact bug: EWR 7:29 PM local (summer, EDT = UTC-4) → 23:29 UTC ──
t("EWR 19:29 naive (EDT) → 23:29 UTC (the 4h fix)", () => {
  const r = toUTC("2026-07-30T19:29:00", "EWR");
  assert.strictEqual(r.iso, "2026-07-30T23:29:00.000Z");
  assert.strictEqual(r.converted, true);
});
t("PIT 21:06 naive (EDT) → 2026-07-31T01:06 UTC", () => {
  assert.strictEqual(toUTC("2026-07-30T21:06:00", "PIT").iso, "2026-07-31T01:06:00.000Z");
});

// ── Other zones ──
t("LAX 09:00 naive (PDT = UTC-7) → 16:00 UTC", () => {
  assert.strictEqual(toUTC("2026-07-30T09:00:00", "LAX").iso, "2026-07-30T16:00:00.000Z");
});
t("LHR 09:00 naive (BST = UTC+1, summer) → 08:00 UTC", () => {
  assert.strictEqual(toUTC("2026-07-30T09:00:00", "LHR").iso, "2026-07-30T08:00:00.000Z");
});
t("NRT 10:00 naive (JST = UTC+9, no DST) → 01:00 UTC", () => {
  assert.strictEqual(toUTC("2026-07-30T10:00:00", "NRT").iso, "2026-07-30T01:00:00.000Z");
});
t("winter EST (UTC-5): EWR 08:00 on Jan 15 → 13:00 UTC (DST-aware)", () => {
  assert.strictEqual(toUTC("2026-01-15T08:00:00", "EWR").iso, "2026-01-15T13:00:00.000Z");
});
t("PHX 12:00 (no DST, UTC-7 year-round) → 19:00 UTC", () => {
  assert.strictEqual(toUTC("2026-07-30T12:00:00", "PHX").iso, "2026-07-30T19:00:00.000Z");
});

// ── Idempotence / already-zoned: never double-convert ──
t("already-UTC (Z) → passes through, converted:false", () => {
  const r = toUTC("2026-07-30T23:29:00Z", "EWR");
  assert.strictEqual(r.iso, "2026-07-30T23:29:00.000Z");
  assert.strictEqual(r.converted, false);
});
t("already-offset (+09:00) → normalized to UTC, not re-shifted", () => {
  assert.strictEqual(toUTC("2026-07-30T10:00:00+09:00", "NRT").iso, "2026-07-30T01:00:00.000Z");
});

// ── Honest failure: unknown airport left ALONE, flagged (never guessed) ──
t("unknown airport → unchanged, converted:false, reason unknown_airport", () => {
  const r = toUTC("2026-07-30T19:29:00", "ZZZ");
  assert.strictEqual(r.iso, "2026-07-30T19:29:00");
  assert.strictEqual(r.converted, false);
  assert.strictEqual(r.reason, "unknown_airport");
});
t("null / empty → unchanged", () => {
  assert.strictEqual(toUTC(null, "EWR").iso, null);
  assert.strictEqual(toUTC("", "EWR").converted, false);
});
t("unparseable → unchanged", () => {
  assert.strictEqual(toUTC("sometime tuesday", "EWR").converted, false);
});

// ── helpers ──
t("IANA_OF: EWR → America/New_York; lowercase + full code ok", () => {
  assert.strictEqual(IANA_OF("ewr"), "America/New_York");
  assert.strictEqual(IANA_OF("PIT"), "America/New_York");
  assert.strictEqual(IANA_OF("ZZZ"), null);
});
t("hasExplicitZone: detects Z and ±offset, not naive", () => {
  assert.strictEqual(hasExplicitZone("2026-07-30T23:29:00Z"), true);
  assert.strictEqual(hasExplicitZone("2026-07-30T10:00:00+09:00"), true);
  assert.strictEqual(hasExplicitZone("2026-07-30T19:29:00"), false);
});

// ── correctNaiveInstant (the backfill repair for already-stored wrong rows) ──
t("repair: EWR stored 19:29Z (naive EDT) → 23:29Z", () => {
  assert.strictEqual(correctNaiveInstant("2026-07-30T19:29:00.000Z", "EWR").iso, "2026-07-30T23:29:00.000Z");
});
t("repair: PIT stored 21:06Z → 2026-07-31T01:06Z", () => {
  assert.strictEqual(correctNaiveInstant("2026-07-30T21:06:00.000Z", "PIT").iso, "2026-07-31T01:06:00.000Z");
});
t("repair: LAX stored 09:00Z (naive PDT) → 16:00Z", () => {
  assert.strictEqual(correctNaiveInstant("2026-07-30T09:00:00.000Z", "LAX").iso, "2026-07-30T16:00:00.000Z");
});
t("repair: unknown airport → unchanged (never guessed)", () => {
  const r = correctNaiveInstant("2026-07-30T19:29:00.000Z", "ZZZ");
  assert.strictEqual(r.converted, false);
  assert.strictEqual(r.iso, "2026-07-30T19:29:00.000Z");
});
t("repair: null → unchanged", () => assert.strictEqual(correctNaiveInstant(null, "EWR").converted, false));

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
