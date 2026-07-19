#!/usr/bin/env node
// test-grouping.js — the mega-trip, and the loop that kept rebuilding it.
//
//   node test-grouping.js
//
// A trip appeared on screen called "Nashville → Chicago → Smoky Mountains area."
// Three unrelated plans, welded into one journey. The title was honest — the trip
// really did hold all three — so the fault was upstream, in what decides that two
// bookings belong together.
//
// It was the confirmation number, used in three places that disagreed:
//
//   findOrCreateGroupedTrip  united legs on ANY shared confirmation string.
//   unmergeMegaTrips         refused to unite legs whose shared confirmation
//                            spanned more than a journey.
//   the leg de-duplicator    DISCARDED a booking whose confirmation already existed.
//
// Each is defensible alone. Together: the importer merged, the repair split, the
// next import merged again — a loop that never settles, which from the outside is
// indistinguishable from a fix that didn't work. And the third one is worse than
// mis-filing: a second booking carrying "N/A" was dropped, silently, as a duplicate
// of the first thing that ever carried "N/A".
//
// So both questions now have ONE answer each, and this file is where they're asked.

const assert = require("assert");
const { usableConfirmation, confirmationReachOk } = require("./grouping");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const DAY = 86400000;
const iso = (d) => new Date(d).toISOString();
const MAX = 30;

console.log(`\n${b}What counts as a booking reference${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a real airline record locator is a reference", () => {
  assert.strictEqual(usableConfirmation("H3K9QP"), "h3k9qp");
  assert.strictEqual(usableConfirmation("  ABC123XY "), "abc123xy");
});

// These are the strings that actually caused the damage. A parser asked for "the
// confirmation number" and, finding none, wrote what the email said.
for (const junk of ["N/A", "n/a", "None", "Pending", "Confirmed", "TBD", "unknown", "-", "0"]) {
  t(`"${junk}" is NOT a reference`, () => {
    assert.strictEqual(usableConfirmation(junk), null, `"${junk}" was accepted as a booking reference`);
  });
}

t("a bare short number is not a reference (fare class, seat, row)", () => {
  assert.strictEqual(usableConfirmation("42"), null);
  assert.strictEqual(usableConfirmation("2024"), null);
});

t("empty and missing are not references", () => {
  assert.strictEqual(usableConfirmation(""), null);
  assert.strictEqual(usableConfirmation(null), null);
  assert.strictEqual(usableConfirmation(undefined), null);
});

// The guard must not go so far that it rejects real ones. Over-tightening here
// would split genuine round-trips — the opposite failure, equally visible.
t("a long numeric reference IS still a reference", () => {
  assert.strictEqual(usableConfirmation("1234567890"), "1234567890");
});

console.log(`\n${b}How far a shared reference is allowed to reach${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

const now = Date.now();

t("a return flight 10 days after the outbound is the same booking", () => {
  const res = confirmationReachOk(iso(now + 10 * DAY), iso(now), iso(now + DAY), MAX);
  assert.ok(res.ok, `refused a 10-day-out return (${res.days} days) — that tears one booking in half`);
});

t("a leg the day of is obviously the same booking", () => {
  assert.ok(confirmationReachOk(iso(now), iso(now), iso(now + DAY), MAX).ok);
});

// The mega-trip itself.
t("a booking 9 months away is a COLLISION, not a booking", () => {
  const res = confirmationReachOk(iso(now + 270 * DAY), iso(now), iso(now + 2 * DAY), MAX);
  assert.strictEqual(res.ok, false, "a reference reached 270 days and was allowed to — this is the mega-trip");
  assert.ok(res.days > 200, `reported ${res.days} days`);
});

t("...and backwards too — a February leg must not join an August trip", () => {
  const res = confirmationReachOk(iso(now - 180 * DAY), iso(now), iso(now + 3 * DAY), MAX);
  assert.strictEqual(res.ok, false);
});

// The boundary, both sides, so the limit is a real limit rather than a decoration.
t("the boundary holds on both sides", () => {
  assert.strictEqual(confirmationReachOk(iso(now + MAX * DAY), iso(now), iso(now), MAX).ok, true);
  assert.strictEqual(confirmationReachOk(iso(now + (MAX + 5) * DAY), iso(now), iso(now), MAX).ok, false);
});

// Absence of evidence is not evidence. A dateless booking has nothing to
// contradict the reference with, so the reference stands.
t("no date on either side → the reference is not overruled", () => {
  assert.ok(confirmationReachOk(null, iso(now), iso(now), MAX).ok);
  assert.ok(confirmationReachOk(iso(now), null, null, MAX).ok);
});

t("garbage dates don't silently become 1970", () => {
  const res = confirmationReachOk("not a date", iso(now), iso(now), MAX);
  assert.ok(res.ok, "an unparseable date became NaN → epoch → a 20,000-day 'collision'");
});

console.log(`\n${b}And the two halves now agree${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// This is the actual regression: the importer and the repair must reach the same
// verdict on the same pair, or they will undo each other forever. Simulate both.
const groupWouldUnite = (conf, whenISO, tripStart, tripEnd) =>
  !!usableConfirmation(conf) && confirmationReachOk(whenISO, tripStart, tripEnd, MAX).ok;

const splitterWouldUnite = (conf, aStart, bEnd) => {
  if (!usableConfirmation(conf)) return false;
  return Math.abs(new Date(bEnd) - new Date(aStart)) <= MAX * DAY;
};

t("both refuse the 270-day reference", () => {
  const conf = "ABC123", a = iso(now), far = iso(now + 270 * DAY);
  assert.strictEqual(groupWouldUnite(conf, far, a, a), false, "importer would re-merge it");
  assert.strictEqual(splitterWouldUnite(conf, a, far), false, "repair would re-merge it");
});

t("both accept the genuine round-trip", () => {
  const conf = "ABC123", a = iso(now), ret = iso(now + 9 * DAY);
  assert.strictEqual(groupWouldUnite(conf, ret, a, a), true);
  assert.strictEqual(splitterWouldUnite(conf, a, ret), true);
});

t("both refuse to unite on junk, at any distance", () => {
  const a = iso(now), soon = iso(now + DAY);
  assert.strictEqual(groupWouldUnite("N/A", soon, a, a), false,
    "'N/A' still unites bookings — and on the dedupe path it DELETES them");
  assert.strictEqual(splitterWouldUnite("N/A", a, soon), false);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
