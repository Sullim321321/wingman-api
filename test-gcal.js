#!/usr/bin/env node
// test-gcal.js — the calendar is the spine, so it must not carry junk.
//
//   node test-gcal.js
//
// The calendar is the highest-trust input, which makes its failures the most
// dangerous: a declined meeting treated as a commitment would have Wingman route
// you to a room you told it you're skipping. So the interesting assertions here
// are the REFUSALS — the events on your calendar that are NOT commitments.

const assert = require("assert");
const { normalizeEvent, commitmentsFrom } = require("./gcal");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

console.log(`\n${b}What the calendar feed contains that is NOT a commitment${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a declined meeting is not a commitment", () => {
  const ev = {
    id: "a", summary: "Standup", status: "confirmed",
    start: { dateTime: "2026-07-23T14:00:00-05:00" },
    end:   { dateTime: "2026-07-23T14:30:00-05:00" },
    attendees: [{ self: true, responseStatus: "declined" }],
  };
  assert.strictEqual(normalizeEvent(ev), null, "a meeting you declined was treated as where you'll be");
});

t("a cancelled event is not a commitment", () => {
  assert.strictEqual(normalizeEvent({ id: "b", status: "cancelled", start: { dateTime: "2026-07-23T14:00:00Z" } }), null);
});

t("an event with no usable time is dropped, not guessed", () => {
  assert.strictEqual(normalizeEvent({ id: "c", summary: "Someday" }), null);
});

t("a garbage date is dropped, never coerced to 1970", () => {
  const ev = { id: "d", summary: "Broken", start: { dateTime: "whenever" } };
  assert.strictEqual(normalizeEvent(ev), null, "an unparseable date became epoch instead of being dropped");
});

console.log(`\n${b}What IS a commitment — and keeps its shape${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a timed, accepted meeting is a busy commitment", () => {
  const c = normalizeEvent({
    id: "e", summary: "Chicago client meeting", location: "225 W Wacker Dr",
    status: "confirmed",
    start: { dateTime: "2026-07-23T14:00:00-05:00" },
    end:   { dateTime: "2026-07-23T15:00:00-05:00" },
    attendees: [{ self: true, responseStatus: "accepted" }],
  });
  assert.ok(c, "a normal meeting was dropped");
  assert.strictEqual(c.busy, true);
  assert.strictEqual(c.all_day, false);
  assert.strictEqual(c.certain, true);            // calendar = stated, not inferred
  assert.strictEqual(c.location, "225 W Wacker Dr");
  assert.strictEqual(c.title, "Chicago client meeting");
});

t("an all-day event is flagged all_day, not turned into a midnight meeting", () => {
  const c = normalizeEvent({ id: "f", summary: "Conference", start: { date: "2026-07-23" }, end: { date: "2026-07-24" } });
  assert.ok(c);
  assert.strictEqual(c.all_day, true);
});

t("a transparent 'free' event is kept but marked not-busy", () => {
  const c = normalizeEvent({
    id: "h", summary: "Dave's birthday", transparency: "transparent",
    start: { date: "2026-07-23" }, end: { date: "2026-07-24" },
  });
  assert.ok(c, "a free event was dropped entirely — we still want to know it's there");
  assert.strictEqual(c.busy, false, "a birthday was treated as occupying your day");
});

t("a missing end becomes a point in time, not NaN", () => {
  const c = normalizeEvent({ id: "i", summary: "Call", start: { dateTime: "2026-07-23T14:00:00Z" } });
  assert.strictEqual(c.end, c.start);
});

t("self is matched by email when the self flag is absent", () => {
  const ev = {
    id: "j", summary: "Skipped", status: "confirmed",
    start: { dateTime: "2026-07-23T14:00:00Z" },
    attendees: [{ email: "MADDIE@welcometothefight.club", responseStatus: "declined" }],
  };
  assert.strictEqual(normalizeEvent(ev, { selfEmail: "maddie@welcometothefight.club" }), null,
    "declined-by-email wasn't recognized as you");
});

console.log(`\n${b}The list: filtered, sorted, honest${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

const feed = [
  { id: "2", summary: "Late", status: "confirmed", start: { dateTime: "2026-07-23T17:00:00Z" }, end: { dateTime: "2026-07-23T18:00:00Z" } },
  { id: "1", summary: "Early", status: "confirmed", start: { dateTime: "2026-07-23T09:00:00Z" }, end: { dateTime: "2026-07-23T10:00:00Z" } },
  { id: "x", summary: "Declined", status: "confirmed", start: { dateTime: "2026-07-23T12:00:00Z" }, attendees: [{ self: true, responseStatus: "declined" }] },
  { id: "b", summary: "Birthday", transparency: "transparent", start: { date: "2026-07-23" }, end: { date: "2026-07-24" } },
];

t("commitmentsFrom drops declined and sorts by start", () => {
  const cs = commitmentsFrom(feed);
  assert.deepStrictEqual(cs.map((c) => c.calendar_id), ["b", "1", "2"].sort ? cs.map((c) => c.calendar_id) : []);
  // explicit: no declined, and Early before Late
  assert.ok(!cs.some((c) => c.title === "Declined"), "a declined event survived into the list");
  const timed = cs.filter((c) => !c.all_day).map((c) => c.title);
  assert.deepStrictEqual(timed, ["Early", "Late"], "not sorted by start");
});

t("busyOnly strips the birthday but keeps the meetings", () => {
  const cs = commitmentsFrom(feed, { busyOnly: true });
  assert.ok(!cs.some((c) => c.title === "Birthday"), "a free event survived busyOnly");
  assert.strictEqual(cs.length, 2);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
