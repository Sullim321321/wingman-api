// test-arrival.js — the arrival plan judges honestly, or says it can't.
const assert = require("assert");
const { plan, isArrivalActive, pickActiveFlight } = require("./arrival");

let pass = 0, fail = 0;
const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", x = "\x1b[0m";
const t = (n, fn) => { try { fn(); console.log(`  ${g}✓${x} ${n}`); pass++; } catch (e) { console.log(`  ${r}✗ ${n}${x}\n    ${e.message}`); fail++; } };

const land = "2026-07-25T18:00:00Z";                 // wheels down
const meetSoon = { start: "2026-07-25T20:30:00Z", title: "Board sit-down", venue: "Nash HQ" };

t("comfortable: lands 18:00, 30-min drive, meeting 20:30 → leave by ~19:55, ~35 slack", () => {
  const p = plan(land, meetSoon, 30);
  assert.strictEqual(p.ready_to_leave_at, "2026-07-25T18:20:00.000Z"); // +20 deplane
  assert.strictEqual(p.leave_airport_by, "2026-07-25T19:55:00.000Z");  // 20:30 -5 pad -30 drive
  assert.strictEqual(p.slack_minutes, 95);
  assert.strictEqual(p.verdict, "comfortable");
});

t("tight: same landing, meeting only 70 min out → small positive slack", () => {
  const p = plan(land, { start: "2026-07-25T19:10:00Z" }, 30);
  // leave by 19:10 -5 -30 = 18:35; ready 18:20 → slack 15
  assert.strictEqual(p.slack_minutes, 15);
  assert.strictEqual(p.verdict, "tight");
});

t("wont_make_it: meeting starts before you could ever get there", () => {
  const p = plan(land, { start: "2026-07-25T18:30:00Z" }, 45);
  assert.strictEqual(p.verdict, "wont_make_it");
  assert.ok(p.slack_minutes < 0);
});

t("checked bag pushes ready-to-leave later", () => {
  const p = plan(land, meetSoon, 30, { bagsMin: 20 });
  assert.strictEqual(p.ready_to_leave_at, "2026-07-25T18:40:00.000Z"); // +20 +20
});

t("no meeting → verdict no_meeting, land time still stated", () => {
  const p = plan(land, null, null);
  assert.strictEqual(p.verdict, "no_meeting");
  assert.strictEqual(p.land_at, "2026-07-25T18:00:00.000Z");
  assert.strictEqual(p.leave_airport_by, null);
});

t("meeting known but NO route → unknown, never a guessed leave-by", () => {
  const p = plan(land, meetSoon, null);
  assert.strictEqual(p.verdict, "unknown");
  assert.strictEqual(p.leave_airport_by, null);
  assert.strictEqual(p.travel_minutes, null);
});

t("no arrival → unknown, nothing derived", () => {
  const p = plan(null, meetSoon, 30);
  assert.strictEqual(p.verdict, "unknown");
  assert.strictEqual(p.ready_to_leave_at, null);
});

// ── active window (Roadmap v4, C) — the gate that stops the 15h-early card ──
const NOW = Date.parse("2026-07-28T12:00:00Z"), H = 3600000;
const fl = (depOff, arrOff) => ({ type: "flight",
  departs_at: new Date(NOW + depOff).toISOString(),
  arrives_at: arrOff == null ? null : new Date(NOW + arrOff).toISOString() });

t("active: in the air (departed, not yet landed)", () => assert.strictEqual(isArrivalActive(fl(-1*H, 2*H), NOW), true));
t("active: landed 90 min ago (<2h)", () => assert.strictEqual(isArrivalActive(fl(-4*H, -1.5*H), NOW), true));
t("active: boarding window, departs in 3h (<4h)", () => assert.strictEqual(isArrivalActive(fl(3*H, 6*H), NOW), true));
t("NOT active: departs in 15h — the exact bug", () => assert.strictEqual(isArrivalActive(fl(15*H, 18*H), NOW), false));
t("NOT active: landed 5h ago (>2h)", () => assert.strictEqual(isArrivalActive(fl(-8*H, -5*H), NOW), false));
t("NOT active: malformed leg (arrives before it departs)", () => assert.strictEqual(isArrivalActive(fl(5*H, 2*H), NOW), false));
t("NOT active: no arrival time", () => assert.strictEqual(isArrivalActive(fl(2*H, null), NOW), false));
t("pickActiveFlight: prefers the in-air leg over a later boarding one", () => {
  const picked = pickActiveFlight([fl(-1*H, 2*H), fl(3*H, 6*H)], NOW);
  assert.strictEqual(picked.departs_at, new Date(NOW - 1*H).toISOString());
});
t("pickActiveFlight: returns null when nothing is active (all far out)", () => {
  assert.strictEqual(pickActiveFlight([fl(15*H, 18*H), fl(40*H, 43*H)], NOW), null);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
