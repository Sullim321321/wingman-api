// test-arrival.js — the arrival plan judges honestly, or says it can't.
const assert = require("assert");
const { plan, isArrivalActive, pickActiveFlight, retimedArrival, shouldNudgeLeaveBy, shouldNudgeCheckin } = require("./arrival");

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

// ── O2 re-time (delay shifts the landing → re-push the leave-by) ──
const arrIso = "2026-07-28T15:00:00Z";
t("O2: live estimate wins → returns the new arrival", () => {
  assert.strictEqual(retimedArrival(arrIso, { estimatedArrival: "2026-07-28T15:40:00Z" }), "2026-07-28T15:40:00.000Z");
});
t("O2: no estimate, use delay minutes → old arrival + delay", () => {
  assert.strictEqual(retimedArrival(arrIso, { delayMinutes: 50 }), "2026-07-28T15:50:00.000Z");
});
t("O2: shift ≤5 min → null (not worth re-pushing)", () => {
  assert.strictEqual(retimedArrival(arrIso, { delayMinutes: 4 }), null);
});
t("O2: nothing to go on → null", () => {
  assert.strictEqual(retimedArrival(arrIso, {}), null);
  assert.strictEqual(retimedArrival(null, { delayMinutes: 60 }), null);
});

// ── leave-by nudge window (imminent = within next 90m, ≤15m past) ──
t("nudge: door time 60 min out → yes", () => assert.strictEqual(shouldNudgeLeaveBy(NOW + 60*60000, NOW), true));
t("nudge: door time 10 min past → yes (grace)", () => assert.strictEqual(shouldNudgeLeaveBy(NOW - 10*60000, NOW), true));
t("nudge: door time 2h out → no (too early)", () => assert.strictEqual(shouldNudgeLeaveBy(NOW + 120*60000, NOW), false));
t("nudge: door time 30 min past → no (missed)", () => assert.strictEqual(shouldNudgeLeaveBy(NOW - 30*60000, NOW), false));
t("nudge: null → no", () => assert.strictEqual(shouldNudgeLeaveBy(null, NOW), false));

// ── O4 check-in nudge gate (trigger is arrival, not the clock) ──
t("checkin: trip has flights + inbound landed → nudge", () => assert.strictEqual(shouldNudgeCheckin({ hasFlights: true, inboundLanded: true, checkInMs: NOW, nowMs: NOW }), true));
t("checkin: trip has flights, still in the air → wait", () => assert.strictEqual(shouldNudgeCheckin({ hasFlights: true, inboundLanded: false, checkInMs: NOW, nowMs: NOW }), false));
t("checkin: drive trip, check-in in 2h → nudge", () => assert.strictEqual(shouldNudgeCheckin({ hasFlights: false, checkInMs: NOW + 2*H, nowMs: NOW }), true));
t("checkin: drive trip, check-in 8h out → too early", () => assert.strictEqual(shouldNudgeCheckin({ hasFlights: false, checkInMs: NOW + 8*H, nowMs: NOW }), false));
t("checkin: drive trip, check-in 7h ago → too late", () => assert.strictEqual(shouldNudgeCheckin({ hasFlights: false, checkInMs: NOW - 7*H, nowMs: NOW }), false));

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
