#!/usr/bin/env node
// test-meeting.js — a Zoom call is not a trip to Dallas.
//
//   node test-meeting.js
//
// The dangerous mistakes here are the two that would book a flight for a meeting
// you attend from your couch. So the load-bearing assertions are: a virtual
// meeting is never in_person, and a meeting with BOTH a link and a place is
// AMBIGUOUS (a question), never a confident trip.

const assert = require("assert");
const { classifyMeeting } = require("./meeting");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

console.log(`\n${b}Virtual — you attend from wherever you are${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a Microsoft Teams meeting is virtual (your real 'Update Call')", () => {
  const m = classifyMeeting({ title: "Update Call", location: "Microsoft Teams Meeting" });
  assert.strictEqual(m.nature, "virtual");
  assert.strictEqual(m.physical, false, "a Teams call was read as a place to travel to");
});

t("a bare 'Microsoft Teams' location is virtual (your 'Madeline Sullivan and Daniel Hayes')", () => {
  assert.strictEqual(classifyMeeting({ title: "Madeline Sullivan and Daniel Hayes", location: "Microsoft Teams" }).nature, "virtual");
});

t("a Zoom link in the location is virtual", () => {
  assert.strictEqual(classifyMeeting({ location: "https://mackco.zoom.us/j/87085612824" }).nature, "virtual");
});

t("a Google Meet link in the DESCRIPTION is virtual even if location is blank", () => {
  const m = classifyMeeting({ title: "Sync", description: "Join: https://meet.google.com/abc-defg-hij" });
  assert.strictEqual(m.nature, "virtual");
});

t("Google's own conferenceData (video) is a hard virtual signal", () => {
  const m = classifyMeeting({ title: "1:1", conference: ["video"] });
  assert.strictEqual(m.nature, "virtual");
  assert.ok(m.signals.includes("google_conference_video"));
});

t("a conference call / dial-in is virtual", () => {
  assert.strictEqual(classifyMeeting({ title: "Board call", location: "Conference call, dial-in 555-123-4567" }).nature, "virtual");
});

console.log(`\n${b}In person — a real place, no way to dial in${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a street address is in_person", () => {
  const m = classifyMeeting({ title: "Client meeting", location: "225 W Wacker Dr, Chicago, IL" });
  assert.strictEqual(m.nature, "in_person");
  assert.ok(/Wacker/.test(m.place), "the place wasn't carried through for trip inference");
});

t("a city/venue with no dial-in is in_person", () => {
  assert.strictEqual(classifyMeeting({ title: "Lunch", location: "Gramercy Tavern, New York" }).nature, "in_person");
});

t("a plain city is in_person", () => {
  const m = classifyMeeting({ title: "Site visit", location: "Nashville, TN" });
  assert.strictEqual(m.nature, "in_person");
  assert.strictEqual(m.place, "Nashville TN");
});

console.log(`\n${b}Ambiguous and unknown are NOT the same${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("BOTH a Zoom link and a physical place is AMBIGUOUS — your Texas Rangers meeting", () => {
  const m = classifyMeeting({
    title: "Preston DeLong — Texas Rangers Opportunity Investor List Review — 11:30AM CST",
    location: "https://mackco.zoom.us/j/87085612824?pwd=xxx; Conference — Dallas — Executive",
  });
  assert.strictEqual(m.nature, "ambiguous", "a meeting you might dial into was treated as certain travel");
  assert.ok(m.virtual && m.physical);
  assert.ok(/Dallas/.test(m.place), "the possible-travel city wasn't preserved for the question we'll ask");
});

t("no location and no link is UNKNOWN, not a guess", () => {
  const m = classifyMeeting({ title: "Focus time" });
  assert.strictEqual(m.nature, "unknown");
  assert.strictEqual(m.place, null);
});

t("unknown is distinct from ambiguous", () => {
  assert.notStrictEqual(classifyMeeting({ title: "x" }).nature, "ambiguous");
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
