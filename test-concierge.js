#!/usr/bin/env node
// test-concierge.js — the booking-request email composer (C6c).
//
//   node test-concierge.js
//
// For hotels Duffel can't book, Wingman drafts a request the user sends themselves. The
// composer must be HONEST: it asks the hotel to confirm availability and rate — it never
// states a reservation exists or invents a confirmation number. It also must not leak a
// preference (loyalty number) that wasn't given.

const assert = require("assert");
const { composeBookingEmail } = require("./concierge");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const base = {
  hotelName: "The Hoxton", area: "Williamsburg",
  checkIn: "2026-09-10", checkOut: "2026-09-13",
  guestName: "Madeline Sullivan",
};

console.log(`\n${b}composeBookingEmail${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("subject names the hotel and the dates", () => {
  const { subject } = composeBookingEmail(base);
  assert.match(subject, /Hoxton/);
  assert.match(subject, /Sep/);
});
t("body carries guest, both dates, and the night count", () => {
  const { body } = composeBookingEmail(base);
  assert.match(body, /Madeline Sullivan/);
  assert.match(body, /Sep 10/);
  assert.match(body, /Sep 13/);
  assert.match(body, /3 nights/);
});
t("it ASKS to confirm availability + rate — never asserts a reservation", () => {
  const { body } = composeBookingEmail(base);
  assert.match(body, /confirm (availability|the rate)|please confirm/i);
  assert.doesNotMatch(body, /your reservation is confirmed|booking reference|is booked/i);
});
t("loyalty line appears only when a number is provided", () => {
  assert.doesNotMatch(composeBookingEmail(base).body, /loyalty|member(ship)? number/i);
  const withLoyalty = composeBookingEmail({ ...base, loyalty: { program: "Discovery", number: "GHA123" } });
  assert.match(withLoyalty.body, /Discovery/);
  assert.match(withLoyalty.body, /GHA123/);
});
t("preferences are included only when given, phrased as requests", () => {
  const { body } = composeBookingEmail({ ...base, preferences: ["high floor", "late checkout"] });
  assert.match(body, /high floor/i);
  assert.match(body, /late checkout/i);
});
t("a missing hotel name is refused rather than emailed to nobody", () => {
  assert.throws(() => composeBookingEmail({ ...base, hotelName: "" }));
});
t("returns a mailto that URL-encodes subject and body", () => {
  const { mailto, to } = composeBookingEmail({ ...base, to: "reservations@hoxton.com" });
  assert.match(mailto, /^mailto:reservations@hoxton\.com\?/);
  assert.match(mailto, /subject=/);
  assert.match(mailto, /body=/);
  assert.ok(!/\s/.test(mailto.split("?")[1]), "query string should be encoded (no raw spaces)");
  assert.strictEqual(to, "reservations@hoxton.com");
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
