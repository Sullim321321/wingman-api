#!/usr/bin/env node
// test-inbound.js — the attacks /inbound/email must now refuse.
//
//   node test-inbound.js
//
// The endpoint used to identify a user from the `From:` header. `From:` is a string
// the sender types. So anyone could forge it — or skip email entirely and POST JSON
// at the URL — and write bookings into ANY user's account. Since those bookings are
// then fed to the concierge, it was also a prompt-injection channel into somebody
// else's assistant.
//
// This exercises the guard logic directly, no server, no database.

const crypto = require("crypto");

const SECRET = "s3cret-webhook-key";
const USERS  = { "a1b2c3d4e5f60718": "maddie@example.com" };   // token → user

// The endpoint's decision logic, lifted verbatim in shape from server.js.
function inbound({ headers = {}, query = {}, body = {} }) {
  const presented = headers["x-wingman-inbound-secret"] || query.k || "";
  const a = Buffer.from(String(presented));
  const b = Buffer.from(SECRET);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { status: 401, wrote: null };

  const toRaw = body.to || body.envelope?.to || body.recipient || "";
  const m = String(Array.isArray(toRaw) ? toRaw.join(",") : toRaw).toLowerCase().match(/\+([a-z0-9]{16,})@/);
  const token = m ? m[1] : null;
  if (!token) return { status: 200, wrote: null, reason: "no token" };

  const user = USERS[token];
  if (!user) return { status: 200, wrote: null, reason: "unknown token" };
  return { status: 200, wrote: user };
}

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const refuses = (name, res) => {
  const ok = res.wrote === null;
  console.log(`  ${ok ? g + "✓ refused" : r + "✗ WROTE TO " + res.wrote}${x} ${name}`);
  ok ? pass++ : fail++;
};
const allows = (name, res, who) => {
  const ok = res.wrote === who;
  console.log(`  ${ok ? g + "✓ accepted" : r + "✗ rejected"}${x} ${name}`);
  ok ? pass++ : fail++;
};

console.log(`\n${b}Attacks on /inbound/email${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

// THE ORIGINAL HOLE: forge the From: header, own the account.
refuses("a forged From: header (the old way in)", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { from: "maddie@example.com", to: "import@wingmantravel.app", subject: "Flight", text: "x".repeat(50) },
}));

refuses("POSTing straight at the endpoint, no secret", inbound({
  body: { from: "maddie@example.com", to: "import+a1b2c3d4e5f60718@wingmantravel.app", text: "x".repeat(50) },
}));

refuses("a wrong webhook secret", inbound({
  headers: { "x-wingman-inbound-secret": "not-the-secret" },
  body: { to: "import+a1b2c3d4e5f60718@wingmantravel.app" },
}));

refuses("a guessed / malformed token", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { to: "import+0000000000000000@wingmantravel.app" },
}));

refuses("the bare address, with no token at all", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { from: "maddie@example.com", to: "import@wingmantravel.app" },
}));

console.log(`\n${b}And the real thing still works${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

allows("a forward to the user's private address", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { from: "maddie@example.com", to: "import+a1b2c3d4e5f60718@wingmantravel.app", text: "x".repeat(50) },
}), "maddie@example.com");

allows("...even forwarded from a DIFFERENT address", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  // Her assistant forwards it, or she sends from her work account. Identity comes
  // from the token, so this just works — and it couldn't, when identity came from From:.
  body: { from: "someone.else@work.com", to: "import+a1b2c3d4e5f60718@wingmantravel.app", text: "x".repeat(50) },
}), "maddie@example.com");

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
