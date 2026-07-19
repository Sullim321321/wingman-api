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
const USERS  = {
  "a1b2c3d4e5f60718": "maddie@example.com",   // legacy 20-hex token
  "k7m2xq9rt4vn":     "maddie@example.com",   // new 12-char base32 token
};

// The endpoint's decision logic, lifted verbatim in shape from server.js.
function inbound({ headers = {}, query = {}, body = {} }) {
  const presented = headers["x-wingman-inbound-secret"] || query.k || "";
  const a = Buffer.from(String(presented));
  const b = Buffer.from(SECRET);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { status: 401, wrote: null };

  // Search EVERY recipient field, concatenated — not just the first truthy one.
  // (Matches the endpoint after the auto-forward fix.)
  const flat = (v) => (Array.isArray(v) ? v.join(",") : (v == null ? "" : String(v)));
  const allRecipients = [
    body.to, body.envelope?.to, body.recipient, body.cc, body.bcc,
    body["envelope-to"], body.delivered_to, body["delivered-to"],
  ].map(flat).join(",").toLowerCase();
  // Both address shapes must resolve — the new bare token AND the legacy import+ form.
  const candidates = new Set();
  for (const m of allRecipients.matchAll(/\+([a-z0-9]{10,})@/g)) candidates.add(m[1]);
  for (const m of allRecipients.matchAll(/(?:^|[,\s<])([a-z0-9]{10,})@/g)) candidates.add(m[1]);
  if (candidates.size === 0) return { status: 200, wrote: null, reason: "no token" };

  let user = null;
  for (const c of candidates) if (USERS[c]) { user = USERS[c]; break; }
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

// The one that was silently broken: a Gmail AUTO-FORWARD filter. The header `To:` is
// still the user's OWN address; the import address is only the envelope recipient. The
// old code read `body.to` first and never looked at envelope.to — so the automatic
// path, the one people set up once and rely on, failed every time while manual forwards
// worked. This is the case that most needs to pass, and the one no manual test finds.
allows("a Gmail AUTO-FORWARD (token only in the envelope, not the To: header)", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: {
    from: "united@united.com",
    to: "maddie@example.com",                                    // her own address
    envelope: { to: "import+a1b2c3d4e5f60718@wingmantravel.app" }, // token lives here
    text: "x".repeat(50),
  },
}), "maddie@example.com");

allows("...and a provider that only sets Delivered-To", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { from: "united@united.com", "delivered-to": "import+a1b2c3d4e5f60718@wingmantravel.app", text: "x".repeat(50) },
}), "maddie@example.com");

// ── The shorter address, and the promise not to orphan the old one ──────────
allows("the NEW short address (no import+ prefix)", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { from: "united@united.com", to: "k7m2xq9rt4vn@inbox.wingmantravel.app", text: "x".repeat(50) },
}), "maddie@example.com");

// Changing the address format must not silently kill an address someone already put
// into a mail-forwarding rule. That breaks ingestion weeks later, with no error anywhere.
allows("...and the LEGACY import+ address still resolves", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { from: "united@united.com", to: "import+a1b2c3d4e5f60718@inbox.wingmantravel.app", text: "x".repeat(50) },
}), "maddie@example.com");

refuses("a short address that matches no user", inbound({
  headers: { "x-wingman-inbound-secret": SECRET },
  body: { from: "x@y.com", to: "zzzzzzzzzzzz@inbox.wingmantravel.app", text: "x".repeat(50) },
}));

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
