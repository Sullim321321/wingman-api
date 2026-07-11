#!/usr/bin/env node
/**
 * smoke-test.js — hit every safe endpoint once and flag anything that 500s.
 *
 * Every bug we found by hand (req.user never set, phantom activity_log table,
 * missing property_name column, dead cascade routes) shared one signature: the
 * endpoint threw a 500 the moment it was actually called. Nothing ever called
 * them. This does.
 *
 *   USAGE:
 *     node smoke-test.js
 *
 *   It signs you in exactly the way the app does — emails you a 6-digit code,
 *   you type it in, the SERVER mints the token. That means the token is always
 *   signed with the secret the server is actually running, so it can never
 *   mismatch. You never need to touch JWT_SECRET, and no secret ever lands on
 *   your laptop or in your shell history.
 *
 * SAFETY: GET requests only. Nothing here writes, books, charges, or deletes.
 */

const readline = require("readline");

// Must match src/config.js in the app. A wrong host makes EVERY route 404, which
// looks like "all endpoints broken" when really you're just talking to nobody.
const API = process.env.API || "https://wingman-api-y39a.onrender.com";
// This must be an account with REAL DATA. /auth/verify creates the user if it
// doesn't exist, so signing in with the wrong address silently mints an empty
// account and every endpoint returns a cheerful 200 over nothing. See the
// zero-data guard below.
const DEFAULT_EMAIL = process.env.EMAIL || "sullim321@gmail.com";

const RESET = "\x1b[0m", RED = "\x1b[31m", GREEN = "\x1b[32m", YELLOW = "\x1b[33m", DIM = "\x1b[2m", BOLD = "\x1b[1m";

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (a) => { rl.close(); resolve(a.trim()); }));
}

async function post(path, body) {
  const r = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, text };
}

/**
 * Sign in the same way the app does: request an emailed code, verify it, get a
 * server-signed token back. No JWT_SECRET anywhere.
 */
async function login() {
  const email = (await ask(`  Email ${DIM}[${DEFAULT_EMAIL}]${RESET}: `)) || DEFAULT_EMAIL;

  const req = await post("/auth/request", { email });
  if (req.status !== 200) {
    console.log(`\n  ${RED}✗ Couldn't send the code (${req.status}): ${req.text.slice(0, 120)}${RESET}\n`);
    process.exit(1);
  }
  console.log(`  ${GREEN}✓${RESET} Code sent to ${email}. Check your inbox.\n`);

  const code = await ask("  6-digit code: ");
  const ver = await post("/auth/verify", { email, code });
  if (ver.status !== 200 || !ver.json?.token) {
    console.log(`\n  ${RED}✗ Sign-in failed (${ver.status}): ${ver.text.slice(0, 120)}${RESET}`);
    console.log(`  ${DIM}Codes expire after 10 minutes.${RESET}\n`);
    process.exit(1);
  }
  console.log(`  ${GREEN}✓${RESET} Signed in.\n`);
  return ver.json.token;
}

// Endpoints that need a real id are filled in from live data below.
const STATIC_GETS = [
  "/me",
  "/trips",
  "/activity",
  "/decisions",
  "/insights/roi",
  "/insights/roi/history?months=12",
  "/onboarding/summary",
  "/policy",
  "/profile/passenger",
  "/subscription/plans",
  "/loyalty",
  "/points",
  "/me/travel-profile",       // NOT /travel-profile — that route doesn't exist

  "/me/memory",
  "/today-events",
  "/me/data-export",          // was broken: phantom activity_log table
  "/destination/image?city=Paris",
];

const withTripId = (id) => [
  // No /risk-profile here: that route never existed server-side. api.js had a
  // getTripRiskProfile() calling it, but nothing called that — dead code, deleted.
  `/trips/${id}/checklist`,
  `/trips/${id}/companions`,
  `/trips/${id}/standing-order`,   // Roadmap 2
];

async function hit(path, token) {
  const started = Date.now();
  try {
    const r = await fetch(API + path, { headers: { Authorization: `Bearer ${token}` } });
    const ms = Date.now() - started;
    let detail = "";
    if (r.status >= 400) {
      const body = await r.text().catch(() => "");
      detail = body.slice(0, 140).replace(/\s+/g, " ");
    }
    return { path, status: r.status, ms, detail };
  } catch (e) {
    return { path, status: 0, ms: Date.now() - started, detail: e.message };
  }
}

(async () => {
  console.log(`\n  ${BOLD}Smoke-testing${RESET} ${API}\n`);

  const token = process.env.TOKEN || (await login());

  // Sanity: if /me doesn't resolve, we're talking to the wrong host. Without this
  // check, every route 404s and the script cheerfully reports "no 500s" — a false
  // all-clear, which is worse than no test at all.
  const probe = await hit("/me", token);
  if (probe.status === 404 || probe.status === 0) {
    console.log(`  ${RED}✗ /me returned ${probe.status || "no response"} — the API URL is almost certainly wrong.${RESET}`);
    console.log(`    Trying: ${API}`);
    console.log(`    Check API_BASE in wingman-app/src/config.js and pass it:`);
    console.log(`    ${DIM}API="https://<your-host>" node smoke-test.js${RESET}\n`);
    process.exit(1);
  }
  if (probe.status === 401) {
    console.log(`  ${RED}✗ /me returned 401 even after signing in — that shouldn't be possible.${RESET}\n`);
    process.exit(1);
  }

  // Pull a real trip id so the :tripId routes are exercised for real.
  // ?all=true is essential: /trips defaults to upcoming-only, so with no future
  // travel booked it returns [] and we'd silently skip every per-trip route —
  // exactly the endpoints most likely to be broken.
  let tripId = null;
  try {
    const r = await fetch(`${API}/trips?all=true`, { headers: { Authorization: `Bearer ${token}` } });
    const d = await r.json();
    tripId = d?.trips?.[0]?.id ?? null;
  } catch {}

  // A zero-trip account is not a passing test — it's an untested one. /auth/verify
  // creates users on demand, so a typo'd email mints an empty account and every
  // endpoint returns 200 over nothing at all. That reads as sixteen green lines
  // and tests approximately zero code. Refuse to continue.
  if (!tripId) {
    console.log(`  ${RED}✗ This account has no trips — even with ?all=true.${RESET}`);
    console.log(`    That means the per-trip endpoints can't be tested, and a green run here`);
    console.log(`    would be meaningless. It usually means you signed in as the wrong account`);
    console.log(`    (sign-in CREATES the user if it doesn't exist, so typos look like success).`);
    console.log(`\n    Re-run with the account that actually has your travel data:`);
    console.log(`    ${DIM}EMAIL="you@example.com" node smoke-test.js${RESET}\n`);
    process.exit(1);
  }

  const paths = [...STATIC_GETS, ...withTripId(tripId)];

  const results = [];
  for (const p of paths) results.push(await hit(p, token));

  const fails    = results.filter(r => r.status >= 500 || r.status === 0);
  const auth     = results.filter(r => r.status === 401 || r.status === 403);
  const notfound = results.filter(r => r.status === 404);
  const ok       = results.filter(r => r.status >= 200 && r.status < 400);

  for (const r of results) {
    const bad = r.status >= 500 || r.status === 0;
    const colour = bad ? RED : r.status >= 400 ? YELLOW : GREEN;
    const code = r.status === 0 ? "ERR" : r.status;
    console.log(`  ${colour}${String(code).padEnd(4)}${RESET} ${r.path.padEnd(42)} ${DIM}${r.ms}ms${RESET}${r.detail ? `\n       ${DIM}${r.detail}${RESET}` : ""}`);
  }

  console.log(`\n  ${GREEN}${ok.length} ok${RESET} · ${YELLOW}${notfound.length} 404${RESET} · ${YELLOW}${auth.length} auth${RESET} · ${RED}${fails.length} failing${RESET}\n`);

  if (fails.length) {
    console.log(`  ${RED}These are throwing server-side — the exact signature of every bug we found by hand:${RESET}`);
    for (const f of fails) console.log(`    ${f.path}  →  ${f.detail || f.status}`);
    console.log("");
    process.exit(1);
  }
  console.log(`  ${GREEN}No 500s. Every endpoint tested actually runs.${RESET}\n`);
})();
