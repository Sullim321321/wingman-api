#!/usr/bin/env node
/**
 * repair-trips.js — split trips that swallowed unrelated travel.
 *
 * A hotel booking parsed with the wrong check-out year produced legs spanning
 * hundreds of days ("11 Howard · 266 nights"). Such a leg overlaps every date
 * window, so every later booking to the same city matched it and was absorbed.
 * One "New York" trip ended up holding a year of unrelated flights.
 *
 * This shows you exactly what it WOULD change, waits for you to say yes, and only
 * then writes. Nothing is destroyed: legs are moved, never deleted, and the
 * earliest cluster keeps the original trip id (so ratings and standing orders
 * survive).
 *
 *   node repair-trips.js
 *
 * Signs you in the same way the app does — an emailed code. No JWT_SECRET needed.
 */

const readline = require("readline");

const API = process.env.API || "https://wingman-api-y39a.onrender.com";
const DEFAULT_EMAIL = process.env.EMAIL || "sullim321@gmail.com";

const R = "\x1b[0m", RED = "\x1b[31m", GRN = "\x1b[32m", YEL = "\x1b[33m", DIM = "\x1b[2m", B = "\x1b[1m";

function ask(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(r => rl.question(q, a => { rl.close(); r(a.trim()); }));
}

async function post(path, body, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(API + path, { method: "POST", headers, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, text };
}

async function login() {
  const email = (await ask(`  Email ${DIM}[${DEFAULT_EMAIL}]${R}: `)) || DEFAULT_EMAIL;
  const req = await post("/auth/request", { email });
  if (req.status !== 200) {
    console.log(`\n  ${RED}✗ Couldn't send the code (${req.status})${R}\n`);
    process.exit(1);
  }
  console.log(`  ${GRN}✓${R} Code sent to ${email}.\n`);
  const code = await ask("  6-digit code: ");
  const ver = await post("/auth/verify", { email, code });
  if (ver.status !== 200 || !ver.json?.token) {
    console.log(`\n  ${RED}✗ Sign-in failed (${ver.status})${R}\n`);
    process.exit(1);
  }
  console.log(`  ${GRN}✓${R} Signed in.\n`);
  return ver.json.token;
}

function printReport(rep) {
  console.log(`  ${B}Poison legs (bad check-out year):${R} ${rep.legsDatesFixed}`);
  console.log(`  ${B}Trips to split:${R}                   ${rep.tripsSplit}`);
  console.log(`  ${B}New trips created:${R}                ${rep.tripsCreated}`);
  console.log(`  ${B}Undated legs → Needs review:${R}      ${rep.legsOrphaned}\n`);
  if (rep.details?.length) {
    for (const d of rep.details) {
      console.log(d.startsWith("  ") ? `    ${DIM}${d.trim()}${R}` : `  ${YEL}•${R} ${d}`);
    }
    console.log("");
  }
}

(async () => {
  console.log(`\n  ${B}Trip repair${R} — ${API}\n`);
  const token = await login();

  console.log(`  ${B}DRY RUN${R} ${DIM}(nothing is being changed yet)${R}\n`);
  const dry = await post("/admin/unmerge-trips", null, token);
  if (dry.status !== 200) {
    console.log(`  ${RED}✗ ${dry.status}: ${dry.text.slice(0, 200)}${R}\n`);
    process.exit(1);
  }
  printReport(dry.json);

  if (!dry.json.tripsSplit && !dry.json.legsDatesFixed) {
    console.log(`  ${GRN}Nothing to repair.${R}\n`);
    return;
  }

  const ok = await ask(`  Apply these changes? ${DIM}(yes/no)${R} `);
  if (ok.toLowerCase() !== "yes") {
    console.log(`\n  Nothing changed.\n`);
    return;
  }

  const live = await post("/admin/unmerge-trips?apply=true", null, token);
  if (live.status !== 200) {
    console.log(`\n  ${RED}✗ ${live.status}: ${live.text.slice(0, 200)}${R}\n`);
    process.exit(1);
  }
  console.log(`\n  ${GRN}✓ Split.${R}`);

  // ── Second pass: re-join anything a booking says belongs together ────────────
  // Splitting on date gaps alone tears a round trip in half: the return leg on the
  // same confirmation can easily sit 10+ days after the outbound. A shared
  // confirmation number is the strongest signal there is, and it OVERRIDES the date
  // heuristic. cleanup-trips merges trips that share one, so we always run it after
  // a split — split, then reconcile.
  const merge = await post("/admin/cleanup-trips?apply=true", null, token);
  if (merge.status === 200 && merge.json) {
    const m = merge.json.tripsMerged || 0;
    console.log(`  ${GRN}✓ Reconciled${R} — ${m} trip(s) re-joined on a shared confirmation number.`);
  } else {
    console.log(`  ${YEL}! cleanup-trips returned ${merge.status} — round trips may still be split.${R}`);
  }

  console.log(`\n  ${GRN}Done.${R} Run ${B}node smoke-test.js${R} to confirm the invariants hold.\n`);
})();
