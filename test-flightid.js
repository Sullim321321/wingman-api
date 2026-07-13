/**
 * test-flightid.js — the name and the key are different strings.
 *
 * Run: node test-flightid.js
 *
 * Every case below is a shape that is ACTUALLY in the database, written by one of the
 * three producers (email parser, Duffel, concierge WRITE action). The old code fed all
 * of them to FlightAware as `carrier + flight_number` and got a 404 every time.
 */

const assert = require("assert");
const fid = require("./flightid");

let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ✓ ${name}`); pass++; }
  catch (e) { console.log(`  ✗ ${name}\n      ${e.message}`); fail++; }
};

console.log("\nTHE BUG THAT WENT DARK\n");

t("the exact leg from the screenshot: 'Japan Airlines' + 'JL 623'", () => {
  const leg = { carrier: "Japan Airlines", flight_number: "JL 623" };
  // What the old code sent to AeroAPI:
  const old = (leg.carrier || "") + (leg.flight_number || "");
  assert.strictEqual(old, "Japan AirlinesJL 623");   // 404. Every time. Silently.

  assert.strictEqual(fid.apiKey(leg), "JL623");
  assert.strictEqual(fid.displayName(leg), "Japan Airlines JL 623");
});

t("Duffel's shape: name + code-jammed number, no space", () => {
  const leg = { carrier: "Japan Airlines", flight_number: "JL623" };
  assert.strictEqual(fid.apiKey(leg), "JL623");
  assert.strictEqual(fid.displayName(leg), "Japan Airlines JL 623");
});

t("the two producers disagree, and now they resolve to the SAME key", () => {
  const fromEmail  = { carrier: "Japan Airlines", flight_number: "JL 623" };
  const fromDuffel = { carrier: "Japan Airlines", flight_number: "JL623" };
  assert.strictEqual(fid.apiKey(fromEmail), fid.apiKey(fromDuffel));
});

console.log("\nSHAPES IN THE WILD\n");

t("code in the carrier field, bare number", () => {
  const leg = { carrier: "JL", flight_number: "623" };
  assert.strictEqual(fid.apiKey(leg), "JL623");
  // "JL" is a key, not a name. Don't print it as though it were an airline.
  assert.strictEqual(fid.displayName(leg), "JL 623");
});

t("leading zeros are stripped — UA0412 is UA412", () => {
  assert.strictEqual(fid.apiKey({ carrier: "United", flight_number: "UA0412" }), "UA412");
  assert.strictEqual(fid.apiKey({ carrier: "United Airlines", flight_number: "0412" }), "UA412");
});

t("numeric airline codes survive (B6, 9W)", () => {
  assert.strictEqual(fid.apiKey({ carrier: "JetBlue", flight_number: "B6 22" }), "B622");
  assert.strictEqual(fid.apiKey({ carrier: "jetBlue", flight_number: "22" }), "B622");
});

t("case and spacing in the airline name don't matter", () => {
  assert.strictEqual(fid.apiKey({ carrier: "BRITISH AIRWAYS", flight_number: "112" }), "BA112");
  assert.strictEqual(fid.apiKey({ carrier: "british airways", flight_number: "112" }), "BA112");
});

console.log("\nTHE REFUSAL — an absent key is not a wrong key\n");

t("an airline it doesn't recognise → null, and it SAYS why", () => {
  const leg = { carrier: "Hogwarts Air", flight_number: "42" };
  assert.strictEqual(fid.apiKey(leg), null);
  assert.ok(/don't recognise/i.test(fid.whyNoKey(leg)));
  // But it still renders something a person can read.
  assert.strictEqual(fid.displayName(leg), "Hogwarts Air #42");
});

t("no flight number at all → null, and it says so", () => {
  const leg = { carrier: "Amtrak", flight_number: null };
  assert.strictEqual(fid.apiKey(leg), null);
  assert.ok(/no flight number/i.test(fid.whyNoKey(leg)));
});

t("a hotel is not a flight and does not pretend to be one", () => {
  const leg = { type: "hotel", carrier: null, property_name: "Palace Hotel Tokyo" };
  assert.strictEqual(fid.apiKey(leg), null);
});

t("a valid key is never returned with a space in it", () => {
  const legs = [
    { carrier: "Japan Airlines", flight_number: "JL 623" },
    { carrier: "United Airlines", flight_number: "UA 0412" },
    { carrier: "JL", flight_number: " 623 " },
  ];
  for (const l of legs) {
    const k = fid.apiKey(l);
    assert.ok(k && !/\s/.test(k), `key "${k}" has whitespace — AeroAPI will 404`);
    assert.ok(/^[A-Z0-9]{2}\d{1,4}$/.test(k), `key "${k}" is not a valid ident`);
  }
});

t("a display name is never a mangled join", () => {
  const n = fid.displayName({ carrier: "Japan Airlines", flight_number: "JL623" });
  assert.ok(!/AirlinesJL/.test(n), `"${n}" — the exact string on the screenshot`);
});

console.log("\nTHE TWIN — two copies that can disagree are the same bug in a new costume\n");

// The app carries a copy of this module (ESM exports instead of CommonJS). If the two
// drift, the name the app renders and the key the server looks up stop agreeing — which
// is exactly the failure this file was written to kill, reintroduced by the fix for it.
//
// This check is skipped when the app repo isn't a sibling folder, and it SAYS it was
// skipped. A check that silently passes when it couldn't run is worse than no check —
// that is the lesson of this entire bug.
t("the app's copy has not drifted from this one", () => {
  const fs = require("fs");
  const path = require("path");
  const twin = path.join(__dirname, "..", "wingman-app", "src", "flightid.js");
  if (!fs.existsSync(twin)) {
    console.log("      (skipped — wingman-app isn't a sibling folder here)");
    return;
  }
  const strip = (s) =>
    s.replace(/^[\s\S]*?(?=\/\*\*\n \* flightid\.js)/, "")   // drop the app's banner
     .replace(/^(module\.exports = |export )\{[^}]*\};?\s*$/m, "")
     .trim();
  const mine  = strip(fs.readFileSync(path.join(__dirname, "flightid.js"), "utf8"));
  const theirs = strip(fs.readFileSync(twin, "utf8"));
  assert.strictEqual(theirs, mine,
    "wingman-app/src/flightid.js has drifted. Re-copy it, or the two will disagree about what a flight is called.");
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
