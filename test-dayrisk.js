// test-dayrisk.js — the "what could ruin my day" core.
//   node test-dayrisk.js
const assert = require("assert");
const { assessDay, tightConnections, weatherRisk } = require("./dayrisk");

let pass = 0, fail = 0;
const t = (name, fn) => { try { fn(); pass++; } catch (e) { fail++; console.log(`\x1b[31m✗\x1b[0m ${name}\n   ${e.message}`); } };

const F = (dep, arr, extra = {}) => ({ departs_at: dep, arrives_at: arr, ...extra });

// tight connections
t("a comfortable connection raises nothing", () => {
  const r = tightConnections([
    F("2026-08-10T12:00:00Z", "2026-08-10T13:30:00Z", { destination: "ORD" }),
    F("2026-08-10T15:30:00Z", "2026-08-10T17:00:00Z"), // 2h layover
  ], 45);
  assert.strictEqual(r.length, 0);
});
t("a 30-min layover under 45-min comfort is medium", () => {
  const r = tightConnections([
    F("2026-08-10T12:00:00Z", "2026-08-10T13:30:00Z", { destination: "ORD" }),
    F("2026-08-10T14:00:00Z", "2026-08-10T15:30:00Z", { carrier: "United", flight_number: "UA100" }),
  ], 45);
  assert.strictEqual(r.length, 1);
  assert.strictEqual(r[0].severity, "medium");
  assert.ok(/UA100/.test(r[0].why) && /ORD/.test(r[0].why));
});
t("a 15-min layover (< half comfort) is high", () => {
  const r = tightConnections([
    F("2026-08-10T12:00:00Z", "2026-08-10T13:30:00Z"),
    F("2026-08-10T13:45:00Z", "2026-08-10T15:00:00Z"),
  ], 45);
  assert.strictEqual(r[0].severity, "high");
});
t("a 10-hour gap is not a connection", () => {
  const r = tightConnections([
    F("2026-08-10T06:00:00Z", "2026-08-10T07:30:00Z"),
    F("2026-08-10T18:00:00Z", "2026-08-10T19:30:00Z"),
  ], 45);
  assert.strictEqual(r.length, 0);
});

// weather
t("null weather is UNKNOWN, not calm", () => {
  const r = weatherRisk(null, "PIT");
  assert.strictEqual(r[0].severity, "unknown");
  assert.ok(/PIT/.test(r[0].why));
});
t("a clear day raises nothing", () => {
  assert.strictEqual(weatherRisk({ condition: "Clear sky" }).length, 0);
});
t("a snowstorm is a high weather risk", () => {
  const r = weatherRisk({ condition: "Heavy snow" }, "ORD");
  assert.strictEqual(r[0].severity, "high");
  assert.ok(/snow/i.test(r[0].why));
});

// assessment + ranking
t("assessDay ranks high above unknown", () => {
  const risks = assessDay({
    flights: [
      F("2026-08-10T12:00:00Z", "2026-08-10T13:30:00Z"),
      F("2026-08-10T13:40:00Z", "2026-08-10T15:00:00Z"), // 10 min → high tight connection
    ],
    weather: null, // unknown
    minConnMins: 45,
  });
  assert.strictEqual(risks[0].severity, "high");
  assert.strictEqual(risks[risks.length - 1].severity, "unknown");
});
t("a clean day with known-good weather has no risks", () => {
  const risks = assessDay({
    flights: [F("2026-08-10T12:00:00Z", "2026-08-10T13:30:00Z")],
    weather: { condition: "Sunny" },
  });
  assert.strictEqual(risks.length, 0);
});

// bags (I2) — honest risk, never a status claim
const { bagRisk } = require("./dayrisk");
t("a high tight connection raises a checked-bag caution", () => {
  const risks = assessDay({
    flights: [
      F("2026-08-10T12:00:00Z", "2026-08-10T13:30:00Z"),
      F("2026-08-10T13:40:00Z", "2026-08-10T15:00:00Z"), // 10 min → high
    ],
    minConnMins: 45,
  });
  assert.ok(risks.some((r) => r.kind === "bag"));
  assert.ok(risks.some((r) => r.kind === "bag" && /checked bag/i.test(r.why) && !/where your bag/i.test(r.why)));
});
t("a merely-medium connection raises no bag caution", () => {
  assert.strictEqual(bagRisk([{ kind: "tight_connection", severity: "medium" }]).length, 0);
});
t("no connection → no bag risk", () => assert.strictEqual(bagRisk([]).length, 0));

console.log("\n" + "─".repeat(58));
console.log(fail ? `\x1b[31m${fail} FAILED\x1b[0m, ${pass} passed` : `\x1b[32mall ${pass} passed\x1b[0m`);
process.exit(fail ? 1 : 0);
