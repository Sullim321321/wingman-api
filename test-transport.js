// test-transport.js — a movement leg knows its mode, whether it's watchable, and how to speak.
const assert = require("assert");
const {
  modeOf, isTransportLeg, endpointsOf, hasEndpoints, isWatchable, vocab, displayName,
  networkOf, railNarrative,
} = require("./transport");

let pass = 0, fail = 0;
const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", x = "\x1b[0m";
const t = (n, fn) => { try { fn(); console.log(`  ${g}✓${x} ${n}`); pass++; } catch (e) { console.log(`  ${r}✗ ${n}${x}\n    ${e.message}`); fail++; } };

const dep = "2026-08-01T09:00:00Z", arr = "2026-08-01T13:30:00Z";
const air = (o = {}) => ({ type: "flight", origin: "EDI", destination: "LHR", carrier: "British Airways", flight_number: "BA 1447", departs_at: dep, arrives_at: arr, ...o });
const rail = (o = {}) => ({ type: "train", station_from: "Edinburgh", station_to: "London Kings Cross", carrier: "LNER", flight_number: "1E12", departs_at: dep, arrives_at: arr, ...o });

// ── modeOf / isTransportLeg ──
t("modeOf: flight → air", () => assert.strictEqual(modeOf(air()), "air"));
t("modeOf: train → rail", () => assert.strictEqual(modeOf(rail()), "rail"));
t("modeOf: hotel → null (not a movement)", () => assert.strictEqual(modeOf({ type: "hotel" }), null));
t("modeOf: ferry → null (reserved, not wired)", () => assert.strictEqual(modeOf({ type: "ferry" }), null));
t("modeOf: null leg → null", () => assert.strictEqual(modeOf(null), null));
t("isTransportLeg: a train is transport", () => assert.strictEqual(isTransportLeg(rail()), true));
t("isTransportLeg: a hotel is not", () => assert.strictEqual(isTransportLeg({ type: "hotel" }), false));

// ── endpointsOf / hasEndpoints ──
t("endpointsOf: air reads origin/destination", () => assert.deepStrictEqual(endpointsOf(air()), { from: "EDI", to: "LHR" }));
t("endpointsOf: rail reads station_from/station_to", () => assert.deepStrictEqual(endpointsOf(rail()), { from: "Edinburgh", to: "London Kings Cross" }));
t("endpointsOf: rail falls back to origin/destination if stations absent", () => {
  assert.deepStrictEqual(endpointsOf({ type: "train", origin: "York", destination: "Leeds", departs_at: dep }), { from: "York", to: "Leeds" });
});
t("hasEndpoints: a routeless train → false", () => assert.strictEqual(hasEndpoints({ type: "train", departs_at: dep }), false));

// ── isWatchable (the mode-generalized spine guard) ──
t("watchable: a sound flight → yes", () => assert.strictEqual(isWatchable(air()), true));
t("watchable: a sound train → yes (the whole point)", () => assert.strictEqual(isWatchable(rail()), true));
t("watchable: a hotel → no", () => assert.strictEqual(isWatchable({ type: "hotel", departs_at: dep }), false));
t("watchable: a ferry → no (reserved mode, not yet watched)", () => assert.strictEqual(isWatchable({ type: "ferry", origin: "A", destination: "B", departs_at: dep }), false));
t("watchable: routeless train → no", () => assert.strictEqual(isWatchable(rail({ station_from: null, station_to: null })), false));
t("watchable: epoch departure → no", () => assert.strictEqual(isWatchable(rail({ departs_at: "1970-01-01T00:00:00Z" })), false));
t("watchable: arrives before departs → no", () => assert.strictEqual(isWatchable(rail({ arrives_at: "2026-08-01T06:00:00Z" })), false));
t("watchable: missing arrival only → still yes", () => assert.strictEqual(isWatchable(rail({ arrives_at: null })), true));

// ── vocab ──
t("vocab(air): gate / airport / terminal / flight", () => {
  const v = vocab("air");
  assert.strictEqual(v.node, "gate"); assert.strictEqual(v.hub, "airport");
  assert.strictEqual(v.terminal, "terminal"); assert.strictEqual(v.vehicle, "flight");
});
t("vocab(rail): platform / station / no terminal / train", () => {
  const v = vocab("rail");
  assert.strictEqual(v.node, "platform"); assert.strictEqual(v.hub, "station");
  assert.strictEqual(v.terminal, null); assert.strictEqual(v.vehicle, "train");
});
t("vocab(unknown): falls back to air (safe default)", () => assert.strictEqual(vocab("spaceship").node, "gate"));

// ── displayName ──
t("displayName: air delegates to flightid → 'British Airways BA 1447'", () => assert.strictEqual(displayName(air()), "British Airways BA 1447"));
t("displayName: rail names operator + service → 'LNER 1E12'", () => assert.strictEqual(displayName(rail()), "LNER 1E12"));
t("displayName: rail with no operator falls back to route", () => assert.strictEqual(displayName(rail({ carrier: null, flight_number: null })), "Edinburgh → London Kings Cross"));

// ── networkOf (who do we ask about a delay — or can we?) ──
t("networkOf: LNER → uk_nr", () => assert.strictEqual(networkOf(rail()), "uk_nr"));
t("networkOf: Avanti West Coast → uk_nr", () => assert.strictEqual(networkOf(rail({ carrier: "Avanti West Coast" })), "uk_nr"));
t("networkOf: Amtrak → amtrak", () => assert.strictEqual(networkOf(rail({ carrier: "Amtrak" })), "amtrak"));
t("networkOf: Acela → amtrak", () => assert.strictEqual(networkOf(rail({ carrier: "Amtrak Acela" })), "amtrak"));
t("networkOf: unrecognised operator → null (watch nothing, don't guess)", () => assert.strictEqual(networkOf(rail({ carrier: "SNCF" })), null));
t("networkOf: a flight → null", () => assert.strictEqual(networkOf(air()), null));

// ── railNarrative (the pure rail disruption decision, in rail vocab) ──
t("railNarrative: no reading → null", () => assert.strictEqual(railNarrative(rail(), null, "Scheduled"), null));
t("railNarrative: unchanged status → null", () => assert.strictEqual(railNarrative(rail(), { status: "On Time" }, "On Time"), null));
t("railNarrative: cancelled → push + cascade, speaks 'train' not 'flight'", () => {
  const n = railNarrative(rail(), { status: "Cancelled" }, "On Time");
  assert.strictEqual(n.newStatus, "Cancelled");
  assert.ok(/cancelled/i.test(n.push.title));
  assert.ok(/train/i.test(n.activity.body));
  assert.deepStrictEqual(n.cascade, { kind: "cancelled", delayMins: 0 });
});
t("railNarrative: delayed 75m → cascade fires (>=60), platform surfaced", () => {
  const n = railNarrative(rail(), { status: "Delayed", delayMins: 75, platform: "4" }, "On Time");
  assert.ok(/75m/.test(n.push.title));
  assert.ok(/Platform 4/.test(n.push.body));
  assert.strictEqual(n.cascade.kind, "delayed");
  assert.strictEqual(n.reTimeArrival, true);
});
t("railNarrative: delayed 20m → no cascade (<60), but re-time leave-by", () => {
  const n = railNarrative(rail(), { status: "Delayed", delayMins: 20 }, "On Time");
  assert.strictEqual(n.cascade, null);
  assert.strictEqual(n.reTimeArrival, true);
});
t("railNarrative: recovery to On Time from Delayed → recovery push", () => {
  const n = railNarrative(rail(), { status: "On Time" }, "Delayed");
  assert.strictEqual(n.activity.type, "recovery");
});
t("railNarrative: 'No services' reading → logged, NEVER a fake reassurance push", () => {
  const n = railNarrative(rail(), { status: "No services" }, "Scheduled");
  assert.strictEqual(n.push, null);
  assert.strictEqual(n.activity.type, "status");
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
