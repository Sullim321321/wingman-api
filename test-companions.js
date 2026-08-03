// test-companions.js — the multi-traveler reasoning core.
//   node test-companions.js
const assert = require("assert");
const {
  normalizeTravelers, isShared, travelersForLeg, legsForTraveler,
  perTravelerItinerary, validateAssignment,
} = require("./companions");

let pass = 0, fail = 0;
const t = (name, fn) => { try { fn(); pass++; } catch (e) { fail++; console.log(`\x1b[31m✗\x1b[0m ${name}\n   ${e.message}`); } };

const TRAVELERS = [
  { id: "maddie", name: "Maddie", role: "owner" },
  { email: "sam@x.com", name: "Sam" },
];

// normalize
t("normalize dedupes by id/email and fills name", () => {
  const n = normalizeTravelers([{ id: "A", name: "Alpha" }, { id: "a" }, { email: "B@x.com" }]);
  assert.strictEqual(n.length, 2);
  assert.strictEqual(n[0].name, "Alpha");
  assert.strictEqual(n[1].id, "b@x.com");
});
t("normalize drops empties", () => assert.strictEqual(normalizeTravelers([null, {}, { name: "x" }]).length, 0));

// shared vs subset
t("a leg with no traveler_ids is shared", () => assert.strictEqual(isShared({ type: "flight" }), true));
t("a leg with an empty traveler_ids is shared", () => assert.strictEqual(isShared({ traveler_ids: [] }), true));
t("a leg naming a subset is not shared", () => assert.strictEqual(isShared({ traveler_ids: ["sam@x.com"] }), false));

// travelersForLeg
t("shared flight applies to everyone", () => {
  assert.deepStrictEqual(travelersForLeg({ type: "flight" }, TRAVELERS).sort(), ["maddie", "sam@x.com"]);
});
t("subset hotel applies only to the named traveler", () => {
  assert.deepStrictEqual(travelersForLeg({ type: "hotel", traveler_ids: ["Sam@X.com"] }, TRAVELERS), ["sam@x.com"]);
});
t("unknown ids are dropped, not invented", () => {
  // only 'maddie' is real here; 'ghost' is dropped → resolves to just maddie
  assert.deepStrictEqual(travelersForLeg({ traveler_ids: ["maddie", "ghost"] }, TRAVELERS), ["maddie"]);
});
t("an all-unknown subset falls back to shared (never nobody)", () => {
  assert.deepStrictEqual(travelersForLeg({ traveler_ids: ["ghost"] }, TRAVELERS).sort(), ["maddie", "sam@x.com"]);
});

// legsForTraveler — "two rooms, one shared flight"
const LEGS = [
  { id: 1, type: "flight" },                                   // shared
  { id: 2, type: "hotel", traveler_ids: ["maddie"] },          // Maddie's room
  { id: 3, type: "hotel", traveler_ids: ["sam@x.com"] },       // Sam's room
];
t("Maddie sees the shared flight + her room, not Sam's", () => {
  assert.deepStrictEqual(legsForTraveler("maddie", LEGS, TRAVELERS).map((l) => l.id), [1, 2]);
});
t("Sam sees the shared flight + his room, not Maddie's", () => {
  assert.deepStrictEqual(legsForTraveler("sam@x.com", LEGS, TRAVELERS).map((l) => l.id), [1, 3]);
});

// perTravelerItinerary
t("per-traveler breakdown counts shared vs solo", () => {
  const it = perTravelerItinerary(TRAVELERS, LEGS);
  const maddie = it.find((x) => x.traveler.id === "maddie");
  assert.strictEqual(maddie.legs.length, 2);
  assert.strictEqual(maddie.sharedCount, 1);
  assert.strictEqual(maddie.soloCount, 1);
});

// validateAssignment
t("validateAssignment separates known from unknown ids", () => {
  const r = validateAssignment(["maddie", "ghost", "SAM@x.com"], TRAVELERS);
  assert.deepStrictEqual(r.valid.sort(), ["maddie", "sam@x.com"]);
  assert.deepStrictEqual(r.unknown, ["ghost"]);
});

console.log("\n" + "─".repeat(58));
console.log(fail ? `\x1b[31m${fail} FAILED\x1b[0m, ${pass} passed` : `\x1b[32mall ${pass} passed\x1b[0m`);
process.exit(fail ? 1 : 0);
