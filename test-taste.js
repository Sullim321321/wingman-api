#!/usr/bin/env node
// test-taste.js — the brief reflects what you actually did, and admits what it doesn't know.
//
//   node test-taste.js

const assert = require("assert");
const { assembleBrief } = require("./taste");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const src = {
  hotelAffinity: [
    { property_name: "Kimpton Gray", brand: "Kimpton", city: "Chicago", stay_count: 3 },
    { property_name: "Kimpton Aertson", brand: "Kimpton", city: "Nashville", stay_count: 5 },
    { property_name: "The Hoxton", brand: "Hoxton", city: "London", stay_count: 1 },
  ],
  restaurantAffinity: [
    { restaurant_name: "Elske", cuisine: "New American", city: "Chicago", visit_count: 2 },
    { restaurant_name: "Kumiko", cuisine: "cocktails", city: "Chicago", visit_count: 1 },
  ],
  prefs: { dietary: ["vegetarian", "vegan"], cabin_preference: "business", price_tier: "premium",
           loved_cuisines: ["omakase", "natural wine"], dining_notes: "counter seats, quiet enough to talk" },
  sources: ["NYT 36 Hours", "Service 95", "Hotels Above Par", "Service 95"],
};

console.log(`\n${b}The brief reflects your real history${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("hotels rank by how often you returned", () => {
  const brief = assembleBrief(src);
  assert.strictEqual(brief.hotels.favorites[0].name, "Kimpton Aertson"); // 5 stays first
  assert.deepStrictEqual(brief.hotels.brands.slice(0, 2), ["Kimpton", "Hoxton"]);
});

t("dietary lines carry through", () => {
  assert.deepStrictEqual(assembleBrief(src).dining.dietary, ["vegetarian", "vegan"]);
});

t("cuisines come from your restaurants", () => {
  assert.ok(assembleBrief(src).dining.cuisines.includes("New American"));
});

t("loved cuisines and free-text dining notes carry through", () => {
  const brief = assembleBrief(src);
  assert.ok(brief.dining.loved.includes("omakase"));
  assert.strictEqual(brief.dining.notes, "counter seats, quiet enough to talk");
});

t("sources are deduped", () => {
  const brief = assembleBrief(src);
  assert.strictEqual(brief.sources.filter((s) => s === "Service 95").length, 1);
});

t("cabin and tier pass through", () => {
  const brief = assembleBrief(src);
  assert.strictEqual(brief.cabin, "business");
  assert.strictEqual(brief.price_tier, "premium");
});

console.log(`\n${b}It admits what it doesn't know${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("no history + no sources → known:false, empty brief", () => {
  const brief = assembleBrief({});
  assert.strictEqual(brief.known, false);
  assert.deepStrictEqual(brief.hotels.brands, []);
  assert.deepStrictEqual(brief.dining.dietary, []);
});

t("just one named source is enough to be 'known'", () => {
  assert.strictEqual(assembleBrief({ sources: ["Service 95"] }).known, true);
});

t("home bases default to New York and London when unset", () => {
  assert.deepStrictEqual(assembleBrief({}).home_bases, ["New York", "London"]);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
