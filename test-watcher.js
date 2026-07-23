#!/usr/bin/env node
// test-watcher.js — an unattended actor must not overreach.
//
//   node test-watcher.js
//
// The whole risk of 5d is the same sentence in three forms: it acts while you're not
// looking. So the tests are the backstops — never spend real money on its own, never
// double-act, never cascade past the cap — plus the ordinary "hold means hold".

const assert = require("assert");
const { planRun } = require("./watcher");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", x = "\x1b[0m";
let pass = 0, fail = 0;
const t = (name, fn) => {
  try { fn(); console.log(`  ${g}✓${x} ${name}`); pass++; }
  catch (e) { console.log(`  ${r}✗${x} ${name}\n      ${e.message}`); fail++; }
};

const offer = { id: "o1", price: 210, currency: "USD" };
const book  = (key) => ({ key, decision: { action: "book", offer, reason: "within your rules" } });
const hold  = (key) => ({ key, decision: { action: "hold", offer, reason: "holding" } });
const suggest = (key) => ({ key, decision: { action: "suggest", offer, reason: "fyi" } });
const watch = (key) => ({ key, decision: { action: "watch", offer: null } });

console.log(`\n${b}The money backstop${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("test mode may auto-BOOK (no charge, no seat)", () => {
  const { actions } = planRun({ items: [book("a")], liveMoney: false });
  assert.strictEqual(actions[0].action, "book");
  assert.strictEqual(actions[0].downgraded, false);
});

t("live money DOWNGRADES a book to a hold — never auto-spends", () => {
  const { actions } = planRun({ items: [book("a")], liveMoney: true });
  assert.strictEqual(actions[0].action, "hold", "it auto-booked with real money");
  assert.strictEqual(actions[0].downgraded, true);
  assert.ok(/confirmation/.test(actions[0].reason));
});

console.log(`\n${b}Never double-act, never cascade${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("an item already acted on is skipped", () => {
  const { actions, skipped } = planRun({ items: [book("a")], actedKeys: ["a"] });
  assert.strictEqual(actions.length, 0);
  assert.ok(skipped.some((s) => s.key === "a" && /already/.test(s.why)));
});

t("the per-run cap holds", () => {
  const items = [book("a"), book("b"), book("c"), book("d"), book("e")];
  const { actions, skipped } = planRun({ items, maxActions: 3 });
  assert.strictEqual(actions.length, 3, "cap exceeded");
  assert.strictEqual(skipped.filter((s) => /cap/.test(s.why)).length, 2);
});

console.log(`\n${b}hold means hold; watch/suggest touch nothing${x}`);
console.log(`${d}──────────────────────────────────────────────────────────${x}`);

t("a hold decision produces a hold action", () => {
  assert.strictEqual(planRun({ items: [hold("a")] }).actions[0].action, "hold");
});

t("suggest and watch are never executed", () => {
  const { actions } = planRun({ items: [suggest("a"), watch("b")] });
  assert.strictEqual(actions.length, 0);
});

t("a book with no offer is not executed", () => {
  const { actions } = planRun({ items: [{ key: "a", decision: { action: "book", offer: null } }] });
  assert.strictEqual(actions.length, 0);
});

console.log(`\n${d}──────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
