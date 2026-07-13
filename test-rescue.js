#!/usr/bin/env node
// test-rescue.js — "ranked by what they protect, not by price."
//
//   node test-rescue.js
//
// The scenario is Maddie's, from the real transcript. JL 623 to Tokyo is delayed.
// Downstream: a seaplane transfer with 40 minutes of measured slack, and the Palace
// Hotel — which she chose over Aman for one reason, the cold plunge, because there is
// a 5K time trial eight weeks out.
//
// Three real alternatives. The cheapest one strands her.
//
// The old code asked Duffel for offers with sort:"total_amount" and took the first.
// This test is the proof that we no longer do that.

const rescue = require("./rescue");

const g = "\x1b[32m", r = "\x1b[31m", d = "\x1b[2m", b = "\x1b[1m", cy = "\x1b[36m", x = "\x1b[0m";
let pass = 0, fail = 0;
const is = (what, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log(`  ${ok ? g + "✓" : r + "✗"}${x} ${what}${ok ? "" : `\n      ${d}got ${JSON.stringify(got)}, want ${JSON.stringify(want)}${x}`}`);
  ok ? pass++ : fail++;
};

// ── the trip ────────────────────────────────────────────────────────────────
const constraints = [
  { id: 1, hardness: "strong", rationale: "Business on the long-hauls",
    predicate: { op: "cabin_at_least", value: "business", subject: "flight" } },
  { id: 2, hardness: "must",   rationale: "No budget carriers",
    predicate: { op: "exclude_carrier_class", value: "low_cost" } },
  { id: 3, hardness: "strong", rationale: "Cold plunge — the 5K is 8 weeks out",
    predicate: { op: "facility_present", subject: "lodging", value: "cold_plunge" } },
];

// Downstream, with MEASURED slack. The seaplane can absorb 40 minutes. Not 41.
const nodes = [
  { leg_id: 10, label: "Seaplane transfer", verdict: "at_risk", slack_minutes: 40,
    reasons: [{ id: 9, hardness: "must", rationale: "Only transfer to the island that day", strength: 1 }] },
  { leg_id: 11, label: "Palace Hotel Tokyo", verdict: "at_risk", slack_minutes: 300,
    reasons: [{ id: 3, hardness: "strong", rationale: "Cold plunge — the 5K is 8 weeks out", strength: 1 }] },
];

const ORIGINAL_ARRIVAL = "2026-09-22T15:00:00Z";
const offer = (id, carrier, iata, cabin, price, arriveISO) => ({
  id, total_amount: String(price), total_currency: "USD",
  slices: [{ segments: [{
    marketing_carrier: { name: carrier, iata_code: iata },
    marketing_carrier_flight_number: "999",
    departing_at: "2026-09-22T09:00:00Z",
    arriving_at: arriveISO,
    passengers: [{ cabin_class: cabin }],
  }] }],
});

const offers = [
  // Cheapest. Lands 2h late — the seaplane is gone. The old code books this.
  offer("off_cheap", "Scoot", "TR", "economy", 210, "2026-09-22T17:00:00Z"),
  // Costs more. Lands 30 min late — inside the 40-minute slack. Everything survives.
  offer("off_protects", "Lufthansa", "LH", "business", 890, "2026-09-22T15:30:00Z"),
  // Mid price, business, but 90 min late — seaplane dies, hotel survives.
  offer("off_middle", "ANA", "NH", "business", 540, "2026-09-22T16:30:00Z"),
];

console.log(`\n${b}JL 623 is delayed. Three real alternatives.${x}`);
console.log(`${d}──────────────────────────────────────────────────────────────${x}`);

const out = rescue.rank({ offers, constraints, nodes, originalArrival: ORIGINAL_ARRIVAL });

for (const [i, o] of out.options.entries()) {
  const rec = o.offer_id === out.recommended_id;
  console.log(`  ${cy}${i + 1}.${x} ${o.carrier.padEnd(10)} $${String(o.price).padEnd(5)} ${String(o.cabin).padEnd(9)} ${rec ? g + "◆ RECOMMENDED" + x : ""}`);
  if (o.protects.length) console.log(`      ${g}keeps${x}  ${d}${o.protects.join(", ")}${x}`);
  if (o.loses.length)    console.log(`      ${r}loses${x}  ${d}${o.loses.map((l) => l.what).join(", ")}${x}`);
  if (o.breaks.length)   console.log(`      ${r}breaks${x} ${d}${o.breaks.map((br) => br.rationale).join(", ")}${x}`);
}

console.log(`\n${b}The assertions${x}`);
console.log(`${d}──────────────────────────────────────────────────────────────${x}`);

const [first] = out.options;
const cheap = out.options.find((o) => o.offer_id === "off_cheap");

is("the CHEAPEST option does not win",            first.offer_id !== "off_cheap", true);
is("the option that protects everything wins",    first.offer_id, "off_protects");
is("...and it is the one recommended",            out.recommended_id, "off_protects");

// The cheap one is a budget carrier — that's a 'must' she stated. Not compensable.
is("a budget carrier breaks a stated 'must'",     cheap.breaks.some((br) => br.hardness === "must"), true);
is("...so it is scored beneath everything",       out.options[out.options.length - 1].offer_id, "off_cheap");
is("...and we can NAME what it loses",            cheap.loses.map((l) => l.what), ["Seaplane transfer"]);

// The middle option: business class, respectable — and it still strands her.
const mid = out.options.find((o) => o.offer_id === "off_middle");
is("a 90-min-late option eats the 40-min slack",  mid.loses.map((l) => l.what), ["Seaplane transfer"]);
is("...and we say WHY that booking mattered",     mid.loses[0].why, "Only transfer to the island that day");
is("...but it does keep the hotel (300m slack)",  mid.protects, ["Palace Hotel Tokyo"]);

console.log(`\n${b}And when it can't stand behind an answer${x}`);
console.log(`${d}──────────────────────────────────────────────────────────────${x}`);

// Only the stranding options exist. Wingman must NOT recommend one — it must say why.
const grim = rescue.rank({
  offers: [offers[0], offers[2]], constraints, nodes, originalArrival: ORIGINAL_ARRIVAL,
});
is("no option is recommended when the best breaks a must… ", grim.recommended_id, null);
is("…or when the top option strands her, it still explains", typeof grim.no_recommendation_because, "string");
console.log(`      ${d}"${grim.no_recommendation_because}"${x}`);

// A lodging constraint is unanswerable from a flight offer. UNKNOWN, never PASS.
is("a flight offer can't evaluate a cold plunge → unknown",
   rescue.evaluate(constraints[2], offers[1]), null);

console.log(`\n${d}──────────────────────────────────────────────────────────────${x}`);
console.log(`${fail === 0 ? g + "all " + pass + " held" : r + fail + " FAILED, " + pass + " held"}${x}\n`);
process.exit(fail ? 1 : 0);
