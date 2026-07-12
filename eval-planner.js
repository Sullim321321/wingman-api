#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════════
// eval-planner.js — can Wingman reach the same trip you did?
//
//   node --env-file=.env eval-planner.js            # ~25 turns, no DB, no web
//   node --env-file=.env eval-planner.js --verbose  # show every constraint
//
// Your Asia transcript is a labelled dataset. We know what forty turns of real
// planning SHOULD produce, because you produced it. So this is not a demo — it is a
// score. Feed the planner your actual turns, one at a time, and ask whether it
// arrives at the same constraint set: two rooms, Star Alliance, no budget carriers,
// Technogym, a cold plunge, and the reason underneath all of it — a 5K eight to ten
// weeks out.
//
// IMPORTANT: this writes NOTHING. It runs the graph against an in-memory fake, so
// the real guards fire (an inferred 'must' is still refused) without touching
// production. The refusals are printed, because a refusal is the system working.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require("fs");
const path = require("path");
const planner = require("./planner");
const graph = require("./constraints");

const VERBOSE  = process.argv.includes("--verbose");
const RESEARCH = process.argv.includes("--research");
let searched = 0;
const c = { d:"\x1b[2m", g:"\x1b[32m", y:"\x1b[33m", r:"\x1b[31m", b:"\x1b[1m", cy:"\x1b[36m", x:"\x1b[0m" };
const say = (s="") => console.log(s);

if (!process.env.ANTHROPIC_API_KEY) {
  console.error("ANTHROPIC_API_KEY not set. Add it to .env.");
  process.exit(1);
}

// ── an in-memory stand-in for Postgres ───────────────────────────────────────
// Mimics exactly the two statements the graph issues, so addConstraint()'s real
// guards run — unchanged — against a fake table. The eval must be judged by the
// same rules production is.
let nextId = 1;
const TABLE = [];
function fakeSql(strings, ...v) {
  const q = strings.join("?");
  if (/INSERT INTO\s+constraints/i.test(q)) {
    const row = {
      id: nextId++, user_email: v[0], trip_id: v[1], intent_id: v[2], kind: v[3],
      predicate: JSON.parse(v[4]), rationale: v[5], hardness: v[6], source: v[7],
      evidence: JSON.parse(v[8]), confidence: v[9], expires_at: v[11],
      status: v[12], scope: v[13], superseded_by: null,
    };
    TABLE.push(row);
    return Promise.resolve([row]);
  }
  if (/UPDATE constraints SET superseded_by/i.test(q)) {
    const old = TABLE.find((r) => r.id === v[1]);
    if (old) old.superseded_by = v[0];
    return Promise.resolve([]);
  }
  return Promise.resolve([]);
}
const live = () => TABLE.filter((r) => r.superseded_by === null);

// ── The golden set ───────────────────────────────────────────────────────────
// What YOUR conversation actually established. Each is a thing Wingman must know
// by the end, or it has not understood the trip.
//
// `research` = we do not expect this without a web-search tool, and we say so
// rather than quietly marking it wrong. Honesty applies to the scorecard too.
const GOLD = [
  { id: "rooms",      want: /two rooms|2 rooms|separate rooms/i,                      hardness: "must",   note: "Travelling with a friend — two rooms." },
  { id: "origin",     want: /london/i,                                                 note: "Flying from London." },
  { id: "no_budget",  want: /budget|low.?cost|economy airline/i,                       hardness: "strong", note: "No budget carriers." },
  { id: "business",   want: /business/i,                                               hardness: "strong", note: "Business on the long-hauls." },
  { id: "star",       want: /star alliance|\bstar\b/i,                                 note: "Star Alliance — it lines up with EVA, ANA, Asiana, Air China." },
  { id: "asiana_cut", want: /asiana/i,                    expires: true,               note: "Asiana stops earning on 15 Oct 2026.",           research: true },
  { id: "no_doha",    want: /doha|qatar/i,                                             note: "Not via Doha." },
  { id: "technogym",  want: /technogym|treadmill/i,                                    hardness: "strong", note: "Technogym treadmills." },
  { id: "recovery",   want: /cold plunge|recovery|ice|plunge/i,                        hardness: "strong", note: "Cold plunge / recovery." },
  { id: "pool",       want: /pool|swim/i,                                              note: "A real lap pool." },
  { id: "shows",      want: /show|tour|concert|shanghai.*9\/24|24 sep/i,               hardness: "must",   note: "The six tour dates anchor everything." },
  { id: "training",   want: /5k|olympic|thanksgiving|race|training/i,                  note: "THE REASON UNDER EVERYTHING — a 5K, 8–10 weeks out." },
  { id: "climate",    want: /cool|climate|temp|heat|tropical/i,  notMust: true,        note: "Cooler climates suit the training block. (Inferred — must NOT be 'must'.)" },
  { id: "sydney5",    want: /sydney/i,                                                 note: "Five nights in Sydney." },
  { id: "companion",  want: /solo|companion|boyfriend|tbd|one room/i,                  note: "Back half is companion-neutral." },
  { id: "china_visa", want: /china|visa|shanghai.*visa/i,       hardness: "must",      note: "US passports need an L visa for China.",         research: true },
  { id: "aus_eta",    want: /eta|australia|601/i,               hardness: "must",      note: "US citizens need the Australian ETA, not eVisitor.", research: true },
];

(async () => {
  const turns = JSON.parse(fs.readFileSync(path.join(__dirname, "eval/asia_turns.json"), "utf8"));

  say();
  say(`${c.b}Can Wingman reach the same trip you did?${c.x}`);
  say(`${c.d}${turns.length} real turns · model ${planner.MODEL} · nothing is written${c.x}`);
  say(RESEARCH
    ? `${c.d}web search ON — entry rules will be looked up, not recalled${c.x}`
    : `${c.d}web search OFF — entry rules can't be verified, so they can't be asserted. --research to enable.${c.x}`);
  say(`${c.d}──────────────────────────────────────────────────────────────${c.x}`);

  const history = [];
  const refusals = [], supersessions = [], keeps = [], proposals_ = [], enrichments = [];
  let inTok = 0, outTok = 0, dupes = 0;

  for (let i = 0; i < turns.length; i++) {
    const turn = turns[i];
    const known = live();

    // Look it up rather than recall it. Only on turns that hinge on a checkable
    // external fact, and only when asked for — research costs money.
    let findings = null;
    if (RESEARCH && planner.NEEDS_LOOKUP.test(turn)) {
      try {
        const r = await planner.research(turn, history);
        inTok += r.usage?.input_tokens || 0;
        outTok += r.usage?.output_tokens || 0;
        if (r.text && !/^nothing to check/i.test(r.text)) {
          findings = r.text;
          searched++;
        }
      } catch (e) {
        say(`      ${c.y}research failed on turn ${i + 1}: ${e.message}${c.x}`);
      }
    }

    let proposals;
    try {
      proposals = await planner.readTurn({ turn, known, history, findings });
    } catch (e) {
      say(`  ${c.r}turn ${i + 1} failed:${c.x} ${e.message}`);
      break;
    }
    inTok  += proposals.usage?.input_tokens  || 0;
    outTok += proposals.usage?.output_tokens || 0;

    const res = await planner.commit(fakeSql, {
      user_email: "eval@wingman", trip_id: 1, proposals, known,
    });
    refusals.push(...res.refused);
    supersessions.push(...res.superseded);
    keeps.push(...(res.kept || []));
    proposals_.push(...(res.proposed || []));
    dupes += (res.duplicates || []).length;
    enrichments.push(...(res.enriched || []));
    history.push(turn);

    const n = res.written.length;
    const flag = res.refused.length ? ` ${c.r}${res.refused.length} refused${c.x}` : "";
    const sup  = res.superseded.length ? ` ${c.cy}${res.superseded.length} superseded${c.x}` : "";
    const kpt  = (res.kept || []).length ? ` ${c.g}${res.kept.length} kept${c.x}` : "";
    const prp  = (res.proposed || []).length ? ` ${c.y}${res.proposed.length} proposed${c.x}` : "";
    say(`  ${c.d}${String(i + 1).padStart(2)}.${c.x} ${turn.split("\n")[0].slice(0, 54).padEnd(54)} ${c.d}→${c.x} ${n ? `${n} new` : `${c.d}—${c.x}`}${flag}${sup}${kpt}${prp}`);

    if (VERBOSE) for (const w of res.written) {
      const sc = w.scope ? ` ${c.cy}@${w.scope}${c.x}` : "";
      const st = w.status === "proposed" ? ` ${c.y}(proposed)${c.x}` : "";
      say(`      ${c.d}[${w.hardness}/${w.source} ${w.confidence}]${c.x}${sc}${st} ${w.rationale}`);
    }
  }

  // ── Score ──────────────────────────────────────────────────────────────────
  const all = live();
  const hay = (r) => `${r.rationale} ${JSON.stringify(r.predicate)}`;

  say();
  say(`${c.b}The scorecard${c.x}   ${c.d}did it understand the trip?${c.x}`);
  say(`${c.d}──────────────────────────────────────────────────────────────${c.x}`);

  let got = 0, missed = 0, needsResearch = 0, wrongHardness = 0;
  for (const g of GOLD) {
    // ── BEST match, not FIRST match ──────────────────────────────────────────
    // The first version took `.find()`, and it was grading the wrong rows. The gold
    // matcher for the Australian ETA is /eta|australia|601/, which happily matched
    // "Travelling solo in Australia" — a perfectly correct 'nice' — and then reported
    // the ETA as mis-weighted. The planner was being blamed for the eval's mistake.
    //
    // A scorecard that scores the wrong row is worse than no scorecard: it sends you
    // off to fix a bug that isn't there, which is exactly what I nearly did. Rank the
    // candidates and take the one that best satisfies the expectation, so a constraint
    // is only marked wrong when NOTHING in the graph gets it right.
    const cands = all.filter((r) => g.want.test(hay(r)));
    const ok = (r) =>
      (!g.hardness || r.hardness === g.hardness) &&
      (!g.notMust  || r.hardness !== "must") &&
      (!g.expires  || !!r.expires_at);
    const hit = cands.find(ok) || cands[0];

    if (!hit) {
      if (g.research) { needsResearch++; say(`  ${c.y}◐ needs research${c.x}  ${g.note}`); }
      else            { missed++;        say(`  ${c.r}✗ missed${c.x}         ${g.note}`); }
      continue;
    }
    // Getting the constraint is not enough. Getting its WEIGHT right is the job.
    if (g.hardness && hit.hardness !== g.hardness) {
      wrongHardness++;
      say(`  ${c.y}~ soft${c.x}           ${g.note}\n      ${c.d}recorded as '${hit.hardness}', should be '${g.hardness}'${c.x}`);
      continue;
    }
    if (g.notMust && hit.hardness === "must") {
      wrongHardness++;
      say(`  ${c.r}✗ OVERREACH${c.x}      ${g.note}\n      ${c.d}marked 'must' — Wingman invented a hard rule.${c.x}`);
      continue;
    }
    if (g.expires && !hit.expires_at) {
      wrongHardness++;
      say(`  ${c.y}~ no expiry${c.x}      ${g.note}\n      ${c.d}captured, but with no expires_at — it will be cited after it stops being true.${c.x}`);
      continue;
    }
    got++;
    say(`  ${c.g}✓${c.x} ${c.d}[${hit.hardness}/${hit.source}]${c.x} ${hit.rationale}`);
  }

  say();
  say(`${c.d}──────────────────────────────────────────────────────────────${c.x}`);
  say(`  ${c.b}${got}/${GOLD.length}${c.x} understood` +
      (wrongHardness ? `   ${c.y}${wrongHardness} mis-weighted${c.x}` : "") +
      (missed        ? `   ${c.r}${missed} missed${c.x}` : "") +
      (needsResearch ? `   ${c.y}${needsResearch} need a research tool${c.x}` : ""));
  say(`  ${c.d}${all.length} constraints held · ${supersessions.length} revised · ${refusals.length} refused` +
      (dupes ? ` · ${dupes} duplicates dropped` : "") +
      (enrichments.length ? ` · ${enrichments.length} enriched with sources` : "") + `${c.x}`);

  if (enrichments.length) {
    say();
    say(`${c.b}It found the receipt for something you'd told it${c.x}`);
    say(`${c.d}Same fact, better provenance. Upgraded in place, not stored twice.${c.x}`);
    for (const e of enrichments) say(`  ${c.cy}+${c.x} ${e.rationale}\n    ${c.d}${e.with}${c.x}`);
  }

  if (proposals_.length) {
    say();
    say(`${c.b}It thinks these are non-negotiable — but it worked them out, so it's asking${c.x}`);
    say(`${c.d}Stored as 'proposed'. They gate nothing until you confirm. This is what should have${c.x}`);
    say(`${c.d}happened to the China visa instead of it being filed as a 'nice'.${c.x}`);
    for (const p of proposals_) say(`  ${c.y}?${c.x} [${p.hardness}] ${p.rationale}`);
  }

  if (supersessions.length) {
    say();
    say(`${c.b}It changed its mind${c.x}  ${c.d}— a real contradiction. Old fact is now false.${c.x}`);
    for (const s of supersessions) say(`  ${c.cy}↻${c.x} ${c.d}${s.old}${c.x}\n    → ${s.now}`);
  }

  if (keeps.length) {
    say();
    say(`${c.b}It tried to delete a true thing. It was stopped.${c.x}`);
    say(`${c.d}The planner asked to supersede; the graph found no contradiction and kept both.${c.x}`);
    for (const k of keeps) {
      say(`  ${c.g}✓ kept${c.x} ${c.d}${k.old}${c.x}`);
      say(`    ${c.d}alongside${c.x} ${k.now}`);
      say(`    ${c.d}${k.why}${c.x}`);
    }
  }

  if (refusals.length) {
    say();
    say(`${c.b}It was refused${c.x}  ${c.d}— the model tried to assert what it hadn't earned. The schema said no.${c.x}`);
    for (const f of refusals) {
      say(`  ${c.r}✗${c.x} ${f.rationale ?? c.d + "(no rationale emitted)" + c.x}`);
      say(`    ${c.d}${f.why}${c.x}`);
      // If the refusal is structural rather than principled, show the payload —
      // otherwise we are debugging by seance.
      if (/required|unknown predicate/.test(f.why)) {
        say(`    ${c.d}${JSON.stringify(f.raw).slice(0, 220)}${c.x}`);
      }
    }
  }

  // Sonnet 4.5: $3/Mtok in, $15/Mtok out. Rough, but you're watching the balance.
  const cost = (inTok / 1e6) * 3 + (outTok / 1e6) * 15 + searched * 0.01;
  say();
  say(`  ${c.d}${inTok.toLocaleString()} in · ${outTok.toLocaleString()} out` +
      (searched ? ` · ${searched} searches` : "") + ` · ~$${cost.toFixed(2)}${c.x}`);
  say();
})();
