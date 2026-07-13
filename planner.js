// ═══════════════════════════════════════════════════════════════════════════════
// planner.js — the missing front door.
//
// Turns a conversation into a constraint graph. This is PLAN, the half of the deck
// we never built: the app could file a trip, never make one, so the most valuable
// forty turns of a user's life happened in somebody else's chat window.
//
// The planner does exactly one thing: read a turn, and propose constraints. It does
// NOT decide whether they're allowed — graph.addConstraint() does that, and it will
// throw. That split is deliberate. The model is a witness, not a judge:
//
//   · it may not invent a hard rule            (inferred + must → refused)
//   · it may not cite research with no source  (researched + no url → refused)
//   · it may not be surer than its evidence    (confidence clamped to the ceiling)
//
// So the model can hallucinate freely and the graph still can't be poisoned. That is
// the point of putting the guards in the schema instead of in the prompt.
// ═══════════════════════════════════════════════════════════════════════════════

const Anthropic = require("@anthropic-ai/sdk");
const graph = require("./constraints");
const { link } = graph;

// maxRetries covers the transport failures that are NOT the model's fault — the
// "Premature close" class, where the connection dies mid-response. The default of 2
// is not enough on a long-running planning loop, and a single dropped socket 3 turns
// in would otherwise throw away the whole conversation.
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
  maxRetries: 4,
  timeout: 120000,
});
const MODEL = process.env.PLANNER_MODEL || "claude-sonnet-4-5";

// The tool the model must speak through. A closed shape is a cheap, hard guardrail:
// it cannot emit a constraint without also emitting where it came from.
const TOOLS = [{
  name: "record",
  description: "Record what this turn established about the trip. Emit ONLY what the user actually said or what you looked up — never what you assume.",
  input_schema: {
    type: "object",
    properties: {
      intents: {
        type: "array",
        description: "What the trip is FOR. Rare — usually only in the first few turns. e.g. 'Attend all six tour dates', 'Qualify for Olympic trials in the 5K'.",
        items: {
          type: "object",
          properties: {
            kind: { type: "string", enum: ["event", "goal", "occasion", "obligation"] },
            summary: { type: "string" },
          },
          required: ["kind", "summary"],
        },
      },
      // ── The SHAPE of the trip — not bookings. ────────────────────────────────
      // This is the most dangerous field in the system.
      //
      // A model asked for "legs" will cheerfully produce JL 623, departing 11:40,
      // confirmation ABC123 — a flight that does not exist, stored in the same table
      // as flights that do, rendered by the same components, and shown to someone at
      // an airport. Every failure this app has had is a milder version of that.
      //
      // So: shape, never bookings. A city, a span of nights, an intent. NO flight
      // numbers, NO confirmations, NO times. Those can only come from Duffel or from
      // the user's inbox — from the world, not from a language model. The schema below
      // literally has nowhere to put them, and stripShape() throws them away if the
      // model smuggles them in anyway.
      shape: {
        type: "array",
        description: "The SHAPE of the trip so far — cities and spans, in order. Never a specific flight or a confirmation number: you are sketching, not booking.",
        items: {
          type: "object",
          properties: {
            kind:  { type: "string", enum: ["stay", "move", "event"] },
            city:  { type: "string", description: "e.g. 'Kyoto'. For a move: the destination." },
            from:  { type: "string", description: "For a move: the origin city." },
            nights:{ type: "number", description: "For a stay." },
            date:  { type: "string", description: "ISO date, ONLY if the user gave it or it's fixed by an event. Never guessed." },
            why:   { type: "string", description: "Which constraint or intent puts this here. 'The Shanghai show on 9/24.'" },
          },
          required: ["kind", "city", "why"],
        },
      },
      constraints: {
        type: "array",
        items: {
          type: "object",
          properties: {
            kind: { type: "string", enum: ["entry","routing","cabin","loyalty","lodging","facility","timing","party","budget","climate"] },
            predicate: {
              type: "object",
              description: "Machine-checkable. op must be one of: facility_present, within_distance, alliance_is, credits_to, cabin_at_least, exclude_carrier_class, rooms, entry_document, arrive_before, depart_after, climate_max_temp_c, budget_max_cents, free_text",
              properties: { op: { type: "string" } },
              required: ["op"],
            },
            rationale: { type: "string", description: "WHY, in one sentence, in the user's own terms. This is the most important field in the system — it is what lets Wingman defend the booking later instead of merely replacing it." },
            hardness: { type: "string", enum: ["must","strong","nice"] },
            source: { type: "string", enum: ["stated","observed","researched","inferred"] },
            evidence: { type: "object", description: "{url, retrieved_at} for researched. {turn} for stated." },
            scope: { type: "string", description: "Which leg this applies to, if not the whole trip: 'asia', 'sydney', 'singapore'. Omit if it holds throughout." },
            expires_at: { type: "string", description: "ISO date, if this stops being true on a known date (e.g. an alliance earning cutoff)." },
            supersedes: { type: "string", description: "The rationale text of an EXISTING constraint this replaces, if the user just changed their mind or gave new facts that invalidate it." },
          },
          required: ["kind","predicate","rationale","hardness","source"],
        },
      },
    },
    required: ["constraints"],
  },
}];

const SYSTEM = `You are Wingman's planner. You read one turn of a travel-planning conversation and record what it established.

You are a WITNESS, not a designer. Record only what is actually there:

- The user SAID it            → source "stated",     confidence 1.0. This is the only source that may be "must".
- You LOOKED IT UP            → source "researched",  and you MUST supply evidence.url. No link, no constraint.
- You worked it out yourself  → source "inferred",    and it may NEVER be "must". Propose it as "strong" or "nice".

Hardness — record what the constraint IS, never what is convenient to store:
- must   = the trip fails without it. A show date. A visa. "Two rooms."
- strong = it's why they're paying you. "Technogym treadmills." "No budget airlines."
- nice   = a preference. "Window seat."

NEVER downgrade a hardness to get past a rule. If you infer that a US passport needs
an L visa for China, that is a "must" and you say so — set source "inferred" and it
will be stored as PROPOSED, awaiting confirmation. That is correct and expected.
Filing a visa as a "nice" because "inferred must" felt disallowed is a lie, and it is
the kind of lie that leaves someone at the airport without a visa. Say the true weight.

SCOPE — which leg of the trip does this apply to?
Set "scope" to a short tag ("asia", "sydney", "singapore") when a constraint only
holds for part of the journey. Leave it out when it applies throughout.
"Two rooms, travelling with a friend" is scope "asia". "One room with my boyfriend"
is scope "sydney". These do NOT contradict each other — they are different legs, and
BOTH ARE TRUE. Do not supersede one with the other.

The rationale is the whole point. Write the REASON, not the rule:
  BAD:  "Cold plunge required"
  GOOD: "Cold plunge for recovery — the Thanksgiving 5K is 8-10 weeks after this trip"
A booking whose reason you recorded can be defended during a disruption. One without can only be replaced.

SUPERSEDE ONLY ON A REAL CONTRADICTION. Set "supersedes" to the old constraint's rationale text only when the new fact makes the old one FALSE — a changed passport, a moved date, a reversed decision. "I'm leaving on the 16th, not the 17th" supersedes. "I'll be in Sydney with my boyfriend" does NOT supersede "two rooms with a friend in Asia" — those are different legs and both are true. Nor does a duration supersede a hotel. When in doubt, ADD; do not replace. Deleting a true constraint is far worse than holding two.

Most turns establish nothing. A question ("what does recovery-grade mean?") is not a constraint. Return an empty array and move on. Recording nothing is a correct answer; inventing something is not.`;

// ── Research ──────────────────────────────────────────────────────────────────
// Some facts may not be recalled. They must be looked up.
//
// The eval kept filing "US citizens need the Australian ETA" as a *nice-to-have*.
// Two prompt rewrites didn't move it, and I'm glad they didn't — the model was
// right and I was wrong. It has no way to VERIFY that claim, it correctly senses it
// shouldn't assert it as fact, and with no honest outlet it downgrades the weight
// instead. The tension is real; the resolution was just bad.
//
// Entry rules, alliance cutoffs, what's actually in a hotel gym: these go stale, and
// being wrong about one means someone is turned away at a border. The transcript's
// Claude didn't recall China's L visa requirement. It looked it up. So does this.
//
// A cheap prefilter, deliberately biased toward over-triggering.
//
// The costs are wildly asymmetric. A search fired needlessly costs about a penny and
// comes back "nothing to check" — the research prompt is told to say exactly that.
// A search NOT fired costs a constraint, and the constraint it costs is the kind
// that leaves someone at a border without a visa.
//
// So this net is loose on purpose. "what about aman in otemachi" is a question about
// what a specific hotel actually has, and it must fire. That "what does a recovery-
// grade gym mean?" also fires is a penny well spent.
const NEEDS_LOOKUP = new RegExp([
  "passport|visa|entry|eta\\b|esta|customs|border",          // getting in
  "alliance|star|oneworld|skyteam|miles|tiles|earn|credit|status|partner",  // loyalty
  "technogym|gym|pool|plunge|sauna|spa|lounge|recovery|treadmill|track",    // facilities
  "hotel|resort|property|suite|aman|raffles|capella|peninsula|mandarin|conrad|four seasons",
  "business class|first class|cabin|seat|allegris|lie.?flat",
].join("|"), "i");

// Research runs on HAIKU, not Sonnet.
//
// The 25-turn eval cost $1.74 and burned 469k input tokens. I first assumed that was
// the findings I passed forward and capped them — wrong lever, no change. The tokens
// are the search RESULTS, which the server injects into the research call's context:
// twelve searches, each dragging in tens of thousands of tokens of web page, all
// priced at Sonnet's $3/Mtok.
//
// But reading a government visa page and reporting what it says is extraction, not
// judgment. Haiku does that at a third of the price. Sonnet's reasoning is worth
// paying for in readTurn — deciding what a turn *establishes*, what supersedes what —
// and wasted on "what does this page say about entry requirements".
const RESEARCH_MODEL = process.env.RESEARCH_MODEL || "claude-haiku-4-5";

async function research(turn, history = []) {
  const res = await anthropic.messages.create({
    model: RESEARCH_MODEL,
    max_tokens: 1200,
    // 2, not 3. Each use pulls a page into context. The third search rarely changed
    // the finding and always cost for it.
    tools: [{ type: "web_search_20250305", name: "web_search", max_uses: 2 }],
    messages: [{
      role: "user",
      content:
        `Travel-planning context:\n${history.slice(-4).map((h) => `- ${h}`).join("\n")}\n\n` +
        `The traveller just said:\n"""${turn}"""\n\n` +
        `If this depends on a checkable external fact — an entry requirement, an alliance ` +
        `earning rule and its cutoff date, what equipment a specific hotel actually has — ` +
        `look it up and state ONLY what you found, each with its source URL and the date ` +
        `the rule applies from/until. If nothing here needs checking, reply "nothing to check".`,
    }],
  });
  const text = res.content.filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
  // Cap the findings. The full research transcript ran to thousands of tokens and was
  // then re-sent into readTurn — 449k input tokens across a 25-turn run, $1.68 for one
  // eval. The constraint we want out of it is two sentences and a URL; the rest is the
  // model showing its working.
  return { text: text.slice(0, 1800), usage: res.usage };
}

/**
 * Read one turn. Returns { intents, constraints } as PROPOSALS — not yet written.
 * `known` is the constraint set so far, so the model can supersede rather than duplicate.
 * `findings` is verified research, which is what lets a constraint be sourced
 * 'researched' with a real URL instead of quietly demoted to a preference.
 */
async function readTurn({ turn, known = [], history = [], findings = null }) {
  const knownList = known.length
    ? known.map((c) => `- [${c.hardness}/${c.source}] ${c.rationale}`).join("\n")
    : "(nothing yet)";

  const res = await anthropic.messages.create({
    model: MODEL,
    max_tokens: 1500,
    system: [{ type: "text", text: SYSTEM, cache_control: { type: "ephemeral" } }],
    tools: TOOLS,
    tool_choice: { type: "tool", name: "record" },
    messages: [{
      role: "user",
      content:
        `Already established:\n${knownList}\n\n` +
        (history.length ? `Conversation so far:\n${history.slice(-6).map((h) => `- ${h}`).join("\n")}\n\n` : "") +
        (findings
          ? `VERIFIED RESEARCH (you looked this up just now — you may cite it as source "researched", ` +
            `with its URL in evidence.url, at its TRUE hardness. A visa requirement is a "must"):\n${findings}\n\n`
          : "") +
        `The user's new turn:\n"""${turn}"""\n\n` +
        `What does THIS turn establish? Only this turn.`,
    }],
  });

  const use = res.content.find((b) => b.type === "tool_use");
  const out = use?.input || { constraints: [] };

  // PLANNER_DEBUG=1 dumps exactly what the model emitted. Guessing at a payload
  // shape is how you end up "fixing" the wrong thing twice — look at the bytes.
  if (process.env.PLANNER_DEBUG) {
    console.error("\n── raw tool_use input ──\n" + JSON.stringify(out, null, 2) + "\n");
  }

  return {
    intents: asArray(out.intents),
    constraints: asArray(out.constraints).map(normalize),
    usage: res.usage,
  };
}

// ── Fields a PLAN may never contain ──────────────────────────────────────────
// A sketched leg must be structurally incapable of impersonating a booking. If the
// model volunteers a flight number or a confirmation code — and it will, because it
// is trying to be helpful — those are the exact fields that make a fiction look like
// a fact to a person standing in an airport.
//
// The tool schema doesn't offer these fields. This throws them away when the model
// invents them anyway. Belt and braces, because the cost of being wrong is someone
// arriving for a flight that never existed.
const FORBIDDEN_ON_A_PLAN = [
  "flight_number", "carrier", "confirmation", "pnr", "booking_reference",
  "departs_at", "arrives_at", "seat", "gate", "terminal", "record_locator",
];

function stripShape(leg) {
  const clean = {};
  for (const k of ["kind", "city", "from", "nights", "date", "why"]) {
    if (leg[k] != null) clean[k] = leg[k];
  }
  const smuggled = FORBIDDEN_ON_A_PLAN.filter((k) => leg[k] != null);
  if (smuggled.length) clean._stripped = smuggled;   // reported, never stored
  return clean;
}

/**
 * Coerce whatever came back into a list.
 *
 * I have now assumed the payload's shape twice and been wrong twice — first that
 * each constraint was an object with a nested predicate, then that `constraints` was
 * an array at all. The model may hand back a JSON string, a single bare object, or a
 * dict keyed by name. All of those carry the same information.
 *
 * The rule this encodes: be liberal about SHAPE, strict about TRUTH. Reshaping costs
 * nothing and loses nothing. The things that actually matter — can this be evaluated,
 * is it sourced, is it entitled to be a 'must' — are still adjudicated downstream by
 * addConstraint(), and none of that is relaxed here.
 */
function asArray(v) {
  if (v == null) return [];
  if (Array.isArray(v)) return v;
  if (typeof v === "string") {
    try { return asArray(JSON.parse(v)); } catch { return []; }
  }
  if (typeof v === "object") {
    // A single bare constraint, unwrapped.
    if (v.predicate || v.op || v.rationale) return [v];
    // A dict keyed by name: { rooms: {...}, cabin: {...} }
    const vals = Object.values(v);
    if (vals.length && vals.every((x) => x && typeof x === "object")) return vals;
  }
  return [];
}

/**
 * Meet the model where it is.
 *
 * A tool schema is a request, not a guarantee. The model will sometimes flatten the
 * predicate (`{op, value}` at the top level), or hand back a JSON string instead of
 * an object. Rejecting those is technically correct and practically useless — the
 * information IS there, it is just wearing a different coat.
 *
 * Note carefully what this does NOT do: it never invents an `op`, never upgrades a
 * hardness, never fabricates evidence. It reshapes; it does not decide. Everything
 * that matters is still adjudicated by addConstraint().
 */
function normalize(p) {
  if (!p || typeof p !== "object") return p;
  const q = { ...p };

  if (typeof q.predicate === "string") {
    try { q.predicate = JSON.parse(q.predicate); } catch { q.predicate = { op: "free_text", value: q.predicate }; }
  }
  // Flattened: { op: "rooms", value: 2, ... } with no predicate wrapper.
  if (!q.predicate && q.op) {
    const { kind, rationale, hardness, source, evidence, expires_at, supersedes, ...rest } = q;
    q.predicate = rest;
  }
  // Wrapped one level too deep: { predicate: { predicate: {...} } }
  if (q.predicate?.predicate?.op) q.predicate = q.predicate.predicate;

  if (typeof q.evidence === "string") q.evidence = { note: q.evidence };
  return q;
}

/**
 * Write the proposals into the graph. Refusals are CAUGHT AND REPORTED, never
 * swallowed — a refusal is the system working, and it is the most interesting line
 * of output we produce. It means the model tried to assert something it had not
 * earned, and the schema stopped it.
 */
async function commit(sql, { user_email, trip_id, proposals, known = [] }) {
  const written = [], refused = [], superseded = [], kept = [], proposed = [];
  const duplicates = [], enriched = [];

  // Normalize HERE too, not just in readTurn. commit() is the only door into the
  // graph, so the reshaping belongs at the door — otherwise any future caller that
  // skips readTurn silently loses it, which is exactly how the first version of this
  // "fix" would have failed while its test passed.
  // Deduplicate against what's already live. The research pass re-states things the
  // user already said — "Recovery options needed for the 5K" arrived twice, once
  // 'stated' and once 'researched' — and a graph that holds the same fact twice will
  // eventually weigh it twice. scoreOption() sums over constraints; a duplicated
  // 'must' is worth 200 instead of 100, and the ranking quietly bends.
  const sameFact = (a, b) =>
    a.kind === b.kind &&
    a.predicate?.op === b.predicate?.op &&
    JSON.stringify(a.predicate?.value ?? null) === JSON.stringify(b.predicate?.value ?? null) &&
    (a.scope || null) === (b.scope || null);

  for (const p of asArray(proposals.constraints).map(normalize)) {
    try {
      const dup = known.find((k) => sameFact(k, p));
      if (dup) {
        // Not a new fact. But if the newcomer carries better provenance — a URL where
        // the original had only the user's word, or an expiry the original lacked —
        // that is worth keeping. Upgrade in place rather than storing it twice.
        if ((p.source === "researched" && p.evidence?.url && !dup.evidence?.url) ||
            (p.expires_at && !dup.expires_at)) {
          await sql`
            UPDATE constraints
               SET evidence   = COALESCE(${JSON.stringify(p.evidence || {})}::jsonb, evidence),
                   expires_at = COALESCE(${p.expires_at || null}::TIMESTAMPTZ, expires_at)
             WHERE id = ${dup.id}`;
          enriched.push({ rationale: dup.rationale, with: p.evidence?.url || `expires ${p.expires_at}` });
        } else {
          duplicates.push(p.rationale);
        }
        continue;
      }
      const spec = {
        user_email, trip_id, kind: p.kind, predicate: p.predicate,
        rationale: p.rationale, hardness: p.hardness, source: p.source,
        evidence: p.evidence || {}, expires_at: p.expires_at || null,
        scope: p.scope || null,
      };

      if (p.supersedes) {
        const old = known.find((k) => k.rationale === p.supersedes);
        if (old) {
          // Pass the OLD ROW, so canSupersede() can actually adjudicate. The first
          // version didn't, which is how "two rooms" got deleted by a fact about a
          // different leg of the trip.
          const fresh = await graph.supersede(sql, old.id, spec, old);
          if (fresh._supersededNothing) {
            kept.push({ old: old.rationale, now: p.rationale, why: fresh._supersededNothing });
          } else {
            superseded.push({ old: old.rationale, now: p.rationale });
          }
          written.push(fresh);
          continue;
        }
      }
      const row = await graph.addConstraint(sql, spec);
      if (row.status === "proposed") proposed.push(row);
      written.push(row);
    } catch (e) {
      // Keep the raw payload. A refusal we can't inspect is a refusal we can't learn
      // from — and "undefined: predicate.op required" told us nothing the first time.
      refused.push({
        rationale: p.rationale, hardness: p.hardness, source: p.source,
        why: e.message, raw: p,
      });
    }
  }
  return { written, refused, superseded, kept, proposed, duplicates, enriched };
}

/**
 * Write the trip's SHAPE — the thing that makes Plan more than a chat log.
 *
 * Legs land at state 'proposed', booked_by 'wingman', with NO confirmation, NO flight
 * number, NO times. They are the outline of a journey, not a claim about the world.
 * The app must render them as visibly unbooked, and invariant #9 fails loudly if one
 * ever acquires a confirmation without also becoming 'booked'.
 *
 * And each one gets `satisfies` edges: this stay exists BECAUSE of the Shanghai show,
 * BECAUSE of the training block. That is the link no other travel app stores, and it
 * is the whole reason the cascade can defend a trip later instead of merely rebooking it.
 */
async function shapeTrip(sql, { user_email, trip_id, shape = [], constraints = [] }) {
  const legs = [], smuggled = [];

  for (const raw of asArray(shape)) {
    const leg = stripShape(raw);
    if (leg._stripped) smuggled.push({ city: leg.city, fields: leg._stripped });
    if (!leg.city) continue;

    const type  = leg.kind === "stay" ? "hotel" : leg.kind === "move" ? "flight" : "activity";
    const title = leg.kind === "stay"  ? `${leg.city}${leg.nights ? ` · ${leg.nights} nights` : ""}`
                : leg.kind === "move"  ? `${leg.from || "?"} → ${leg.city}`
                : leg.city;

    // Idempotent: re-planning the same city must not stack up copies of it.
    const [existing] = await sql`
      SELECT id FROM trip_legs
      WHERE trip_id = ${trip_id} AND state = 'proposed'
        AND type = ${type} AND COALESCE(property_name, destination) = ${title}
      LIMIT 1`;

    let legId;
    if (existing) {
      legId = existing.id;
    } else {
      const [row] = await sql`
        INSERT INTO trip_legs
          (trip_id, type, destination, destination_city, property_name, nights,
           departs_at, state, booked_by, raw_data)
        VALUES
          (${trip_id}, ${type}, ${title}, ${leg.city},
           ${leg.kind === "stay" ? title : null}, ${leg.nights || null},
           ${leg.date || null}::TIMESTAMPTZ,          -- only if the USER fixed it
           'proposed', 'wingman',
           ${JSON.stringify({ why: leg.why, planned: true })}::jsonb)
        RETURNING id`;
      legId = row.id;
    }
    legs.push({ id: legId, title, city: leg.city, why: leg.why, type });

    // ── the reason edge ──────────────────────────────────────────────────────
    // Match the leg's stated `why` back to the constraints it serves. Conservative on
    // purpose: a wrong reason is worse than no reason, because a wrong reason is what
    // the rescue engine will later defend.
    const words = String(leg.why || "").toLowerCase();
    for (const c of constraints) {
      const r = String(c.rationale || "").toLowerCase();
      const hit =
        (c.scope && leg.city && c.scope.toLowerCase() === leg.city.toLowerCase()) ||
        (r && leg.city && r.includes(leg.city.toLowerCase())) ||
        (words && r && words.split(/\W+/).filter((w) => w.length > 4).some((w) => r.includes(w)));
      if (hit) await link(sql, legId, c.id, 1.0, leg.why || null);
    }
  }
  return { legs, smuggled };
}

/** A trip called "Untitled trip" is a trip nobody will open. */
function titleFor(shape = [], fallback = "Untitled trip") {
  const cities = [...new Set(asArray(shape).map((s) => s.city).filter(Boolean))];
  if (!cities.length) return fallback;
  if (cities.length <= 3) return cities.join(" → ");
  return `${cities[0]} → ${cities[cities.length - 1]} · ${cities.length} stops`;
}

// ── converse() — the Plan tab's engine ────────────────────────────────────────
//
// readTurn() only listens. A planner has to ANSWER: recommend, push back, and ask
// the question it needs answered before it can go further. The transcript's Claude
// asked four questions before it built anything — which shows / where from / what
// tier / how much detail — and those weren't small talk. They were the four `must`
// constraints it couldn't proceed without.
//
// So the clarifying question isn't a conversational nicety bolted on top. It IS the
// model noticing a hole in the graph. That's why coverage is computed here and handed
// to the model, rather than hoping it remembers to ask.
//
// One call does both: it replies in text AND records via the tool. Two calls would be
// double the money and would let the reply drift from what was actually stored.

const SLOTS = [
  { id: "when",    test: (cs) => cs.some((c) => /timing|date/i.test(c.kind) || /arrive_before|depart_after/.test(c.predicate?.op)),
    ask: "when you're going" },
  { id: "from",    test: (cs) => cs.some((c) => /origin|from|flying from/i.test(c.rationale || "")),
    ask: "where you're flying from" },
  { id: "who",     test: (cs) => cs.some((c) => c.kind === "party" || /rooms/.test(c.predicate?.op || "")),
    ask: "who's going, and how many rooms" },
  { id: "tier",    test: (cs) => cs.some((c) => /lodging|cabin|budget/.test(c.kind)),
    ask: "roughly what standard you want" },
];

function coverage(known) {
  return SLOTS.filter((s) => !s.test(known)).map((s) => s.ask);
}

const CONVERSE_SYSTEM = `You are Wingman — a chief of staff for travel, not a chatbot.

You are planning a trip WITH the person, and everything you learn is recorded in a constraint graph. Two jobs, every turn:

1. REPLY. Be the person from a very good private travel office. Concrete, warm, unpadded. Recommend, don't enumerate — "Palace Hotel over Aman: same Imperial Palace loop, it has the cold plunge Aman lacks, and it's about half the price" is worth more than five bullet points. Say the trade-off out loud. If something they want is a bad idea, tell them, kindly, and say why.

2. RECORD. Call the "record" tool with what the turn established — every constraint, with its reason. The reason is the point: a booking whose reason you recorded can be DEFENDED when a flight is cancelled. One without it can only be replaced.

ASK BEFORE YOU BUILD. If you don't yet know something you genuinely need, ask for it — one or two questions, not an interrogation. Don't invent a plan on top of a hole.

NEVER pad. No "Great question!". No summarising back what they just said. No numbered lists of options nobody asked for. If the honest answer is one sentence, write one sentence.

LOOK IT UP — DON'T CLAIM YOU DID.
You have web_search. Use it whenever the answer turns on a fact about the world you cannot verify from memory: tour dates, entry requirements, alliance cutoffs, what a specific hotel actually has, whether a route exists.

NEVER say "let me check" and then answer from memory. NEVER say "I have the dates" unless you searched and actually have them. If you searched, give the ANSWER — the cities, the dates, the specifics — not a status update. If you couldn't find it, say so plainly and ask them for it.

A status update is not an answer. "Let me check the exact dates" followed by "Yes, I have the dates" — with no dates — is the single most damaging thing you can do here, because it teaches them to trust you when you haven't earned it.

ALWAYS REPLY IN TEXT. Even when you record constraints, say something. A tool call with no words is a silent turn, and a silent turn reads as a broken app.`;

async function converse({ message, known = [], history = [], findings = null }) {
  const gaps = coverage(known);
  const knownList = known.length
    ? known.map((c) => `- [${c.hardness}${c.scope ? "/@" + c.scope : ""}] ${c.rationale}`).join("\n")
    : "(nothing yet — this is the start)";

  const res = await anthropic.messages.create({
    model: MODEL,
    max_tokens: 2000,
    system: [{ type: "text", text: CONVERSE_SYSTEM + "\n\n" + SYSTEM, cache_control: { type: "ephemeral" } }],
    // ── Give it a real way to look things up ───────────────────────────────────
    // Research used to be gated by a REGEX I wrote in advance — NEEDS_LOOKUP. Which
    // means it could only check the things I had thought of. Ask it about a band's
    // tour dates and the regex misses, no search runs, and the model — having said
    // "let me check the exact dates" — comes back with "Yes, I have the LANY Asia
    // dates." It never checked. It couldn't. So it just said it had.
    //
    // That is not the model misbehaving. That is me building a system where claiming
    // to have checked was the only available move. A prefilter cannot know what needs
    // checking; only the thing doing the reasoning can. So it gets the tool.
    tools: [
      { type: "web_search_20250305", name: "web_search", max_uses: 3 },
      ...TOOLS,
    ],
    // auto, NOT forced: a turn can be pure conversation ("what does recovery-grade
    // mean?") and recording nothing is the correct answer to it.
    tool_choice: { type: "auto" },
    messages: [
      ...history.map((h) => ({ role: h.role, content: h.content })),
      {
        role: "user",
        content:
          `[What you already know about this trip:\n${knownList}]\n\n` +
          (gaps.length
            ? `[You still don't know: ${gaps.join("; ")}. Ask, if you need it to go further.]\n\n`
            : "") +
          (findings ? `[You just looked this up — cite it, with the URL:\n${findings}]\n\n` : "") +
          message,
      },
    ],
  });

  let reply = res.content.filter((b) => b.type === "text").map((b) => b.text).join("\n").trim();
  const use = res.content.find((b) => b.type === "tool_use" && b.name === "record");
  const out = use?.input || {};

  const constraints = asArray(out.constraints).map(normalize);

  // ── A silent turn must never reach the screen ──────────────────────────────
  // The model can legitimately return a tool call with no text — it happened, and the
  // app rendered an empty WINGMAN bubble. To the user that is not "the model chose
  // brevity", it is a broken app: they said something and the assistant stared back.
  //
  // If it recorded but didn't speak, say what it heard. Never render silence.
  if (!reply) {
    if (constraints.length) {
      const said = constraints.map((c) => c.rationale).filter(Boolean).slice(0, 3);
      reply = said.length
        ? `Noted — ${said.join("; ").replace(/\.$/, "")}.` +
          (gaps.length ? ` Still need to know ${gaps.slice(0, 2).join(" and ")}.` : "")
        : "Noted.";
    } else {
      reply = gaps.length
        ? `Tell me ${gaps.slice(0, 2).join(" and ")} and I can start putting this together.`
        : "Tell me a little more.";
    }
  }

  return {
    reply,
    intents: asArray(out.intents),
    constraints,
    shape: asArray(out.shape).map(stripShape),
    gaps,
    usage: res.usage,
  };
}

module.exports = {
  readTurn, converse, commit, research, coverage,
  shapeTrip, titleFor, stripShape, FORBIDDEN_ON_A_PLAN,
  normalize, asArray, NEEDS_LOOKUP, MODEL, RESEARCH_MODEL,
};
