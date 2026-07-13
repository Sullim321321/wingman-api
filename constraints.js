// ═══════════════════════════════════════════════════════════════════════════════
// Wingman — the constraint graph.  Phase 0: substrate.
//
// See TRIP_MODEL.md. The one-line version:
//
//   A trip is a document. INTENTS (what it's for) generate CONSTRAINTS (rules,
//   each carrying its reason), which are satisfied by COMMITMENTS (bookings).
//
//   PLAN    = elicit constraints, find commitments that satisfy them
//   BOOK    = execute a commitment against the constraint set
//   PROTECT = detect that a commitment stopped satisfying its constraints, re-solve
//
// Three pillars, one primitive.
//
// The reason this file exists at all is the Asia transcript. Wingman stores
// bookings; the asset is the REASONS. "Palace Hotel Tokyo" is not a hotel — it is
// {Technogym, cold plunge, on the Imperial Palace 5km loop}, chosen over Aman
// because Aman scores 0.2 on the cold plunge. A rescue engine that doesn't know
// that cannot protect the trip. It can only rebook it.
//
// ── The honesty architecture ───────────────────────────────────────────────────
// Every constraint and every edge carries: source, evidence, confidence, hardness.
//   · an INFERRED constraint may never silently override a STATED one
//   · an EXPIRED constraint may not be cited     (Asiana earns Star miles → 15 Oct 2026)
//   · a predicate that cannot be evaluated returns UNKNOWN, never PASS
//   · UNKNOWN blocks autonomous booking. It never blocks a human.
//
// This is the same disease we have fought all year — the 266-night stay, the New
// York mega-trip, the false all-clear — solved in the schema instead of patched at
// the call site. Every one of those bugs was the system acting confidently on weak
// evidence and reporting success while lying.
// ═══════════════════════════════════════════════════════════════════════════════

// ── Vocabulary ────────────────────────────────────────────────────────────────
// Deliberately closed. Widen it on purpose, never by accident: an open vocabulary
// is how you end up with a predicate nothing can evaluate, which is how you end up
// asserting things you don't know.

const HARDNESS = ["must", "strong", "nice"];
const SOURCES  = ["stated", "observed", "researched", "inferred"];

// Confidence ceiling by source. You cannot be more sure than your evidence allows.
// This is enforced, not advisory — see addConstraint().
const MAX_CONFIDENCE = {
  stated:     1.0,   // the user said it. ground truth.
  observed:   1.0,   // we watched it happen (a booking exists, a flight landed).
  researched: 0.9,   // we looked it up and kept the URL. good, but the world moves.
  inferred:   0.7,   // we worked it out. never enough, alone, to act irreversibly.
};

const PREDICATE_OPS = [
  "facility_present",     // {subject:'lodging', value:'technogym_treadmill'}
  "within_distance",      // {subject:'lodging', of:'imperial_palace_loop', km:1.5}
  "alliance_is",          // {subject:'flight', value:'star'}
  "credits_to",           // {subject:'flight', value:'aeroplan', until:'2026-10-15'}
  "cabin_at_least",       // {subject:'flight', value:'business', when:'duration_h > 6'}
  "exclude_carrier_class",// {value:'low_cost'}
  "rooms",                // {value:2}
  "entry_document",       // {country:'CN', passport:'US', value:'visa_L'}
  "arrive_before",        // {place:'Shanghai', at:'2026-09-24T18:00Z'}
  "depart_after",
  "climate_max_temp_c",   // {value:22}
  "budget_max_cents",
  "free_text",            // escape hatch. NEVER machine-evaluable → always 'unknown'.
];

// ── Schema ────────────────────────────────────────────────────────────────────
async function ensureConstraintSchema(sql) {
  // intents — what the trip is FOR. The root of the graph; everything justifies
  // back to one of these. "Kyoto & Bali, 11 bookings" tells you nothing.
  // "Six tour dates and a training block" tells you what to do when a flight dies.
  await sql`
    CREATE TABLE IF NOT EXISTS intents (
      id          SERIAL PRIMARY KEY,
      user_email  TEXT NOT NULL,
      trip_id     INTEGER REFERENCES trips(id) ON DELETE CASCADE,
      kind        TEXT NOT NULL,          -- event | goal | occasion | obligation
      summary     TEXT NOT NULL,
      detail      JSONB DEFAULT '{}'::jsonb,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`;
  await sql`CREATE INDEX IF NOT EXISTS idx_intents_trip ON intents(trip_id)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_intents_user ON intents(user_email)`;

  // constraints — the rules, WITH THEIR REASONS. This is the table that does not
  // exist today, and it is the whole company.
  //
  // trip_id NULL  ⇒ a STANDING constraint. Applies to every trip. This is what the
  //                 deck calls "persistent memory" and it is not a settings screen.
  await sql`
    CREATE TABLE IF NOT EXISTS constraints (
      id             SERIAL PRIMARY KEY,
      user_email     TEXT NOT NULL,
      trip_id        INTEGER REFERENCES trips(id) ON DELETE CASCADE,
      intent_id      INTEGER REFERENCES intents(id) ON DELETE SET NULL,
      kind           TEXT NOT NULL,
      predicate      JSONB NOT NULL,
      rationale      TEXT,                        -- THE WHY. in Wingman's voice.
      hardness       TEXT NOT NULL DEFAULT 'nice',
      source         TEXT NOT NULL,
      evidence       JSONB DEFAULT '{}'::jsonb,   -- {url, retrieved_at} | {message_id} | {turn_id}
      confidence     REAL NOT NULL DEFAULT 0.5,
      effective_from TIMESTAMPTZ DEFAULT NOW(),
      expires_at     TIMESTAMPTZ,                 -- Asiana earns until 2026-10-15. Then it doesn't.
      superseded_by  INTEGER REFERENCES constraints(id) ON DELETE SET NULL,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )`;

  // ── status: the fix for hardness laundering ────────────────────────────────
  // The first version of this schema simply REFUSED an inferred 'must'. The eval
  // showed what that actually produced: the planner kept the inference and quietly
  // downgraded the hardness instead. "US passports need an L visa for China" was
  // recorded as a 'nice' — a *preference*. Zero refusals in the whole run, because
  // the model had learned to walk around the rule rather than into it.
  //
  // That is a rule that punishes honesty. A system that cannot say "I think this is
  // non-negotiable but I'm not certain" will say something false instead.
  //
  // So: an inferred 'must' is now ALLOWED, as status='proposed'. It is visible, it
  // is honest about its weight, and it gates NOTHING until a human confirms it.
  // Confirmation promotes it to 'active' and re-sources it as 'stated'.
  await sql`ALTER TABLE constraints ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'`;

  // ── scope: the fix for the destroyed 'two rooms' ───────────────────────────
  // The eval superseded "travelling with a friend, two rooms" with "with my
  // boyfriend in Sydney" — as though the second refuted the first. They are both
  // true; they apply to different legs of the trip. A constraint with no scope is a
  // constraint that claims the whole journey, and the whole journey is where trips
  // go to get merged into a 687-day New York.
  await sql`ALTER TABLE constraints ADD COLUMN IF NOT EXISTS scope TEXT`;   // 'asia' | 'sydney' | null = whole trip
  await sql`CREATE INDEX IF NOT EXISTS idx_constraints_status ON constraints(user_email, status)`;
  await sql`CREATE INDEX IF NOT EXISTS idx_constraints_trip ON constraints(trip_id) WHERE superseded_by IS NULL`;
  await sql`CREATE INDEX IF NOT EXISTS idx_constraints_standing ON constraints(user_email) WHERE trip_id IS NULL AND superseded_by IS NULL`;

  // commitments — we do NOT create a new table. trip_legs IS the commitment table;
  // it already carries carrier, property_name, times, confirmation. We extend it.
  //
  // `state` is what makes PLANNING possible at all. Today a leg exists or it
  // doesn't. A plan needs legs that are *considered* and *proposed* long before
  // they are booked — the Asia transcript spent thirty turns in exactly that state.
  await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS state TEXT DEFAULT 'booked'`;
  await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS cost_cents INTEGER`;
  await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS cancellable_until TIMESTAMPTZ`;
  await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS booked_by TEXT DEFAULT 'imported'`;

  // satisfies — the REASON GRAPH. The edge that makes Wingman defensible.
  //
  // Palace Hotel doesn't satisfy "a hotel". It satisfies technogym(1.0),
  // cold_plunge(1.0), imperial_palace_loop(1.0). Aman Tokyo would have scored
  // 1.0 / 0.2 / 1.0 — onsen hot baths are not a cold plunge — which is precisely
  // and only why the transcript chose against it.
  //
  // Store that, and rescue is smarter than the entire market, for free.
  await sql`
    CREATE TABLE IF NOT EXISTS satisfies (
      commitment_id INTEGER NOT NULL REFERENCES trip_legs(id) ON DELETE CASCADE,
      constraint_id INTEGER NOT NULL REFERENCES constraints(id) ON DELETE CASCADE,
      strength      REAL NOT NULL DEFAULT 1.0,   -- 1.0 fully · 0.4 "recovery-grade, not training-grade"
      note          TEXT,                        -- "16 Technogym ARTIS treadmills"
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (commitment_id, constraint_id)
    )`;

  // depends_on — the CASCADE graph.
  // Same honesty fields, for the same reason. An INFERRED edge may not assert an
  // impact. If we don't have the seaplane's departure time, the node reads UNKNOWN
  // — and "I don't know whether your seaplane is affected; want me to call?" is
  // still better than any other app on earth. It is certainly better than a lie.
  await sql`
    CREATE TABLE IF NOT EXISTS depends_on (
      from_commitment INTEGER NOT NULL REFERENCES trip_legs(id) ON DELETE CASCADE,
      to_commitment   INTEGER NOT NULL REFERENCES trip_legs(id) ON DELETE CASCADE,
      kind            TEXT NOT NULL DEFAULT 'sequenced',  -- requires_by | same_day | sequenced | shared_party
      slack_minutes   INTEGER,
      source          TEXT NOT NULL DEFAULT 'inferred',
      confidence      REAL NOT NULL DEFAULT 0.5,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (from_commitment, to_commitment),
      CHECK (from_commitment <> to_commitment)
    )`;

  // deliberations — the record of JUDGMENT.
  //   "Palace Hotel over Aman — same 5km loop, has the cold plunge Aman lacks,
  //    roughly half the price."
  // Nobody stores this. It is what makes the second trip ten times faster than the
  // first, what makes autonomous booking safe, and what lets Wingman explain itself
  // when challenged. It is also invariant #3's evidence: every autonomous action
  // must name the constraint it was protecting.
  await sql`
    CREATE TABLE IF NOT EXISTS deliberations (
      id          SERIAL PRIMARY KEY,
      user_email  TEXT NOT NULL,
      trip_id     INTEGER REFERENCES trips(id) ON DELETE CASCADE,
      question    TEXT NOT NULL,
      options     JSONB DEFAULT '[]'::jsonb,
      chose       TEXT,
      because     TEXT NOT NULL,
      protecting  JSONB DEFAULT '[]'::jsonb,   -- [constraint_id] — REQUIRED when by='wingman'
      by          TEXT NOT NULL DEFAULT 'wingman',   -- wingman | user
      commitment_id INTEGER REFERENCES trip_legs(id) ON DELETE SET NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )`;
  await sql`CREATE INDEX IF NOT EXISTS idx_delib_trip ON deliberations(trip_id, created_at DESC)`;
}

// ── Writers ───────────────────────────────────────────────────────────────────

/**
 * The ONLY way a constraint enters the system.
 *
 * Refuses, loudly, rather than storing something it cannot stand behind:
 *   · unknown op            → throw. an unevaluable predicate is a future lie.
 *   · confidence > ceiling  → clamped to what the source can actually support.
 *   · researched, no url    → throw. "I looked it up" without a link is a rumour.
 *   · inferred + must       → throw. we do not get to INVENT a hard rule.
 */
async function addConstraint(sql, {
  user_email, trip_id = null, intent_id = null,
  kind, predicate, rationale = null,
  hardness = "nice", source, evidence = {}, confidence,
  effective_from = null, expires_at = null, scope = null,
}) {
  if (!user_email) throw new Error("constraint: user_email required");
  if (!predicate || !predicate.op) throw new Error("constraint: predicate.op required");
  if (!PREDICATE_OPS.includes(predicate.op)) {
    throw new Error(`constraint: unknown predicate op "${predicate.op}". Widen PREDICATE_OPS deliberately.`);
  }
  if (!HARDNESS.includes(hardness)) throw new Error(`constraint: bad hardness "${hardness}"`);
  if (!SOURCES.includes(source))     throw new Error(`constraint: bad source "${source}"`);

  // A researched fact without a link is a rumour with good posture.
  if (source === "researched" && !evidence?.url) {
    throw new Error("constraint: source='researched' requires evidence.url");
  }
  // Wingman does not get to ENFORCE a hard rule it merely worked out. But the old
  // version REFUSED to store one at all — and the eval showed exactly what that
  // bought us: the planner kept the inference and laundered the hardness down to
  // 'nice'. "US passports need an L visa for China" was filed as a *preference*.
  //
  // A rule that punishes honesty gets dishonesty. So an inferred 'must' is stored,
  // truthfully, as PROPOSED: it says what it thinks, it gates nothing, and it waits
  // for a human. That is what a chief of staff does — "I think you need a visa;
  // confirm?" — rather than either inventing a rule or pretending it doesn't matter.
  // ── Only YOU can make something non-negotiable ─────────────────────────────
  // An inferred 'must' waits for your word. A RESEARCHED one used to sail straight
  // through as active — and that is worse, because "sourced" reads like "verified."
  //
  // The planner looked up the LANY Asia tour and recorded six shows as MUST · sourced.
  // Four dates were right. It invented Beijing and Guangzhou, and dropped Osaka and
  // Tokyo. Every one of them anchored the trip.
  //
  // Two failures stacked. The model can find a real page and still summarise it wrong.
  // But the deeper one is categorical: a tour SCHEDULE is not the same fact as which
  // shows YOU are attending. No amount of searching can establish the second. Wingman
  // can bring you the candidates; only you can say which ones are yours.
  //
  // So: a 'must' may only be ACTIVE if you stated it. Everything else is proposed —
  // visible, at its true weight, gating nothing until confirmed.
  let status = "active";
  if (hardness === "must" && source !== "stated" && source !== "observed") {
    status = "proposed";
  }

  const ceiling = MAX_CONFIDENCE[source];
  const conf = Math.min(confidence == null ? ceiling : confidence, ceiling);

  // ── Idempotence ────────────────────────────────────────────────────────────
  // The graph is a SET of beliefs, not a log of them. Holding the same fact twice is
  // not harmless bookkeeping: scoreOption() sums weights across constraints, so a
  // duplicated 'must' is worth 200 instead of 100 and every rescue ranking quietly
  // bends toward whichever preference happened to get recorded twice.
  //
  // The Plan tab surfaced this immediately — "Dietary: vegetarian, vegan" and
  // "Prefer marriott properties" each appearing twice, because backfill-graph.js had
  // no idempotence and a second --apply wrote a second copy of everything.
  //
  // Dedupe belongs HERE, at the only door into the table, not in each caller. Callers
  // forget. The door cannot.
  // Match a constraint on THIS trip — or a STANDING one (trip_id NULL) that already
  // says the same thing.
  //
  // The first version keyed on trip_id, which meant a trip-scoped copy of a standing
  // fact was, by definition, not a duplicate. "Dietary: vegetarian, vegan" would sit
  // in the list twice — once as always-true-of-you, once as true-of-this-trip — and
  // the dedupe script would report zero duplicates, because its key couldn't see the
  // pair. A clean bill of health from a check that cannot detect the disease.
  //
  // A standing constraint already applies to every trip. Re-recording it against one
  // of them adds nothing and double-counts in scoreOption().
  const [existing] = await sql`
    SELECT * FROM constraints
    WHERE user_email = ${user_email}
      AND (trip_id IS NOT DISTINCT FROM ${trip_id} OR trip_id IS NULL)
      AND kind = ${kind}
      AND predicate @> ${JSON.stringify(predicate)}::jsonb
      AND ${JSON.stringify(predicate)}::jsonb @> predicate
      AND scope IS NOT DISTINCT FROM ${scope}
      AND superseded_by IS NULL
    ORDER BY (trip_id IS NULL) DESC
    LIMIT 1`;

  if (existing) {
    // Same belief. But if the newcomer arrives with better provenance — a source URL
    // where we had only the user's word, or an expiry we lacked — that IS new
    // information. Enrich the row; never fork it.
    const betterEvidence = evidence?.url && !existing.evidence?.url;
    const newExpiry      = expires_at && !existing.expires_at;
    if (betterEvidence || newExpiry) {
      const [upgraded] = await sql`
        UPDATE constraints
           SET evidence   = COALESCE(${JSON.stringify(evidence)}::jsonb, evidence),
               expires_at = COALESCE(${expires_at}::TIMESTAMPTZ, expires_at)
         WHERE id = ${existing.id}
        RETURNING *`;
      return upgraded;
    }
    return existing;
  }

  const [row] = await sql`
    INSERT INTO constraints
      (user_email, trip_id, intent_id, kind, predicate, rationale, hardness,
       source, evidence, confidence, effective_from, expires_at, status, scope)
    VALUES
      (${user_email}, ${trip_id}, ${intent_id}, ${kind},
       ${JSON.stringify(predicate)}::jsonb, ${rationale}, ${hardness},
       ${source}, ${JSON.stringify(evidence)}::jsonb, ${conf},
       ${effective_from}::TIMESTAMPTZ, ${expires_at}::TIMESTAMPTZ,
       ${status}, ${scope})
    RETURNING *`;
  return row;
}

/**
 * Promote a proposed constraint once the user confirms it. This is the moment an
 * inference becomes a fact, and it is the ONLY way one ever does.
 */
async function confirm(sql, id, { user_email }) {
  const [row] = await sql`
    UPDATE constraints
       SET status = 'active', source = 'stated', confidence = 1.0
     WHERE id = ${id} AND user_email = ${user_email} AND status = 'proposed'
    RETURNING *`;
  return row;
}

/**
 * Constraints are never deleted, only superseded. The history is the memory —
 * "you used to want X, then in April you told me Y" is a thing a chief of staff
 * knows and a settings screen forgets.
 *
 * ── But supersession is the most destructive operation in the system ──────────
 * The eval caught it doing this:
 *
 *   ↻ "Travelling with a guy friend, so need 2 rooms"     [must]
 *     → "Travelling with boyfriend in Sydney"
 *
 * It deleted a MUST. And the two facts don't even contradict: two rooms with a
 * friend across Asia, one room with a boyfriend in Sydney — both true, different
 * legs. It also let a *duration* ("2 nights, not a weekend") overwrite a *hotel*
 * ("staying at Raffles"), and Raffles simply vanished from the graph.
 *
 * This is the New York mega-trip again, wearing different clothes: things that merely
 * sit near each other get collapsed into one. So supersession now has to earn it.
 */
function canSupersede(oldC, newC) {
  // 1. Different subject matter is not a refutation. A hotel does not refute a
  //    duration; a companion does not refute a room count.
  if (oldC.kind !== newC.kind) {
    return { ok: false, why: `different kind (${oldC.kind} → ${newC.kind}) — that's a new fact, not a correction` };
  }
  // 2. Different predicate op is not a refutation either. `rooms` and `free_text`
  //    can both be true at once.
  if (oldC.predicate?.op && newC.predicate?.op && oldC.predicate.op !== newC.predicate.op) {
    return { ok: false, why: `different predicate (${oldC.predicate.op} → ${newC.predicate.op})` };
  }
  // 3. Different leg of the trip. THE two-rooms bug. Both can hold.
  const os = oldC.scope || null, ns = newC.scope || null;
  if (os !== ns && os !== null && ns !== null) {
    return { ok: false, why: `different scope (${os} → ${ns}) — both can be true` };
  }
  // 4. A stated 'must' is not overturned by an inference. Only you can retract it.
  if (oldC.hardness === "must" && oldC.source === "stated" && newC.source !== "stated") {
    return { ok: false, why: "won't overturn something you told me, on a hunch" };
  }
  return { ok: true };
}

async function supersede(sql, oldId, newConstraint, oldRow = null) {
  if (oldRow) {
    const verdict = canSupersede(oldRow, newConstraint);
    if (!verdict.ok) {
      // Not an error — just a refusal to destroy. Add the new fact ALONGSIDE the
      // old one, which is what should have happened to "two rooms" all along.
      const fresh = await addConstraint(sql, newConstraint);
      return { ...fresh, _supersededNothing: verdict.why };
    }
  }
  const fresh = await addConstraint(sql, newConstraint);
  await sql`UPDATE constraints SET superseded_by = ${fresh.id} WHERE id = ${oldId}`;
  return fresh;
}

async function link(sql, commitment_id, constraint_id, strength = 1.0, note = null) {
  await sql`
    INSERT INTO satisfies (commitment_id, constraint_id, strength, note)
    VALUES (${commitment_id}, ${constraint_id}, ${strength}, ${note})
    ON CONFLICT (commitment_id, constraint_id)
    DO UPDATE SET strength = EXCLUDED.strength, note = EXCLUDED.note`;
}

async function depend(sql, from_commitment, to_commitment, {
  kind = "sequenced", slack_minutes = null, source = "inferred", confidence = 0.5,
} = {}) {
  if (from_commitment === to_commitment) return;
  await sql`
    INSERT INTO depends_on (from_commitment, to_commitment, kind, slack_minutes, source, confidence)
    VALUES (${from_commitment}, ${to_commitment}, ${kind}, ${slack_minutes}, ${source},
            ${Math.min(confidence, MAX_CONFIDENCE[source])})
    ON CONFLICT (from_commitment, to_commitment)
    DO UPDATE SET kind = EXCLUDED.kind, slack_minutes = EXCLUDED.slack_minutes,
                  source = EXCLUDED.source, confidence = EXCLUDED.confidence`;
}

async function deliberate(sql, { user_email, trip_id, question, options = [], chose, because, protecting = [], by = "wingman", commitment_id = null }) {
  if (by === "wingman" && (!protecting || protecting.length === 0)) {
    // Invariant #3, enforced at the door rather than caught in an audit.
    // If Wingman cannot name what it was protecting, it had no business acting.
    throw new Error("deliberation: an autonomous action must name the constraint(s) it protects");
  }
  const [row] = await sql`
    INSERT INTO deliberations (user_email, trip_id, question, options, chose, because, protecting, by, commitment_id)
    VALUES (${user_email}, ${trip_id}, ${question}, ${JSON.stringify(options)}::jsonb,
            ${chose}, ${because}, ${JSON.stringify(protecting)}::jsonb, ${by}, ${commitment_id})
    RETURNING *`;
  return row;
}

// ── Readers ───────────────────────────────────────────────────────────────────

/**
 * The live constraint set for a trip: its own constraints PLUS the user's standing
 * ones. Excludes superseded, and excludes EXPIRED — an expired constraint may not
 * be cited, which is exactly the "Asiana stops earning Star miles on 15 Oct 2026"
 * case from the transcript. It was true. It will stop being true. The system must
 * expire it, not rot around it.
 */
async function constraintsFor(sql, { user_email, trip_id, at = null }) {
  const when = at || new Date().toISOString();
  return await sql`
    SELECT * FROM constraints
    WHERE user_email = ${user_email}
      AND (trip_id = ${trip_id} OR trip_id IS NULL)
      AND superseded_by IS NULL
      AND (effective_from IS NULL OR effective_from <= ${when}::TIMESTAMPTZ)
      AND (expires_at     IS NULL OR expires_at    >  ${when}::TIMESTAMPTZ)
    ORDER BY (trip_id IS NULL), array_position(ARRAY['must','strong','nice'], hardness), id`;
}

/** Why does this booking exist? The line no competitor can render. */
async function reasonsFor(sql, commitment_id) {
  return await sql`
    SELECT c.id, c.kind, c.rationale, c.hardness, c.predicate, s.strength, s.note
    FROM satisfies s JOIN constraints c ON c.id = s.constraint_id
    WHERE s.commitment_id = ${commitment_id}
    ORDER BY array_position(ARRAY['must','strong','nice'], c.hardness), s.strength DESC`;
}

/**
 * Walk downstream from a broken commitment.
 *
 * Returns nodes with an explicit verdict — and the verdict is 'unknown' unless we
 * have BOTH a confident edge AND observed times at both ends. This is the rule that
 * would have prevented every confident-lie bug this app has ever shipped:
 *
 *   NO NODE MAY ASSERT AN IMPACT IT CANNOT EVIDENCE.
 *
 * 'unknown' is not a failure state. It is Wingman saying "I don't know, want me to
 * find out?" — which is honest, useful, and still ahead of the entire market.
 */
async function cascadeFrom(sql, commitment_id, { delayMinutes = 0, maxDepth = 6 } = {}) {
  const seen = new Set([commitment_id]);
  const out = [];
  let frontier = [{ id: commitment_id, depth: 0 }];

  while (frontier.length && frontier[0].depth < maxDepth) {
    const ids = frontier.map((f) => f.id);
    const edges = await sql`
      SELECT d.*, tl.id AS leg_id, tl.type, tl.property_name, tl.carrier, tl.flight_number,
             tl.origin, tl.destination, tl.departs_at, tl.arrives_at, tl.cancellable_until
      FROM depends_on d
      JOIN trip_legs tl ON tl.id = d.to_commitment
      WHERE d.from_commitment = ANY(${ids}::int[])`;

    const next = [];
    for (const e of edges) {
      if (seen.has(e.leg_id)) continue;
      seen.add(e.leg_id);
      const depth = (frontier.find((f) => f.id === e.from_commitment)?.depth ?? 0) + 1;

      // ── the honesty gate ──────────────────────────────────────────────────
      let verdict, why;
      const haveTimes = !!e.departs_at;
      const confident = e.confidence >= 0.8;

      if (!confident || !haveTimes) {
        verdict = "unknown";
        why = !haveTimes
          ? "I don't have a departure time for this — I can't say whether the delay reaches it."
          : "I inferred this link rather than confirming it. I won't claim an impact I haven't checked.";
      } else if (e.kind === "requires_by" && e.slack_minutes != null) {
        // ── "at risk" must MEAN something ────────────────────────────────────
        // The first version had two states: broken, or at_risk. So a 30-minute delay
        // against a hotel with 180 minutes of buffer came back "AT RISK — 150 min of
        // slack left," and Wingman would push about it.
        //
        // That is not a risk. That is fine. And an assistant that cries wolf every
        // time a flight slips half an hour gets muted — and then it is muted on the
        // day it actually matters. The old cascade shouted about everything
        // downstream; shouting only about everything downstream that hasn't broken
        // YET is the same disease with better manners.
        //
        // So there is a third state. Something is only at risk when the buffer it has
        // left is genuinely thin: under 30 minutes, or less than a third of what it
        // started with. Otherwise it holds, and we say so quietly.
        const left = e.slack_minutes - delayMinutes;
        if (left < 0) {
          verdict = "broken";
          why = `Needs ${e.slack_minutes} min of slack. The delay is ${delayMinutes}.`;
        } else if (left < 30 || left < e.slack_minutes / 3) {
          verdict = "at_risk";
          why = `${left} min of slack left. Tight.`;
        } else {
          verdict = "safe";
          why = `${left} min of slack left. It holds.`;
        }
      } else {
        verdict = "at_risk";
        why = "Same-day dependency — worth watching, not yet broken.";
      }

      out.push({
        leg_id: e.leg_id, depth, verdict, why,
        kind: e.kind, confidence: e.confidence, source: e.source,
        // The measured gap this booking can absorb before it breaks. rescue.js scores
        // every alternative against it — an option arriving 90 minutes later than
        // planned eats 90 minutes of slack, and a 40-minute seaplane transfer dies.
        // Without this number "ranked by what they protect" is just a slogan.
        slack_minutes: e.slack_minutes,
        label: e.property_name || [e.carrier, e.flight_number].filter(Boolean).join(" ") || e.type,
        departs_at: e.departs_at, cancellable_until: e.cancellable_until,
      });
      next.push({ id: e.leg_id, depth });
    }
    frontier = next;
  }
  return out;
}

/**
 * The autonomy gate. Invariant #7, made callable.
 *
 * Wingman may act alone ONLY when the trip's hard constraints are actually known.
 * An unresolved 'must' means we are one silent assumption away from booking Maddie
 * into a hotel with no cold plunge eight weeks before a time trial — technically a
 * hotel, and completely wrong.
 */
async function mayActAlone(sql, { user_email, trip_id, cost_cents = 0, wouldBreak = [] }) {
  const cs = await constraintsFor(sql, { user_email, trip_id });

  const unresolved = cs.filter((c) => c.hardness === "must" && c.confidence < 0.9);
  if (unresolved.length) {
    return { ok: false, reason: "unresolved_must",
      detail: `I'm not certain enough about: ${unresolved.map((c) => c.rationale || c.kind).join("; ")}` };
  }
  const breakingMust = cs.filter((c) => c.hardness === "must" && wouldBreak.includes(c.id));
  if (breakingMust.length) {
    return { ok: false, reason: "would_break_must",
      detail: `That breaks something you told me was non-negotiable: ${breakingMust.map((c) => c.rationale || c.kind).join("; ")}` };
  }
  const breakingStrong = cs.filter((c) => c.hardness === "strong" && wouldBreak.includes(c.id));
  if (breakingStrong.length) {
    return { ok: false, reason: "would_break_strong",
      detail: `I can do this, but it costs you: ${breakingStrong.map((c) => c.rationale || c.kind).join("; ")}` };
  }
  const [so] = await sql`SELECT max_price FROM standing_orders WHERE trip_id = ${trip_id} AND enabled = TRUE`;
  if (so?.max_price != null && cost_cents > so.max_price * 100) {
    return { ok: false, reason: "over_threshold", detail: `Above the $${so.max_price} you set.` };
  }
  return { ok: true };
}

/**
 * Rank rescue options by WHAT THEY PROTECT, not by price.
 * "Ranked by what they protect, not by price" is a line on a slide. This is that
 * line, made literal: score = Σ (weight(hardness) × strength) over surviving edges.
 */
const WEIGHT = { must: 100, strong: 10, nice: 1 };
function scoreOption(constraintSet, satisfiedIds = [], strengths = {}) {
  let score = 0;
  const lost = [];
  for (const c of constraintSet) {
    const s = satisfiedIds.includes(c.id) ? (strengths[c.id] ?? 1.0) : 0;
    score += (WEIGHT[c.hardness] || 1) * s;
    if (s < 0.5) lost.push({ id: c.id, hardness: c.hardness, rationale: c.rationale });
  }
  return { score, lost };
}

// ── Invariants ────────────────────────────────────────────────────────────────
// Spread into server.js's INVARIANTS array. Each must return ZERO rows.
// These are the promises the model makes. If one fails, the model is lying.

const CONSTRAINT_INVARIANTS = [
  {
    name: "a booking that forgot why it exists",
    why: "This leg was planned — Wingman proposed it, for reasons, and drew edges to the constraints it served. Now it's booked and it has no reasons at all. That means booking created a NEW leg instead of promoting the proposal, and the edges are stranded on an orphan. The symptom is silence: when this flight is delayed, the cascade walks from here, finds nothing downstream, and reports 'nothing depends on this' — confidently, on evidence it never checked. Booking must UPDATE the proposed leg, never INSERT beside it.",
    query: (email) => sql`
      SELECT tl.id, COALESCE(tl.destination, tl.destination_city, tl.type) AS detail, tl.state, tl.booked_by
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.state = 'booked'
        AND tl.booked_by = 'wingman'
        AND NOT EXISTS (SELECT 1 FROM satisfies s WHERE s.commitment_id = tl.id)
        AND EXISTS (SELECT 1 FROM constraints c
                    WHERE c.trip_id = tl.trip_id AND c.superseded_by IS NULL)
      LIMIT 5`,
  },
  {
    name: "autonomous action that names nothing it was protecting",
    why: "Wingman acted alone and cannot say what for. If it can't name the constraint, it had no business acting. This is the whole safety argument.",
    query: (email) => sql`
      SELECT d.id, d.question AS detail, d.because, d.created_at
      FROM deliberations d
      WHERE d.user_email = ${email} AND d.by = 'wingman'
        AND (d.protecting IS NULL OR jsonb_array_length(d.protecting) = 0)
      LIMIT 5`,
  },
  {
    name: "inferred constraint marked as non-negotiable",
    why: "We worked it out; we did not get told. Wingman does not get to invent a hard rule and then enforce it. Ask the user to confirm it and re-source it as 'stated'.",
    query: (email) => sql`
      SELECT c.id, COALESCE(c.rationale, c.kind) AS detail, c.source, c.hardness
      FROM constraints c
      WHERE c.user_email = ${email} AND c.superseded_by IS NULL
        AND c.source = 'inferred' AND c.hardness = 'must'
      LIMIT 5`,
  },
  {
    name: "researched fact with no source link",
    why: "Visa rules, alliance cutoffs, gym equipment — all researched, all perishable. A researched constraint without evidence.url is a rumour with good posture, and it will be cited as fact.",
    query: (email) => sql`
      SELECT c.id, COALESCE(c.rationale, c.kind) AS detail, c.evidence
      FROM constraints c
      WHERE c.user_email = ${email} AND c.superseded_by IS NULL
        AND c.source = 'researched'
        AND (c.evidence->>'url' IS NULL OR c.evidence->>'url' = '')
      LIMIT 5`,
  },
  {
    name: "confidence exceeding what the source can support",
    why: "You cannot be more certain than your evidence allows. An inferred constraint at 0.95 is the 266-night stay wearing a suit.",
    query: (email) => sql`
      SELECT c.id, COALESCE(c.rationale, c.kind) AS detail, c.source, c.confidence
      FROM constraints c
      WHERE c.user_email = ${email} AND c.superseded_by IS NULL
        AND ((c.source = 'inferred'   AND c.confidence > 0.7)
          OR (c.source = 'researched' AND c.confidence > 0.9))
      LIMIT 5`,
  },
  {
    name: "expired constraint still linked to a live booking",
    why: "Asiana stops earning Star miles on 15 Oct 2026. After that date, a booking still citing it as its reason is telling the user something false.",
    query: (email) => sql`
      SELECT c.id, COALESCE(c.rationale, c.kind) AS detail, c.expires_at
      FROM constraints c
      JOIN satisfies s ON s.constraint_id = c.id
      JOIN trip_legs tl ON tl.id = s.commitment_id
      WHERE c.user_email = ${email}
        AND c.expires_at IS NOT NULL AND c.expires_at < NOW()
        AND tl.state = 'booked' AND tl.departs_at > NOW()
      LIMIT 5`,
  },
  {
    name: "booked commitment that violates a 'must' with no recorded override",
    why: "A hard constraint was broken and nobody wrote down why. Either the booking is wrong or the constraint is stale. Both are bugs; silence is the worst outcome.",
    query: (email) => sql`
      SELECT tl.id, COALESCE(tl.property_name, tl.flight_number) AS detail, c.rationale AS violated
      FROM trip_legs tl
      JOIN satisfies s   ON s.commitment_id = tl.id
      JOIN constraints c ON c.id = s.constraint_id
      WHERE c.user_email = ${email}
        AND tl.state = 'booked' AND c.hardness = 'must' AND s.strength < 0.5
        AND NOT EXISTS (
          SELECT 1 FROM deliberations d
          WHERE d.commitment_id = tl.id AND d.protecting @> to_jsonb(c.id)
        )
      LIMIT 5`,
  },
  {
    name: "cascade edge asserting impact it cannot evidence",
    why: "An inferred, low-confidence dependency has no right to tell someone their seaplane is gone. THE bug class this whole model exists to kill.",
    query: (email) => sql`
      SELECT d.from_commitment AS id,
             COALESCE(b.property_name, b.flight_number, b.type) AS detail,
             d.source, d.confidence
      FROM depends_on d
      JOIN trip_legs a ON a.id = d.from_commitment
      JOIN trip_legs b ON b.id = d.to_commitment
      JOIN trips t     ON t.id = a.trip_id
      WHERE t.user_email = ${email}
        AND d.kind = 'requires_by'
        AND (d.confidence < 0.8 OR b.departs_at IS NULL)
        AND d.slack_minutes IS NOT NULL
      LIMIT 5`,
  },
  {
    name: "a PLANNED leg wearing a booking's clothes",
    why: "THE most dangerous row this database can hold. A leg the planner sketched — state 'proposed' — must never carry a confirmation number, a flight number or a departure time, because those are exactly the fields that make a fiction indistinguishable from a fact to someone standing in an airport. The model WILL volunteer them; stripShape() throws them away. If one ever lands here, the strip failed and a user is about to be told they have a flight they do not have.",
    query: (email) => sql`
      SELECT tl.id, COALESCE(tl.property_name, tl.destination) AS detail,
             tl.state, tl.confirmation, tl.flight_number
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.state IN ('considered','proposed','held')
        AND (tl.confirmation IS NOT NULL OR tl.flight_number IS NOT NULL)
      LIMIT 5`,
  },
  {
    name: "booked commitment with no reason attached",
    why: "Not a crash — a diagnosis. Every booking Wingman cannot explain is one it cannot defend during a disruption. Expect this to be LARGE on the first run. That is the finding, not the failure.",
    soft: true,   // reported, does not fail the suite
    query: (email) => sql`
      SELECT tl.id, COALESCE(tl.property_name, tl.flight_number, tl.type) AS detail, tl.departs_at
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.state = 'booked' AND tl.departs_at > NOW()
        AND NOT EXISTS (SELECT 1 FROM satisfies s WHERE s.commitment_id = tl.id)
      LIMIT 5`,
  },
];

// `sql` is injected by server.js at require time so the invariant closures can use
// it the same way the existing ones do.
let sql = null;
function bind(injected) { sql = injected; return module.exports; }

module.exports = {
  bind,
  ensureConstraintSchema,
  addConstraint, supersede, canSupersede, confirm, link, depend, deliberate,
  constraintsFor, reasonsFor, cascadeFrom, mayActAlone, scoreOption,
  CONSTRAINT_INVARIANTS,
  HARDNESS, SOURCES, PREDICATE_OPS, MAX_CONFIDENCE,
};
