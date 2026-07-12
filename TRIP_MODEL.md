# Wingman — The Trip Model

*The foundation. Everything else is derived from this.*
*Written July 2026, against the pre-seed deck and the Asia Tour 2026 planning transcript.*

---

## 0. Why this document exists

We have been building the second half of the trip.

The deck promises **Plan → Book → Protect**. What we shipped is **Ingest → Monitor → Protect**. The difference is that ingestion assumes the trip already exists — planned elsewhere, booked elsewhere, arriving at Wingman as an email receipt. Every screen in the app today is downstream of that assumption.

The Asia transcript is what Plan actually looks like: forty exchanges that accumulate a constraint system — two rooms, companion TBD; Star Alliance credited to Aeroplan; Asiana earns nothing after 15 Oct 2026; Technogym treadmills, cold plunge, 30m pool, because there is an Olympic-qualifying 5K eight to ten weeks out; training-grade not recovery-grade; cool climates over the reef *because of the training block*; Palace Hotel over Aman — same Imperial Palace loop, has the cold plunge, half the price.

**Wingman stores bookings. The asset is the reasons.**

And the reasons are not a nicety for the planning half. They are what makes the protecting half work at all:

> If Tokyo is disrupted and Wingman must move the hotel, today's system finds *a hotel in Tokyo*. It should know the constraint is **flat 5km loop, Technogym, cold plunge, eight weeks out from a time trial** — and that "Aman" was never the point.

**A rescue engine that does not know why you booked something cannot protect it.** Protection without reasons is rebooking.

So Plan and Protect are not two pillars. They are the same graph, read in two directions.

---

## 1. The model in one paragraph

A **trip** is a document. The document is a set of **intents** (what the trip is for), which generate **constraints** (rules that must or should hold), which are satisfied by **commitments** (the actual bookings). Wingman's entire job is to keep commitments consistent with constraints — and to say so, loudly and honestly, when it cannot.

- **Planning** is the act of eliciting constraints and finding commitments that satisfy them.
- **Booking** is executing a commitment against a constraint set.
- **Protecting** is detecting that a commitment has stopped satisfying its constraints, and re-solving.

Three pillars, one primitive.

---

## 2. The objects

### `intents` — what the trip is for
The root of the graph. Everything justifies back to one of these.

```
intents (
  id, trip_id, user_email,
  kind        TEXT,   -- 'event' | 'goal' | 'occasion' | 'obligation'
  summary     TEXT,   -- "Attend all six tour dates"
                      -- "Qualify for Olympic trials in the 5K (Thanksgiving race, ~8-10wks out)"
                      -- "A week with my boyfriend in Sydney"
  detail      JSONB,
  created_at
)
```

Intents are the thing that makes a trip *legible*. "Kyoto & Bali, 11 bookings" tells you nothing. "Six shows and a training block" tells you everything, including what to do when a flight dies.

### `constraints` — the rules, with their reasons
The heart of the system. This is what does not exist today.

```
constraints (
  id, trip_id, user_email,        -- trip_id NULL = a standing constraint (applies to all trips)
  intent_id   INTEGER,            -- what this serves. NULL = free-standing preference.
  kind        TEXT,               -- 'entry' | 'routing' | 'cabin' | 'loyalty' | 'lodging'
                                  -- | 'facility' | 'timing' | 'party' | 'budget' | 'climate'
  predicate   JSONB,              -- machine-checkable. see §3.
  rationale   TEXT,               -- THE WHY. free text, in Wingman's voice.
                                  -- "Cold plunge, because the Thanksgiving 5K is 8 weeks out."
  hardness    TEXT,               -- 'must' | 'strong' | 'nice'
  source      TEXT,               -- 'stated' | 'inferred' | 'researched' | 'observed'
  evidence    JSONB,              -- {url, retrieved_at} | {message_id} | {booking_id} | {turn_id}
  confidence  REAL,               -- 0..1. 1.0 only for 'stated' and 'observed'.
  effective_from TIMESTAMPTZ,
  expires_at  TIMESTAMPTZ,        -- Asiana earns Star miles until 2026-10-15. Then it doesn't.
  superseded_by INTEGER,          -- constraints are never deleted, only superseded
  created_at
)
```

Four fields carry the entire honesty architecture — `source`, `evidence`, `confidence`, `hardness`. A constraint Wingman **inferred** may never silently override one you **stated**. A constraint that has **expired** may not be cited. A constraint with no **evidence** may not be asserted as fact.

This is the same disease we have fought all year — the 266-night stay, the New York mega-trip, the false all-clear — solved structurally instead of patched.

### `commitments` — the bookings *(evolves `trip_legs`)*
Keep the existing table and columns. Add:

```
ALTER TABLE trip_legs ADD COLUMN state TEXT DEFAULT 'booked';
  -- 'considered' | 'proposed' | 'held' | 'booked' | 'cancelled'
ALTER TABLE trip_legs ADD COLUMN cost_cents INTEGER;
ALTER TABLE trip_legs ADD COLUMN cancellable_until TIMESTAMPTZ;
ALTER TABLE trip_legs ADD COLUMN booked_by TEXT;  -- 'user' | 'wingman' | 'imported'
```

`state` is what makes planning possible. Today a leg exists or it doesn't. A plan needs legs that are *considered* and *proposed* before they are ever booked — the transcript spent thirty turns in that state.

### `satisfies` — the reason graph
The edge that makes Wingman defensible.

```
satisfies (
  commitment_id, constraint_id,
  strength  REAL,     -- how well. 1.0 = fully. 0.4 = partially ("recovery-grade, not training-grade")
  note      TEXT      -- "16 Technogym ARTIS treadmills"
)
```

When Palace Hotel Tokyo is booked, it does not satisfy "a hotel." It satisfies *Technogym*, *cold plunge*, *on the Imperial Palace 5km loop*, at *strength 1.0, 1.0, 1.0* — and Aman Tokyo would have satisfied the first and third but scored **0.2** on the second, which is exactly why the transcript chose against it.

Store that, and rescue becomes trivially smarter than any competitor.

### `depends_on` — the cascade graph
```
depends_on (
  from_commitment, to_commitment,
  kind        TEXT,     -- 'requires_by' | 'same_day' | 'sequenced' | 'shared_party'
  slack_minutes INTEGER,
  source      TEXT,     -- 'stated' | 'inferred' | 'observed'
  confidence  REAL
)
```

Same honesty fields. **An inferred edge may not assert an impact.** If Wingman does not have the seaplane's departure time, the cascade node reads `unknown` — and *"I don't know whether your seaplane is affected; want me to call?"* is still better than any other app on earth.

### `deliberations` — the record of judgment
```
deliberations (
  id, trip_id, question TEXT, options JSONB,
  chose INTEGER, because TEXT, at TIMESTAMPTZ, by TEXT  -- 'wingman' | 'user'
)
```

> *"Palace Hotel over Aman Tokyo — same 5km loop, has the cold plunge Aman lacks, roughly half the price."*

Nobody stores this. It is what makes the second trip ten times faster than the first, what makes autonomous booking safe, and what lets Wingman explain itself when challenged.

---

## 3. Predicates

`predicate` must be machine-checkable or it is decoration. A small closed vocabulary, extended deliberately:

```json
{"op":"facility_present","subject":"lodging","value":"technogym_treadmill"}
{"op":"facility_present","subject":"lodging","value":"cold_plunge"}
{"op":"within_distance","subject":"lodging","of":"imperial_palace_loop","km":1.5}
{"op":"alliance_is","subject":"flight","value":"star"}
{"op":"credits_to","subject":"flight","value":"aeroplan","until":"2026-10-15"}
{"op":"cabin_at_least","subject":"flight","value":"business","when":"duration_h > 6"}
{"op":"exclude_carrier_class","value":"low_cost"}
{"op":"rooms","value":2}
{"op":"entry_document","country":"CN","passport":"US","value":"visa_L"}
{"op":"arrive_before","place":"Shanghai","at":"2026-09-24T18:00Z"}
{"op":"climate_max_temp_c","value":22,"rationale_ref":"training_block"}
```

If a proposed commitment cannot be evaluated against a predicate, the result is **`unknown`, never `pass`.** Unknown blocks autonomous booking. It does not block a human.

---

## 4. The honesty invariants

Added to the existing `INVARIANTS` array. Each must return zero rows.

1. No `booked` commitment violates a `must` constraint without a recorded `deliberations` override.
2. No cascade impact is asserted on a `depends_on` edge with `confidence < 0.8` **and** missing observed data at either endpoint.
3. Every autonomous action (`booked_by = 'wingman'`) names, in its `deliberations` row, the constraint it was protecting.
4. No constraint is cited in user-facing copy after `expires_at`.
5. No `inferred` constraint supersedes a `stated` one.
6. Every `satisfies` edge with `strength < 0.5` is disclosed in the document, not hidden. *(This is the "recovery-grade, not training-grade" rule — the system must volunteer its own compromises.)*
7. Autonomous booking is blocked while any `must` constraint on the trip is unresolved.
8. Every constraint of source `researched` has an `evidence.url` and an `evidence.retrieved_at` within its validity window. *(Visa rules go stale. Ours must expire, not rot.)*

---

## 5. The document

The trip *is* the document. Its chapters are **views of the graph**, generated — never hand-authored:

| Chapter | Generated from |
|---|---|
| **What this trip is for** | `intents` |
| **Entry & eligibility** | `constraints` where `kind='entry'`, with source URLs and retrieval dates |
| **Routing & cabins** | `commitments` type flight + the loyalty-crediting constraints |
| **Where you're staying, and why** | lodging commitments + their `satisfies` edges — *the reason line renders under each hotel* |
| **Day by day** | commitments ordered by time |
| **The layer** | whatever this trip's intent demands — training & recovery here; it could be childcare, or dialysis, or a wedding |
| **What's watched** | `depends_on` edges + live monitors |

Compare the transcript's itinerary document. It has exactly these chapters. It was not designed — it *emerged*, because it is the natural shape of the graph.

---

## 6. The screens, re-derived

The mockups I made are downstream of the wrong model. Corrected:

**Plan — the missing front door.** A conversation that builds a document. Wingman asks clarifying questions *because it is filling in `must` constraints with low coverage* — that is not a chat affectation, it is the model asking for what it needs. Every answer writes a constraint with `source='stated', confidence=1.0`. The document assembles beside the conversation, visibly.

This is the tab that doesn't exist, and it's the front door.

**Trips — the document, not a list.** With the reason line under every commitment. *"Palace Hotel. Technogym, cold plunge, on the Imperial Palace loop."* No other travel app can render that line, because no other travel app stored it.

**Home — the Brief.** "Nothing needs you" now has a precise meaning: **no constraint is currently unmet.** It's a graph query, not a vibe.

**The Situation.** A constraint-violation view. Not "your flight is late" but *"your flight is late, and these four constraints are now at risk, and here is what still satisfies them."* Rescue options are ranked by **how many constraints survive**, weighted by hardness — which is precisely what "ranked by what they protect, not by price" means, made literal.

**You — the standing constraint set.** The persistent memory the deck promises. Not a settings screen; the list of things that are true about you, each with its reason and its provenance, each editable. *"Always ask for a window seat"* sits alongside *"Technogym, because of the 5K."*

**The dial.** Autonomy is per-constraint-class, not one global number. *Rebook a flight while preserving all `must` constraints, under $500 → act silently. Anything that breaks a `strong` constraint → wake me.* The dial becomes readable as English because it is defined in terms of what it is allowed to sacrifice.

---

## 7. Migration

**Phase 0 — substrate.** Create the tables. Dual-write. Change no UI. Ship the invariants first, with the existing data, so the graph is born honest.

**Phase 1 — backfill.** Mine `users.taste_profile`, `standing_orders`, `preferences`, and the concierge history into standing constraints. Every existing `trip_leg` gets a `satisfies` edge or an explicit `unknown`. Expect this to be revealing: most bookings will have *no* reason attached, which is the whole point.

**Phase 2 — the planner.** Conversation → constraints → document. This is the demo, and it is the company. Ship it as a real surface.

**Phase 3 — booking.** Duffel, executing against the constraint set. The autonomy gate is invariant #7.

**Phase 4 — rewire the cascade.** Delete the hand-written special-case cascade code; replace it with a graph walk. The trip-wide cascade broke silently once already precisely because it was special-cased.

**Phase 5 — redesign.** The screens now follow from the model rather than being painted on top of it.

---

## 8. The first thing to build

**Reproduce the Asia transcript inside Wingman, on Maddie's real account.** Same six tour dates, same forty turns. Wingman must arrive at the same constraint set, the same document, the same judgment calls — and then keep watching it.

The transcript is a gift: it is a **labeled dataset and an eval in one.** We know what the right answer looks like, turn by turn. We can measure whether the system reaches it.

If Wingman can do what that conversation did, *and then defend it for six weeks*, there is no competitor. If it can't, no amount of parchment saves us.

---

*We protect what depends on them.* The deck's line is exact, and it has always been about the reasons. We just weren't storing them.
