# Wingman — Product Roadmap
### UI · UX · Style/Design — from where we are to the product you actually want to build

---

## 0. The feel: three layers, not three choices

You asked how I'd envision all three. The honest answer is that "invisible autopilot,"
"trusted chief of staff," and "quiet-luxury travel office" are not competing directions —
they're three layers of one product, each answering a different question:

- **Invisible autopilot** — *what it does.* The engine. It watches your calendar, inbox,
  and the world, and it acts: rebooks the cancelled flight, holds the room, cancels what
  fell through, flags what needs you. Success here is measured in **things handled without
  you opening the app**. Fewer taps, not more. The best day is the one where Wingman did
  everything and all you got was a calm "handled it — here's what and why."

- **Trusted chief of staff** — *how it relates to you.* The voice and the relationship.
  When you *do* open it, or when it reaches you, it speaks like the best EA you've ever had:
  brief, certain about what it knows, honest about what it doesn't, never narrating its own
  plumbing. It earns autonomy the way a person does — by getting the small calls right until
  you stop checking. Success here is **trust**: the delegation dial moving from "ask me" to
  "just do it" because it deserved to.

- **Quiet-luxury travel office** — *how it feels to touch.* The surface. On the rare,
  deliberate occasions you open it — planning a trip, reading the Curator, confirming a
  booking — every screen should feel considered: ivory, deep ink, one bronze accent, sage
  for what it knows; editorial typography; restraint; nothing shouting. Success here is that
  opening Wingman feels like stepping into a well-run office, not a dashboard.

**How they compose — a day in the life:**
Most days you never open it (autopilot). Tuesday it pushes: *"Your Thursday BNA→ORD was
just cancelled. I've held the 9:10 that protects your 2pm — confirm?"* — that's the chief of
staff, reaching you only because it matters, with a one-tap confirm. Friday you land in
Nashville and open Explore because you *want* to — the Curator greets you with what's good,
pulled from your taste, and it's beautiful to read. Same product, three altitudes:
**autopilot is the default, chief-of-staff is the interruption, quiet-luxury is the visit.**

The design implication is a hierarchy: **the best interface is no interface (push/autopilot);
the second-best is one glance (the brief, the arc, a confirm card); the screens you scroll
are the exception, and they earn their weight by being beautiful.** Every roadmap item below
serves one of those three layers.

---

## 1. Where we are (honest state, mid-2026)

**Built and working:** the calendar spine and multi-account read; meeting classification,
geocoding, trip inference; message reconciliation; the constraint graph + cascade; the
decision spine and reversible autonomy; the delegation dial + standing orders + proactive
watcher; the Curator (taste engine, curation, Explore tab, dining ask); C6 real-booking
scaffolding (stays, flights, concierge-email) on a hold-then-confirm safety rail; the
whole-app quiet-luxury retheme; and a hard pass on data honesty (trip grouping, date sanity,
the repair, ride/stay/placeholder collapse, the Dossier "arc").

**The through-line of your feedback** — the thing the roadmap must keep answering — has been
remarkably consistent: **less clutter, more honesty, remove friction, make it feel
considered.** Every "too much info," every "that's not a real flight," every "this is a
planning tab, not the product" pointed the same way.

**Where it still falls short:** density and consistency vary screen to screen; the autopilot
is real but mostly invisible in the *wrong* way (you can't see it working, so you can't trust
it yet); the Curator lives only in Explore; bookings are test-mode; and the visual language is
applied but not yet *finished* (spacing scale, motion, iconography, the masthead).

---

## 2. The invariants (never traded away, at any phase)

1. **Inferred never overrides stated. Unknown blocks the machine, not you.** A suggestion is
   never rendered as a fact. Sources cited, the "why" always available, time-math always real.
2. **No autonomous real-money spend.** Holds are free and reversible; charges wait for an
   explicit, matching, live confirm. This is architecture, not a setting.
3. **Calm by default.** A screen shows the shape first; the granular is one tap away. Nothing
   shouts unless it needs you.
4. **The design language is fixed:** ivory ground, deep ink, one bronze accent, sage for
   "known," coral for risk. Serif voice, italic reasons, mono for facts. Restraint over
   decoration.

---

## 3. Phase 1 — A lovable v1 (make what exists feel *finished*)

The goal of Phase 1 is not new capability — it's coherence. Every screen calm, consistent,
honest, and beautiful, so the product feels like one considered thing.

### UI (density, consistency, the components)
- **Extend the "arc" pattern everywhere.** The Dossier now leads with the spine; apply the
  same "shape first, detail collapsed" treatment to every list-heavy surface (Trips detail,
  Situation, Insights, Settings sub-pages).
- **A single card system.** Audit every card (Home, Dossier, Curator, booking) onto one set
  of tokens: radius, padding, hairline, shadow, the raised/lifted/inverted planes. Kill the
  last hardcoded colors and one-off spacings.
- **Empty / loading / error honesty, everywhere.** Every surface must distinguish "nothing
  here" from "couldn't load" from "still loading" — no dark monitors, no invented all-clears.
- **Density pass per screen.** Home, Trips, Plan, Explore, Settings each get the same edit you
  just did to the Dossier: remove anything that isn't the shape or an action.

### UX (the front door, the confirm, the notifications)
- **Home is the brief.** Lead with what needs you, then where you are + what's good, then the
  settled day. The cached Curator surface and the coherence guards are steps toward this;
  finish it so Home answers "what do I need to know / do right now" in one glance.
- **One consistent confirm moment.** Every side-effectful action (book, hold, send, cancel)
  uses one calm confirm component that states exactly what will happen, the cost, and the
  reversibility. This is where trust is won or lost.
- **Notifications that only ever matter.** Push is the primary autopilot surface; ruthlessly
  tune it so every push is something you're glad arrived, with inline actions.
- **Onboarding that shows value in 60 seconds** and sets the delegation dial honestly.

### Style / Design (finish the language)
- **A real type ramp and spacing scale.** Codify sizes/leading/letter-spacing and an 8pt
  spacing scale as tokens; apply app-wide so rhythm is consistent.
- **Signature motion, restrained.** One entrance, one confirm, one success animation —
  consistent, quiet, never bouncy.
- **Iconography + the W-mark / masthead.** A single icon set at one weight; finish the
  wordmark and how it appears across screens.
- **Contrast + accessibility pass** on the ivory palette (the faint pills you flagged), and a
  decision on whether a true dark variant is worth designing or whether ivory is the identity.

---

## 4. Phase 2 — The Guardian deepens (make the autopilot *visible and trusted*)

Autopilot is built but invisible; you can't trust what you can't see. Phase 2 makes the
Guardian legible.

- **The ledger as a trust engine.** Every autonomous act (watched, held, rebooked, flagged)
  writes a clear, human line: what, why, what it protected, what it cost/saved. Surface it so
  the delegation dial graduates on *evidence*.
- **Disruption → re-book, end to end.** The cascade already knows what breaks; close the loop
  so a cancellation becomes a held alternative + a one-tap confirm, with the reasons carried.
- **"When to leave."** Join commitments + location + real travel time so Wingman tells you the
  door time, not just the departure time (#96).
- **Entry checks / pre-trip, authoritative.** Never assert visa/document rules; link the
  source and flag what to verify.
- **Graduating autonomy for real.** The dial moves from watch → suggest → hold → book-under-$X
  → full, and the product actively *earns* each step and tells you when it's ready to.

---

## 5. Phase 3 — The Curator completes (make every trip feel planned by someone who knows you)

- **The arrival plan (confirm-first).** On landing: where you're staying, how to get to the
  city (with buy-tickets), and the first evening curated to your taste.
- **Time-pocket awareness.** Wire `gaps.js` into surfaces that say "you have Thu 3–6pm free
  near X — here's something you'd like," aware of location and travel time.
- **Proactive dining.** Beyond the ask box: infer where you'll want to eat and pre-suggest,
  learning from what you book and skip.
- **Real bookings live (C6).** Take Duffel Stays/flights + concierge-email from test to live,
  still hold-then-confirm; wire the taste slate to bookable rooms.
- **The taste loop.** Sources you read + bookings you make continuously sharpen the brief;
  make adding a source and correcting a pick effortless.

---

## 6. Phase 4 — The relationship matures (autopilot as the default)

- **Autopilot moments.** For the calls it has earned, Wingman acts and *tells* you, rather
  than asking — with an undo window. The interface recedes.
- **Delegation to your people.** The EA/CoS multi-user model (Town on maddie@…) done properly:
  who can see and do what, on your behalf.
- **Voice / ambient.** The brief as something you can hear; the chief of staff you can talk to.

---

## 7. Cross-cutting (true throughout, not a phase)

- **Data hygiene at the source.** The repair fixed history; now fix *import* so hotel legs
  never lose their name to the city, dates are always sane, and reservations consolidate as
  they arrive — so the beautiful surfaces always sit on clean data.
- **Performance & reliability.** Home must open instantly (the GPS fix was step one); no
  screen waits on a slow call; the backend never lets one heavy LLM request stall the rest.
- **The honesty audit, ongoing.** Every new surface gets checked against invariant #1 before
  it ships.

---

## 8. Suggested sequencing

**Now → v1 (Phase 1):** density + component system + confirm moment + notification tuning +
type/spacing/motion tokens + contrast pass. This is what makes it *lovable* and shippable.

**Then (Phase 2):** ledger visibility + disruption re-book loop + when-to-leave. This is what
makes it *trusted*.

**Then (Phase 3):** arrival plan + time pockets + live bookings + taste loop. This is what
makes it *indispensable*.

**Then (Phase 4):** autopilot-by-default + delegation + voice. This is the product you
actually want to build — the one you rarely have to open, that has already thought of
everything, and that feels like a private office when you do.

---

*The test for every item: does it make Wingman more invisible when it should be, more
trustworthy when it speaks, or more beautiful when you visit? If it does none of the three,
it doesn't belong on the roadmap.*
