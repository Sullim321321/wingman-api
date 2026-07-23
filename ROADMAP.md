# Wingman — Roadmap v2

*Rebuilt from what you actually said you wanted, over a long night of testing on your own real trips.*

*(v1 is preserved in git history. This version reorganizes around your words, and adds the pillar v1 was missing: the app has to stay clean without you grooming it.)*

---

## The one sentence

**Your calendar and your inbox already know where you're going. Wingman is the travel brain that reads all of it, proposes the trip before you ask, and is honest about what it can't do — so you never assemble a trip by hand again.**

Not a general chief of staff (that's Town, and you already have it). The travel-specific brain that sits on top of everything else you use.

---

## What you said you wanted (in your words, from last night)

1. **"It should be smart enough to know where my meetings are, what I'm doing, when my flight is — or based on my schedule when it's *expected* to be — what off-time I have, and what needs filling in."**
2. **"My life is across so many apps"** — calendar, email, WhatsApp, my Town profile, and any other integration.
3. **"If I searched a BNA→Chicago flight 3 days ago, it should know that, flag it, hold it — or ask to — and be able to change or cancel with permission."**
4. **The chat felt laborious.** A chief of staff wouldn't ask "which Thursday" — it would already know. It should *propose*, not interrogate.
5. **"This is still super messy."** You should never have to hand-delete stray legs. The app has to keep itself clean.

Underneath all five: **it has to be trustworthy.** The Booking.com CEO named trust as the thing AI can't manufacture. That's the moat, and it's the thing you were implicitly testing every time you caught Wingman asserting something it hadn't checked.

---

## The five pillars

Each pillar is one of your wants, translated into what gets built. The order is deliberate: each depends on the one before it.

### Pillar 1 — It knows me (the inputs)
*Your want #1 and #2.*

> **Status: 🟢 calendar LIVE · 🟡 texts started.** Google Calendar reads across both accounts (work `maddie@` for meetings, `sullim321@` for bookings) with honest connection states; the OAuth account-clobber bug is fixed. Text/message reconciliation (`reconcile.js`) is built and tested but not wired live. Email ingest pre-exists; Town profile not started.

Wingman interrogates because it's **blind** — it has no calendar, so it has to ask. No amount of prompt-tuning fixes a missing input. So the whole arc starts here.

- **Calendar first** (Google / Apple, read-only). This is the skeleton — your committed time, highest trust. It's what lets Wingman infer "you have Chicago meetings Thursday, so you need a flight in Wednesday night."
- **Email/bookings** re-pointed as a reader into the graph (it already ingests; stop letting it *build trips*, start letting it *confirm facts*).
- **Town profile** — your preferences and patterns, so proposals sound like you.
- **WhatsApp / texts** — last, because they're the noisiest. "Thinking about Tokyo" is a maybe, never a booking.

**One source at a time, each verified on your real data before the next.** Every mess this app has came from stacking unverified inputs.

### Pillar 2 — It proposes, it doesn't interrogate
*Your want #4.*

> **Status: 🟢 LIVE on your phone (calendar-driven).** classifier (virtual/in-person/ambiguous) → geocoding (gazetteer + Nominatim) → distance-based inference → trip proposal on Home from your real location. Your 18-meeting week collapsed to one Chicago trip. Remaining: the *taste* layer — feed 17 years of history so proposals name the hotel you actually use.

Once it can see your week and your history, the planner stops asking and starts offering.

- Feed the planner standing context: calendar, loyalty, 17 years of where you actually stay.
- Target: *"Chicago Thursday — I'd put you back at the Kimpton, in Wednesday night on the 6pm. Hold it?"* — not four questions.
- **Done when** "where should I stay in Chicago Thursday" returns a specific, bookable proposal.

### Pillar 3 — It acts on intent, with permission
*Your want #3 — the showcase.*

> **Status: ⬜ not started.** "Fill in the trip" (propose the flight in + your usual hotel) is the on-ramp and is next. Live booking needs the real Duffel key.

The search→flag→hold→book→change loop. This is **not a new system** — it's a new soft input plus the booking verb, permission gate, and ledger you already built.

- **Capture** searches via a consented, travel-scoped browser extension + one-tap Share-sheet. (iOS won't let any app passively watch you — this is the honest, legal way.)
- **Flag** against the calendar: a BNA→Chicago search *means* "book it" if Thursday shows Chicago meetings, and "just noting" if it doesn't. The calendar is what turns a glance into a plan.
- **Hold / book / change / cancel** — one "yes," always logged.
- **Honest about limits:** most fares can't be held free; changes are bounded by fare rules; live booking needs the real Duffel key. "Priced it, will book the second you nod, and tells you when a fare won't budge" beats competitors implying magic.

### Pillar 4 — It stays clean on its own *(the pillar v1 missed)*
*Your want #5 — the thing that frustrated you most last night.*

> **Status: 🟡 partial.** Killed the Tokyo seed phantom and hardened the seed cleanup (matches on `source='seed'`, not a title the app can rename). Reconciliation is itself a hygiene mechanism (a cancelled-by-text meeting stops proposing a trip). Still to build: stale-leg guard at ingest, name backfill, one-tap tidy.

You should **never** hand-delete a stray leg. That you had to, twenty times, is the failure. Trips accumulate junk from years of imports; the app has to groom itself.

- **Stale-leg guard at ingest:** a flight that departed long before the email reporting it never joins a current trip (confirm the mechanism from the real email first, test before building).
- **Name backfill:** a dining or activity leg must never fall back to showing the city ("Nashville") — it shows the venue, or it's collapsed into a count, but it's never a mystery card.
- **One-tap tidy / rebuild:** a "clean up this trip" action that re-runs grouping, drops orphans, and relabels — so a messy trip is one tap from right, not twenty deletes.
- **Escape hatch:** deleting a whole trip is one clear action (a dead trip isn't worth grooming).
- **Done when** you can go a month without manually removing a single leg.

### Pillar 5 — It earns more autonomy over time
*The payoff.*

> **Status: ⬜ not advanced.** The delegation dial pre-exists; it doesn't yet govern the calendar→trip loop.

You already have the delegation dial. Make it govern the loop: Watch → Suggest → Hold-for-me → Book-under-$X → Full, with standing orders ("aisle, never red-eyes, book the Kimpton under $400"). Every step logged to the ledger.

---

## Build sequence

```
Phase 0  Foundation        ✅ done — OTA now GENUINELY works (channel was never
         wired; fixed in build 324). crash guard · dismiss/remove legs · instant JS deploys
Phase 1  It knows me        ← calendar first, then email, Town, WhatsApp
Phase 2  It proposes        ← priors into the planner
Phase 3  It acts on intent  ← the search→book loop (needs live Duffel)
Phase 4  It stays clean     ← woven through 1–3, not bolted on after
Phase 5  It earns autonomy  ← the dial governs the loop
```

Pillar 4 (hygiene) isn't a late phase — it ships alongside every input, because each new source is a new way for junk to enter. Every source lands with its own cleanup rule.

---

## The invariants (unchanged — they are the moat)

1. **Inferred never overrides stated.** A search, a text, a hunch — all stay "maybe" until you confirm.
2. **Unknown blocks the machine, never you.** If Wingman can't verify, it asks; it never guesses and presents the guess as fact.
3. **Every side effect is permissioned and logged.** No silent book/change/cancel, ever.
4. **A suggestion is never a fact.** The bug behind the whole night — proposals can't name a trip, become "your flight," or trigger a briefing.
5. **When it reports success, ask whether the check could have failed.** Green lights must be able to go red.

---

## What last night proved

- The architecture is right: the constraint graph with provenance is exactly what a five-source, self-tidying, trust-first travel brain needs. You didn't build a travel app — you built the substrate this roadmap runs on.
- The failures were all one shape — *the system reporting confidently on evidence it never checked* — and they're now guarded, not just patched.
- The verify loop is finally cheap (OTA), which is what makes building the rest sane.
- The remaining frustration (messy trips) is a **missing pillar**, not a missing fix. That's why it's now first-class here.
