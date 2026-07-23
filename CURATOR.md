# Wingman — The Curator

*Autopilot for your taste and your time. Written from a long design session with a 200+-day-a-year traveler who said, plainly: "be my autopilot to remove friction on my life."*

---

## The one sentence

**The Guardian makes sure nothing falls through. The Curator makes every trip feel like it was planned by someone who knows you — and autopilot removes the friction between.** You can't protect what doesn't exist, so the Curator comes first: it creates the substance the Guardian then keeps safe.

---

## What the Curator is aware of

Four things, at once. Take any one away and it's just a search box.

1. **The shape of your time.** Not only your meetings — the *gaps*: a free two hours between them, an open evening, a layover. (`gaps.js`)
2. **Where you are.** Right now, from the device — and therefore what's actually reachable and back before your next commitment. (geolocation + travel time)
3. **Your taste.** Two sources, fused:
   - **Revealed** — 17 years of the hotels, restaurants, flights, and activities you actually chose (affinity tables).
   - **Aspirational** — the editors you read: NYT 36 Hours, Service 95, Hotels Above Par, and whatever else you name or forward. This is the part history can't capture, and it's the differentiator.
4. **How far to go before asking.** Confirm-first to start; graduates to autopilot as you confirm (the autonomy dial).

---

## The three moments

### 1. The arrival plan — confirm-first
"Here's how I'd do Chicago." A settled proposal, nothing booked until you say so:
- Flight in (to your rules — aisle, no red-eye).
- Ground: car to the door, or the transit option with the exact door and cost.
- **A hotel slate, not one pick** — variety with *reasons*: your usual (Kimpton), a deal I found (Graduate), worth-a-try (Hoxton), you-loved-it-before (CAA). Four kinds of "why," you choose.
- Dinner and off-beat things to do (below).
- Graduates: the more you confirm, the more it just handles. At full autopilot the same plan reads "booked," not "confirm."

### 2. Off-beat things to do — attributed to your sources
Not TripAdvisor. The candlelit Baroque concert *Service 95* sent you to; the Pilsen loop from *36 Hours*; the rooftop *Hotels Above Par* rates. Every item **credits its source**. Each user brings their own editors, so the engine is universal and the taste is theirs.

### 3. Time-pockets — the alive part
Wingman notices the free window and fills it: *"Two hours to yourself until the 3pm. The Art Institute is 6 minutes away — the Monet room Service 95 loved. Back by 2:40."* It only surfaces when you're **genuinely free** — never over a meeting — and only what **fits the window** with travel both ways.

---

## Build order (soul first, vendors later)

```
C1  This spec                                                     ← you are here
C2  gaps.js — free-pocket detection from the calendar (pure, tested)
C3  Taste library — history + named/forwarded sources → a taste brief
C4  Curation engine — city/window + taste brief → picks w/ why + source credit
C5  Surfaces — arrival plan (confirm-first) + pocket cards, in the new design language
C6  Actions — Duffel Stays (real rooms), concierge-email booking, transit tickets
```

C2–C4 need **no new vendor** — they run on the calendar, the affinity we already keep, forwarded newsletters (the email path exists), and Claude reasoning over *your* corpus.

---

## The honesty rules (same spine as the Guardian)

1. **Cite the source, show the why.** Never "top-rated" — "Service 95 sent you here" or "your brand, 3 stays." A real source item outranks an "in the spirit of" one, and the difference is labeled.
2. **Show the time-math.** "Back by 2:40" is a claim that must be true — computed from real travel time, never asserted.
3. **Never over a meeting.** A pocket is only offered when the calendar says you're actually free.
4. **Confirm-first until trusted.** Nothing books unattended until the dial says so; a slate is offered, not a decision made for you.
5. **Variety is a feature, not noise.** The hotel slate deliberately mixes habit, deal, discovery, and memory — a great concierge surprises you on purpose.

---

## Design language

Ivory paper, deep ink, a single bronze accent, sage reserved to mean *handled / known*. Serif headlines that state the truth ("Chicago's set." / "Two hours to yourself."), bronze small-caps section labels, hairline-grouped rows, source-attribution pills. Calm and expensive — a note from your private office, not another dark dashboard.
