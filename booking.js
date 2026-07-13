/**
 * booking.js — the missing verb.
 *
 * The planner writes legs as `proposed`. The cascade defends legs that are `booked`.
 * Nothing turned the first into the second, so the deck's middle promise — "help book,
 * or book autonomously" — had no implementation. This is that step.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE ONE RULE THIS FILE EXISTS TO ENFORCE:
 *
 *   Booking PROMOTES the proposed leg. It does not create a new one.
 *
 * The obvious implementation is to call the existing POST /flights/book, which works
 * and is well-tested. It also creates a brand-new trip and a brand-new leg. Do that,
 * and the proposed leg — the one carrying every `satisfies` edge the planner drew, the
 * one that knows Kyoto is for the LANY show and the seaplane is the only way to the
 * island — sits there, still proposed, still holding all the reasons, while a shiny
 * new leg with no reasons at all becomes the real flight.
 *
 * Then the flight is delayed, and the cascade walks the graph from the booked leg and
 * finds nothing downstream, because the edges are all on the orphan. It says
 * "nothing depends on this." Confidently. On evidence it never checked.
 *
 * So: booking would have QUIETLY DESTROYED THE GRAPH, and the only symptom would have
 * been Wingman going silent at exactly the moment it was built to speak. The whole
 * point of the plan is to become the booking, carrying its reasons across.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const rescue = require("./rescue");
const graph  = require("./constraints");

/* ────────────────────────────────────────────────────────────────────────────
 * 1. READINESS — what the plan doesn't know yet
 *
 * A proposal is deliberately thinner than a booking. It has a city, not an airport;
 * a span, not a date; a traveller in the abstract, not a passport. Booking needs all
 * of it, and the honest move is to NAME what's missing rather than to guess it.
 *
 * Every gap returns a question, not a default. A default here is a fabricated fact
 * with a booking reference attached to it.
 * ──────────────────────────────────────────────────────────────────────────── */

function readiness({ leg, trip, passenger }) {
  const missing = [];
  const raw = leg?.raw_data || {};

  if (!leg) return { ready: false, missing: [{ field: "leg", ask: "That leg doesn't exist." }] };

  if (leg.state !== "proposed") {
    return {
      ready: false,
      already: leg.state,
      missing: [{
        field: "state",
        ask: leg.state === "booked"
          ? "This is already booked."
          : `This leg is '${leg.state}', not a proposal. I only book proposals.`,
      }],
    };
  }

  if (leg.type !== "flight") {
    return {
      ready: false,
      missing: [{
        field: "type",
        ask: `I can only book flights right now. This is a ${leg.type}.`,
        why: "Hotels and restaurants go through different suppliers. Not built yet — and I'd rather say so than pretend.",
      }],
    };
  }

  const fromCity = raw.from_city || null;
  const toCity   = raw.to_city || leg.destination_city || null;

  if (!fromCity) missing.push({
    field: "from_city",
    ask: "Where are you flying from?",
    why: "The plan recorded where you're going, not where you're leaving from.",
  });
  if (!toCity) missing.push({
    field: "to_city",
    ask: "Where is this flight going?",
  });

  // The date is the one the planner refused to invent, and it was right to refuse.
  if (!leg.departs_at) missing.push({
    field: "departs_at",
    ask: `What day are you flying${toCity ? ` to ${toCity}` : ""}?`,
    why: "I never guessed a date for this — you hadn't given me one. I'm not going to start now by booking one.",
  });

  // Duffel will not sell a ticket to an abstraction.
  if (!passenger?.given_name || !passenger?.family_name || !passenger?.born_on) {
    missing.push({
      field: "passenger",
      ask: "I need your name as it appears on your passport, and your date of birth.",
      why: "The airline needs it. I'll keep it and stop asking.",
      route: "PassengerProfile",
    });
  }

  return {
    ready: missing.length === 0,
    missing,
    from_city: fromCity,
    to_city: toCity,
    departs_at: leg.departs_at || null,
    trip_id: trip?.id ?? leg.trip_id,
  };
}

/* ────────────────────────────────────────────────────────────────────────────
 * 2. AIRPORTS — a city is not an airport
 *
 * "Tokyo" is two airports 60km apart, and picking the wrong one costs ninety minutes
 * that the seaplane doesn't have. So we resolve and we SAY which we picked; we never
 * silently collapse a city into its most famous runway.
 * ──────────────────────────────────────────────────────────────────────────── */

async function resolveAirport(duffel, city) {
  if (!city) return null;
  const result = await duffel.suggestions.list({ query: String(city) });
  const places = result?.data || [];

  // Prefer a city node (it fans out to all its airports — Duffel handles TYO → HND+NRT).
  const cityNode = places.find((p) => p.type === "city" && p.iata_code);
  if (cityNode) {
    return {
      iata: cityNode.iata_code,
      name: cityNode.name,
      kind: "city",
      covers: (cityNode.airports || []).map((a) => a.iata_code).filter(Boolean),
    };
  }
  const airport = places.find((p) => p.type === "airport" && p.iata_code);
  if (airport) return { iata: airport.iata_code, name: airport.name, kind: "airport", covers: [airport.iata_code] };

  return null;   // unresolvable → the caller must say so, not shrug and pick one
}

/* ────────────────────────────────────────────────────────────────────────────
 * 3. OFFERS — ranked by what they protect, not by what they cost
 *
 * Reuses rescue.rank() verbatim, and that is the point: the machinery that saves a
 * trip when a flight is cancelled is the same machinery that chooses the flight in
 * the first place. If they were different, they could disagree — and then Wingman
 * would book a flight its own rescue engine considers a mistake.
 *
 * One honest asymmetry. In a rescue there is an original arrival time to measure
 * against, so `survives()` can say what a 90-minute slip destroys. On a fresh plan
 * there is no original — nothing has been promised yet — so every downstream verdict
 * comes back `unknown`, protectScore is zero for every option, and the ranking falls
 * back to constraint satisfaction. That's not a degraded mode. That's the truth:
 * before you book the first leg, nothing downstream depends on it yet.
 * ──────────────────────────────────────────────────────────────────────────── */

async function offersFor(sql, duffel, { leg, from, to, departs_at, cabin_class, passengers = 1 }) {
  const offerRequest = await duffel.offerRequests.create({
    slices: [{
      origin: from.iata,
      destination: to.iata,
      departure_date: new Date(departs_at).toISOString().slice(0, 10),
    }],
    passengers: Array.from({ length: passengers }, () => ({ type: "adult" })),
    ...(cabin_class ? { cabin_class } : {}),
    return_offers: true,
    supplier_timeout: 15000,
  });

  const offers = (offerRequest.data.offers || []).slice(0, 30);

  // What would this flight, once booked, be holding up? On a plan: usually nothing yet.
  const cascade = await graph.cascadeFrom(sql, leg.id, { delayMinutes: 0 }).catch(() => ({ nodes: [] }));
  const constraints = await graph.constraintsFor(sql, {
    user_email: leg.user_email,
    trip_id: leg.trip_id,
  });

  // rank() returns { options, recommended_id, no_recommendation_because } — an OBJECT,
  // not an array. Worth stating out loud: the first version of this file treated it as
  // an array and called .slice() on it. It would have thrown on the very first real
  // search — but only in production, because the unit tests mocked the ranker instead of
  // using it. A test that mocks the thing it's integrating with cannot fail the way the
  // system fails.
  const result = rescue.rank({
    offers,
    constraints,
    nodes: cascade.nodes || [],
    originalArrival: null,          // nothing was promised yet. Say so; don't fake one.
  });

  return { ...result, constraints, offer_request_id: offerRequest.data.id };
}

/* ────────────────────────────────────────────────────────────────────────────
 * 4. PROMOTE — the plan becomes the booking, and keeps its reasons
 *
 * UPDATE, not INSERT. Same row, same id, therefore the same `satisfies` edges and the
 * same `depends_on` edges. The graph doesn't notice anything happened except that a
 * sketch acquired a flight number — which is exactly what happened.
 * ──────────────────────────────────────────────────────────────────────────── */

async function promote(sql, { leg, order, offer, by = "wingman" }) {
  const seg = order?.slices?.[0]?.segments?.[0] || offer?.slices?.[0]?.segments?.[0];
  const last = order?.slices?.[0]?.segments?.slice(-1)[0] || offer?.slices?.[0]?.segments?.slice(-1)[0];
  if (!seg) throw new Error("promote: the order has no segments — refusing to mark a leg booked on nothing");

  const carrier = seg.marketing_carrier?.name || null;
  const iata    = seg.marketing_carrier?.iata_code || "";
  const num     = seg.marketing_carrier_flight_number || "";
  // Space it. This string is a NAME, and it is read by a person.
  const flightNumber = [iata, num].filter(Boolean).join(" ") || null;

  const cents = offer?.total_amount ? Math.round(parseFloat(offer.total_amount) * 100) : null;
  const cancellable = offer?.conditions?.refund_before_departure?.allowed
    ? (seg.departing_at || null)
    : null;

  const [updated] = await sql`
    UPDATE trip_legs SET
      state            = 'booked',
      booked_by        = ${by},
      carrier          = ${carrier},
      flight_number    = ${flightNumber},
      origin           = ${seg.origin?.iata_code || null},
      destination      = ${last?.destination?.iata_code || seg.destination?.iata_code || null},
      departs_at       = ${seg.departing_at || null},
      arrives_at       = ${last?.arriving_at || seg.arriving_at || null},
      confirmation     = ${order?.booking_reference || null},
      cost_cents       = ${cents},
      cancellable_until= ${cancellable},
      status           = 'upcoming',
      raw_data         = COALESCE(raw_data, '{}'::jsonb) || ${JSON.stringify({
                            duffel_order_id: order?.id || null,
                            segment_id: seg.id || null,
                            planned: false,
                            promoted_from_proposal: true,
                            booked_at: new Date().toISOString(),
                          })}::jsonb
    WHERE id = ${leg.id} AND state = 'proposed'
    RETURNING *`;

  // The WHERE clause is a guard, not decoration: if someone else already promoted this
  // leg, we've just paid Duffel for a ticket we're about to lose track of. Say it loudly.
  if (!updated) throw new Error(`promote: leg ${leg.id} was no longer 'proposed' — refusing to double-book`);

  // Did the reasons survive? This is the whole thesis of the file; assert it.
  const kept = await sql`SELECT constraint_id FROM satisfies WHERE commitment_id = ${leg.id}`;
  return { leg: updated, reasons_kept: kept.length };
}

/* ────────────────────────────────────────────────────────────────────────────
 * 5. MAY I? — autonomy is a question the graph answers, not a setting
 * ──────────────────────────────────────────────────────────────────────────── */

// `choice` is one element of rescue.rank().options — so the field names are ITS field
// names: `breaks`, `loses`, `cannot_assess`, `brokeMust`, `losesMust`. Not invented ones.
async function permission(sql, { user_email, trip_id, choice }) {
  if (!choice) return { ok: false, reason: "no_options", detail: "Nothing came back." };

  // An option that breaks a must, or destroys one, is not a candidate for autonomy —
  // regardless of what the rest of the graph says.
  if (choice.brokeMust || choice.losesMust) {
    return {
      ok: false,
      reason: choice.brokeMust ? "would_break_must" : "would_lose_must",
      detail: choice.brokeMust
        ? `It breaks something you told me was non-negotiable: ${(choice.breaks || []).filter((b) => b.hardness === "must").map((b) => b.rationale).join("; ")}`
        : `It quietly costs you something you can't get back: ${(choice.loses || []).filter((l) => l.hardness === "must").map((l) => l.what).join("; ")}`,
    };
  }

  const verdict = await graph.mayActAlone(sql, {
    user_email,
    trip_id,
    cost_cents: choice.price ? Math.round(choice.price * 100) : 0,
    wouldBreak: (choice.breaks || []).map((b) => b.id).filter(Boolean),
  });

  // An option we couldn't fully evaluate is not an option we may book alone.
  // "Unknown" blocks Wingman. It never blocks a human — she can look at the same
  // uncertainty and decide anyway. That asymmetry is the entire safety argument.
  const unsure = choice.cannot_assess || [];
  if (verdict.ok && unsure.length) {
    return {
      ok: false,
      reason: "unevaluable",
      detail: `I can't check ${unsure.length} thing${unsure.length === 1 ? "" : "s"} you told me matter: ${unsure.slice(0, 2).join("; ")}. I won't book past a question I can't answer.`,
    };
  }
  return verdict;
}

module.exports = { readiness, resolveAirport, offersFor, promote, permission };
