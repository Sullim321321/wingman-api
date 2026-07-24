/**
 * regroup.js — cluster legs into trips by TIME, not by destination.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE BUG THIS EXISTS TO KILL:
 *
 *   Legs were filed into a trip by their destination. So every leg that ever ended in
 *   New York — an Albany train in April, a JFK flight two years later, a DC bus, a
 *   Pittsburgh red-eye — collapsed into ONE "New York" trip spanning seventeen years,
 *   which then rendered as a single upcoming card. A trip is not "everywhere you've
 *   gone to a city"; it is a continuous journey bounded in time.
 *
 * So membership is temporal: sort the committed legs, and start a NEW trip wherever the
 * gap between one leg and the next exceeds `gapDays`. A trip may never span more than
 * `maxTripDays`. Destination supplies the TITLE, never the membership. Corrupt dates
 * (epoch, absurd years) are dropped rather than allowed to anchor a phantom trip.
 *
 * Pure and dependency-free, so it can be unit-tested and also run in a repair pass over
 * existing data.
 * ────────────────────────────────────────────────────────────────────────────── */

const DAY = 86400000;

/**
 * plausibleDate — is this ISO date a real, usable travel date?
 * Rejects: unparseable, epoch-1970 (the classic null→Date trap), and years far outside
 * a sane window (recent past through near future). Recent past is allowed — completed
 * trips are real.
 */
function plausibleDate(iso, nowMs = Date.now(), { pastYears = 3, futureYears = 3 } = {}) {
  if (!iso) return false;
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return false;
  const y = new Date(ms).getUTCFullYear();
  if (y <= 1971) return false;                 // epoch / null-date artifacts
  const nowY = new Date(nowMs).getUTCFullYear();
  if (y < nowY - pastYears) return false;      // absurdly old (e.g. 2009 for a 2026 user)
  if (y > nowY + futureYears) return false;    // absurdly far out
  return true;
}

function legTime(l) {
  const ms = Date.parse(l?.departs_at || "");
  return Number.isNaN(ms) ? null : ms;
}
function legEnd(l) {
  const ms = Date.parse(l?.arrives_at || l?.departs_at || "");
  return Number.isNaN(ms) ? legTime(l) : ms;
}

/**
 * clusterLegs(legs, opts) → [{ legs, start, end, days, title }]
 *
 * Only committed legs with a plausible date participate in membership (a proposal or a
 * corrupt-date leg neither forces nor splits a trip). Legs are sorted by departure; a new
 * cluster starts when the gap from the running cluster's end to the next departure exceeds
 * gapDays, or when adding the next leg would push the span past maxTripDays.
 */
function clusterLegs(legs = [], opts = {}) {
  const { gapDays = 4, maxTripDays = 30, nowMs = Date.now() } = opts;
  const gapMs = gapDays * DAY, maxMs = maxTripDays * DAY;

  const usable = (legs || [])
    .filter((l) => l && l.state !== "proposed" && plausibleDate(l.departs_at, nowMs))
    .map((l) => ({ leg: l, start: legTime(l), end: legEnd(l) }))
    .filter((r) => r.start != null)
    .sort((a, b) => a.start - b.start);

  const clusters = [];
  let cur = null;
  for (const r of usable) {
    if (!cur) { cur = { legs: [r.leg], start: r.start, end: r.end }; continue; }
    const gap = r.start - cur.end;
    const spanIfAdded = Math.max(cur.end, r.end) - cur.start;
    if (gap <= gapMs && spanIfAdded <= maxMs) {
      cur.legs.push(r.leg);
      cur.end = Math.max(cur.end, r.end);
    } else {
      clusters.push(cur);
      cur = { legs: [r.leg], start: r.start, end: r.end };
    }
  }
  if (cur) clusters.push(cur);

  return clusters.map((c) => ({
    legs: c.legs,
    start: c.start,
    end: c.end,
    days: Math.max(1, Math.round((c.end - c.start) / DAY)),
    title: titleFor(c.legs),
  }));
}

/**
 * titleFor — the trip's name is where it takes you. Use the destination of the last
 * outbound-ish leg, preferring a real place name over an airport code. If the last leg
 * returns to the first leg's origin (a round trip), the title is the away destination.
 */
function titleFor(legs = []) {
  if (!legs.length) return "Trip";
  const origin0 = (legs[0].origin || "").trim();
  // Prefer a destination that isn't just going home.
  for (let i = 0; i < legs.length; i++) {
    const dest = (legs[i].destination || "").trim();
    if (dest && dest.toLowerCase() !== origin0.toLowerCase()) return dest;
  }
  return (legs[legs.length - 1].destination || legs[0].destination || "Trip").trim() || "Trip";
}

module.exports = { clusterLegs, plausibleDate, titleFor };
