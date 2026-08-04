// dayrisk.js — "what could ruin my day?" A single, honest ranking of a day's real risks.
//
// Epic I (deeper proactive intelligence), Slice 1: the reasoning core. Pure + dependency-free
// and test-first, mirroring arrival.js / companions.js. Wiring it onto Home is a later slice —
// this is the tested foundation the surface will read.
//
// THE DISCIPLINE (same as the cascade): every risk carries a `why` you could defend, and when
// a signal is MISSING we return `unknown` rather than inventing calm. "I can't see the weather"
// is more useful than a false "all clear". Nothing here asserts a risk it can't evidence.

const HOUR = 3600000, MIN = 60000;
const ms = (v) => { const t = Date.parse(v); return Number.isNaN(t) ? null : t; };

// Severity ordering, for ranking the day's risks.
const RANK = { high: 3, medium: 2, low: 1, unknown: 0 };

const SEVERE_WX = /storm|thunder|snow|blizzard|ice|icy|freezing|sleet|hurricane|tornado|hail|flood/i;

/**
 * Tight connections: consecutive flights whose layover falls below the traveler's comfort
 * (min_connection_mins). Below half the comfort is high, otherwise medium. A gap over 6h isn't
 * a connection, it's a break in the day — skipped.
 */
function tightConnections(flights, minConnMins = 45) {
  const fs = (flights || [])
    .filter((f) => f && f.departs_at && f.arrives_at)
    .map((f) => ({ ...f, dep: ms(f.departs_at), arr: ms(f.arrives_at) }))
    .filter((f) => f.dep != null && f.arr != null && f.arr >= f.dep)
    .sort((a, b) => a.dep - b.dep);

  const out = [];
  for (let i = 0; i < fs.length - 1; i++) {
    const a = fs[i], b = fs[i + 1];
    const gapMin = (b.dep - a.arr) / MIN;
    if (gapMin < 0 || gapMin > 6 * 60) continue;          // not a connection
    if (gapMin < minConnMins) {
      const next = [b.carrier, b.flight_number].filter(Boolean).join(" ").trim() || "your next flight";
      out.push({
        kind: "tight_connection",
        severity: gapMin < minConnMins / 2 ? "high" : "medium",
        why: `Only ${Math.round(gapMin)} min to make ${next} at ${a.destination || "the connection"} — under your ${minConnMins}-min comfort.`,
      });
    }
  }
  return out;
}

/**
 * Bag risk (I2). Honest without a tracking feed: we do NOT claim to know where your bag is.
 * We reason about it — a checked bag on a tight connection is the first thing that misses the
 * plane. So on a HIGH-severity tight connection we raise one conditional caution ("if you
 * checked a bag…"). No feed, no assertion of status — just the risk, stated as a risk.
 */
function bagRisk(tightConns) {
  const worst = (tightConns || []).some((c) => c.severity === "high");
  if (!worst) return [];
  return [{
    kind: "bag",
    severity: "medium",
    why: "On a connection this tight, a checked bag often doesn't transfer in time — carry-on is the safer bet.",
  }];
}

/**
 * Weather risk at a relevant airport. `null` weather → unknown (we can't see it), not calm.
 * Only genuinely disruptive conditions raise a risk; a cloudy day is not news.
 */
function weatherRisk(weather, airportLabel = null) {
  const at = airportLabel ? ` at ${airportLabel}` : "";
  if (weather == null) {
    return [{ kind: "weather", severity: "unknown", why: `I can't see the weather${at} right now.` }];
  }
  const cond = String(weather.condition || weather.summary || weather.description || "").trim();
  if (cond && SEVERE_WX.test(cond)) {
    return [{ kind: "weather", severity: "high", why: `${cond}${at} — a real delay or cancellation risk.` }];
  }
  return [];
}

/**
 * Assess a day. Returns risks ranked most-severe first. `unknown`s sort last but are kept —
 * the thing Wingman can't assess is exactly what the traveler should know it can't.
 *
 * @param flights     [{ departs_at, arrives_at, carrier, flight_number, destination }]
 * @param weather     { condition|summary } | null  (weather at the departure/connection airport)
 * @param weatherLabel airport/city label for the weather line
 * @param minConnMins traveler's comfort (default 45)
 */
function assessDay({ flights = [], weather = undefined, weatherLabel = null, minConnMins = 45 } = {}) {
  const conns = tightConnections(flights, minConnMins);
  const risks = [...conns, ...bagRisk(conns)];
  // weather === undefined → caller has no weather to offer, skip it entirely.
  // weather === null → we LOOKED and couldn't see it, which is an honest `unknown` risk.
  if (weather !== undefined) risks.push(...weatherRisk(weather, weatherLabel));
  return risks.sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0));
}

module.exports = { assessDay, tightConnections, bagRisk, weatherRisk, RANK };
