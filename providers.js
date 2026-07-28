// providers.js — the seam for real-world feeds (Roadmap v3, Epic 4).
//
// Wingman's honesty architecture says: never assert a number we cannot measure. Today
// the ground layer is deep-links and links to authoritative sources — because the
// connector registry has no rideshare-dispatch, security-wait, terminal-map, or
// ground-transit feed the SERVER can call. (There IS an Uber *estimate* connector, but
// it's an MCP the user connects in their client, not a server credential.)
//
// This module is the single place those capabilities resolve, so the day a real feed
// becomes connectable it drops in here — behind an env flag — and every surface that
// already reads `source` starts showing "live" instead of "link", with no rewrite.
//
// Every function returns a `source` the UI can badge honestly:
//   "live"     — a real feed answered (only when a provider is configured)
//   "estimate" — a real estimate answered (price/ETA, not a live dispatch)
//   "link"     — we can't measure it; here's the authoritative place to look
//   "none"     — nothing available and nothing to link to

const enc = encodeURIComponent;

// ── RIDE ──────────────────────────────────────────────────────────────────────
// A ride is always a LINK the user taps — never an autonomous order (no-spend rail).
// If an Uber Rides estimate token is ever configured on the server, we ALSO attach a
// real price/ETA estimate; the user still taps to order. No token → link only, as today.
async function rideOptions({ pickup, dropoff } = {}) {
  const nick = enc(`${pickup?.label || "Airport"}`);
  const base = pickup
    ? `action=setPickup&pickup[latitude]=${pickup.lat}&pickup[longitude]=${pickup.lng}&pickup[nickname]=${nick}`
    : "action=setPickup&pickup=my_location";
  const drop = dropoff?.address ? `&dropoff[addressString]=${enc(dropoff.address)}` : "";
  const links = {
    deepLink: `uber://?${base}${drop}`,
    webFallback: `https://m.uber.com/ul/?${base}${drop}`,
    dropoff: dropoff?.address || null,
  };

  // Drop-in slot: a real estimate, only if a server token is configured AND we have
  // both endpoints. Guarded so an unconfigured prod can never reach the network call.
  if (process.env.UBER_ESTIMATE_TOKEN && pickup && dropoff?.lat && dropoff?.lng) {
    try {
      const est = await fetchUberEstimate(pickup, dropoff);
      if (est) return { source: "estimate", ...links, estimate: est };
    } catch (_) { /* fall through to the honest link */ }
  }
  return { source: "link", ...links, estimate: null };
}

// Isolated so it's trivially mockable in a test and never runs without a token.
async function fetchUberEstimate(pickup, dropoff) {
  const r = await fetch(
    `https://api.uber.com/v1.2/estimates/price?start_latitude=${pickup.lat}` +
    `&start_longitude=${pickup.lng}&end_latitude=${dropoff.lat}&end_longitude=${dropoff.lng}`,
    { headers: { Authorization: `Token ${process.env.UBER_ESTIMATE_TOKEN}`, Accept: "application/json" } }
  );
  if (!r.ok) return null;
  const j = await r.json();
  const p = (j.prices || [])[0];
  if (!p) return null;
  // Only fields a real feed actually returns — no fabrication.
  return { display: p.estimate || null, low: p.low_estimate ?? null, high: p.high_estimate ?? null,
           currency: p.currency_code || null, duration_min: p.duration ? Math.round(p.duration / 60) : null,
           product: p.display_name || null };
}

// ── SECURITY WAIT ───────────────────────────────────────────────────────────────
// No live feed exists in the registry, and TSA has no public wait-time API. We point at
// MyTSA (the authoritative source) and say so plainly.
//
// DROP-IN CONTRACT: set SECURITY_WAIT_URL to an endpoint that takes `?airport=XXX` and
// returns JSON { wait_min: <number>, checkpoint?: <string> }. When it's set and answers,
// we badge `source:"live"` with a real number; otherwise we fall back to the honest link.
// Whoever wires a real provider only has to satisfy that four-field contract — no rewrite.
async function securityInfo(airport) {
  if (!airport) return { source: "none", note: null };
  const url = process.env.SECURITY_WAIT_URL;
  if (url) {
    try {
      const sep = url.includes("?") ? "&" : "?";
      const r = await fetch(`${url}${sep}airport=${enc(airport)}`, { headers: { Accept: "application/json" } });
      if (r.ok) {
        const j = await r.json();
        if (typeof j.wait_min === "number") {
          return { source: "live", wait_min: Math.round(j.wait_min), checkpoint: j.checkpoint || null,
                   link: "https://www.tsa.gov/mobile" };
        }
      }
    } catch (_) { /* fall through to the honest link */ }
  }
  return {
    source: "link",
    link: "https://www.tsa.gov/mobile",
    note: "No live security-wait feed exists; check MyTSA for current waits.",
  };
}

// ── TERMINAL MAP ─────────────────────────────────────────────────────────────────
// DROP-IN CONTRACT: set TERMINAL_MAP_URL to a template containing `{airport}` (e.g. an
// interactive terminal-map provider). When set, we return that resolved URL as `live`;
// otherwise a Google-maps search link, as today.
function terminalMap(airport) {
  if (!airport) return { source: "none", link: null };
  const tmpl = process.env.TERMINAL_MAP_URL;
  if (tmpl && tmpl.includes("{airport}")) {
    return { source: "live", link: tmpl.replace("{airport}", enc(airport)) };
  }
  return {
    source: "link",
    link: `https://www.google.com/maps/search/?api=1&query=${enc(airport + " airport terminal map")}`,
  };
}

module.exports = { rideOptions, fetchUberEstimate, securityInfo, terminalMap };
