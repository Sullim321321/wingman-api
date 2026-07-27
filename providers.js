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
// No live feed exists in the registry. We point at MyTSA (the authoritative source)
// and say so plainly. The drop-in slot activates the moment a feed is connectable.
function securityInfo(airport) {
  if (!airport) return { source: "none", note: null };
  // (Slot: if process.env.SECURITY_WAIT_PROVIDER → return { source: "live", wait_min } here.)
  return {
    source: "link",
    link: "https://www.tsa.gov/mobile",
    note: "No live security-wait feed exists; check MyTSA for current waits.",
  };
}

// ── TERMINAL MAP ─────────────────────────────────────────────────────────────────
function terminalMap(airport) {
  if (!airport) return { source: "none", link: null };
  return {
    source: "link",
    link: `https://www.google.com/maps/search/?api=1&query=${enc(airport + " airport terminal map")}`,
  };
}

module.exports = { rideOptions, fetchUberEstimate, securityInfo, terminalMap };
