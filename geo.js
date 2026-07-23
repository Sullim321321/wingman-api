// geo.js — turn a place string into a point on the earth, so "near Chicago" is a
// measured fact instead of a string that happens to match.
//
// ─────────────────────────────────────────────────────────────────────────────
// The gazetteer version asked about "Evanston, IL" because it had never heard of
// Evanston — even though it's 12 miles from the Chicago meeting and obviously the
// same trip. String matching can't know that; coordinates can. So this resolves a
// place to { city, lat, lng } and lets the caller reason by distance.
//
// Three layers, cheapest first:
//   1. cache        — we never geocode the same string twice in a run.
//   2. gazetteer    — your common cities, with coordinates baked in, no network.
//   3. Nominatim    — OpenStreetMap's geocoder for everything else. Free, no key.
//
// Honesty preserved: when nothing resolves, city/lat/lng are null and `source`
// says why. The caller then ASKS instead of inventing a location — the same rule
// the whole project runs on. `fetchImpl` is injected so tests never touch the net.
// ─────────────────────────────────────────────────────────────────────────────

// Common cities with coordinates — the fast path that avoids a network call for
// the places you actually go. Extend freely; misses fall through to Nominatim.
const GAZETTEER = {
  "new york":      { city: "New York",      lat: 40.7128, lng: -74.0060 },
  "nyc":           { city: "New York",      lat: 40.7128, lng: -74.0060 },
  "manhattan":     { city: "New York",      lat: 40.7831, lng: -73.9712 },
  "london":        { city: "London",        lat: 51.5074, lng: -0.1278 },
  "nashville":     { city: "Nashville",     lat: 36.1627, lng: -86.7816 },
  "chicago":       { city: "Chicago",       lat: 41.8781, lng: -87.6298 },
  "dallas":        { city: "Dallas",        lat: 32.7767, lng: -96.7970 },
  "austin":        { city: "Austin",        lat: 30.2672, lng: -97.7431 },
  "houston":       { city: "Houston",       lat: 29.7604, lng: -95.3698 },
  "san francisco": { city: "San Francisco", lat: 37.7749, lng: -122.4194 },
  "los angeles":   { city: "Los Angeles",   lat: 34.0522, lng: -118.2437 },
  "seattle":       { city: "Seattle",       lat: 47.6062, lng: -122.3321 },
  "boston":        { city: "Boston",        lat: 42.3601, lng: -71.0589 },
  "washington":    { city: "Washington",    lat: 38.9072, lng: -77.0369 },
  "atlanta":       { city: "Atlanta",       lat: 33.7490, lng: -84.3880 },
  "miami":         { city: "Miami",         lat: 25.7617, lng: -80.1918 },
  "denver":        { city: "Denver",        lat: 39.7392, lng: -104.9903 },
  "toronto":       { city: "Toronto",       lat: 43.6532, lng: -79.3832 },
  "paris":         { city: "Paris",         lat: 48.8566, lng: 2.3522 },
};
// Cities big enough to name a trip when a cluster spans several towns (Evanston +
// Chicago → "Chicago"). Derived from the gazetteer's canonical names.
const HUBS = [...new Set(Object.values(GAZETTEER).map((g) => g.city))];

// Great-circle distance in miles. Infinity when either point is unknown, so an
// unresolved place is never accidentally "close" to anything.
function haversineMiles(a, b) {
  if (!a || !b || a.lat == null || b.lat == null) return Infinity;
  const R = 3958.8, rad = (d) => (d * Math.PI) / 180;
  const dLat = rad(b.lat - a.lat), dLng = rad(b.lng - a.lng);
  const s = Math.sin(dLat / 2) ** 2 +
    Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(s));
}

const _cache = new Map();

// A calendar location is messy — "Starbucks Coffee Company\n1734 Sherman Ave,
// Evanston, IL 60201, United States". Nominatim's free-form search does badly with
// a business-name prefix, so we try a few progressively cleaner queries and take
// the first that resolves: the street address without the business name, the whole
// thing, then just "city, state, country".
function queryCandidates(raw) {
  const one = raw.replace(/\s+/g, " ").trim();
  const parts = one.split(",").map((s) => s.trim()).filter(Boolean);
  const out = [];
  const fromDigit = one.match(/\d.*/);            // "1734 Sherman Ave, Evanston, IL..."
  if (fromDigit) out.push(fromDigit[0]);
  out.push(one);
  if (parts.length >= 3) out.push(parts.slice(-3).join(", "));
  if (parts.length >= 2) out.push(parts.slice(-2).join(", "));
  return [...new Set(out)];
}

// Nominatim asks for <= 1 request/second. Serialize network calls to stay polite.
let _lastCall = 0;
async function throttle() {
  const wait = 1100 - (Date.now() - _lastCall);
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
  _lastCall = Date.now();
}

async function resolvePlace(text, { fetchImpl } = {}) {
  const raw = String(text || "").trim();
  if (!raw) return { city: null, lat: null, lng: null, source: "empty" };
  const key = raw.toLowerCase();
  if (_cache.has(key)) return _cache.get(key);

  // gazetteer: a known city name appearing anywhere in the text wins immediately.
  for (const name of Object.keys(GAZETTEER)) {
    const re = new RegExp("\\b" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "i");
    if (re.test(raw)) {
      const r = { ...GAZETTEER[name], source: "gazetteer" };
      _cache.set(key, r);
      return r;
    }
  }

  const f = fetchImpl || (typeof fetch !== "undefined" ? fetch : null);
  if (!f) { const r = { city: null, lat: null, lng: null, source: "no_fetch" }; _cache.set(key, r); return r; }

  let detail = "no match";
  for (const q of queryCandidates(raw)) {
    try {
      if (!fetchImpl) await throttle(); // don't throttle mocked tests
      const url = "https://nominatim.openstreetmap.org/search?format=jsonv2&addressdetails=1&limit=1&q=" + encodeURIComponent(q);
      const resp = await f(url, { headers: { "User-Agent": "Wingman/1.0 (personal travel assistant; maddie@welcometothefight.club)" } });
      if (resp && resp.ok === false) { detail = "http " + resp.status; continue; }
      const arr = await resp.json();
      if (Array.isArray(arr) && arr[0]) {
        const a = arr[0], ad = a.address || {};
        const city = ad.city || ad.town || ad.village || ad.suburb || ad.municipality || ad.county || null;
        const r = {
          city, lat: parseFloat(a.lat), lng: parseFloat(a.lon),
          state: ad.state || null, country: ad.country || null,
          source: "nominatim", query: q, display: a.display_name || null,
        };
        _cache.set(key, r);
        return r;
      }
    } catch (e) {
      detail = e.message;
      console.error("[geo] nominatim failed for", JSON.stringify(q), "-", e.message);
    }
  }
  const miss = { city: null, lat: null, lng: null, source: "geocode_failed", detail };
  _cache.set(key, miss);
  return miss;
}

// Reverse: device coordinates → a city name, so "where you are" (from the phone's
// GPS, which has no city string) can resolve to an airport. Cached + throttled like
// the forward path; honest null when it can't tell.
async function resolveCoords(lat, lng, { fetchImpl } = {}) {
  const la = parseFloat(lat), lo = parseFloat(lng);
  if (Number.isNaN(la) || Number.isNaN(lo)) return { city: null, lat: null, lng: null, source: "bad_coords" };
  const key = `rev:${la.toFixed(3)},${lo.toFixed(3)}`;
  if (_cache.has(key)) return _cache.get(key);

  const f = fetchImpl || (typeof fetch !== "undefined" ? fetch : null);
  if (!f) { const r = { city: null, lat: la, lng: lo, source: "no_fetch" }; _cache.set(key, r); return r; }
  try {
    if (!fetchImpl) await throttle();
    const url = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&zoom=10&lat=${la}&lon=${lo}`;
    const resp = await f(url, { headers: { "User-Agent": "Wingman/1.0 (personal travel assistant; maddie@welcometothefight.club)" } });
    if (resp && resp.ok === false) { const r = { city: null, lat: la, lng: lo, source: "http " + resp.status }; _cache.set(key, r); return r; }
    const data = await resp.json();
    const ad = (data && data.address) || {};
    const city = ad.city || ad.town || ad.village || ad.municipality || ad.county || null;
    const r = { city, lat: la, lng: lo, state: ad.state || null, country: ad.country || null, source: "nominatim_reverse" };
    _cache.set(key, r);
    return r;
  } catch (e) {
    console.error("[geo] reverse failed:", e.message);
    const r = { city: null, lat: la, lng: lo, source: "reverse_failed" };
    _cache.set(key, r);
    return r;
  }
}

module.exports = { resolvePlace, resolveCoords, haversineMiles, GAZETTEER, HUBS };
