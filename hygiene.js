// hygiene.js — the app grooms itself, so you never hand-delete a stray leg again.
//
// ─────────────────────────────────────────────────────────────────────────────
// Pillar 4. The Nashville trip showed the failure exactly: the SAME hotel three
// times ("Kimpton Aertson Hotel", again as a sketch, and "Kimpton Aertson Hotel by
// IHG"), and a Southwest flight from MAY filed under a JULY trip. The old dedupe
// only caught byte-identical rows, so a brand suffix or a stray date walked right
// past it.
//
// Two pure rules here, both conservative — they collapse or flag, they never invent:
//   dedupeStays  — "Kimpton Aertson Hotel" and "…by IHG" are one stay. Keep the
//                  most-booked, most-complete copy; drop the rest.
//   staleLegs    — a leg whose date sits far outside the trip's real cluster (the
//                  May flight among July legs) doesn't belong to this trip.
//
// Conservative on purpose: when in doubt it keeps things. Deleting a real leg is
// worse than leaving a stray one, so the thresholds favour keeping.
// ─────────────────────────────────────────────────────────────────────────────

const LODGING = new Set(["hotel", "lodging", "airbnb", "stay", "accommodation"]);

// Canonical identity of a property: strip the chain/brand noise that makes the same
// hotel look like two. "Kimpton Aertson Hotel by IHG" → "kimpton aertson".
function normalizeProperty(name) {
  let s = String(name || "").toLowerCase().trim();
  if (!s) return "";
  s = s
    .replace(/\bby\s+(ihg|marriott|hilton|hyatt|accor|wyndham|choice|best western)\b.*$/i, " ")
    .replace(/[-–—,|].*$/, " ")                                  // drop "- IHG", ", Downtown", etc.
    .replace(/\b(hotel|hotels|resort|resorts|inn|suites?|lodge|the|and|&|spa|collection|by)\b/gi, " ")
    .replace(/[^a-z0-9 ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return s;
}

const dayOf = (v) => { const t = new Date(v).getTime(); return Number.isNaN(t) ? null : Math.floor(t / 86400000); };
const isLodging = (l) => l && (LODGING.has(String(l.type || "").toLowerCase()) || !!l.property_name);

// How complete / trustworthy a leg is — used to pick which duplicate to KEEP.
function legScore(l) {
  let s = 0;
  if (String(l.state || "") !== "proposed") s += 4;   // a real booking beats a sketch
  if (l.confirmation) s += 3;
  if (l.departs_at) s += 2;
  if (l.arrives_at) s += 1;
  return s;
}

/**
 * Collapse duplicate stays (same property, same trip) that differ only by brand
 * suffix / punctuation. Returns { kept, removed } — `removed` are the losers.
 * Non-lodging legs pass through untouched.
 */
function dedupeStays(legs) {
  const groups = new Map();
  const passthrough = [];
  for (const l of legs || []) {
    if (!isLodging(l)) { passthrough.push(l); continue; }
    const key = normalizeProperty(l.property_name || l.title);
    if (!key) { passthrough.push(l); continue; }
    // Group by property + check-in day (undated stays group on property alone), so
    // two genuinely different stays at the same hotel on different trips survive.
    const d = dayOf(l.departs_at);
    const bucket = `${key}|${d == null ? "x" : Math.round(d / 3)}`; // within ~3 days = same stay
    if (!groups.has(bucket)) groups.set(bucket, []);
    groups.get(bucket).push(l);
  }
  const kept = [...passthrough], removed = [];
  for (const [, group] of groups) {
    group.sort((a, b) => legScore(b) - legScore(a) || (a.id || 0) - (b.id || 0));
    kept.push(group[0]);
    for (const loser of group.slice(1)) removed.push(loser);
  }
  return { kept, removed };
}

/**
 * Flag legs whose date sits far outside the trip's real cluster. Uses the MEDIAN of
 * dated legs as the anchor; anything more than `maxDays` from it is stale. Undated
 * legs are never stale (nothing to judge). With too few dated legs to form a cluster
 * (< 3), we don't guess — return none.
 */
function staleLegs(legs, { maxDays = 30 } = {}) {
  const dated = (legs || []).filter((l) => dayOf(l.departs_at) != null);
  if (dated.length < 3) return [];
  const days = dated.map((l) => dayOf(l.departs_at)).sort((a, b) => a - b);
  const median = days[Math.floor(days.length / 2)];
  return dated.filter((l) => Math.abs(dayOf(l.departs_at) - median) > maxDays);
}

module.exports = { normalizeProperty, dedupeStays, staleLegs, legScore };
