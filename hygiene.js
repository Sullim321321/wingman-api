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

// NOTE: `new Date(null)` is 1970, not "invalid" — so a null date must be rejected
// BEFORE parsing, or an undated leg reads as an epoch outlier and gets wrongly
// flagged stale. This is the 1970 trap; it bites every time it isn't guarded.
const dayOf = (v) => {
  if (v == null || v === "") return null;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? null : Math.floor(t / 86400000);
};
const minuteOf = (v) => {
  if (v == null || v === "") return null;
  const t = new Date(v).getTime();
  return Number.isNaN(t) ? null : Math.floor(t / 60000);
};
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
const STAY_OUTLIER_DAYS = 45; // a same-property stay this far from the trip cluster is mis-dated

function dedupeStays(legs) {
  const passthrough = [];
  const stays = [];
  for (const l of legs || []) {
    if (isLodging(l) && normalizeProperty(l.property_name || l.title)) stays.push(l);
    else passthrough.push(l);
  }
  // The trip's real date cluster: median check-in of ALL dated legs. A same-property stay
  // far from it is a mis-parse (the Dec-31 Graduate that was really the July one), not a
  // second booking.
  const allDays = (legs || []).map((l) => dayOf(l.departs_at)).filter((d) => d != null).sort((a, b) => a - b);
  const median = allDays.length ? allDays[Math.floor(allDays.length / 2)] : null;

  const byProp = new Map();
  for (const l of stays) {
    const k = normalizeProperty(l.property_name || l.title);
    if (!byProp.has(k)) byProp.set(k, []);
    byProp.get(k).push(l);
  }

  const kept = [...passthrough], removed = [];
  const distToCluster = (l) => {
    const d = dayOf(l.departs_at);
    return (median != null && d != null) ? Math.abs(d - median) : Number.MAX_SAFE_INTEGER;
  };
  for (const [, group] of byProp) {
    if (group.length === 1) { kept.push(group[0]); continue; }
    // Primary = the copy most IN the trip's date cluster, then the most complete.
    group.sort((a, b) => distToCluster(a) - distToCluster(b) || legScore(b) - legScore(a) || (a.id || 0) - (b.id || 0));
    const survivors = [group[0]];
    for (const l of group.slice(1)) {
      const d = dayOf(l.departs_at);
      const dupNear = survivors.some((s) => {
        const sd = dayOf(s.departs_at);
        return sd != null && d != null && Math.abs(sd - d) <= 3;   // same check-in ≈ same stay
      });
      const outlier = median != null && d != null && Math.abs(d - median) > STAY_OUTLIER_DAYS;
      if (dupNear || outlier || d == null) removed.push(l);          // duplicate / mis-dated / undated copy
      else survivors.push(l);                                        // a genuine, plausibly-dated re-stay
    }
    kept.push(...survivors);
  }
  return { kept, removed };
}

/**
 * Canonical flight identity. Two rows are the SAME flight only when they share a real
 * identifier: the same flight number on the same day, or (number missing) the same
 * carrier + exact route on the same day. Deliberately conservative — two DIFFERENT
 * flights to the same city (AA 4611 JFK→PIT vs UA 3403 EWR→PIT) get different keys and
 * are NEVER merged. That's a genuine choice for the traveler, not a duplicate to delete.
 */
function flightKey(l) {
  const day = dayOf(l && l.departs_at);
  if (day == null) return null;                                   // undated → don't guess
  const num = String((l && l.flight_number) || "").toUpperCase().replace(/\s+/g, "");
  if (num) return `n|${num}|${day}`;                              // strongest signal
  const carrier = String((l && l.carrier) || "").toLowerCase().replace(/\s+/g, "");
  const o = String((l && l.origin) || "").toUpperCase().trim();
  const d = String((l && l.destination) || "").toUpperCase().trim();
  if (carrier && o && d) return `r|${carrier}|${o}|${d}|${day}`;  // carrier + route + day
  return null;                                                    // too little → keep
}

/**
 * Collapse exact-duplicate flights (same flight, imported twice). Returns { kept, removed }.
 * Non-flight legs and flights we can't positively identify pass through untouched.
 */
function dedupeFlights(legs) {
  const groups = new Map();
  const passthrough = [];
  for (const l of legs || []) {
    if (String((l && l.type) || "").toLowerCase() !== "flight") { passthrough.push(l); continue; }
    const key = flightKey(l);
    if (!key) { passthrough.push(l); continue; }
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(l);
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
 * Codeshare identity. Two flight rows are the SAME physical flight — sold under two
 * carriers' numbers (AA 4611 operated as / marketed as UA 3403) — when they share the
 * exact route AND the exact departure minute. This is deliberately DIFFERENT from
 * flightKey(): that one trusts the flight number and so (correctly) keeps genuinely
 * different flights apart. Here we IGNORE the number, because the number is exactly what
 * differs in a codeshare. Conservative: requires origin, destination, and a real
 * departure time. If two rows share route + departure minute they are the same flight —
 * unless BOTH carry an arrival time and those DISAGREE, which means it isn't one aircraft.
 */
function codeshareKey(l) {
  if (String((l && l.type) || "").toLowerCase() !== "flight") return null;
  const dep = minuteOf(l && l.departs_at);
  if (dep == null) return null;
  const o = String((l && l.origin) || "").toUpperCase().trim();
  const d = String((l && l.destination) || "").toUpperCase().trim();
  if (!o || !d) return null;
  return `${o}|${d}|${dep}`;
}

/**
 * Collapse codeshare duplicates — one physical flight imported under two carrier numbers.
 * Returns { kept, removed }. Keeps the most complete row (legScore). Runs alongside
 * dedupeFlights, which handles exact same-number duplicates; this handles the cross-number
 * case flightKey() intentionally leaves alone.
 */
function dedupeCodeshares(legs) {
  const groups = new Map();
  const passthrough = [];
  for (const l of legs || []) {
    const key = codeshareKey(l);
    if (!key) { passthrough.push(l); continue; }
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(l);
  }
  const kept = [...passthrough], removed = [];
  for (const [, group] of groups) {
    if (group.length < 2) { kept.push(group[0]); continue; }
    // Safety: if the group carries two or more DIFFERENT arrival times, these aren't the
    // same aircraft — don't merge any of them.
    const arrs = new Set(group.map((l) => minuteOf(l.arrives_at)).filter((m) => m != null));
    if (arrs.size >= 2) { kept.push(...group); continue; }
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

module.exports = { normalizeProperty, dedupeStays, dedupeFlights, dedupeCodeshares, flightKey, codeshareKey, staleLegs, legScore };
