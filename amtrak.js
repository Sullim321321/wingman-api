// amtrak.js — read a live Amtrak status out of the Amtraker (community) feed, honestly.
//
// ─────────────────────────────────────────────────────────────────────────────
// Amtrak has no official public real-time API. The community Amtraker v3 feed
// (api.amtraker.com) is the realistic source: an object keyed by train number,
// each value an array of running instances, each instance a list of `stations`
// with scheduled vs. actual times, a free-text delay comment ("45 MIN LATE"), a
// platform, and a `trainState` (Predeparture / Active / Completed).
//
// This module is the PURE adapter: given that payload and the leg we care about, it
// finds the right train + the right station stop and reads a status in the shape the
// rail spine already understands ({ status, delayMins, platform }). The network call
// lives in the server; the interpretation lives here so it can be tested against
// fixtures — and so its one non-negotiable rule is enforceable: a train that hasn't
// reported anything is "Unknown", NEVER a fabricated "On Time".
// ─────────────────────────────────────────────────────────────────────────────

const onlyDigits = (s) => { const m = String(s || "").match(/\d+/); return m ? m[0] : null; };

// Flatten Amtraker's { "5": [inst, …], … } (or a single-train { "5": [inst] }) to a list.
function flattenTrains(payload) {
  if (Array.isArray(payload)) return payload;
  const out = [];
  for (const k of Object.keys(payload || {})) if (Array.isArray(payload[k])) out.push(...payload[k]);
  return out;
}

// Does an Amtraker station stop refer to the same place as our leg endpoint? Match on
// the 3-letter code or a name overlap, case-insensitively.
function stationMatches(stop, ref) {
  if (!ref || !stop) return false;
  const r = String(ref).trim().toLowerCase();
  if (!r) return false;
  const code = String(stop.code || "").toLowerCase();
  const name = String(stop.name || "").toLowerCase();
  return code === r || (name && (name.includes(r) || r.includes(name)));
}

// Parse Amtrak's free-text delay comment. "1 HR 30 MIN LATE" → 90; "12 MIN LATE" → 12;
// "5 MIN EARLY" → -5; "ON TIME" → 0; "SERVICE CANCELLED" → {cancelled}; "" → null (silent).
function parseComment(cmnt) {
  const s = String(cmnt || "").toUpperCase().trim();
  if (!s) return null;
  if (s.includes("CANCEL")) return { cancelled: true };
  const late = s.includes("LATE"), early = s.includes("EARLY");
  if (!late && !early) return s.includes("ON TIME") ? { mins: 0 } : null;
  let mins = 0;
  const hr = s.match(/(\d+)\s*HR/), mn = s.match(/(\d+)\s*MIN/);
  if (hr) mins += parseInt(hr[1], 10) * 60;
  if (mn) mins += parseInt(mn[1], 10);
  return { mins: early ? -mins : mins };
}

/**
 * Pick the running train instance + the stop that corresponds to our leg. Prefer a
 * train-number match (Amtrak legs carry the number), then the instance whose
 * origin-stop scheduled departure is closest to the leg's departure (within a day).
 * Returns { train, stop } or { train: null, stop: null }.
 */
function matchTrain(payload, leg = {}) {
  const num = onlyDigits(leg.trainNum);
  let cands = flattenTrains(payload);
  if (num) cands = cands.filter((t) => onlyDigits(t.trainNum) === num);
  if (!cands.length) return { train: null, stop: null };

  const wantMs = leg.departsAt ? Date.parse(leg.departsAt) : NaN;
  const stopFor = (t) => {
    const stns = t.stations || [];
    return stns.find((st) => stationMatches(st, leg.from)) || stns[0] || null;
  };
  let best = null, bestDiff = Infinity;
  for (const t of cands) {
    const stop = stopFor(t);
    if (!stop) continue;
    const depMs = Date.parse(stop.schDep || stop.schArr || "");
    const diff = Number.isFinite(wantMs) && Number.isFinite(depMs) ? Math.abs(depMs - wantMs) : 0;
    if (diff < bestDiff) { bestDiff = diff; best = { train: t, stop }; }
  }
  // If we had a departure time to match on, reject a match more than 36h off — that's
  // a different run of the same train number, not this leg.
  if (best && Number.isFinite(wantMs) && bestDiff > 36 * 3600000) return { train: null, stop: null };
  return best || { train: null, stop: null };
}

/**
 * Read a status from a matched train + stop, in the spine's shape. Conservative by
 * design: only an explicit signal yields Delayed / Cancelled / On Time; anything
 * ambiguous (a not-yet-departed train with no comment) is "Unknown", never invented.
 */
function readStatus(train, stop) {
  if (!train || !stop) return { status: "Unknown", platform: null };
  const platform = stop.platform || null;
  const state = String(train.trainState || "").toLowerCase();
  const blob = `${train.statusMsg || ""} ${stop.arrCmnt || ""} ${stop.depCmnt || ""}`.toUpperCase();
  if (blob.includes("CANCEL") || state === "cancelled") return { status: "Cancelled", platform };

  let mins = null;
  const c = parseComment(stop.depCmnt) || parseComment(stop.arrCmnt);
  if (c && c.cancelled) return { status: "Cancelled", platform };
  if (c && typeof c.mins === "number") mins = c.mins;
  // Fall back to sched-vs-actual, but only for a train that's actually moving, and
  // only to detect a DELAY. A zero gap is indistinguishable from the schedule being
  // echoed, so it must not become a confident "On Time" — that stays Unknown.
  if (mins == null && state === "active" && stop.dep && stop.schDep) {
    const d = Math.round((Date.parse(stop.dep) - Date.parse(stop.schDep)) / 60000);
    if (Number.isFinite(d) && d >= 5) mins = d;
  }
  if (mins == null) return { status: "Unknown", platform };
  if (mins >= 5) return { status: "Delayed", delayMins: mins, platform };
  return { status: "On Time", platform };
}

/** The one call the server makes: payload + leg → the spine's status shape. */
function toStatusResult(payload, leg = {}) {
  const { train, stop } = matchTrain(payload, leg);
  const r = readStatus(train, stop);
  return { ...r, network: "amtrak", source: "amtraker" };
}

module.exports = {
  onlyDigits, flattenTrains, stationMatches, parseComment, matchTrain, readStatus, toStatusResult,
};
