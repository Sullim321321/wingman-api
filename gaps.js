// gaps.js — the shape of your time, not just your meetings.
//
// ─────────────────────────────────────────────────────────────────────────────
// The Curator's alive moment ("two hours to yourself until the 3pm") needs one
// thing the calendar never states outright: the FREE windows between your
// commitments. This finds them — within waking hours, in the future, never
// overlapping anything you're committed to — and can say whether a given outing
// actually FITS, travel both ways included, so "back by 2:40" is a computed fact
// and not a hope.
//
// Pure and dependency-free. Times are handled at a fixed tz offset (hours) so the
// same logic is exact and testable without a timezone database — the destination's
// offset is passed in, the way itinerary.js and autonomy.js take what they need.
// ─────────────────────────────────────────────────────────────────────────────

const HOUR = 3600000, DAY = 86400000;
const ms = (v) => { const t = new Date(v).getTime(); return Number.isNaN(t) ? null : t; };

// UTC-ms of local midnight for "today + d", given a tz offset in hours.
function localMidnightUtc(nowMs, offsetH, d) {
  const off = offsetH * HOUR;
  return Math.floor((nowMs + off) / DAY) * DAY + d * DAY - off;
}

// Subtract busy intervals from [winStart, winEnd] → array of free [start,end] pairs.
function subtract(winStart, winEnd, busy) {
  let free = [[winStart, winEnd]];
  for (const [bs, be] of busy) {
    const next = [];
    for (const [fs, fe] of free) {
      if (be <= fs || bs >= fe) { next.push([fs, fe]); continue; } // no overlap
      if (bs > fs) next.push([fs, Math.min(bs, fe)]);              // piece before busy
      if (be < fe) next.push([Math.max(be, fs), fe]);             // piece after busy
    }
    free = next;
  }
  return free;
}

/**
 * Find free pockets between commitments.
 *
 * @param commitments  [{ start, end }]  (gcal shape; end optional → treated as start)
 * @param opts.now         epoch ms (default Date.now())
 * @param opts.offsetH     destination tz offset in hours (default 0)
 * @param opts.dayStart    waking hour, local (default 8)
 * @param opts.dayEnd      wind-down hour, local (default 22)
 * @param opts.minMinutes  smallest pocket worth surfacing (default 60)
 * @param opts.horizonDays how many days ahead to scan, inclusive of today (default 2)
 * @returns [{ start, end, minutes }] future free windows, chronological
 */
function findFreePockets(commitments, opts = {}) {
  const now = opts.now != null ? opts.now : Date.now();
  const offsetH = opts.offsetH || 0;
  const dayStart = opts.dayStart != null ? opts.dayStart : 8;
  const dayEnd = opts.dayEnd != null ? opts.dayEnd : 22;
  const minMs = (opts.minMinutes != null ? opts.minMinutes : 60) * 60000;
  const horizon = opts.horizonDays != null ? opts.horizonDays : 2;

  // Busy intervals, valid + sorted.
  const busy = (commitments || [])
    .map((c) => [ms(c.start), ms(c.end) != null ? ms(c.end) : ms(c.start)])
    .filter(([s, e]) => s != null && e != null && e >= s)
    .sort((a, b) => a[0] - b[0]);

  const pockets = [];
  for (let d = 0; d <= horizon; d++) {
    const mid = localMidnightUtc(now, offsetH, d);
    const winStart = Math.max(mid + dayStart * HOUR, now); // today starts at NOW
    const winEnd = mid + dayEnd * HOUR;
    if (winStart >= winEnd) continue;
    for (const [fs, fe] of subtract(winStart, winEnd, busy)) {
      if (fe - fs >= minMs) {
        pockets.push({ start: new Date(fs).toISOString(), end: new Date(fe).toISOString(), minutes: Math.round((fe - fs) / 60000) });
      }
    }
  }
  return pockets;
}

/**
 * Does an outing fit a pocket, travel both ways included? The honest check behind
 * "back by X". `back` is when you'd return: travel + activity + travel from the
 * pocket's start.
 */
function fits(pocket, activityMinutes, travelMinutesEachWay = 0) {
  const need = (activityMinutes || 0) + 2 * (travelMinutesEachWay || 0);
  const ok = need <= (pocket?.minutes || 0);
  const back = pocket?.start
    ? new Date(ms(pocket.start) + need * 60000).toISOString()
    : null;
  return { ok, need_minutes: need, back };
}

module.exports = { findFreePockets, fits };
