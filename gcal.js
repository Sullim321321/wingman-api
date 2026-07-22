// gcal.js — turn raw Google Calendar events into clean commitments.
//
// ─────────────────────────────────────────────────────────────────────────────
// Pillar 1: the calendar is the spine. It's the highest-trust input Wingman has —
// you put those events there yourself. But "highest trust" is not "trust blindly."
// A raw Google Calendar feed contains things that are NOT your commitments:
//
//   • events you DECLINED — on your calendar, but you're not going.
//   • CANCELLED events — the meeting that got called off but lingers in the feed.
//   • TRANSPARENT events — "free" blocks: birthdays, someone else's PTO, all-day
//     informational entries. On your calendar, but they don't occupy your time.
//
// Treating any of those as a commitment is the same failure this whole project
// hunts — asserting something the evidence doesn't support. So this module reads
// the event's OWN signals (responseStatus, status, transparency) and only calls
// something a commitment when the calendar actually says it is one.
//
// Pure and dependency-free, so it's testable without Google, a token, or a network.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normalize ONE Google Calendar event into Wingman's shape, or null if it isn't
 * a real commitment (declined / cancelled / no usable time).
 *
 * A Google event carries time as EITHER:
 *   start.dateTime — a timed event (has a real instant + timezone)
 *   start.date     — an all-day event (a calendar date, no time)
 * We keep the distinction: an all-day "Conference" is a different thing from a
 * 2pm meeting, and travel reasoning needs to know which.
 */
function normalizeEvent(ev, { selfEmail = null } = {}) {
  if (!ev || typeof ev !== "object") return null;

  // Cancelled events linger in incremental syncs. They are not commitments.
  if (ev.status === "cancelled") return null;

  // Did YOU decline? Google marks the self attendee with responseStatus. A
  // declined event is on the calendar but is explicitly NOT where you'll be.
  const self = (ev.attendees || []).find(
    (a) => a && (a.self === true || (selfEmail && a.email && a.email.toLowerCase() === selfEmail.toLowerCase())),
  );
  if (self && self.responseStatus === "declined") return null;

  const allDay = !!(ev.start && ev.start.date && !ev.start.dateTime);
  const startRaw = ev.start && (ev.start.dateTime || ev.start.date);
  const endRaw = ev.end && (ev.end.dateTime || ev.end.date);
  if (!startRaw) return null; // no time we can place → not usable

  // Validate rather than trust: an unparseable date is dropped, never coerced to
  // 1970 (the epoch bug that put things in "the distant past").
  const startMs = new Date(startRaw).getTime();
  if (Number.isNaN(startMs)) return null;
  let endMs = endRaw ? new Date(endRaw).getTime() : NaN;
  if (Number.isNaN(endMs)) endMs = startMs; // point in time if end is missing/bad

  // "transparent" = shows as Free. It's on the calendar but doesn't occupy you —
  // a soft signal, not a hard commitment. We keep it but flag busy=false so the
  // caller can weight it correctly rather than treat a birthday like a meeting.
  const busy = ev.transparency !== "transparent";

  return {
    source: "calendar",
    calendar_id: ev.id || null,
    title: (ev.summary || "").trim() || "(no title)",
    location: (ev.location || "").trim() || null,
    all_day: allDay,
    start: new Date(startMs).toISOString(),
    end: new Date(endMs).toISOString(),
    busy,
    // Calendar is the highest-trust source: you put it there. Stated, not inferred.
    certain: true,
    response: self ? self.responseStatus || "accepted" : "accepted",
  };
}

/**
 * Normalize a list of raw events, dropping the ones that aren't commitments,
 * sorted by start. `busyOnly` filters out transparent/free entries entirely —
 * useful when the caller wants only things that actually occupy the day.
 */
function commitmentsFrom(events, { selfEmail = null, busyOnly = false } = {}) {
  const out = [];
  for (const ev of events || []) {
    const c = normalizeEvent(ev, { selfEmail });
    if (!c) continue;
    if (busyOnly && !c.busy) continue;
    out.push(c);
  }
  out.sort((a, b) => new Date(a.start) - new Date(b.start));
  return out;
}

module.exports = { normalizeEvent, commitmentsFrom };
