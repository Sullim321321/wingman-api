/**
 * concierge.js — C6c: draft a booking-request email for hotels Duffel can't book.
 *
 * Wingman writes the request; the user sends it from their own mail client (a mailto:),
 * so every send is theirs to make. The composer is pure and honest:
 *   · it ASKS the hotel to confirm availability, rate, and cancellation terms;
 *   · it NEVER states a reservation exists or invents a confirmation number;
 *   · it includes a preference (loyalty number, room request) ONLY when given — no
 *     leaking a detail that wasn't provided.
 *
 * True send-on-behalf (one tap, no mail client) would need an outbound email provider
 * wired in; that's an optional follow-on. This delivers the value now with no new infra.
 */

function fmtDay(iso) {
  const dt = new Date(String(iso) + (String(iso).length === 10 ? "T00:00:00Z" : ""));
  if (Number.isNaN(dt.getTime())) return String(iso);
  return dt.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
}
function nightsBetween(ci, co) {
  const a = Date.parse(ci + "T00:00:00Z"), b = Date.parse(co + "T00:00:00Z");
  if (Number.isNaN(a) || Number.isNaN(b) || b <= a) return null;
  return Math.round((b - a) / 864e5);
}

/**
 * composeBookingEmail — build { to, subject, body, mailto }.
 * @param o.hotelName   required — refuse without it (no emailing nobody)
 * @param o.area        optional neighbourhood, for the greeting
 * @param o.checkIn/checkOut  YYYY-MM-DD
 * @param o.guestName   who the room is for
 * @param o.to          hotel reservations address (optional; user can fill it)
 * @param o.loyalty     { program, number } — included only if present
 * @param o.preferences string[] — phrased as polite requests, only if present
 * @param o.roomPreference  free text (e.g. "a quiet king room")
 */
function composeBookingEmail(o = {}) {
  const hotelName = (o.hotelName || "").trim();
  if (!hotelName) throw new Error("hotelName is required to draft a booking request.");

  const guest = (o.guestName || "").trim() || "our guest";
  const ci = o.checkIn ? fmtDay(o.checkIn) : null;
  const co = o.checkOut ? fmtDay(o.checkOut) : null;
  const nights = o.checkIn && o.checkOut ? nightsBetween(o.checkIn, o.checkOut) : null;

  const subjectDates = ci ? `, ${ci}${co ? `–${co}` : ""}` : "";
  const subject = `Reservation request — ${hotelName}${subjectDates}`;

  const lines = [];
  lines.push(`Hello,`);
  lines.push("");
  const stay = ci && co
    ? `I'd like to request a room at ${hotelName}${o.area ? ` in ${o.area}` : ""} for ${ci} to ${co}${nights ? ` (${nights} night${nights === 1 ? "" : "s"})` : ""}.`
    : `I'd like to request a room at ${hotelName}${o.area ? ` in ${o.area}` : ""}.`;
  lines.push(stay);
  lines.push(`The reservation would be under ${guest}.`);

  if (o.roomPreference) lines.push(`If available, I'd prefer ${o.roomPreference}.`);

  if (Array.isArray(o.preferences) && o.preferences.length) {
    lines.push("");
    lines.push(`A few preferences, if they can be accommodated: ${o.preferences.join(", ")}.`);
  }

  if (o.loyalty && (o.loyalty.number || o.loyalty.program)) {
    const prog = o.loyalty.program ? `${o.loyalty.program} ` : "";
    const numb = o.loyalty.number ? `number ${o.loyalty.number}` : "membership";
    lines.push("");
    lines.push(`Please apply my ${prog}loyalty ${numb} to the stay.`);
  }

  lines.push("");
  lines.push(`Could you please confirm availability, the nightly rate, and the cancellation policy? I'll reply to confirm once I hear back.`);
  lines.push("");
  lines.push(`Thank you,`);
  lines.push(guest);

  const body = lines.join("\n");
  const to = (o.to || "").trim();
  const mailto = `mailto:${encodeURIComponent(to)}`.replace(/%40/g, "@")
    + `?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

  return { to, subject, body, mailto };
}

module.exports = { composeBookingEmail };
