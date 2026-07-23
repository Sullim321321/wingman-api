// meeting.js — is this a place you have to BE, or a place you dial into?
//
// ─────────────────────────────────────────────────────────────────────────────
// The whole point of reading your calendar is to infer travel: a meeting in a
// city you're not in means you have to get there. But most meetings are not
// travel — they're Zoom, Teams, a phone call. Proposing a flight to Dallas for a
// video call would be the exact failure this project hunts: a suggestion built on
// evidence that doesn't support it.
//
// So before anything infers a trip, it must answer one question honestly:
//
//   VIRTUAL     there's a video/phone link — you attend from wherever you are.
//   IN_PERSON   there's a real place (a street, a venue, a city) and no dial-in.
//   AMBIGUOUS   there's BOTH — a Zoom link AND "Conference · Dallas". You might
//               fly, you might dial in. We do NOT guess; ambiguous is a question,
//               never a trip. (This is your real Texas Rangers meeting.)
//   UNKNOWN     no location, no link — we can't tell, so we say we can't.
//
// AMBIGUOUS and UNKNOWN are deliberately different: one is conflicting evidence,
// the other is no evidence. Collapsing them would let "I don't know" masquerade
// as "it's complicated," and both would quietly become a booked flight.
//
// Pure and dependency-free — no calendar, no token, no network needed to test it.
// ─────────────────────────────────────────────────────────────────────────────

// Video-conferencing hosts. A URL to any of these is a hard "you can attend remotely".
const VIDEO_HOST = /zoom\.us|teams\.microsoft\.com|teams\.live\.com|meet\.google\.com|webex\.com|whereby\.com|gotomeeting\.com|bluejeans\.com|chime\.aws|meet\.jit\.si|around\.co|riverside\.fm|hangouts\.google\.com/i;
// Named platforms / phrases that mean "virtual" even without a URL.
const VIDEO_WORD = /\b(zoom|microsoft teams|ms teams|google meet|google hangouts?|hangouts?|webex|gotomeeting|blue\s?jeans|skype|facetime|whereby|video ?call|video ?conference|virtual meeting|online meeting)\b/i;
// Phone-only signals.
const PHONE_WORD = /\b(conference call|dial[-\s]?in|dial in|phone call|call[-\s]?in|tele-?conference|audio only|by phone|call details)\b/i;
const URL = /\bhttps?:\/\/\S+/gi;
// A street address is unambiguous physical presence.
const STREET = /\b\d{1,6}\s+[0-9a-z.\s]+?\b(street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln|way|court|ct|place|pl|plaza|square|sq|suite|ste|floor|fl|highway|hwy|parkway|pkwy|terrace|ter)\b/i;
// Video/phone LABELS to remove from the location before deciding if a real place remains.
const LABELS = /microsoft teams(?:\s+meeting)?|ms teams|google meet|google hangouts?|zoom(?:\s+meeting)?|webex|gotomeeting|blue\s?jeans|skype|hangouts?|whereby|video ?call|video ?conference|conference call|dial[-\s]?in|phone call/gi;

const s = (v) => String(v == null ? "" : v).trim();

/**
 * Classify one meeting. Accepts either a normalized commitment (from gcal.js) or a
 * raw-ish event: it reads title/summary, location, description, and `conference`
 * (an array like ["video","phone"] derived from Google's conferenceData).
 *
 * Returns { nature, virtual, physical, signals, place } where `place` is the real
 * location text when physical (for the trip-inference step to resolve to a city),
 * or null.
 */
function classifyMeeting(m = {}) {
  const title = s(m.title || m.summary);
  const location = s(m.location);
  const description = s(m.description);
  const conf = Array.isArray(m.conference) ? m.conference : (m.conference ? [m.conference] : []);

  // Virtual can be signalled anywhere — the link often lives in the notes.
  const hay = [location, description, title].join("  ");
  const signalsV = [];
  if (conf.includes("video")) signalsV.push("google_conference_video");
  if (conf.includes("phone")) signalsV.push("google_conference_phone");
  if (VIDEO_HOST.test(hay)) signalsV.push("video_link");
  if (VIDEO_WORD.test(hay)) signalsV.push("video_word");
  if (PHONE_WORD.test(hay)) signalsV.push("phone_word");

  // Physical presence is judged from the LOCATION field only — descriptions are
  // full of boilerplate ("join by phone", org addresses in signatures) that would
  // produce false "in person" reads. A real place is what's LEFT in `location`
  // after we remove any URL and any conferencing label.
  const hasStreet = STREET.test(location);
  let residue = location.replace(URL, " ").replace(LABELS, " ")
    .replace(/\bmeeting\b/gi, " ")
    .replace(/[;,|·—–]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const signalsP = [];
  if (hasStreet) signalsP.push("street_address");
  else if (residue && /[a-z]{3,}/i.test(residue)) signalsP.push("place_text");

  const virtual = signalsV.length > 0;
  const physical = signalsP.length > 0;

  let nature;
  if (virtual && physical) nature = "ambiguous";
  else if (virtual) nature = "virtual";
  else if (physical) nature = "in_person";
  else nature = "unknown";

  return {
    nature,
    virtual,
    physical,
    signals: [...signalsV, ...signalsP],
    place: physical ? (hasStreet ? location.replace(URL, " ").trim() : residue) : null,
  };
}

module.exports = { classifyMeeting };
