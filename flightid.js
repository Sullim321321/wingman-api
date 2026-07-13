/**
 * flightid.js — a flight has a NAME and it has a KEY, and they are not the same string.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT THIS FIXES, AND WHY IT MATTERS MORE THAN IT LOOKS
 *
 * Two producers write flight legs, and they do not agree:
 *
 *   email parser →  carrier: "Japan Airlines"   flight_number: "JL 623"
 *   Duffel       →  carrier: "Japan Airlines"   flight_number: "JL623"
 *
 * And every caller that needed a FlightAware identifier built it the same way:
 *
 *   const ident = (leg.carrier || "") + (leg.flight_number || "");
 *   → "Japan AirlinesJL623"
 *
 * AeroAPI wants "JL623". It answers "Japan AirlinesJL623" with a 404, and the
 * status fetcher does `if (!r.ok) return null` — so a malformed key and a flight
 * with nothing to report produce the IDENTICAL result: null. No error. No log.
 *
 * Which means the delay monitor was DARK. Not wrong — dark. It polled, got nothing
 * back, concluded there was nothing to report, and said nothing. The entire protect
 * half of the product, the cascade, the Situation screen, the push notification that
 * is the reason this app exists — none of it could ever fire on a real flight,
 * because the key it was looking things up with was a display string with an
 * airline's full name jammed onto the front of it.
 *
 * The bug was invisible precisely BECAUSE it was total. A monitor that never fires
 * looks exactly like a world where nothing has gone wrong.
 *
 * So: two functions, two purposes, and a hard refusal in the middle.
 *
 *   displayName(leg) → "Japan Airlines JL 623"   for a person to read
 *   apiKey(leg)      → "JL623"                   for a machine to look up
 *   apiKey returns NULL when it cannot build a real one — and callers must not
 *   fetch with null. An absent key is not a key that happens to be wrong.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// Airline names, as the parsers actually write them, → IATA. Deliberately explicit:
// guessing a two-letter code from an airline's name is how you monitor the wrong plane.
// Unknown name → we say we don't know, rather than inventing a code.
const NAME_TO_IATA = {
  "aer lingus": "EI", "aeromexico": "AM", "air canada": "AC", "air china": "CA",
  "air france": "AF", "air india": "AI", "air new zealand": "NZ", "alaska": "AS",
  "alaska airlines": "AS", "alitalia": "AZ", "all nippon": "NH", "all nippon airways": "NH",
  "american": "AA", "american airlines": "AA", "ana": "NH", "asiana": "OZ",
  "asiana airlines": "OZ", "austrian": "OS", "austrian airlines": "OS",
  "avianca": "AV", "british airways": "BA", "brussels airlines": "SN",
  "cathay pacific": "CX", "china airlines": "CI", "china eastern": "MU",
  "china southern": "CZ", "copa": "CM", "copa airlines": "CM", "delta": "DL",
  "delta air lines": "DL", "delta airlines": "DL", "eva air": "BR", "egyptair": "MS",
  "emirates": "EK", "ethiopian": "ET", "ethiopian airlines": "ET", "etihad": "EY",
  "etihad airways": "EY", "eurowings": "EW", "finnair": "AY", "frontier": "F9",
  "garuda": "GA", "garuda indonesia": "GA", "hawaiian": "HA", "hawaiian airlines": "HA",
  "iberia": "IB", "icelandair": "FI", "itа airways": "AZ", "ita airways": "AZ",
  "japan airlines": "JL", "jal": "JL", "jetblue": "B6", "jetstar": "JQ",
  "kenya airways": "KQ", "klm": "KL", "korean air": "KE", "lot": "LO",
  "lot polish airlines": "LO", "lufthansa": "LH", "malaysia airlines": "MH",
  "norwegian": "DY", "qantas": "QF", "qatar": "QR", "qatar airways": "QR",
  "royal air maroc": "AT", "royal jordanian": "RJ", "ryanair": "FR",
  "sas": "SK", "scandinavian airlines": "SK", "saudia": "SV", "singapore airlines": "SQ",
  "south african airways": "SA", "southwest": "WN", "southwest airlines": "WN",
  "spirit": "NK", "spirit airlines": "NK", "srilankan": "UL", "swiss": "LX",
  "swiss international air lines": "LX", "tap": "TP", "tap air portugal": "TP",
  "thai": "TG", "thai airways": "TG", "turkish": "TK", "turkish airlines": "TK",
  "united": "UA", "united airlines": "UA", "vietnam airlines": "VN",
  "virgin atlantic": "VS", "virgin australia": "VA", "vueling": "VY",
  "westjet": "WS", "easyjet": "U2", "wizz air": "W6", "air asia": "AK", "airasia": "AK",
  "aeroflot": "SU", "tarom": "RO", "shenzhen airlines": "ZH", "aegean": "A3",
  "aegean airlines": "A3", "philippine airlines": "PR", "china eastern airlines": "MU",
};

// An airline code is two chars (letters, or a letter+digit like "B6", "9W").
const LOOKS_LIKE_CODE = (s) => /^[A-Z0-9]{2}$/.test(s) && /[A-Z]/.test(s);

/**
 * Pull the airline code and the flight's number out of a leg, however it was written.
 *
 * Handles, in the wild:
 *   { carrier: "Japan Airlines", flight_number: "JL 623" }
 *   { carrier: "Japan Airlines", flight_number: "JL623"  }   ← Duffel
 *   { carrier: "JL",             flight_number: "623"    }
 *   { carrier: "United",         flight_number: "UA0412" }   ← leading zeros
 *   { carrier: "Amtrak",         flight_number: null     }   ← not a flight at all
 */
function parts(leg = {}) {
  const carrierRaw = String(leg.carrier || "").trim();
  const numRaw     = String(leg.flight_number || "").trim().toUpperCase();

  let iata = null;
  let number = null;

  // 1. The flight_number usually carries the code already. Trust it first — it came
  //    from the ticket.
  const m = numRaw.match(/^([A-Z0-9]{2})\s*0*(\d{1,4})$/);
  if (m && /[A-Z]/.test(m[1])) {
    iata = m[1];
    number = m[2];
  } else if (/^0*(\d{1,4})$/.test(numRaw)) {
    // 2. Bare digits — the code must come from the carrier field.
    number = numRaw.replace(/^0+/, "");
  }

  // 3. Resolve the carrier field to a code, if we still need one.
  if (!iata && carrierRaw) {
    const up = carrierRaw.toUpperCase();
    if (LOOKS_LIKE_CODE(up)) iata = up;
    else iata = NAME_TO_IATA[carrierRaw.toLowerCase()] || null;
  }

  // The carrier's human name, if we have one. "JL" is a key, not a name.
  const name = carrierRaw && !LOOKS_LIKE_CODE(carrierRaw.toUpperCase()) ? carrierRaw : null;

  return { iata, number: number || null, name };
}

/**
 * What a person reads.  "Japan Airlines JL 623"
 *
 * Never concatenated without a space, because a human is going to read this off a
 * screen in an airport. Degrades gracefully — a name alone, a code alone, whatever
 * we actually have — rather than printing a mangled join.
 */
function displayName(leg = {}) {
  const { iata, number, name } = parts(leg);
  const flight = iata && number ? `${iata} ${number}` : (number ? `#${number}` : null);
  return [name, flight].filter(Boolean).join(" ") || name || flight || null;
}

/**
 * What a machine looks up.  "JL623"
 *
 * Returns NULL when we cannot build a real identifier — and null must be treated as
 * "I cannot check this", never as "nothing is wrong". That distinction is the entire
 * reason this file exists.
 */
function apiKey(leg = {}) {
  const { iata, number } = parts(leg);
  if (!iata || !number) return null;
  return `${iata}${number}`;
}

/**
 * Why we can't look it up — so the failure can be SAID rather than swallowed.
 */
function whyNoKey(leg = {}) {
  const { iata, number } = parts(leg);
  if (iata && number) return null;
  if (!number) return `No flight number on this leg.`;
  return `I don't recognise "${leg.carrier}" as an airline I can track.`;
}

module.exports = { displayName, apiKey, whyNoKey, parts, NAME_TO_IATA };
