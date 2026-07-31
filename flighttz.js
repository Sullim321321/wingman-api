// flighttz.js — a departure time is a WALL CLOCK at an airport, not a UTC instant.
//
// ─────────────────────────────────────────────────────────────────────────────
// The email says "7:29 PM" — that's 7:29 PM *in Newark*. The parser emitted it as a
// naive ISO string ("2026-07-30T19:29:00"), and everything downstream read it as UTC.
// Rendered back in the traveler's Eastern zone, 7:29 PM became 3:29 PM — four hours
// early — so the day-of state machine believed the flight had already left and the
// traveler had arrived, hours before either was true. The whole promise of the app is
// being right about the day; this is the bug that breaks it.
//
// The fix: interpret a naive flight time as the WALL time at the origin airport, and
// convert it to a true UTC instant using that airport's timezone. Pure and dependency-
// free — it uses the platform's own IANA database via Intl, so there's no library to
// keep current. An unknown airport is left UNCHANGED and flagged, never guessed.
// ─────────────────────────────────────────────────────────────────────────────

// IATA → IANA timezone. Covers the airports the app already knows (AIRPORT_COORDS)
// plus common US/intl hubs. Unknown codes fall through to "leave it alone, say so".
const AIRPORT_TZ = {
  // US Eastern
  JFK: "America/New_York", EWR: "America/New_York", LGA: "America/New_York",
  BOS: "America/New_York", MIA: "America/New_York", ATL: "America/New_York",
  PIT: "America/New_York", DCA: "America/New_York", IAD: "America/New_York",
  PHL: "America/New_York", CLT: "America/New_York", MCO: "America/New_York",
  FLL: "America/New_York", BWI: "America/New_York", DTW: "America/New_York",
  // US Central
  ORD: "America/Chicago", DFW: "America/Chicago", MDW: "America/Chicago",
  IAH: "America/Chicago", MSP: "America/Chicago", STL: "America/Chicago",
  MCI: "America/Chicago", AUS: "America/Chicago", NSH: "America/Chicago",
  BNA: "America/Chicago",
  // US Mountain / Denver
  DEN: "America/Denver", SLC: "America/Denver", PHX: "America/Phoenix",
  ABQ: "America/Denver",
  // US Pacific
  LAX: "America/Los_Angeles", SFO: "America/Los_Angeles", SEA: "America/Los_Angeles",
  SAN: "America/Los_Angeles", PDX: "America/Los_Angeles", LAS: "America/Los_Angeles",
  SJC: "America/Los_Angeles", OAK: "America/Los_Angeles",
  // International
  LHR: "Europe/London", LGW: "Europe/London", MAN: "Europe/London",
  EDI: "Europe/London", DUB: "Europe/Dublin",
  CDG: "Europe/Paris", ORY: "Europe/Paris", AMS: "Europe/Amsterdam",
  FRA: "Europe/Berlin", MUC: "Europe/Berlin", MAD: "Europe/Madrid",
  BCN: "Europe/Madrid", FCO: "Europe/Rome", ZRH: "Europe/Zurich",
  NRT: "Asia/Tokyo", HND: "Asia/Tokyo", SIN: "Asia/Singapore",
  HKG: "Asia/Hong_Kong", ICN: "Asia/Seoul", DXB: "Asia/Dubai",
  SYD: "Australia/Sydney", MEL: "Australia/Melbourne",
  GRU: "America/Sao_Paulo", YYZ: "America/Toronto", YVR: "America/Vancouver",
  MEX: "America/Mexico_City",
};

const hasExplicitZone = (s) => /[zZ]$|[+-]\d{2}:?\d{2}$/.test(String(s || "").trim());

/** The offset (ms) that `tz` is ahead of UTC at the given UTC instant. */
function tzOffsetMs(utcMs, tz) {
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
  const p = {};
  for (const part of dtf.formatToParts(new Date(utcMs))) p[part.type] = part.value;
  const h = p.hour === "24" ? 0 : Number(p.hour);
  const asTz = Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), h, Number(p.minute), Number(p.second));
  return asTz - utcMs;
}

const IANA_OF = (iata) => AIRPORT_TZ[String(iata || "").trim().toUpperCase().slice(0, 3)] || null;

/**
 * Convert a flight time to a correct UTC ISO string, interpreting a naive value as the
 * WALL time at `iata`. Returns { iso, converted, reason }:
 *   • already zoned (has Z or ±offset) → normalized to UTC, converted:false (nothing to fix)
 *   • naive + known airport            → true UTC, converted:true
 *   • naive + unknown airport          → input unchanged, converted:false, reason set
 *   • empty / unparseable              → { iso: input, converted:false }
 */
function toUTC(localISO, iata) {
  const raw = localISO == null ? "" : String(localISO).trim();
  if (!raw) return { iso: localISO, converted: false, reason: "empty" };

  if (hasExplicitZone(raw)) {
    const t = Date.parse(raw);
    return Number.isFinite(t)
      ? { iso: new Date(t).toISOString(), converted: false, reason: "already_zoned" }
      : { iso: localISO, converted: false, reason: "unparseable" };
  }

  const tz = IANA_OF(iata);
  if (!tz) return { iso: localISO, converted: false, reason: "unknown_airport" };

  const m = raw.replace(/z$/i, "").match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (!m) return { iso: localISO, converted: false, reason: "unparseable" };
  const [, y, mo, d, h, mi, s] = m;
  const naiveAsUTC = Date.UTC(+y, +mo - 1, +d, +h, +mi, +(s || 0));
  const offset = tzOffsetMs(naiveAsUTC, tz);
  return { iso: new Date(naiveAsUTC - offset).toISOString(), converted: true, reason: "converted", tz };
}

module.exports = { AIRPORT_TZ, IANA_OF, toUTC, tzOffsetMs, hasExplicitZone };
