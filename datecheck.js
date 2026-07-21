// datecheck.js — the weekday and the date must agree, and we check rather than ask.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIRD OCCURRENCE. The history matters, because each fix was better than the last
// and each one was still wrong in the same direction.
//
//   v1  Told the model "TODAY IS Tuesday, July 14." It recorded "Thursday, July 17"
//       as a MUST. July 17 was a Friday. Diagnosis: it was doing arithmetic.
//   v2  Gave it a 21-day lookup table and told it never to compute a weekday.
//       Diagnosis at the time: solved. It was not solved.
//   v3  Today. User says "Going to Chicago Thurs." Today is Sunday July 19, so
//       Thursday is July 23. The table said so, in the prompt, correctly. The model
//       wrote "Arrive Thursday, July 24" — which is a Friday — and filed it as a MUST.
//
// The lesson is not "write a firmer instruction." v2 was already about as firm as
// English gets: "NEVER work out a weekday yourself. It is in the table above."
// Instructions are requests. The model complied twice and drifted the third time,
// which is what probabilistic systems do.
//
// The only thing that holds is CHECKING THE OUTPUT. A weekday and a date are two
// claims about one fact, so they can be cross-examined without asking anyone. If
// they disagree, we don't need the model's opinion about which is right — we have a
// calendar.
//
// WHICH ONE WINS, and why it isn't obvious: the model's date and the model's weekday
// are both suspect, but the USER'S words are not. If she typed "Thurs", the weekday
// is the reliable half and the date is the invention. If she typed "July 24" and the
// model decorated it with a weekday, the date is reliable. So the tiebreak looks at
// what she actually said, and only falls back to the date when she said neither.
// ─────────────────────────────────────────────────────────────────────────────

const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const MONTHS = ["January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"];

/**
 * The same calendar the planner puts in the prompt, as data instead of prose.
 * Built from the phone's clock and timezone — never from the server's.
 */
function buildCalendar(nowISO, timezone = "UTC", days = 21) {
  const d = new Date(nowISO);
  const clock = isNaN(d) ? new Date() : d;
  const out = [];
  for (let k = 0; k < days; k++) {
    const dt = new Date(clock.getTime() + k * 86400000);
    const iso = new Intl.DateTimeFormat("en-CA", { timeZone: timezone }).format(dt);
    const weekday = dt.toLocaleDateString("en-US", { timeZone: timezone, weekday: "long" });
    const [y, m, day] = iso.split("-").map(Number);
    out.push({ iso, weekday, month: m, day, label: `${MONTHS[m - 1]} ${day}` });
  }
  return out;
}

// "Thursday, July 24" / "Thursday July 24" / "Thurs, Jul 24th"
const CLAIM = new RegExp(
  "\\b(" + DAYS.map((d) => d.slice(0, 3)).join("|") + ")[a-z]*\\.?,?\\s+" +
  "(" + MONTHS.map((m) => m.slice(0, 3)).join("|") + ")[a-z]*\\.?\\s+(\\d{1,2})(?:st|nd|rd|th)?\\b",
  "gi",
);

const dayIndex = (s) => DAYS.findIndex((d) => d.toLowerCase().startsWith(String(s).slice(0, 3).toLowerCase()));
const monIndex = (s) => MONTHS.findIndex((m) => m.toLowerCase().startsWith(String(s).slice(0, 3).toLowerCase()));

/**
 * Find every "<weekday>, <month> <day>" claim in `text` and say whether it holds.
 *
 * Returns [{ found, weekday, month, day, ok, actualWeekday, weekdayIso, correction }].
 * A claim about a date outside the calendar window is reported as `unknown` rather
 * than wrong — we can only contradict what we can see. Silence beats a confident
 * correction built on no evidence, which is the failure this file exists to stop.
 */
function verifyDateClaims(text, cal, userSaid = "") {
  const claims = [];
  const said = String(userSaid).toLowerCase();
  for (const m of String(text || "").matchAll(CLAIM)) {
    const [found, dayName, monName, dayNum] = m;
    const di = dayIndex(dayName);
    const mi = monIndex(monName) + 1;
    const num = Number(dayNum);

    const byDate = cal.find((c) => c.month === mi && c.day === num);
    const byWeekday = cal.find((c) => c.weekday === DAYS[di]);

    // ── THE RESTRAINT THAT MATTERS ──────────────────────────────────────────
    // Judgement requires seeing the DATE in the calendar. A weekday alone is not
    // enough: "Tuesday, December 14" has a Tuesday in the next three weeks and a
    // December 14 that is nowhere near it, and an earlier version of this function
    // happily "corrected" December to July — moving a trip five months to fix a
    // typo it could not actually see. Its own test caught it.
    //
    // Outside the window we know nothing, and knowing nothing is reported as
    // nothing. That rule is the entire point of this file; it would be a poor joke
    // to break it while enforcing it.
    if (!byDate) {
      claims.push({ found, ok: null, why: "that date is outside the calendar window — cannot judge" });
      continue;
    }
    if (byDate && byDate.weekday === DAYS[di]) {
      claims.push({ found, ok: true });
      continue;
    }

    // They disagree. Whose half do we trust?
    // The user's own words are evidence; the model's are the thing under audit.
    const userNamedWeekday = new RegExp("\\b" + DAYS[di].slice(0, 3) + "[a-z]*\\b", "i").test(said);
    const userNamedDate = new RegExp("\\b" + MONTHS[mi - 1].slice(0, 3) + "[a-z]*\\.?\\s+" + num + "\\b", "i").test(said);

    let correction, basis, iso;
    if (userNamedWeekday && !userNamedDate && byWeekday) {
      correction = `${byWeekday.weekday}, ${byWeekday.label}`;
      basis = "you said the weekday, so the date was the invention";
      iso = byWeekday.iso;
    } else {
      correction = `${byDate.weekday}, ${byDate.label}`;
      basis = "the date is fixed, so the weekday was the invention";
      iso = byDate.iso;
    }

    claims.push({
      found, ok: false, correction, basis,
      actualWeekday: byDate.weekday,
      weekdayIso: byWeekday ? byWeekday.iso : null,
      iso,
    });
  }
  return claims;
}

/** Rewrite `text` so no claim contradicts the calendar. Returns { text, fixed }. */
function correctDateClaims(text, cal, userSaid = "") {
  const claims = verifyDateClaims(text, cal, userSaid);
  let out = String(text || "");
  const fixed = [];
  for (const c of claims) {
    if (c.ok !== false) continue;
    out = out.split(c.found).join(c.correction);
    fixed.push({ from: c.found, to: c.correction, basis: c.basis });
  }
  return { text: out, fixed };
}

module.exports = { buildCalendar, verifyDateClaims, correctDateClaims, DAYS, MONTHS };
