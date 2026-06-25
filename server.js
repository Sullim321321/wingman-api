// Wingman backend slice — live disruption prediction + dev auth
// Node 18+ (uses global fetch). Run: npm install && npm start
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const PROD = process.env.NODE_ENV === "production";
const SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

// ----------------------------------------------------------------------------
// Dev auth (email one-time code). Replace with a real OTP/email + DB for prod.
// ----------------------------------------------------------------------------
const codes = new Map();   // email -> { code, exp }
const tokens = new Map();  // token -> email

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = "noreply@welcometothefight.club";

async function sendEmail(to, subject, html) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from: FROM_EMAIL, to, subject, html } )
  });
  if (!r.ok) throw new Error(await r.text());
}

app.post("/auth/request", async (req, res) => {
  const email = (req.body && req.body.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) return res.status(400).json({ error: "valid email required" });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  codes.set(email, { code, exp: Date.now() + 10 * 60 * 1000 });
  console.log(`[auth] one-time code for ${email}: ${code}`);
  try {
    await sendEmail(email, "Your Wingman login code", `<p>Your Wingman login code is: <strong>${code}</strong></p><p>Expires in 10 minutes.</p>`);
    res.json({ ok: true });
  } catch(e) {
    console.error("[auth] email error:", e.message);
    res.status(500).json({ error: "Failed to send email" });
  }
});

app.post("/auth/verify", (req, res) => {
  const email = (req.body && req.body.email || "").trim().toLowerCase();
  const code = (req.body && req.body.code || "").trim();
  const rec = codes.get(email);
  if (!rec || rec.code !== code || Date.now() > rec.exp) return res.status(401).json({ error: "invalid or expired code" });
  codes.delete(email);
  const token = crypto.createHmac("sha256", SECRET).update(email + ":" + Date.now()).digest("hex");
  tokens.set(token, email);
  res.json({ token, email });
});

function authed(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  return t && tokens.has(t) ? tokens.get(t) : null;
}

// ----------------------------------------------------------------------------
// Prediction — live weather (aviationweather.gov METAR, free, no key) → risk
// Optional flight status if FLIGHT_API_KEY (AviationStack) is set.
// ----------------------------------------------------------------------------
const ICAO = { DEN: "KDEN", ASE: "KASE", JFK: "KJFK", ORD: "KORD", SFO: "KSFO", LAX: "KLAX", BOS: "KBOS", SLC: "KSLC", LGA: "KLGA", EWR: "KEWR", SEA: "KSEA", MIA: "KMIA" };
const MOUNTAIN = new Set(["ASE", "EGE", "JAC", "SUN", "TEX", "MTJ", "HDN", "GUC"]); // short-runway / weather-sensitive

async function metar(icao) {
  try {
    const r = await fetch(`https://aviationweather.gov/api/data/metar?ids=${icao}&format=json`, { headers: { "User-Agent": "wingman-demo" } });
    if (!r.ok) return null;
    const j = await r.json();
    return Array.isArray(j) && j[0] ? j[0] : null;
  } catch (e) { return null; }
}

function weatherScore(m) {
  if (!m) return { score: 0.12, notes: ["no live report — baseline only"], raw: null };
  let score = 0; const notes = [];
  let vis = m.visib;
  if (typeof vis === "string") vis = parseFloat(vis);
  if (!isNaN(vis)) {
    if (vis < 1) { score += 0.4; notes.push("visibility under 1 mi"); }
    else if (vis < 3) { score += 0.25; notes.push(`low visibility ${vis} mi`); }
  }
  const ceil = (m.clouds || [])
    .filter((c) => ["BKN", "OVC"].includes(c.cover))
    .map((c) => c.base).filter((x) => x != null).sort((a, b) => a - b)[0];
  if (ceil != null) {
    if (ceil < 500) { score += 0.3; notes.push("ceiling under 500 ft"); }
    else if (ceil < 1000) { score += 0.18; notes.push(`low ceiling ${ceil} ft`); }
  }
  const w = m.wgst || m.wspd;
  if (w) {
    if (w >= 35) { score += 0.2; notes.push(`strong winds ${w} kt`); }
    else if (w >= 25) { score += 0.1; notes.push(`gusty ${w} kt`); }
  }
  const wx = String(m.wxString || "");
  if (/SN/.test(wx)) { score += 0.3; notes.push("snow"); }
  if (/TS/.test(wx)) { score += 0.25; notes.push("thunderstorms"); }
  if (/FZ/.test(wx)) { score += 0.2; notes.push("freezing precip"); }
  if (/\bFG\b|\bBR\b/.test(wx)) { score += 0.12; notes.push("fog / mist"); }
  return { score: Math.min(score, 1), notes, raw: m.rawOb || m.rawText || null };
}

function impactOf(points) { return points >= 22 ? "High impact" : points >= 10 ? "Medium" : "Low"; }

app.get("/predict", async (req, res) => {
  const dep = String(req.query.dep || "DEN").toUpperCase();
  const arr = String(req.query.arr || "ASE").toUpperCase();
  const depI = ICAO[dep] || ("K" + dep);
  const arrI = ICAO[arr] || ("K" + arr);

  const [dm, am] = await Promise.all([metar(depI), metar(arrI)]);
  const dw = weatherScore(dm);
  const aw = weatherScore(am);
  const mtn = (MOUNTAIN.has(arr) ? 1 : 0) * 0.85 + (MOUNTAIN.has(dep) ? 1 : 0) * 0.2;

  const fDep = Math.round(dw.score * 34);
  const fArr = Math.round(aw.score * 32);
  const fMtn = Math.round(Math.min(mtn, 1) * 20);
  const fBase = 6;
  let risk = Math.min(fDep + fArr + fMtn + fBase, 95);

  const factors = [
    { label: `Weather at ${dep}`, points: fDep, impact: impactOf(fDep), detail: dw.notes.join(", ") },
    { label: `Weather at ${arr}`, points: fArr, impact: impactOf(fArr), detail: aw.notes.join(", ") },
    { label: "Airport sensitivity", points: fMtn, impact: impactOf(fMtn), detail: MOUNTAIN.has(arr) ? `${arr} has strict weather minimums (short mountain runway)` : "standard airport tolerances" },
    { label: "Connection & baseline", points: fBase, impact: "Low", detail: "layover slack and seasonal cancellation base rate" },
  ].filter((f) => f.points > 0);

  res.json({
    dep, arr, risk,
    live: !!(dm || am),
    summary: risk >= 60
      ? `High disruption risk on ${dep} → ${arr}.`
      : risk >= 35
        ? `Moderate disruption risk on ${dep} → ${arr}.`
        : `Conditions look manageable on ${dep} → ${arr}.`,
    factors,
    sources: ["aviationweather.gov METAR", "airport ops profile"],
    metar: { dep: dw.raw, arr: aw.raw },
    user: authed(req),
    ts: Date.now(),
  });
});

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.listen(PORT, () => console.log(`Wingman API on http://localhost:${PORT}`));
