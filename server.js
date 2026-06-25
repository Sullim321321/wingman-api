// Wingman backend — production-ready
// Persistent OTP via Upstash Redis, user/session storage via Neon PostgreSQL,
// JWT auth, push notifications via Expo Push API, email via Resend.
// Node 18+ required (uses global fetch).

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Redis } = require("@upstash/redis");
const { neon } = require("@neondatabase/serverless");
const { Resend } = require("resend");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const JWT_EXPIRES_IN = "30d";

// ---------------------------------------------------------------------------
// External service clients
// ---------------------------------------------------------------------------
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const sql = neon(process.env.DATABASE_URL);
const resend = new Resend(process.env.RESEND_API_KEY);

// ---------------------------------------------------------------------------
// Database bootstrap — create tables if they don't exist
// ---------------------------------------------------------------------------
async function bootstrapDB() {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        push_token TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      )
    `;
    console.log("[db] tables ready");
  } catch (e) {
    console.error("[db] bootstrap error:", e.message);
  }
}

bootstrapDB();

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------
function signAccessToken(email) {
  return jwt.sign({ email, type: "access" }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

async function verifyAccessToken(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return null;
  try {
    const payload = jwt.verify(t, JWT_SECRET);
    if (payload.type !== "access") return null;
    return payload.email;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// POST /auth/request — send OTP via Resend, store in Redis with 10-min TTL
// ---------------------------------------------------------------------------
app.post("/auth/request", async (req, res) => {
  const email = ((req.body && req.body.email) || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "valid email required" });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const key = "otp:" + email;

  try {
    await redis.set(key, code, { ex: 600 });
  } catch (e) {
    console.error("[redis] set error:", e.message);
    return res.status(500).json({ error: "failed to store code" });
  }

  try {
    await resend.emails.send({
      from: "Wingman Travel <noreply@welcometothefight.club>",
      to: email,
      subject: "Your Wingman login code",
      html: `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:24px"><h2 style="color:#1a1a2e">Wingman Travel</h2><p style="color:#555">Your one-time login code:</p><div style="background:#f4f4f8;border-radius:12px;padding:24px;text-align:center"><span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#1a1a2e">${code}</span></div><p style="color:#888;font-size:13px;margin-top:16px">Expires in 10 minutes.</p></div>`,
    });
    console.log("[auth] OTP sent to " + email);
  } catch (e) {
    console.error("[resend] error:", e.message);
  }

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// POST /auth/verify — validate OTP, upsert user in DB, return JWT
// ---------------------------------------------------------------------------
app.post("/auth/verify", async (req, res) => {
  const email = ((req.body && req.body.email) || "").trim().toLowerCase();
  const code = ((req.body && req.body.code) || "").trim();

  if (!email || !code) {
    return res.status(400).json({ error: "email and code required" });
  }

  const key = "otp:" + email;
  let stored;
  try {
    stored = await redis.get(key);
  } catch (e) {
    console.error("[redis] get error:", e.message);
    return res.status(500).json({ error: "verification failed" });
  }

  if (!stored || String(stored) !== String(code)) {
    return res.status(401).json({ error: "invalid or expired code" });
  }

  await redis.del(key).catch(() => {});

  try {
    await sql`INSERT INTO users (email) VALUES (${email}) ON CONFLICT (email) DO NOTHING`;
  } catch (e) {
    console.error("[db] upsert user error:", e.message);
  }

  const token = signAccessToken(email);
  console.log("[auth] verified " + email);
  res.json({ token, email });
});

// ---------------------------------------------------------------------------
// POST /push-token — store Expo push token for authenticated user
// ---------------------------------------------------------------------------
app.post("/push-token", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });

  const { pushToken } = req.body;
  if (!pushToken || !pushToken.startsWith("ExponentPushToken[")) {
    return res.status(400).json({ error: "invalid push token" });
  }

  try {
    await sql`UPDATE users SET push_token = ${pushToken} WHERE email = ${email}`;
    console.log("[push] stored token for " + email);
    res.json({ ok: true });
  } catch (e) {
    console.error("[db] push token error:", e.message);
    res.status(500).json({ error: "failed to store push token" });
  }
});

// ---------------------------------------------------------------------------
// POST /notify — send push notification to authenticated user
// ---------------------------------------------------------------------------
app.post("/notify", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });

  const { title, body } = req.body;
  if (!title || !body) return res.status(400).json({ error: "title and body required" });

  try {
    const rows = await sql`SELECT push_token FROM users WHERE email = ${email}`;
    const pushToken = rows[0] && rows[0].push_token;
    if (!pushToken) return res.status(404).json({ error: "no push token registered" });

    const response = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ to: pushToken, title, body, sound: "default" }),
    });
    const result = await response.json();
    console.log("[push] sent to " + email + ":", result);
    res.json({ ok: true, result });
  } catch (e) {
    console.error("[push] error:", e.message);
    res.status(500).json({ error: "push failed" });
  }
});

// ---------------------------------------------------------------------------
// GET /me — return current user info
// ---------------------------------------------------------------------------
app.get("/me", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });

  try {
    const rows = await sql`SELECT email, push_token, created_at FROM users WHERE email = ${email}`;
    if (!rows[0]) return res.status(404).json({ error: "user not found" });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// Prediction — live weather (aviationweather.gov METAR, free, no key) -> risk
// ---------------------------------------------------------------------------
const ICAO = {
  DEN: "KDEN", ASE: "KASE", JFK: "KJFK", ORD: "KORD", SFO: "KSFO",
  LAX: "KLAX", BOS: "KBOS", SLC: "KSLC", LGA: "KLGA", EWR: "KEWR",
  SEA: "KSEA", MIA: "KMIA", ATL: "KATL", DFW: "KDFW", LHR: "EGLL",
  CDG: "LFPG", AMS: "EHAM", FRA: "EDDF", ARN: "ESSA",
};
const MOUNTAIN = new Set(["ASE", "EGE", "JAC", "SUN", "TEX", "MTJ", "HDN", "GUC"]);

async function metar(icao) {
  try {
    const r = await fetch(
      "https://aviationweather.gov/api/data/metar?ids=" + icao + "&format=json",
      { headers: { "User-Agent": "wingman-demo" } }
    );
    if (!r.ok) return null;
    const j = await r.json();
    return Array.isArray(j) && j[0] ? j[0] : null;
  } catch {
    return null;
  }
}

function weatherScore(m) {
  if (!m) return { score: 0.12, notes: ["no live report — baseline only"], raw: null };
  let score = 0;
  const notes = [];
  let vis = m.visib;
  if (typeof vis === "string") vis = parseFloat(vis);
  if (!isNaN(vis)) {
    if (vis < 1) { score += 0.4; notes.push("visibility under 1 mi"); }
    else if (vis < 3) { score += 0.25; notes.push("low visibility " + vis + " mi"); }
  }
  const ceil = (m.clouds || [])
    .filter((c) => ["BKN", "OVC"].includes(c.cover))
    .map((c) => c.base)
    .filter((x) => x != null)
    .sort((a, b) => a - b)[0];
  if (ceil != null) {
    if (ceil < 500) { score += 0.3; notes.push("ceiling under 500 ft"); }
    else if (ceil < 1000) { score += 0.18; notes.push("low ceiling " + ceil + " ft"); }
  }
  const w = m.wgst || m.wspd;
  if (w) {
    if (w >= 35) { score += 0.2; notes.push("strong winds " + w + " kt"); }
    else if (w >= 25) { score += 0.1; notes.push("gusty " + w + " kt"); }
  }
  const wx = String(m.wxString || "");
  if (/SN/.test(wx)) { score += 0.3; notes.push("snow"); }
  if (/TS/.test(wx)) { score += 0.25; notes.push("thunderstorms"); }
  if (/FZ/.test(wx)) { score += 0.2; notes.push("freezing precip"); }
  if (/\bFG\b|\bBR\b/.test(wx)) { score += 0.12; notes.push("fog / mist"); }
  return { score: Math.min(score, 1), notes, raw: m.rawOb || m.rawText || null };
}

function impactOf(points) {
  return points >= 22 ? "High impact" : points >= 10 ? "Medium" : "Low";
}

app.get("/predict", async (req, res) => {
  const dep = String(req.query.dep || "DEN").toUpperCase();
  const arr = String(req.query.arr || "ASE").toUpperCase();
  const depI = ICAO[dep] || "K" + dep;
  const arrI = ICAO[arr] || "K" + arr;

  const [dm, am] = await Promise.all([metar(depI), metar(arrI)]);
  const dw = weatherScore(dm);
  const aw = weatherScore(am);
  const mtn = (MOUNTAIN.has(arr) ? 1 : 0) * 0.85 + (MOUNTAIN.has(dep) ? 1 : 0) * 0.2;

  const fDep = Math.round(dw.score * 34);
  const fArr = Math.round(aw.score * 32);
  const fMtn = Math.round(Math.min(mtn, 1) * 20);
  const fBase = 6;
  const risk = Math.min(fDep + fArr + fMtn + fBase, 95);

  const factors = [
    { label: "Weather at " + dep, points: fDep, impact: impactOf(fDep), detail: dw.notes.join(", ") },
    { label: "Weather at " + arr, points: fArr, impact: impactOf(fArr), detail: aw.notes.join(", ") },
    { label: "Airport sensitivity", points: fMtn, impact: impactOf(fMtn), detail: MOUNTAIN.has(arr) ? arr + " has strict weather minimums" : "standard airport tolerances" },
    { label: "Connection & baseline", points: fBase, impact: "Low", detail: "layover slack and seasonal cancellation base rate" },
  ].filter((f) => f.points > 0);

  const email = await verifyAccessToken(req);

  res.json({
    dep, arr, risk,
    live: !!(dm || am),
    summary: risk >= 60
      ? "High disruption risk on " + dep + " -> " + arr + "."
      : risk >= 35
        ? "Moderate disruption risk on " + dep + " -> " + arr + "."
        : "Conditions look manageable on " + dep + " -> " + arr + ".",
    factors,
    sources: ["aviationweather.gov METAR", "airport ops profile"],
    metar: { dep: dw.raw, arr: aw.raw },
    user: email,
    ts: Date.now(),
  });
});


// ---------------------------------------------------------------------------
// Privacy Policy page
// ---------------------------------------------------------------------------
const path = require("path");
app.get("/privacy", (_req, res) => {
  res.sendFile(path.join(__dirname, "privacy.html"));
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.listen(PORT, () => console.log("Wingman API on http://localhost:" + PORT));
