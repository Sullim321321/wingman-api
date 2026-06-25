// Wingman backend — production-ready
// Auth: email OTP (Upstash Redis) + JWT
// Storage: Neon PostgreSQL (users, trips, gmail_tokens)
// Gmail: OAuth2 flow + booking email parser
// Concierge: GPT-4o with trip context
// Push: Expo Push API
// Email: Resend

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Redis } = require("@upstash/redis");
const { neon } = require("@neondatabase/serverless");
const { Resend } = require("resend");
const { google } = require("googleapis");
const Anthropic = require("@anthropic-ai/sdk");
const path = require("path");

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
// Anthropic lazy-loaded so server starts even if key is missing
let _anthropic = null;
function getAnthropic() {
  if (!_anthropic) {
    if (!process.env.ANTHROPIC_API_KEY) throw new Error("ANTHROPIC_API_KEY not set");
    _anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  }
  return _anthropic;
}

// Google OAuth2 client
function makeOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || "https://wingman-api-y39a.onrender.com/auth/gmail/callback"
  );
}

// ---------------------------------------------------------------------------
// Database bootstrap
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
    await sql`
      CREATE TABLE IF NOT EXISTS gmail_tokens (
        id SERIAL PRIMARY KEY,
        user_email TEXT UNIQUE NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expiry_date BIGINT,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS trips (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        title TEXT NOT NULL,
        status TEXT DEFAULT 'upcoming',
        source TEXT DEFAULT 'manual',
        raw_email_id TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS trip_legs (
        id SERIAL PRIMARY KEY,
        trip_id INTEGER REFERENCES trips(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        carrier TEXT,
        flight_number TEXT,
        origin TEXT,
        destination TEXT,
        departs_at TIMESTAMPTZ,
        arrives_at TIMESTAMPTZ,
        confirmation TEXT,
        status TEXT DEFAULT 'upcoming',
        raw_data JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS activity_events (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        body TEXT,
        trip_id INTEGER REFERENCES trips(id) ON DELETE CASCADE,
        leg_id INTEGER REFERENCES trip_legs(id) ON DELETE SET NULL,
        metadata JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_events(user_email, created_at DESC)`;
    console.log("[db] tables ready");
  } catch (e) {
    console.error("[db] bootstrap error:", e.message);
  }
}
bootstrapDB();

// ---------------------------------------------------------------------------
// Activity helpers
// ---------------------------------------------------------------------------
async function logActivity(userEmail, type, title, body, tripId = null, legId = null, metadata = null) {
  try {
    await sql`
      INSERT INTO activity_events (user_email, type, title, body, trip_id, leg_id, metadata)
      VALUES (${userEmail}, ${type}, ${title}, ${body || null}, ${tripId || null}, ${legId || null}, ${metadata ? JSON.stringify(metadata) : null})
    `;
  } catch (e) {
    console.error("[activity] log error:", e.message);
  }
}

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
// POST /auth/request — send OTP
// ---------------------------------------------------------------------------
app.post("/auth/request", async (req, res) => {
  const email = ((req.body && req.body.email) || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "valid email required" });
  }
  const code = String(Math.floor(100000 + Math.random() * 900000));
  try {
    await redis.set("otp:" + email, code, { ex: 600 });
    await resend.emails.send({
      from: "Wingman <noreply@wingmantravel.app>",
      to: email,
      subject: "Your Wingman sign-in code: " + code,
      html: `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px">
        <h2 style="color:#5B8CFF;margin-bottom:8px">✈ Wingman</h2>
        <p style="font-size:16px;color:#222">Your sign-in code is:</p>
        <div style="font-size:48px;font-weight:700;letter-spacing:8px;color:#111;margin:16px 0">${code}</div>
        <p style="color:#666;font-size:13px">Expires in 10 minutes. If you didn't request this, ignore this email.</p>
      </div>`,
    });
    res.json({ ok: true });
  } catch (e) {
    console.error("[auth/request]", e.message);
    res.status(500).json({ error: "failed to send OTP" });
  }
});

// ---------------------------------------------------------------------------
// POST /auth/verify — verify OTP, return JWT
// ---------------------------------------------------------------------------
app.post("/auth/verify", async (req, res) => {
  const email = ((req.body && req.body.email) || "").trim().toLowerCase();
  const code = String((req.body && req.body.code) || "").trim();
  if (!email || !code) return res.status(400).json({ error: "email and code required" });
  try {
    const stored = await redis.get("otp:" + email);
    if (!stored || String(stored) !== code) {
      return res.status(401).json({ error: "invalid or expired code" });
    }
    await redis.del("otp:" + email);
    await sql`
      INSERT INTO users (email) VALUES (${email})
      ON CONFLICT (email) DO NOTHING
    `;
    const token = signAccessToken(email);
    res.json({ ok: true, token, email });
  } catch (e) {
    console.error("[auth/verify]", e.message);
    res.status(500).json({ error: "verification failed" });
  }
});

// ---------------------------------------------------------------------------
// POST /push-token — store Expo push token
// ---------------------------------------------------------------------------
app.post("/push-token", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "token required" });
  try {
    await sql`UPDATE users SET push_token = ${token} WHERE email = ${email}`;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// POST /notify — send push notification
// ---------------------------------------------------------------------------
app.post("/notify", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { title, body } = req.body || {};
  try {
    const rows = await sql`SELECT push_token FROM users WHERE email = ${email}`;
    const token = rows[0]?.push_token;
    if (!token) return res.status(404).json({ error: "no push token" });
    const r = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to: token, title: title || "Wingman", body: body || "Update" }),
    });
    const data = await r.json();
    res.json({ ok: true, data });
  } catch (e) {
    res.status(500).json({ error: "push failed" });
  }
});

// ---------------------------------------------------------------------------
// GET /activity — fetch activity feed for current user
// ---------------------------------------------------------------------------
app.get("/activity", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const limit = Math.min(parseInt(req.query.limit || "50"), 100);
    const events = await sql`
      SELECT ae.id, ae.type, ae.title, ae.body, ae.trip_id, ae.leg_id, ae.metadata, ae.created_at,
             t.title as trip_title
      FROM activity_events ae
      LEFT JOIN trips t ON t.id = ae.trip_id
      WHERE ae.user_email = ${email}
      ORDER BY ae.created_at DESC
      LIMIT ${limit}
    `;
    res.json({ events });
  } catch (e) {
    console.error("[activity]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /me — current user info
// ---------------------------------------------------------------------------
app.get("/me", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const rows = await sql`SELECT email, push_token, created_at FROM users WHERE email = ${email}`;
    if (!rows[0]) return res.status(404).json({ error: "user not found" });
    // Check if Gmail is connected
    const gmailRows = await sql`SELECT id FROM gmail_tokens WHERE user_email = ${email}`;
    res.json({ ...rows[0], gmail_connected: gmailRows.length > 0 });
  } catch (e) {
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// Gmail OAuth — GET /auth/gmail/connect — returns URL to open in browser
// ---------------------------------------------------------------------------
app.get("/auth/gmail/connect", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: ["https://www.googleapis.com/auth/gmail.readonly"],
    state: Buffer.from(email).toString("base64"),
  });
  res.json({ url });
});

// ---------------------------------------------------------------------------
// Gmail OAuth — GET /auth/gmail/callback — handles redirect from Google
// ---------------------------------------------------------------------------
app.get("/auth/gmail/callback", async (req, res) => {
  const { code, state } = req.query;
  if (!code || !state) return res.status(400).send("Missing code or state");
  let userEmail;
  try {
    userEmail = Buffer.from(state, "base64").toString("utf8");
  } catch {
    return res.status(400).send("Invalid state");
  }
  try {
    const oauth2 = makeOAuth2Client();
    const { tokens } = await oauth2.getToken(code);
    await sql`
      INSERT INTO gmail_tokens (user_email, access_token, refresh_token, expiry_date)
      VALUES (${userEmail}, ${tokens.access_token}, ${tokens.refresh_token || null}, ${tokens.expiry_date || null})
      ON CONFLICT (user_email) DO UPDATE SET
        access_token = EXCLUDED.access_token,
        refresh_token = COALESCE(EXCLUDED.refresh_token, gmail_tokens.refresh_token),
        expiry_date = EXCLUDED.expiry_date,
        updated_at = NOW()
    `;
    // Trigger initial email scan in background
    scanGmailForTrips(userEmail, tokens).catch(e => console.error("[gmail scan]", e.message));
    res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:60px">
      <h2 style="color:#5B8CFF">✈ Gmail connected!</h2>
      <p>Wingman is scanning your inbox for travel bookings.</p>
      <p style="color:#666;font-size:13px">You can close this tab and return to the app.</p>
    </body></html>`);
  } catch (e) {
    console.error("[gmail/callback]", e.message);
    res.status(500).send("OAuth error: " + e.message);
  }
});

// ---------------------------------------------------------------------------
// Gmail scanner — parse booking confirmation emails into trips
// ---------------------------------------------------------------------------
async function getGmailClient(userEmail) {
  const rows = await sql`SELECT * FROM gmail_tokens WHERE user_email = ${userEmail}`;
  if (!rows[0]) return null;
  const oauth2 = makeOAuth2Client();
  oauth2.setCredentials({
    access_token: rows[0].access_token,
    refresh_token: rows[0].refresh_token,
    expiry_date: rows[0].expiry_date,
  });
  // Auto-refresh if needed
  oauth2.on("tokens", async (tokens) => {
    if (tokens.access_token) {
      await sql`UPDATE gmail_tokens SET access_token = ${tokens.access_token}, expiry_date = ${tokens.expiry_date || null}, updated_at = NOW() WHERE user_email = ${userEmail}`;
    }
  });
  return google.gmail({ version: "v1", auth: oauth2 });
}

async function scanGmailForTrips(userEmail, tokens) {
  const gmail = await getGmailClient(userEmail);
  if (!gmail) return;
  // Search for booking confirmation emails
  const queries = [
    "from:united.com subject:confirmation",
    "from:delta.com subject:confirmation",
    "from:aa.com subject:confirmation",
    "from:southwest.com subject:confirmation",
    "from:alaskaair.com subject:confirmation",
    "from:jetblue.com subject:confirmation",
    "from:marriott.com subject:confirmation",
    "from:hilton.com subject:confirmation",
    "from:airbnb.com subject:confirmation",
    "from:hotels.com subject:confirmation",
    "from:expedia.com subject:confirmation",
    "from:booking.com subject:confirmation",
    "subject:(flight confirmation OR itinerary OR booking confirmation) newer_than:6m",
  ];
  const seen = new Set();
  for (const q of queries) {
    try {
      const listRes = await gmail.users.messages.list({ userId: "me", q, maxResults: 20 });
      const messages = listRes.data.messages || [];
      for (const msg of messages) {
        if (seen.has(msg.id)) continue;
        seen.add(msg.id);
        try {
          const full = await gmail.users.messages.get({ userId: "me", id: msg.id, format: "full" });
          await parseAndStoreEmail(userEmail, full.data);
        } catch (e) {
          console.error("[gmail parse]", e.message);
        }
      }
    } catch (e) {
      console.error("[gmail list]", q, e.message);
    }
  }
}

function extractEmailBody(payload) {
  if (!payload) return "";
  if (payload.body && payload.body.data) {
    return Buffer.from(payload.body.data, "base64").toString("utf8");
  }
  if (payload.parts) {
    for (const part of payload.parts) {
      const text = extractEmailBody(part);
      if (text) return text;
    }
  }
  return "";
}

async function parseAndStoreEmail(userEmail, message) {
  // Check if already processed
  const existing = await sql`SELECT id FROM trips WHERE user_email = ${userEmail} AND raw_email_id = ${message.id}`;
  if (existing.length > 0) return;

  const headers = message.payload?.headers || [];
  const subject = headers.find(h => h.name === "Subject")?.value || "";
  const from = headers.find(h => h.name === "From")?.value || "";
  const body = extractEmailBody(message.payload);
  const snippet = message.snippet || "";

  // Use GPT to extract structured trip data
  try {
    const prompt = `Extract travel booking information from this email. Return JSON only, no markdown.
Subject: ${subject}
From: ${from}
Body (first 3000 chars): ${(body || snippet).slice(0, 3000)}

Return this exact JSON structure (null for unknown fields):
{
  "type": "flight|hotel|car|other",
  "title": "short trip title e.g. New York Trip",
  "carrier": "airline or hotel name",
  "confirmation": "confirmation/booking number",
  "origin": "departure city or airport code (flights only)",
  "destination": "arrival city or airport code",
  "departs_at": "ISO 8601 datetime or null",
  "arrives_at": "ISO 8601 datetime or null",
  "is_travel_booking": true or false
}`;

    const claudeResp = await getAnthropic().messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 400,
      messages: [{ role: "user", content: prompt }],
    });

    let parsed;
    try {
      const raw = claudeResp.content[0].text.trim();
      const jsonStr = raw.replace(/^```json\n?/, "").replace(/\n?```$/, "").trim();
      parsed = JSON.parse(jsonStr);
    } catch {
      return;
    }

    if (!parsed.is_travel_booking) return;

    // Create or find trip
    const dest = parsed.destination || "Unknown";
    const tripTitle = parsed.title || (dest + " Trip");
    const tripRows = await sql`
      INSERT INTO trips (user_email, title, source, raw_email_id)
      VALUES (${userEmail}, ${tripTitle}, 'gmail', ${message.id})
      ON CONFLICT DO NOTHING
      RETURNING id
    `;
    if (tripRows.length === 0) return;
    const tripId = tripRows[0].id;

    // Add leg
    await sql`
      INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation, raw_data)
      VALUES (
        ${tripId},
        ${parsed.type || "flight"},
        ${parsed.carrier || null},
        ${null},
        ${parsed.origin || null},
        ${parsed.destination || null},
        ${parsed.departs_at || null},
        ${parsed.arrives_at || null},
        ${parsed.confirmation || null},
        ${JSON.stringify(parsed)}
      )
    `;
    await logActivity(
      userEmail, "import",
      `Imported from Gmail: ${tripTitle}`,
      `Booking confirmation found in your inbox and linked automatically.`,
      tripId
    );
    console.log("[gmail] stored trip:", tripTitle, "for", userEmail);
  } catch (e) {
    console.error("[gmail/parse]", e.message);
  }
}

// ---------------------------------------------------------------------------
// POST /auth/gmail/scan — manually trigger a re-scan
// ---------------------------------------------------------------------------
app.post("/auth/gmail/scan", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    scanGmailForTrips(email).catch(e => console.error("[scan]", e.message));
    res.json({ ok: true, message: "Scan started" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /trips — get all trips for current user
// ---------------------------------------------------------------------------
app.get("/trips", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const trips = await sql`
      SELECT t.*, 
        json_agg(tl.* ORDER BY tl.departs_at ASC NULLS LAST) FILTER (WHERE tl.id IS NOT NULL) as legs
      FROM trips t
      LEFT JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
      GROUP BY t.id
      ORDER BY t.created_at DESC
    `;
    res.json({ trips });
  } catch (e) {
    console.error("[trips]", e.message);
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// POST /trips — manually create a trip
// ---------------------------------------------------------------------------
app.post("/trips", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { title, legs } = req.body || {};
  if (!title) return res.status(400).json({ error: "title required" });
  try {
    const tripRows = await sql`
      INSERT INTO trips (user_email, title, source)
      VALUES (${email}, ${title}, 'manual')
      RETURNING id
    `;
    const tripId = tripRows[0].id;
    if (legs && Array.isArray(legs)) {
      for (const leg of legs) {
        await sql`
          INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation)
          VALUES (
            ${tripId},
            ${leg.type || "flight"},
            ${leg.carrier || null},
            ${leg.flight_number || null},
            ${leg.origin || null},
            ${leg.destination || null},
            ${leg.departs_at || null},
            ${leg.arrives_at || null},
            ${leg.confirmation || null}
          )
        `;
      }
    }
    const result = await sql`
      SELECT t.*, json_agg(tl.* ORDER BY tl.departs_at ASC NULLS LAST) FILTER (WHERE tl.id IS NOT NULL) as legs
      FROM trips t LEFT JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.id = ${tripId} GROUP BY t.id
    `;
    // Log activity event
    const legCount = (legs || []).length;
    await logActivity(
      email, "trip",
      `Trip added: ${title}`,
      legCount > 0 ? `${legCount} leg${legCount !== 1 ? "s" : ""} added. Wingman is now monitoring.` : "Wingman is now monitoring.",
      tripId
    );
    res.json({ ok: true, trip: result[0] });
  } catch (e) {
    console.error("[trips/create]", e.message);
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// DELETE /trips/:id — delete a trip
// ---------------------------------------------------------------------------
app.delete("/trips/:id", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    await sql`DELETE FROM trips WHERE id = ${req.params.id} AND user_email = ${email}`;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// POST /concierge — LLM chat with trip context
// ---------------------------------------------------------------------------
app.post("/concierge", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { message, history } = req.body || {};
  if (!message) return res.status(400).json({ error: "message required" });
  try {
    // Fetch user's trips for context
    const trips = await sql`
      SELECT t.id, t.title, t.status, t.created_at,
        json_agg(tl.* ORDER BY tl.departs_at ASC NULLS LAST) FILTER (WHERE tl.id IS NOT NULL) as legs
      FROM trips t
      LEFT JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
      GROUP BY t.id
      ORDER BY t.created_at DESC
      LIMIT 10
    `;

    const today = new Date().toISOString();

    // Enrich trips with live flight status + weather risk (in parallel, best-effort)
    const enrichedTrips = await Promise.all(trips.map(async (trip) => {
      const legs = trip.legs || [];
      const enrichedLegs = await Promise.all(legs.map(async (leg) => {
        if (leg.type !== "flight" || !leg.flight_number) return leg;
        const ident = (leg.carrier || "") + leg.flight_number;
        const [liveStatus, weatherData] = await Promise.allSettled([
          getFlightStatus(ident),
          (leg.origin && leg.destination)
            ? (async () => {
                const depI = ICAO[leg.origin] || "K" + leg.origin;
                const arrI = ICAO[leg.destination] || "K" + leg.destination;
                const [dm, am] = await Promise.all([metar(depI), metar(arrI)]);
                const dw = weatherScore(dm);
                const aw = weatherScore(am);
                const mtn = (MOUNTAIN.has(leg.destination) ? 1 : 0) * 0.85 + (MOUNTAIN.has(leg.origin) ? 1 : 0) * 0.2;
                const risk = Math.min(
                  Math.round(dw.score * 34) + Math.round(aw.score * 32) + Math.round(Math.min(mtn, 1) * 20) + 6,
                  95
                );
                return { risk, depNotes: dw.notes, arrNotes: aw.notes };
              })()
            : Promise.resolve(null),
        ]);
        return {
          ...leg,
          live_status: liveStatus.status === "fulfilled" ? liveStatus.value : null,
          weather_risk: weatherData.status === "fulfilled" ? weatherData.value : null,
        };
      }));
      return { ...trip, legs: enrichedLegs };
    }));

    // Build a concise human-readable summary for the system prompt
    const tripsSummary = enrichedTrips.length === 0
      ? "No trips found yet."
      : enrichedTrips.map(trip => {
          const legs = trip.legs || [];
          const legLines = legs.map(leg => {
            if (leg.type === "flight") {
              const ls = leg.live_status;
              const wr = leg.weather_risk;
              const statusStr = ls ? `Status: ${ls.status}${ls.delay ? ` (${Math.round(ls.delay / 60)}m delay)` : ""}${ls.gate ? `, Gate ${ls.gate}` : ""}` : "Status: unknown";
              const weatherStr = wr ? `Weather risk: ${wr.risk}%` : "";
              return `  - Flight ${leg.carrier || ""}${leg.flight_number || ""}: ${leg.origin || "?"} → ${leg.destination || "?"} at ${leg.departs_at || "TBD"}. ${statusStr}. ${weatherStr}`.trim();
            }
            if (leg.type === "hotel") return `  - Hotel: ${leg.carrier || leg.destination || "Hotel"} check-in ${leg.departs_at || "TBD"}`;
            return `  - ${leg.type}: ${leg.carrier || leg.destination || "Booking"}`;
          }).join("\n");
          return `Trip: "${trip.title}"\n${legLines || "  (no legs)"}`.trim();
        }).join("\n\n");

    const systemPrompt = `You are Wingman, a smart travel concierge AI. You have real-time access to the user's trips, live flight statuses, and weather disruption risk scores.

Today's date/time: ${today}
User: ${email}

=== USER'S TRIPS (with live data) ===
${tripsSummary}

You help with:
- Explaining live flight status, delays, gate changes
- Assessing disruption risk based on weather data above
- Rebooking options and airline policies when flights are cancelled or heavily delayed
- Hotel and restaurant recommendations at layover airports
- General travel advice and packing tips

Guidelines:
- Be concise and direct — the user is likely in a stressful travel situation
- Always reference the user's actual trip data and live statuses above
- If a flight shows a delay or high weather risk, proactively mention it
- For rebooking, mention the airline's app/phone and same-day change policies
- If data is missing or stale, say so honestly`;


    const messages = [
      { role: "system", content: systemPrompt },
      ...(Array.isArray(history) ? history.slice(-10) : []),
      { role: "user", content: message },
    ];

    // Claude requires system prompt separate from messages array
    const systemMsg = messages.find(m => m.role === "system")?.content || "";
    const chatMessages = messages.filter(m => m.role !== "system");
    const claudeResp = await getAnthropic().messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 600,
      system: systemMsg,
      messages: chatMessages,
    });

    const reply = claudeResp.content[0].text;
    res.json({ ok: true, reply });
  } catch (e) {
    console.error("[concierge]", e.message);
    res.status(500).json({ error: "concierge error: " + e.message });
  }
});

// ---------------------------------------------------------------------------
// Prediction — live weather risk
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
  } catch { return null; }
}
function weatherScore(m) {
  if (!m) return { score: 0.12, notes: ["no live report — baseline only"], raw: null };
  let score = 0; const notes = [];
  let vis = m.visib;
  if (typeof vis === "string") vis = parseFloat(vis);
  if (!isNaN(vis)) {
    if (vis < 1) { score += 0.4; notes.push("visibility under 1 mi"); }
    else if (vis < 3) { score += 0.25; notes.push("low visibility " + vis + " mi"); }
  }
  const ceil = (m.clouds || []).filter(c => ["BKN","OVC"].includes(c.cover)).map(c => c.base).filter(x => x != null).sort((a,b) => a-b)[0];
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
  const dw = weatherScore(dm); const aw = weatherScore(am);
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
  ].filter(f => f.points > 0);
  const email = await verifyAccessToken(req);
  res.json({ dep, arr, risk, live: !!(dm || am), summary: risk >= 60 ? "High disruption risk on " + dep + " -> " + arr + "." : risk >= 35 ? "Moderate disruption risk on " + dep + " -> " + arr + "." : "Conditions look manageable on " + dep + " -> " + arr + ".", factors, sources: ["aviationweather.gov METAR", "airport ops profile"], metar: { dep: dw.raw, arr: aw.raw }, user: email, ts: Date.now() });
});

// ---------------------------------------------------------------------------
// FlightAware AeroAPI — live flight status
// ---------------------------------------------------------------------------
const AEROAPI_BASE = "https://aeroapi.flightaware.com/aeroapi";
async function getFlightStatus(flightIdent) {
  const key = process.env.FLIGHTAWARE_API_KEY;
  if (!key) return null;
  try {
    const r = await fetch(`${AEROAPI_BASE}/flights/${encodeURIComponent(flightIdent)}`, {
      headers: { "x-apikey": key, "Accept": "application/json" }
    });
    if (!r.ok) return null;
    const j = await r.json();
    const flights = j.flights || [];
    const now = Date.now();
    const upcoming = flights.filter(f => {
      const dep = f.scheduled_out || f.estimated_out || f.actual_out;
      return dep ? new Date(dep).getTime() > now - 3 * 60 * 60 * 1000 : false;
    });
    const flight = upcoming[0] || flights[0];
    if (!flight) return null;
    const status = flight.status || "Unknown";
    const delay = flight.departure_delay ? Math.round(flight.departure_delay / 60) : 0;
    const gate = flight.gate_origin || null;
    const terminal = flight.terminal_origin || null;
    const actualDep = flight.actual_out || flight.estimated_out || null;
    const scheduledDep = flight.scheduled_out || null;
    return { status, delay, gate, terminal, actualDep, scheduledDep };
  } catch (e) {
    console.error("[aeroapi]", e.message);
    return null;
  }
}

// GET /flight-status?ident=UA412
app.get("/flight-status", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const ident = String(req.query.ident || "").toUpperCase().replace(/\s/g, "");
  if (!ident) return res.status(400).json({ error: "ident required" });
  const status = await getFlightStatus(ident);
  if (!status) return res.json({ ident, status: "Unknown", live: false });
  res.json({ ident, live: true, ...status });
});

// POST /trips/:id/refresh — refresh all leg statuses for a trip
app.post("/trips/:id/refresh", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const tripRows = await sql`SELECT id FROM trips WHERE id=${req.params.id} AND user_email=${email}`;
    if (!tripRows.length) return res.status(404).json({ error: "not found" });
    const legs = await sql`SELECT * FROM trip_legs WHERE trip_id=${req.params.id} ORDER BY departs_at`;
    const updated = [];
    for (const leg of legs) {
      if (!leg.flight_number) continue;
      const s = await getFlightStatus(leg.flight_number);
      if (s) {
        await sql`UPDATE trip_legs SET status=${s.status} WHERE id=${leg.id}`;
        updated.push({ id: leg.id, flight_number: leg.flight_number, ...s });
      }
    }
    res.json({ refreshed: updated.length, legs: updated });
  } catch (e) {
    console.error("[trips/refresh]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Privacy Policy
// ---------------------------------------------------------------------------
app.get("/privacy", (_req, res) => {
  res.sendFile(path.join(__dirname, "privacy.html"));
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// ---------------------------------------------------------------------------
// Disruption polling cron — runs every 15 min
// Checks all upcoming flight legs, detects status changes, sends push + logs activity
// ---------------------------------------------------------------------------
async function sendPushToUser(userEmail, title, body, data = {}) {
  try {
    const rows = await sql`SELECT push_token FROM users WHERE email = ${userEmail}`;
    const token = rows[0]?.push_token;
    if (!token) return;
    await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to: token, title, body, data }),
    });
  } catch (e) {
    console.error("[push]", e.message);
  }
}

async function pollDisruptions() {
  console.log("[poll] checking upcoming flights...");
  try {
    // Get all flight legs departing in the next 48 hours that aren't already cancelled/landed
    const now = new Date();
    const cutoff = new Date(now.getTime() + 48 * 60 * 60 * 1000);
    const legs = await sql`
      SELECT tl.id, tl.trip_id, tl.carrier, tl.flight_number, tl.origin, tl.destination,
             tl.departs_at, tl.status as prev_status,
             t.user_email, t.title as trip_title
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.type = 'flight'
        AND tl.flight_number IS NOT NULL
        AND tl.departs_at IS NOT NULL
        AND tl.departs_at BETWEEN ${now.toISOString()} AND ${cutoff.toISOString()}
        AND tl.status NOT IN ('Cancelled', 'Landed')
    `;
    console.log(`[poll] checking ${legs.length} upcoming flight legs`);

    for (const leg of legs) {
      const ident = (leg.carrier || "") + leg.flight_number;
      const live = await getFlightStatus(ident);
      if (!live || !live.status) continue;

      const newStatus = live.status;
      const prevStatus = leg.prev_status || "Scheduled";

      // Only act on meaningful status changes
      if (newStatus === prevStatus) continue;

      console.log(`[poll] ${ident}: ${prevStatus} -> ${newStatus}`);

      // Update the leg status in DB
      await sql`UPDATE trip_legs SET status = ${newStatus} WHERE id = ${leg.id}`;

      // Build notification content based on new status
      let pushTitle, pushBody, activityTitle, activityBody, activityType;

      if (newStatus === "Cancelled") {
        pushTitle = `✈ ${ident} Cancelled`;
        pushBody = `Your flight from ${leg.origin} to ${leg.destination} has been cancelled. Tap to see options.`;
        activityTitle = `${ident} cancelled`;
        activityBody = `Your ${leg.origin} → ${leg.destination} flight was cancelled. Open Wingman for rebooking help.`;
        activityType = "disruption";
      } else if (newStatus === "Delayed") {
        const delayMins = live.delay ? Math.round(live.delay / 60) : null;
        const delayStr = delayMins ? ` by ${delayMins}m` : "";
        pushTitle = `⏱ ${ident} Delayed${delayStr}`;
        pushBody = `Your ${leg.origin} → ${leg.destination} flight is delayed${delayStr}.${live.gate ? ` Gate ${live.gate}.` : ""}`;
        activityTitle = `${ident} delayed${delayStr}`;
        activityBody = `Your ${leg.origin} → ${leg.destination} flight is delayed${delayStr}.${live.gate ? ` Gate ${live.gate}.` : ""}`;
        activityType = "delay";
      } else if (newStatus === "On Time" && ["Delayed", "Watching"].includes(prevStatus)) {
        pushTitle = `✅ ${ident} Back on Time`;
        pushBody = `Your ${leg.origin} → ${leg.destination} flight is now showing on time.`;
        activityTitle = `${ident} back on time`;
        activityBody = `Your ${leg.origin} → ${leg.destination} flight recovered to on-time status.`;
        activityType = "recovery";
      } else if (newStatus === "In Air") {
        activityTitle = `${ident} is airborne`;
        activityBody = `${leg.origin} → ${leg.destination} departed.`;
        activityType = "departed";
        // No push for in-air unless it was previously delayed
        if (prevStatus === "Delayed") {
          pushTitle = `🛫 ${ident} Departed`;
          pushBody = `Your delayed ${leg.origin} → ${leg.destination} flight has taken off.`;
        }
      } else if (newStatus === "Landed") {
        activityTitle = `${ident} landed`;
        activityBody = `Your ${leg.origin} → ${leg.destination} flight has landed.`;
        activityType = "landed";
      } else {
        activityTitle = `${ident} status: ${newStatus}`;
        activityBody = `${leg.origin} → ${leg.destination}`;
        activityType = "status";
      }

      // Log to activity feed
      await logActivity(
        leg.user_email,
        activityType,
        activityTitle,
        activityBody,
        leg.trip_id,
        leg.id,
        { ident, prevStatus, newStatus, delay: live.delay, gate: live.gate, terminal: live.terminal }
      );

      // Send push notification (only for actionable events)
      if (pushTitle) {
        await sendPushToUser(leg.user_email, pushTitle, pushBody, { route: "Activity" });
      }
    }
    console.log("[poll] done");
  } catch (e) {
    console.error("[poll] error:", e.message);
  }
}

// Run poll on startup (after 30s delay to let server settle) and every 15 min
setTimeout(() => {
  pollDisruptions();
  setInterval(pollDisruptions, 15 * 60 * 1000);
}, 30 * 1000);

app.listen(PORT, () => console.log("Wingman API on http://localhost:" + PORT));
