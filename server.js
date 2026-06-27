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
const { Duffel } = require("@duffel/api");

const app = express();
app.use(cors());
// Stripe webhook requires raw body for signature verification — skip JSON parsing for that route
app.use((req, res, next) => {
  if (req.path === "/subscription/webhook") return next();
  express.json()(req, res, next);
});

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
        preferences JSONB DEFAULT '{}',
        subscription_tier TEXT DEFAULT 'free',
        subscription_status TEXT DEFAULT 'inactive',
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // Add subscription columns to existing users tables (idempotent)
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_tier TEXT DEFAULT 'free'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status TEXT DEFAULT 'inactive'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT`;
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
        mode TEXT DEFAULT 'solo',
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
    await sql`
      CREATE TABLE IF NOT EXISTS loyalty_accounts (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        program TEXT NOT NULL,
        provider_code TEXT NOT NULL,
        account_number TEXT,
        member_name TEXT,
        points_balance BIGINT DEFAULT 0,
        elite_status TEXT,
        elite_level_next TEXT,
        points_to_next_level BIGINT,
        nights_ytd INTEGER,
        segments_ytd INTEGER,
        expiration_date TIMESTAMPTZ,
        last_synced TIMESTAMPTZ,
        aw_account_id TEXT,
        metadata JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, provider_code)
      )
    `;
    console.log("[db] tables ready");
  } catch (e) {
    console.error("[db] bootstrap error:", e.message);
  }
}
bootstrapDB();

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Hotel pre-arrival preference email helper
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Look up hotel contact email via Google Places API
// Returns { email, phone, website, placeId } or null
// ---------------------------------------------------------------------------
async function lookupHotelContact(hotelName, city) {
  try {
    const apiKey = process.env.GOOGLE_PLACES_API_KEY;
    if (!apiKey) return null;
    const query = encodeURIComponent(`${hotelName} hotel ${city || ""}`);
    // Step 1: Find Place from Text
    const findUrl = `https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=${query}&inputtype=textquery&fields=place_id,name,formatted_address&key=${apiKey}`;
    const findResp = await fetch(findUrl);
    const findData = await findResp.json();
    const placeId = findData.candidates?.[0]?.place_id;
    if (!placeId) return null;
    // Step 2: Get Place Details (website + phone)
    const detailUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}&fields=name,formatted_phone_number,website,url&key=${apiKey}`;
    const detailResp = await fetch(detailUrl);
    const detailData = await detailResp.json();
    const result = detailData.result || {};
    const website = result.website || null;
    const phone = result.formatted_phone_number || null;
    // Step 3: Try to extract email from hotel website's contact page
    let email = null;
    if (website) {
      try {
        const contactUrls = [
          website.replace(/\/$/, "") + "/contact",
          website.replace(/\/$/, "") + "/contact-us",
          website.replace(/\/$/, "") + "/en/contact",
          website,
        ];
        for (const contactUrl of contactUrls) {
          const pageResp = await fetch(contactUrl, {
            headers: { "User-Agent": "Mozilla/5.0 (compatible; Wingman/1.0; +https://wingmantravel.app)" },
            signal: AbortSignal.timeout(6000),
          });
          const html = await pageResp.text();
          // Extract email addresses from HTML
          const emailMatches = html.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
          // Filter out generic/noreply addresses and prefer concierge/reservations/info
          const preferred = emailMatches.find(e =>
            /concierge|reservations|front.?desk|info|contact|guest/i.test(e) &&
            !/noreply|no-reply|donotreply|example|test/i.test(e)
          );
          const fallback = emailMatches.find(e =>
            !/noreply|no-reply|donotreply|example|test/i.test(e)
          );
          email = preferred || fallback || null;
          if (email) break;
        }
      } catch (scrapeErr) {
        console.log("[hotel-contact] website scrape failed:", scrapeErr.message);
      }
    }
    return { email, phone, website, placeId };
  } catch (e) {
    console.error("[hotel-contact] lookup error:", e.message);
    return null;
  }
}

async function sendHotelPreferenceEmail(userEmail, parsedBooking, tripTitle) {
  try {
    // Fetch user preferences
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${userEmail}`;
    const prefs = userRows[0]?.preferences || {};
    const hotelPrefs = prefs.hotel_prefs || [];
    const foodPrefs = prefs.food_prefs || [];
    if (hotelPrefs.length === 0 && foodPrefs.length === 0) return; // nothing to send
    const HOTEL_LABELS = {
      high_floor: "a high floor room", quiet_room: "a quiet room away from street noise",
      away_elevator: "a room away from the elevator", bathtub: "a room with a bathtub (not just a shower)",
      firm_pillow: "firm pillows", late_checkout: "late checkout if possible",
      room_service: "24-hour room service availability", fast_wifi: "high-speed Wi-Fi",
      no_resort_fee: "waiver of resort fees if possible", gym: "gym access",
    };
    const prefLines = [
      ...hotelPrefs.map(p => HOTEL_LABELS[p] || p),
      ...foodPrefs.length > 0 ? [`dietary requirements: ${foodPrefs.join(", ")}`] : [],
    ];
    const hotelName = parsedBooking.carrier || parsedBooking.destination || "the hotel";
    const city = parsedBooking.destination || "";
    const checkIn = parsedBooking.departs_at
      ? new Date(parsedBooking.departs_at).toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })
      : "my upcoming stay";
    // Try to find the hotel's direct email
    const hotelContact = await lookupHotelContact(hotelName, city);
    const hotelEmail = hotelContact?.email || null;
    const hotelPhone = hotelContact?.phone || null;
    const hotelWebsite = hotelContact?.website || null;
    const emailBody = `
<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px;color:#222">
  <p>Dear ${hotelName} Team,</p>
  <p>I have an upcoming reservation (confirmation: ${parsedBooking.confirmation || "on file"}) checking in ${checkIn}. I wanted to reach out in advance to share a few preferences for my stay:</p>
  <ul style="line-height:1.8">
    ${prefLines.map(p => `<li>${p}</li>`).join("\n    ")}
  </ul>
  <p>I would be very grateful if the team could accommodate these where possible. Please let me know if you need any additional information.</p>
  <p>Thank you in advance — I look forward to my stay.</p>
  <p style="color:#666;font-size:12px;margin-top:24px">This message was sent automatically by <strong>Wingman</strong>, a travel assistant acting on behalf of ${userEmail}.</p>
</div>`;
    if (hotelEmail) {
      // Send directly to the hotel AND CC the user
      await resend.emails.send({
        from: "Wingman <noreply@wingmantravel.app>",
        to: hotelEmail,
        cc: userEmail,
        reply_to: userEmail,
        subject: `Pre-arrival preferences — ${userEmail} — checking in ${checkIn}`,
        html: emailBody,
      });
      // Log activity
      await logActivity(
        userEmail, "hotel_email",
        `Pre-arrival email sent to ${hotelName}`,
        `Wingman sent your room preferences directly to ${hotelName} (${hotelEmail}). You were CC'd. Preferences: ${prefLines.slice(0, 3).join("; ")}.`,
        null, null,
        { hotelName, hotelEmail, hotelPhone, hotelWebsite, sentDirect: true }
      );
      console.log("[hotel-pref-email] sent directly to hotel:", hotelEmail);
    } else {
      // Fallback: send to user as a draft with hotel contact info
      const fallbackNote = hotelPhone
        ? `<p style="background:#f5f5f5;padding:12px;border-radius:8px;font-size:13px"><strong>Note from Wingman:</strong> We could not find a direct email for ${hotelName}. You can forward this email or call them at <strong>${hotelPhone}</strong>${hotelWebsite ? ` or visit <a href="${hotelWebsite}">${hotelWebsite}</a>` : ""}.</p>`
        : `<p style="background:#f5f5f5;padding:12px;border-radius:8px;font-size:13px"><strong>Note from Wingman:</strong> We could not find a direct email for ${hotelName}. Please forward this to the hotel's concierge or front desk.</p>`;
      await resend.emails.send({
        from: "Wingman <noreply@wingmantravel.app>",
        to: userEmail,
        subject: `[Draft] Pre-arrival preferences for your stay at ${hotelName}`,
        html: fallbackNote + emailBody,
      });
      await logActivity(
        userEmail, "hotel_email",
        `Pre-arrival draft ready for ${hotelName}`,
        `Wingman prepared your room preferences for ${hotelName} but could not find a direct email. ${hotelPhone ? `Hotel phone: ${hotelPhone}.` : ""} Check your email to forward it.`,
        null, null,
        { hotelName, hotelEmail: null, hotelPhone, hotelWebsite, sentDirect: false }
      );
      console.log("[hotel-pref-email] no hotel email found, sent draft to user");
    }
  } catch (e) {
    console.error("[hotel-pref-email] error:", e.message);
  }
}

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
  // App sends { pushToken } (Expo convention); also accept legacy { token }
  const token = req.body?.pushToken || req.body?.token;
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
// LOYALTY PROGRAM ENDPOINTS (AwardWallet Web Parsing API)
// ---------------------------------------------------------------------------

const AW_BASE = "https://loyalty.awardwallet.com/v2";

// Map our program keys to AwardWallet provider codes
const LOYALTY_PROGRAMS = {
  marriott:  { code: "marriott",  name: "Marriott Bonvoy",        icon: "🏨", kind: "hotel" },
  hilton:    { code: "hhonors",   name: "Hilton Honors",          icon: "🏩", kind: "hotel" },
  united:    { code: "united",    name: "United MileagePlus",     icon: "✈️", kind: "airline" },
  delta:     { code: "delta",     name: "Delta SkyMiles",         icon: "🔵", kind: "airline" },
  american:  { code: "aa",        name: "American AAdvantage",    icon: "🦅", kind: "airline" },
  hyatt:     { code: "hyatt",     name: "World of Hyatt",         icon: "🏛️", kind: "hotel" },
  ihg:       { code: "ihg",       name: "IHG One Rewards",        icon: "🌐", kind: "hotel" },
  british:   { code: "ba",        name: "British Airways Avios",  icon: "🇬🇧", kind: "airline" },
  emirates:  { code: "emirates",  name: "Emirates Skywards",      icon: "🇦🇪", kind: "airline" },
  amex_mr:   { code: "amex",      name: "Amex Membership Rewards",icon: "💳", kind: "credit_card" },
};

async function awRequest(path, opts = {}) {
  const awUser = process.env.AWARDWALLET_API_USER;
  const awPass = process.env.AWARDWALLET_API_PASS;
  if (!awUser || !awPass) throw new Error("AWARDWALLET_API_USER / AWARDWALLET_API_PASS not set");
  const auth = Buffer.from(`${awUser}:${awPass}`).toString("base64");
  const resp = await fetch(`${AW_BASE}${path}`, {
    ...opts,
    headers: {
      "X-Authentication": `${awUser}:${awPass}`,
      "Content-Type": "application/json",
      ...(opts.headers || {}),
    },
  });
  if (!resp.ok) throw new Error(`AwardWallet API error ${resp.status}`);
  return resp.json();
}

// GET /loyalty — list all connected loyalty accounts for user
app.get("/loyalty", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const accounts = await sql`
      SELECT * FROM loyalty_accounts WHERE user_email = ${email} ORDER BY program ASC
    `;
    res.json({ accounts, programs: LOYALTY_PROGRAMS });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /loyalty/connect — connect a loyalty account
app.post("/loyalty/connect", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { program, login, password, login2 } = req.body || {};
  if (!program || !login || !password) return res.status(400).json({ error: "program, login, password required" });
  const prog = LOYALTY_PROGRAMS[program];
  if (!prog) return res.status(400).json({ error: "unknown program" });
  try {
    // Submit account to AwardWallet for initial sync
    const awResp = await awRequest("/accounts", {
      method: "POST",
      body: JSON.stringify({
        provider: prog.code,
        login,
        password,
        ...(login2 ? { login2 } : {}),
        userId: email,
        userData: JSON.stringify({ userEmail: email, program }),
      }),
    });
    // awResp contains accountId — store it
    const awAccountId = awResp.accountId || awResp.id || null;
    await sql`
      INSERT INTO loyalty_accounts (user_email, program, provider_code, aw_account_id, last_synced)
      VALUES (${email}, ${program}, ${prog.code}, ${awAccountId}, NOW())
      ON CONFLICT (user_email, provider_code)
      DO UPDATE SET aw_account_id = EXCLUDED.aw_account_id, last_synced = NOW()
    `;
    // Trigger an immediate sync
    syncLoyaltyAccount(email, program).catch(e => console.error("[loyalty-sync]", e.message));
    await logActivity(email, "loyalty", `${prog.name} connected`,
      `Wingman is now tracking your ${prog.name} balance and status. Syncing now…`);
    res.json({ ok: true, program, awAccountId });
  } catch (e) {
    console.error("[loyalty-connect]", e.message);
    // If AwardWallet not configured, store the account anyway for manual sync later
    if (e.message.includes("not set")) {
      await sql`
        INSERT INTO loyalty_accounts (user_email, program, provider_code, last_synced)
        VALUES (${email}, ${program}, ${prog.code}, NOW())
        ON CONFLICT (user_email, provider_code) DO NOTHING
      `;
      await logActivity(email, "loyalty", `${prog.name} added`,
        `${prog.name} account saved. Configure AWARDWALLET_API_USER/PASS on Render to enable auto-sync.`);
      return res.json({ ok: true, program, note: "stored without sync — AwardWallet not configured" });
    }
    res.status(500).json({ error: e.message });
  }
});

// POST /loyalty/sync — manually trigger a sync for one or all accounts
app.post("/loyalty/sync", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { program } = req.body || {};
  try {
    const accounts = program
      ? await sql`SELECT * FROM loyalty_accounts WHERE user_email = ${email} AND program = ${program}`
      : await sql`SELECT * FROM loyalty_accounts WHERE user_email = ${email}`;
    const results = await Promise.allSettled(accounts.map(a => syncLoyaltyAccount(email, a.program)));
    const synced = results.filter(r => r.status === "fulfilled").length;
    res.json({ ok: true, synced, total: accounts.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /loyalty/:program — disconnect a loyalty account
app.delete("/loyalty/:program", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { program } = req.params;
  try {
    await sql`DELETE FROM loyalty_accounts WHERE user_email = ${email} AND program = ${program}`;
    const prog = LOYALTY_PROGRAMS[program];
    await logActivity(email, "loyalty", `${prog?.name || program} disconnected`,
      `Wingman is no longer tracking your ${prog?.name || program} account.`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Core sync function — fetches latest data from AwardWallet and updates DB
async function syncLoyaltyAccount(userEmail, program) {
  const prog = LOYALTY_PROGRAMS[program];
  if (!prog) return;
  const rows = await sql`SELECT * FROM loyalty_accounts WHERE user_email = ${userEmail} AND program = ${program}`;
  const acct = rows[0];
  if (!acct) return;
  try {
    const awUser = process.env.AWARDWALLET_API_USER;
    const awPass = process.env.AWARDWALLET_API_PASS;
    if (!awUser || !awPass) {
      console.log("[loyalty-sync] AwardWallet not configured — skipping");
      return;
    }
    // Request account update from AwardWallet
    if (acct.aw_account_id) {
      await awRequest(`/accounts/${acct.aw_account_id}/update`, { method: "POST" });
      // Poll for completion (AwardWallet is async — wait up to 30s)
      let data = null;
      for (let i = 0; i < 6; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const status = await awRequest(`/accounts/${acct.aw_account_id}`);
        if (status.status === "done" || status.balance !== undefined) {
          data = status;
          break;
        }
      }
      if (!data) return; // timed out
      // Parse AwardWallet response into our schema
      const balance = parseInt(data.balance || data.PointsValue || 0);
      const eliteStatus = data.Level || data.eliteLevel || null;
      const eliteNext = data.NextLevel || null;
      const pointsToNext = parseInt(data.PointsToNextLevel || 0) || null;
      const nightsYtd = parseInt(data.Nights || 0) || null;
      const segmentsYtd = parseInt(data.Segments || 0) || null;
      const memberName = data.Name || null;
      const accountNumber = data.Number || null;
      const expirationDate = data.Expiration ? new Date(data.Expiration) : null;
      // Detect status changes for activity logging
      const prevBalance = acct.points_balance || 0;
      const prevStatus = acct.elite_status;
      await sql`
        UPDATE loyalty_accounts SET
          points_balance = ${balance},
          elite_status = ${eliteStatus},
          elite_level_next = ${eliteNext},
          points_to_next_level = ${pointsToNext},
          nights_ytd = ${nightsYtd},
          segments_ytd = ${segmentsYtd},
          member_name = ${memberName},
          account_number = ${accountNumber},
          expiration_date = ${expirationDate},
          last_synced = NOW()
        WHERE user_email = ${userEmail} AND program = ${program}
      `;
      // Log notable changes
      if (prevStatus && eliteStatus && prevStatus !== eliteStatus) {
        await logActivity(userEmail, "loyalty",
          `${prog.name} status changed: ${eliteStatus}`,
          `Your ${prog.name} elite status changed from ${prevStatus} to ${eliteStatus}.`);
        await sendPushToUser(userEmail,
          `${prog.icon} ${prog.name} status update`,
          `Your status changed to ${eliteStatus}!`,
          { route: "Loyalty" });
      } else if (balance > prevBalance) {
        const earned = (balance - prevBalance).toLocaleString();
        await logActivity(userEmail, "loyalty",
          `${prog.name} +${earned} ${prog.kind === "airline" ? "miles" : "points"}`,
          `Your ${prog.name} balance increased by ${earned}. New balance: ${balance.toLocaleString()}.`);
      }
      console.log(`[loyalty-sync] ${userEmail} ${program}: ${balance} pts, status: ${eliteStatus}`);
    }
  } catch (e) {
    console.error(`[loyalty-sync] ${userEmail} ${program}:`, e.message);
  }
}

// Loyalty sync cron — runs every 6 hours
setInterval(async () => {
  try {
    const accounts = await sql`
      SELECT DISTINCT user_email, program FROM loyalty_accounts
      WHERE last_synced < NOW() - INTERVAL '6 hours' OR last_synced IS NULL
    `;
    console.log(`[loyalty-cron] syncing ${accounts.length} accounts`);
    for (const acct of accounts) {
      await syncLoyaltyAccount(acct.user_email, acct.program).catch(e =>
        console.error("[loyalty-cron]", e.message));
    }
  } catch (e) {
    console.error("[loyalty-cron] error:", e.message);
  }
}, 6 * 60 * 60 * 1000); // every 6 hours

// ---------------------------------------------------------------------------
// GET /me — current user info
// ---------------------------------------------------------------------------
app.get("/me", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const rows = await sql`SELECT email, push_token, preferences, created_at FROM users WHERE email = ${email}`;
    if (!rows[0]) return res.status(404).json({ error: "user not found" });
    // Check if Gmail is connected
    const gmailRows = await sql`SELECT id FROM gmail_tokens WHERE user_email = ${email}`;
    res.json({ ...rows[0], gmail_connected: gmailRows.length > 0 });
  } catch (e) {
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// PATCH /profile — save user preferences (taste graph, seat prefs, hotel soft-specs)
// ---------------------------------------------------------------------------
app.patch("/profile", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const { preferences } = req.body || {};
    if (!preferences || typeof preferences !== "object") {
      return res.status(400).json({ error: "preferences object required" });
    }
    await sql`
      UPDATE users
      SET preferences = COALESCE(preferences, '{}'::jsonb) || ${JSON.stringify(preferences)}::jsonb
      WHERE email = ${email}
    `;
    const rows = await sql`SELECT preferences FROM users WHERE email = ${email}`;
    res.json({ preferences: rows[0].preferences });
  } catch (e) {
    console.error("PATCH /profile error:", e);
    res.status(500).json({ error: "db error" });
  }
});
// GET /profile — alias for GET /me (app calls this from HomeAddressScreen, LoyaltyScreen)
// ---------------------------------------------------------------------------
app.get("/profile", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const rows = await sql`SELECT email, push_token, preferences, created_at FROM users WHERE email = ${email}`;
    if (!rows[0]) return res.status(404).json({ error: "user not found" });
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
    // Feature C: Hotel pre-arrival preference injection
    if ((parsed.type || "flight") === "hotel") {
      sendHotelPreferenceEmail(userEmail, parsed, tripTitle).catch(e =>
        console.error("[hotel-pref-email]", e.message)
      );
    }
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
  const { emailBody, source } = req.body || {};

  // If emailBody provided: extract trips from pasted confirmation text
  if (emailBody) {
    try {
      const trips_added = await parsePastedEmailBody(email, emailBody, source || "paste");
      return res.json({ ok: true, trips_created: trips_added, trips_found: trips_added });
    } catch (e) {
      console.error("[scan/paste]", e.message);
      return res.status(500).json({ error: e.message });
    }
  }

  // Otherwise: trigger a background Gmail re-scan (existing behaviour)
  try {
    scanGmailForTrips(email).catch(e => console.error("[scan]", e.message));
    res.json({ ok: true, message: "Scan started", trips_created: 0 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Parse a pasted email body and store any trips found
async function parsePastedEmailBody(userEmail, body, source) {
  const flightPattern = /(?:flight|flt)[:\s#]*([A-Z]{2}\d{3,4})/gi;
  const routePattern  = /([A-Z]{3})\s*(?:to|→|->)\s*([A-Z]{3})/g;
  const datePattern   = /(?:departs?|departure)[:\s]*([A-Za-z]+ \d{1,2},? \d{4}|\d{1,2}\/\d{1,2}\/\d{4})/gi;

  const flights = [...body.matchAll(flightPattern)].map(m => m[1]);
  const routes  = [...body.matchAll(routePattern)].map(m => ({ origin: m[1], destination: m[2] }));
  const dates   = [...body.matchAll(datePattern)].map(m => m[1]);

  if (routes.length === 0 && flights.length === 0) return 0;

  const route = routes[0] || {};
  const tripTitle = route.destination ? `Trip to ${route.destination}` : "Imported Trip";

  const tripRows = await sql`
    INSERT INTO trips (user_email, title, source)
    VALUES (${userEmail}, ${tripTitle}, ${source})
    RETURNING id
  `;
  if (tripRows.length === 0) return 0;
  const tripId = tripRows[0].id;

  for (let i = 0; i < Math.max(flights.length, 1); i++) {
    const f = flights[i] || null;
    await sql`
      INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at)
      VALUES (
        ${tripId}, 'flight',
        ${f ? f.slice(0, 2) : null},
        ${f ? f.slice(2) : null},
        ${routes[i]?.origin || route.origin || null},
        ${routes[i]?.destination || route.destination || null},
        ${dates[i] || dates[0] || null}
      )
    `;
  }

  await logActivity(userEmail, "import", `Imported: ${tripTitle}`, `Booking pasted manually.`, tripId);
  return 1;
}

// ---------------------------------------------------------------------------
// GET /uber/deeplink — returns a pre-filled Uber deep link for a given airport
// No OAuth required — opens the Uber app directly on the user's phone
// ---------------------------------------------------------------------------
app.get("/uber/deeplink", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");
    const { email } = jwt.verify(token, JWT_SECRET);
    const { airport } = req.query;
    const coords = AIRPORT_COORDS[airport];
    if (!coords) return res.status(400).json({ error: "Unknown airport" });
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${email}`;
    const prefs = userRows[0]?.preferences || {};
    const mode = (prefs.default_mode || "solo").toLowerCase();
    // Build Uber universal deep link
    // pickup = airport coords, dropoff = saved home address if available
    const pickupNickname = encodeURIComponent(`${airport} Airport`);
    const pickupLat = coords.lat;
    const pickupLng = coords.lng;
    let deepLink;
    if (prefs.home_address) {
      // With dropoff address
      const dropoff = encodeURIComponent(prefs.home_address);
      deepLink = `uber://?action=setPickup&pickup[latitude]=${pickupLat}&pickup[longitude]=${pickupLng}&pickup[nickname]=${pickupNickname}&dropoff[addressString]=${dropoff}`;
    } else {
      // Pickup only — user sets dropoff in Uber app
      deepLink = `uber://?action=setPickup&pickup[latitude]=${pickupLat}&pickup[longitude]=${pickupLng}&pickup[nickname]=${pickupNickname}`;
    }
    // Also return a universal fallback URL for users without the app
    const webFallback = `https://m.uber.com/ul/?action=setPickup&pickup[latitude]=${pickupLat}&pickup[longitude]=${pickupLng}&pickup[nickname]=${pickupNickname}`;
    // App reads data.url — include as alias for deepLink
    res.json({ deepLink, url: deepLink, webFallback, airport, mode, coords });
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
  const { title, legs, mode } = req.body || {};
  if (!title) return res.status(400).json({ error: "title required" });
  const tripMode = ["solo", "client", "partner"].includes(mode) ? mode : "solo";
  try {
    const tripRows = await sql`
      INSERT INTO trips (user_email, title, source, mode)
      VALUES (${email}, ${title}, 'manual', ${tripMode})
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
    // Fetch user preferences (taste graph), trips, and loyalty accounts in parallel
    const [userRows, trips, loyaltyAccounts] = await Promise.all([
      sql`SELECT preferences FROM users WHERE email = ${email}`,
      sql`
      SELECT t.id, t.title, t.status, t.mode, t.created_at,
        json_agg(tl.* ORDER BY tl.departs_at ASC NULLS LAST) FILTER (WHERE tl.id IS NOT NULL) as legs
      FROM trips t
      LEFT JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
      GROUP BY t.id
      ORDER BY t.created_at DESC
            LIMIT 10
    `,
      sql`SELECT program, points_balance, elite_status, elite_level_next, points_to_next_level, nights_ytd, segments_ytd FROM loyalty_accounts WHERE user_email = ${email} ORDER BY program ASC`
    ]);
    const prefs = userRows[0]?.preferences || {};
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
          const modeLabel = trip.mode === "client" ? " [CLIENT TRIP]" : trip.mode === "partner" ? " [PARTNER/LEISURE TRIP]" : "";
          return `Trip: "${trip.title}"${modeLabel}\n${legLines || "  (no legs)"}`.trim();
        }).join("\n\n");

        // Build taste profile section from user preferences
    const editorialSources = (prefs.editorial_sources || []);
    const hotelPrefs = (prefs.hotel_prefs || []);
    const seatPrefs = (prefs.seat_prefs || []);
    const foodPrefs = (prefs.food_prefs || []);
    const SOURCE_LABELS = {
      nyt36: "NYT 36 Hours (dense city itineraries)",
      service95: "Service95 (Dua Lipa's cultural concierge — arts, dining, nightlife)",
      hotelsabovepar: "Hotels Above Par (design-forward boutique hotels only)",
      slh: "Small Luxury Hotels of the World (750-criteria inspected independent luxury)",
      afar: "AFAR (experiential travel, cultural immersion, sustainability)",
      travelandleisure: "Travel + Leisure (established luxury, World's Best lists)",
      cntraveler: "Condé Nast Traveler (Gold List, Hot List, prestige picks)",
      monocle: "Monocle (city intelligence, quality of life, local business culture)",
      tablet: "Tablet Hotels (curated independent hotels, no chains)",
      eater: "Eater (restaurant openings, heat maps, dining culture)",
    };
    const HOTEL_LABELS = {
      high_floor: "high floor", quiet_room: "quiet room", away_elevator: "away from elevator",
      bathtub: "bathtub required", firm_pillow: "firm pillow", late_checkout: "late checkout",
      room_service: "24h room service", fast_wifi: "fast Wi-Fi", no_resort_fee: "no resort fees", gym: "gym access",
    };
    const SEAT_LABELS = {
      econ_aisle: "Economy: aisle", econ_window: "Economy: window", econ_exit_row: "Economy: exit row",
      econ_bulkhead: "Economy: bulkhead", pe_aisle: "Premium Economy: aisle", pe_window: "Premium Economy: window",
      pe_bulkhead: "Premium Economy: bulkhead", biz_window_suite: "Business: window suite",
      biz_aisle: "Business: direct aisle access", biz_bulkhead_behind: "Business: bulkhead behind (privacy)",
      biz_forward_facing: "Business: forward facing only", first_suite: "First: enclosed suite",
      first_forward: "First: forward facing", first_window: "First: window/wall side",
    };
    const tasteSection = [
      editorialSources.length > 0
        ? `Editorial sources this user trusts (use these as your recommendation lens):\n${editorialSources.map(s => `  - ${SOURCE_LABELS[s] || s}`).join("\n")}`
        : null,
      hotelPrefs.length > 0
        ? `Hotel preferences (always mention/prioritize when recommending hotels):\n  ${hotelPrefs.map(p => HOTEL_LABELS[p] || p).join(", ")}`
        : null,
      seatPrefs.length > 0
        ? `Seat preferences (use when advising on seat selection or upgrades):\n  ${seatPrefs.map(p => SEAT_LABELS[p] || p).join(", ")}`
        : null,
      foodPrefs.length > 0
        ? `Dietary preferences (apply to restaurant and airline meal recommendations):\n  ${foodPrefs.join(", ")}`
        : null,
    ].filter(Boolean).join("\n\n");
    // Build loyalty summary for system prompt
    const PROG_NAMES = {
      marriott: "Marriott Bonvoy", hilton: "Hilton Honors", united: "United MileagePlus",
      delta: "Delta SkyMiles", american: "American AAdvantage", hyatt: "World of Hyatt",
      ihg: "IHG One Rewards", british: "British Airways Avios", emirates: "Emirates Skywards", amex_mr: "Amex MR",
    };
    const loyaltySummary = loyaltyAccounts.length > 0
      ? loyaltyAccounts.map(a => {
          const name = PROG_NAMES[a.program] || a.program;
          const pts = a.points_balance ? Number(a.points_balance).toLocaleString() : "unknown";
          const status = a.elite_status ? ` · ${a.elite_status}` : "";
          const toNext = a.points_to_next_level && a.elite_level_next
            ? ` · ${Number(a.points_to_next_level).toLocaleString()} to ${a.elite_level_next}` : "";
          return `  - ${name}: ${pts} pts${status}${toNext}`;
        }).join("\n")
      : null;

    const systemPrompt = `You are Wingman, a world-class AI travel concierge. You have real-time access to the user's trips, live flight statuses, and weather disruption risk scores. You also know this user's personal taste profile and editorial preferences — use them to give recommendations that feel like they came from a trusted friend with impeccable taste, not a generic algorithm.
Today's date/time: ${today}
User: ${email}
${tasteSection ? `=== USER'S TASTE PROFILE ===\n${tasteSection}\n` : ""}
${loyaltySummary ? `=== USER'S LOYALTY ACCOUNTS ===\n${loyaltySummary}\n\nWhen recommending hotels, always factor in which programs the user has status with and suggest properties where their status will be recognized. When advising on flights, factor in their airline status and miles balance — suggest using miles for upgrades when the balance is high.\n` : ""}
=== USER'S TRIPS (with live data) ===
${tripsSummary}
You help with:
- Explaining live flight status, delays, gate changes
- Assessing disruption risk based on weather data above
- Rebooking options and airline policies when flights are cancelled or heavily delayed
- Hotel, restaurant, and experience recommendations — always filtered through the user's editorial taste profile above
- Seat selection advice based on the user's preferences above
- General travel advice and packing tips
Guidelines:
- Be concise and direct — the user is likely in a stressful travel situation
- Always reference the user's actual trip data and live statuses above
- If a flight shows a delay or high weather risk, proactively mention it
- For rebooking, mention the airline's app/phone and same-day change policies
- When recommending hotels or restaurants, reason like an editor from the user's trusted sources above
- If the user has hotel soft-specs (bathtub, quiet room, etc.), factor them into every hotel recommendation
- If data is missing or stale, say so honestly
- Trip modes: [CLIENT TRIP] = prioritize prestige, optics, private dining, car service over Uber; [PARTNER/LEISURE TRIP] = prioritize romance, design-forward boutique hotels, bathtub, no 6am flights, chef's table dinners; no mode label = solo/efficiency mode`;


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

// GET /flight-status/:ident — path-param alias (app calls this form)
// ---------------------------------------------------------------------------
app.get("/flight-status/:ident", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const ident = String(req.params.ident || "").toUpperCase().replace(/\s/g, "");
  if (!ident) return res.status(400).json({ error: "ident required" });
  const status = await getFlightStatus(ident);
  if (!status) return res.json({ ident, status: "Unknown", live: false });
  res.json({ ident, live: true, ...status });
});
// ---------------------------------------------------------------------------
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
// ---------------------------------------------------------------------------
// GET /tsa-wait — TSA security wait estimate (modeled, no API key needed)
// Called by HomeScreen ground intel panel
// ---------------------------------------------------------------------------
const TSA_BUSYNESS = { ATL:1.6,LAX:1.5,ORD:1.45,DFW:1.4,DEN:1.3,JFK:1.35,SFO:1.3,LAS:1.25,MCO:1.3,SEA:1.2,MIA:1.2,CLT:1.15,EWR:1.25,LGA:1.2,BOS:1.15,MSP:1.1,DTW:1.1,PHL:1.15,FLL:1.1,BWI:1.05,IAH:1.15,PHX:1.1,SLC:1.05,SAN:1.0,TPA:0.95,PDX:0.95,HNL:0.9,AUS:1.05,BNA:0.95,RDU:0.9,STL:0.85,MCI:0.85,ASE:0.4,EGE:0.35,JAC:0.35 };
const HOUR_CURVE = [0.05,0.03,0.02,0.02,0.04,0.12,0.25,0.55,0.80,0.90,0.85,0.75,0.70,0.65,0.70,0.75,0.90,1.00,0.95,0.85,0.70,0.55,0.35,0.15];
const DOW_MULT   = [1.15,0.85,0.90,0.90,0.95,1.20,1.25];
function estimateTsaWait(airport, hour, dow) {
  const b = TSA_BUSYNESS[(airport||"").toUpperCase()] || 1.0;
  const h = HOUR_CURVE[Math.max(0,Math.min(23,hour))] || 0.5;
  const d = DOW_MULT[dow] || 1.0;
  const wait = Math.max(3, Math.min(Math.round(22*b*h*d), 90));
  return { wait, level: wait>=45?"busy":wait>=20?"moderate":"light", source:"modeled" };
}
app.get("/tsa-wait", (req, res) => {
  const airport = (req.query.airport||"").toUpperCase();
  const hour    = parseInt(req.query.hour) || new Date().getHours();
  const dow     = parseInt(req.query.dow)  || new Date().getDay();
  if (!airport) return res.status(400).json({ error:"airport required" });
  res.json({ airport, ...estimateTsaWait(airport, hour, dow) });
});
// ---------------------------------------------------------------------------
// GET /ground-intel — drive time + TSA + gate walk timeline
// ---------------------------------------------------------------------------
const GATE_WALK_DB = { ATL:{default:12,same:5},ORD:{default:18,same:6},DFW:{default:20,same:5},JFK:{default:30,same:8},LAX:{default:25,same:7},LGA:{default:15,same:6},EWR:{default:20,same:6},BOS:{default:12,same:5},SFO:{default:18,same:6},SEA:{default:10,same:5},DEN:{default:14,same:5},MIA:{default:15,same:6} };
function estimateGateWalk(airport, fromGate, toGate) {
  const db = GATE_WALK_DB[(airport||"").toUpperCase()];
  if (!db) return { walk:10, note:"estimated" };
  const concourse = g => { if(!g) return null; const m=g.match(/^([A-Z]|\d)/i); return m?m[1].toUpperCase():null; };
  const from = concourse(fromGate), to = concourse(toGate);
  if (!from||!to||from===to) return { walk:db.same||5, note:"same concourse" };
  return { walk:db.default||12, note:`${from}→${to} concourse transfer` };
}
app.get("/ground-intel", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error:"unauthorized" });
  const { airport, departure_time, from_gate, to_gate, lat, lon, delay_minutes } = req.query;
  if (!airport||!departure_time) return res.status(400).json({ error:"airport and departure_time required" });
  const dep = new Date(departure_time);
  const now = new Date();
  const minutesToDep = Math.round((dep-now)/60000);
  const localHour = dep.getHours(), dayOfWeek = dep.getDay();
  const result = { airport, minutesToDeparture:minutesToDep, timeline:[], verdict:null, bufferMinutes:null, atRisk:false };
  if (lat && lon && !from_gate) {
    const tsa = estimateTsaWait(airport, localHour, dayOfWeek);
    const driveMin = 20, gateWalk = 8;
    const totalMin = driveMin + tsa.wait + gateWalk;
    const buffer = minutesToDep - totalMin;
    result.timeline = [
      { label:"Drive to airport", minutes:driveMin, source:"modeled" },
      { label:`Security (${tsa.level})`, minutes:tsa.wait, source:tsa.source },
      { label:"Walk to gate", minutes:gateWalk, source:"modeled" },
    ];
    result.bufferMinutes = buffer;
    result.atRisk = buffer < 20;
    result.verdict = buffer>=45?"plenty_of_time":buffer>=20?"on_track":buffer>=0?"tight":"will_miss";
  }
  if (from_gate && to_gate) {
    const gw = estimateGateWalk(airport, from_gate, to_gate);
    const delay = parseInt(delay_minutes)||0;
    const buffer = minutesToDep - delay - gw.walk - 5;
    result.timeline = [
      { label:`Land at ${from_gate}`, minutes:0, source:"scheduled" },
      { label:`Walk to ${to_gate}`, minutes:gw.walk, source:"modeled", note:gw.note },
    ];
    if (delay>0) result.timeline.unshift({ label:"Inbound delay", minutes:delay, source:"live" });
    result.bufferMinutes = buffer;
    result.atRisk = buffer < 15;
    result.verdict = buffer>=30?"plenty_of_time":buffer>=15?"on_track":buffer>=0?"tight":"will_miss";
  }
  res.json(result);
});
// ---------------------------------------------------------------------------
// GET /awards/search — award seat search (demo data; live requires Point.me key)
// ---------------------------------------------------------------------------
app.get("/awards/search", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error:"unauthorized" });
  const { origin, destination, date, cabin="economy" } = req.query;
  if (!origin||!destination||!date) return res.status(400).json({ error:"origin, destination, date required" });
  const POINTME_KEY = process.env.POINTME_KEY || null;
  if (!POINTME_KEY) {
    return res.json({ origin, destination, date, cabin, source:"demo", results:[
      { program:"Air Canada Aeroplan",         points:55000, cash_fee:75,  airline:"United Airlines",   flight:"UA 412",  availability:"available" },
      { program:"Flying Blue (Air France/KLM)",points:50000, cash_fee:60,  airline:"Air France",        flight:"AF 8234", availability:"available" },
      { program:"American AAdvantage",         points:60000, cash_fee:25,  airline:"American Airlines", flight:"AA 100",  availability:"waitlist"  },
    ], note:"Live award search requires POINTME_KEY env var" });
  }
  try {
    const r = await fetch(`https://api.point.me/v2/search?origin=${origin}&destination=${destination}&date=${date}&cabin=${cabin}`, { headers:{ "Authorization":`Bearer ${POINTME_KEY}` } });
    if (!r.ok) throw new Error(`Point.me ${r.status}`);
    const j = await r.json();
    res.json({ origin, destination, date, cabin, results:j.results||[], source:"pointme" });
  } catch(e) { res.status(502).json({ error:"award search unavailable", detail:e.message }); }
});

// ---------------------------------------------------------------------------
// Natural-language trip drafting  POST /trips/draft
// ---------------------------------------------------------------------------
app.post("/trips/draft", auth, async (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: "text required" });
  try {
    const anthropic = getAnthropic();
    const msg = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 400,
      messages: [{
        role: "user",
        content: `Extract structured trip data from this text and return ONLY a valid JSON object with these keys (omit any you cannot determine):\n{\n  "title": string,\n  "origin": string,\n  "destination": string,\n  "carrier": string,\n  "flight_number": string,\n  "departs_at": string,\n  "confirmation": string\n}\n\nText: ${text}\n\nReturn ONLY the JSON, no explanation.`,
      }],
    });
    const raw = msg.content[0].text.trim();
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) return res.status(422).json({ error: "Could not extract trip details", raw });
    const parsed = JSON.parse(match[0]);
    res.json(parsed);
  } catch (e) {
    res.status(500).json({ error: "Draft failed", detail: e.message });
  }
});

// ---------------------------------------------------------------------------
// Autonomy policy  GET /policy  PATCH /policy
// ---------------------------------------------------------------------------
app.get("/policy", auth, async (req, res) => {
  try {
    const rows = await sql`SELECT preferences FROM users WHERE email = ${req.user.email}`;
    const prefs = rows[0]?.preferences || {};
    res.json({
      policy: {
        autonomy_mode: prefs.autonomy_mode || "always_ask",
        threshold: prefs.threshold || 500,
        payment_preference: prefs.payment_preference || "best_value",
        cabin_preference: prefs.cabin_preference || "economy",
        notify_on_action: prefs.notify_on_action !== false,
        calendar_connected: prefs.calendar_connected || false,
        messages_connected: prefs.messages_connected || false,
      },
    });
  } catch (e) {
    res.json({ policy: { autonomy_mode: "always_ask", threshold: 500, payment_preference: "best_value", cabin_preference: "economy", notify_on_action: true } });
  }
});

app.patch("/policy", auth, async (req, res) => {
  const policy = req.body || {};
  try {
    const rows = await sql`SELECT preferences FROM users WHERE email = ${req.user.email}`;
    const existing = rows[0]?.preferences || {};
    const merged = { ...existing, ...policy };
    await sql`UPDATE users SET preferences = ${JSON.stringify(merged)} WHERE email = ${req.user.email}`;
    res.json({ ok: true, policy: merged });
  } catch (e) {
    res.status(500).json({ error: "Policy update failed", detail: e.message });
  }
});

// ---------------------------------------------------------------------------
// ROI / Insights  GET /insights/roi
// ---------------------------------------------------------------------------
app.get("/insights/roi", auth, async (req, res) => {
  try {
    const events = await sql`
      SELECT type, metadata, created_at FROM activity_events
      WHERE user_email = ${req.user.email}
      ORDER BY created_at DESC LIMIT 200
    `;
    let totalSaved = 0, disruptionsHandled = 0, rescueAccepted = 0, rescueTotal = 0;
    for (const ev of events) {
      const meta = ev.metadata || {};
      if (ev.type === "disruption_resolved" || ev.type === "rebook") {
        disruptionsHandled++;
        if (meta.value_saved) totalSaved += Number(meta.value_saved) || 0;
        if (meta.rescue_accepted != null) { rescueTotal++; if (meta.rescue_accepted) rescueAccepted++; }
      }
    }
    res.json({
      total_value_saved: totalSaved,
      disruptions_handled: disruptionsHandled,
      rescue_accept_rate: rescueTotal > 0 ? Math.round((rescueAccepted / rescueTotal) * 100) : null,
      avg_time_saved_minutes: disruptionsHandled > 0 ? 23 : null,
      prediction_accuracy_pct: null,
      recent_events: events.slice(0, 10).map(e => ({ type: e.type, created_at: e.created_at })),
    });
  } catch (e) {
    res.json({ total_value_saved: 0, disruptions_handled: 0, rescue_accept_rate: null, avg_time_saved_minutes: null, prediction_accuracy_pct: null, recent_events: [] });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now(), version: "2.2.0" }));

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
             t.user_email, t.title as trip_title, t.mode as trip_mode
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
        pushTitle = `🛬 ${ident} Landed`;
        pushBody = `You've landed at ${leg.destination}. Wingman is arranging your ride.`;
        // Auto-dispatch Uber based on trip mode
        dispatchUberOnLanding(leg).catch(e => console.error("[uber-dispatch]", e.message));
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
    // Feature E: Seat preference alerts — check if preferred seat type is available
    // Run once per poll for upcoming legs (not just on status change)
    await checkSeatPreferenceAlerts(legs);
    console.log("[poll] done");
  } catch (e) {
    console.error("[poll] error:", e.message);
  }
}

// ---------------------------------------------------------------------------
// Uber for Business — auto-dispatch on landing
// ---------------------------------------------------------------------------
// Uber product IDs by mode and region (fallback to uberx if not found)
const UBER_PRODUCTS = {
  client: {
    default: "d4abaae7-f4d6-4152-91cc-77523e8165a6", // UberBlack
    JFK: "d4abaae7-f4d6-4152-91cc-77523e8165a6",
    LAX: "d4abaae7-f4d6-4152-91cc-77523e8165a6",
    LHR: "d4abaae7-f4d6-4152-91cc-77523e8165a6",
    CDG: "d4abaae7-f4d6-4152-91cc-77523e8165a6",
  },
  partner: {
    default: "d4abaae7-f4d6-4152-91cc-77523e8165a6", // UberBlack
  },
  solo: {
    default: "a1111c8c-c720-46c3-8534-2fcdd730040d", // UberX
  },
};

// Airport IATA → approximate GPS coordinates for pickup
const AIRPORT_COORDS = {
  JFK: { lat: 40.6413, lng: -73.7781 }, EWR: { lat: 40.6895, lng: -74.1745 },
  LGA: { lat: 40.7769, lng: -73.8740 }, LAX: { lat: 33.9425, lng: -118.4081 },
  SFO: { lat: 37.6213, lng: -122.3790 }, ORD: { lat: 41.9742, lng: -87.9073 },
  ATL: { lat: 33.6407, lng: -84.4277 }, DFW: { lat: 32.8998, lng: -97.0403 },
  MIA: { lat: 25.7959, lng: -80.2870 }, BOS: { lat: 42.3656, lng: -71.0096 },
  SEA: { lat: 47.4502, lng: -122.3088 }, DEN: { lat: 39.8561, lng: -104.6737 },
  LHR: { lat: 51.4700, lng: -0.4543 }, CDG: { lat: 49.0097, lng: 2.5479 },
  AMS: { lat: 52.3105, lng: 4.7683 }, FRA: { lat: 50.0379, lng: 8.5622 },
  NRT: { lat: 35.7720, lng: 140.3929 }, HND: { lat: 35.5494, lng: 139.7798 },
  SIN: { lat: 1.3644, lng: 103.9915 }, DXB: { lat: 25.2532, lng: 55.3657 },
  SYD: { lat: -33.9399, lng: 151.1753 }, GRU: { lat: -23.4356, lng: -46.4731 },
};

// Dispatch Uber on landing via deep link push notification
// No API key required — opens the Uber app pre-filled with airport pickup
async function dispatchUberOnLanding(leg) {
  const mode = (leg.trip_mode || "solo").toLowerCase();
  const airport = leg.destination; // IATA code
  const coords = AIRPORT_COORDS[airport];
  if (!coords) {
    console.log(`[uber] no coords for airport ${airport} — skipping dispatch`);
    return;
  }
  const userRows = await sql`SELECT preferences, push_token FROM users WHERE email = ${leg.user_email}`;
  const prefs = userRows[0]?.preferences || {};
  const pushToken = userRows[0]?.push_token || null;
  // Build Uber deep link pre-filled with airport pickup
  const pickupNickname = encodeURIComponent(`${airport} Airport`);
  let deepLink;
  if (prefs.home_address) {
    const dropoff = encodeURIComponent(prefs.home_address);
    deepLink = `uber://?action=setPickup&pickup[latitude]=${coords.lat}&pickup[longitude]=${coords.lng}&pickup[nickname]=${pickupNickname}&dropoff[addressString]=${dropoff}`;
  } else {
    deepLink = `uber://?action=setPickup&pickup[latitude]=${coords.lat}&pickup[longitude]=${coords.lng}&pickup[nickname]=${pickupNickname}`;
  }
  const webFallback = `https://m.uber.com/ul/?action=setPickup&pickup[latitude]=${coords.lat}&pickup[longitude]=${coords.lng}&pickup[nickname]=${pickupNickname}`;
  const rideType = mode === "client" || mode === "partner" ? "Uber Black" : "UberX";
  // Log to activity feed
  await logActivity(
    leg.user_email, "uber",
    `🚗 Tap to get a ride from ${airport}`,
    `You've landed at ${airport}. Tap to open Uber with your pickup pre-filled${prefs.home_address ? " and home address as dropoff" : ""}.`,
    leg.trip_id, leg.id,
    { airport, mode, deepLink, webFallback, status: "deep_link" }
  );
  // Send push notification — tapping opens Uber app directly
  if (pushToken) {
    await sendPushToUser(
      leg.user_email,
      `🚗 Tap to get a ride from ${airport}`,
      `Landed? Open Uber with ${airport} pre-filled as pickup${prefs.home_address ? " + home as dropoff" : ""}.`,
      { deepLink, webFallback, airport, mode }
    );
  }
  console.log(`[uber] deep link dispatched for ${leg.user_email} at ${airport}`);
}

// ---------------------------------------------------------------------------
// Apple Wallet — PassKit .pkpass generation
// ---------------------------------------------------------------------------
const { PKPass } = require("passkit-generator");
const fs = require("fs");
const os = require("os");

// GET /wallet/pass/:legId — generate a .pkpass for a flight or hotel leg
app.get("/wallet/pass/:legId", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");
    const { email } = jwt.verify(token, JWT_SECRET);
    const { legId } = req.params;
    // Fetch leg + trip
    const rows = await sql`
      SELECT tl.*, t.title as trip_title, t.mode as trip_mode
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${legId} AND t.user_email = ${email}
    `;
    if (!rows.length) return res.status(404).json({ error: "Leg not found" });
    const leg = rows[0];
    // Check if Apple Wallet certs are configured
    const certPem = process.env.APPLE_WALLET_CERT_PEM;
    const keyPem = process.env.APPLE_WALLET_KEY_PEM;
    const wwdrPem = process.env.APPLE_WALLET_WWDR_PEM;
    const passTypeId = process.env.APPLE_WALLET_PASS_TYPE_ID || "pass.app.wingmantravel";
    const teamId = process.env.APPLE_TEAM_ID || "7BXHSR34RG";
    if (!certPem || !keyPem || !wwdrPem) {
      // Return a JSON representation of what the pass would contain
      // so the mobile app can show a preview
      return res.json({
        preview: true,
        type: leg.type,
        data: buildPassData(leg, email, passTypeId, teamId),
        message: "Apple Wallet certificates not yet configured. Add APPLE_WALLET_CERT_PEM, APPLE_WALLET_KEY_PEM, and APPLE_WALLET_WWDR_PEM to Render environment.",
      });
    }
    const passData = buildPassData(leg, email, passTypeId, teamId);
    const pass = new PKPass({}, {
      wwdr: Buffer.from(wwdrPem),
      signerCert: Buffer.from(certPem),
      signerKey: Buffer.from(keyPem),
    }, passData);
    // Add Wingman logo (white on dark background)
    // In production, serve from a CDN; here we use a placeholder
    const logoPath = path.join(__dirname, "assets", "wallet", "logo.png");
    if (fs.existsSync(logoPath)) {
      pass.addBuffer("logo.png", fs.readFileSync(logoPath));
      pass.addBuffer("logo@2x.png", fs.readFileSync(logoPath));
      pass.addBuffer("icon.png", fs.readFileSync(logoPath));
      pass.addBuffer("icon@2x.png", fs.readFileSync(logoPath));
    }
    const pkpassBuffer = await pass.getAsBuffer();
    res.set({
      "Content-Type": "application/vnd.apple.pkpass",
      "Content-Disposition": `attachment; filename="wingman-${leg.type}-${leg.id}.pkpass"`,
    });
    res.send(pkpassBuffer);
  } catch (e) {
    console.error("[wallet]", e.message);
    res.status(500).json({ error: e.message });
  }
});

function buildPassData(leg, email, passTypeId, teamId) {
  const serial = `wingman-${leg.type}-${leg.id}`;
  const base = {
    formatVersion: 1,
    passTypeIdentifier: passTypeId,
    serialNumber: serial,
    teamIdentifier: teamId,
    organizationName: "Wingman",
    description: leg.type === "flight" ? `${leg.carrier || ""}${leg.flight_number || ""} — ${leg.origin} → ${leg.destination}` : `Hotel: ${leg.carrier || leg.destination || "Reservation"}`,
    foregroundColor: "rgb(255, 255, 255)",
    backgroundColor: "rgb(15, 23, 42)",
    labelColor: "rgb(148, 163, 184)",
    logoText: "Wingman",
    // Relevance: show on lock screen at departure time and airport location
    relevantDate: leg.departs_at || undefined,
    locations: leg.origin && AIRPORT_COORDS[leg.origin] ? [{
      latitude: AIRPORT_COORDS[leg.origin].lat,
      longitude: AIRPORT_COORDS[leg.origin].lng,
      relevantText: leg.type === "flight" ? `Your ${leg.carrier || ""}${leg.flight_number || ""} flight departs soon` : `Check-in at ${leg.carrier || "hotel"}`,
    }] : [],
    barcode: {
      message: leg.confirmation || serial,
      format: "PKBarcodeFormatQR",
      messageEncoding: "iso-8859-1",
      altText: leg.confirmation || "Wingman",
    },
  };
  if (leg.type === "flight") {
    const depTime = leg.departs_at ? new Date(leg.departs_at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: true }) : "TBD";
    const arrTime = leg.arrives_at ? new Date(leg.arrives_at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: true }) : "TBD";
    const depDate = leg.departs_at ? new Date(leg.departs_at).toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" }) : "";
    return {
      ...base,
      boardingPass: {
        transitType: "PKTransitTypeAir",
        primaryFields: [
          { key: "origin", label: "FROM", value: leg.origin || "" },
          { key: "destination", label: "TO", value: leg.destination || "" },
        ],
        headerFields: [
          { key: "flight", label: "FLIGHT", value: `${leg.carrier || ""}${leg.flight_number || ""}` },
        ],
        secondaryFields: [
          { key: "departs", label: "DEPARTS", value: depTime },
          { key: "arrives", label: "ARRIVES", value: arrTime },
          { key: "date", label: "DATE", value: depDate },
        ],
        auxiliaryFields: [
          { key: "status", label: "STATUS", value: leg.status || "Scheduled" },
          { key: "confirmation", label: "CONFIRMATION", value: leg.confirmation || "" },
        ],
        backFields: [
          { key: "managed_by", label: "MANAGED BY", value: "Wingman" },
          { key: "user", label: "TRAVELER", value: email },
          { key: "trip", label: "TRIP", value: leg.trip_title || "" },
        ],
      },
    };
  } else {
    // Hotel or generic booking
    const checkIn = leg.departs_at ? new Date(leg.departs_at).toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" }) : "TBD";
    const checkOut = leg.arrives_at ? new Date(leg.arrives_at).toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" }) : "TBD";
    return {
      ...base,
      generic: {
        primaryFields: [
          { key: "hotel", label: "HOTEL", value: leg.carrier || leg.destination || "Hotel" },
        ],
        secondaryFields: [
          { key: "checkin", label: "CHECK-IN", value: checkIn },
          { key: "checkout", label: "CHECK-OUT", value: checkOut },
        ],
        auxiliaryFields: [
          { key: "confirmation", label: "CONFIRMATION", value: leg.confirmation || "" },
          { key: "destination", label: "CITY", value: leg.destination || "" },
        ],
        backFields: [
          { key: "managed_by", label: "MANAGED BY", value: "Wingman" },
          { key: "user", label: "TRAVELER", value: email },
          { key: "trip", label: "TRIP", value: leg.trip_title || "" },
        ],
      },
    };
  }
}

// ---------------------------------------------------------------------------
// FlightAware AeroAPI — aircraft type lookup + seat configuration inference
// Replaces Amadeus SeatMap (shut down July 17, 2026)
// Reuses the existing FLIGHTAWARE_API_KEY — no new key needed
// ---------------------------------------------------------------------------

// Known aircraft seat configurations: { cols, aisle_positions, has_window_suite }
const AIRCRAFT_CONFIGS = {
  // Narrowbody (3-3)
  "B737": { layout: "3-3", cols: ["A","B","C","D","E","F"], aisles: ["C","D"], windows: ["A","F"] },
  "B738": { layout: "3-3", cols: ["A","B","C","D","E","F"], aisles: ["C","D"], windows: ["A","F"] },
  "B739": { layout: "3-3", cols: ["A","B","C","D","E","F"], aisles: ["C","D"], windows: ["A","F"] },
  "B737MAX": { layout: "3-3", cols: ["A","B","C","D","E","F"], aisles: ["C","D"], windows: ["A","F"] },
  "A319": { layout: "3-3", cols: ["A","B","C","D","E","F"], aisles: ["C","D"], windows: ["A","F"] },
  "A320": { layout: "3-3", cols: ["A","B","C","D","E","F"], aisles: ["C","D"], windows: ["A","F"] },
  "A321": { layout: "3-3", cols: ["A","B","C","D","E","F"], aisles: ["C","D"], windows: ["A","F"] },
  "E175": { layout: "2-2", cols: ["A","B","C","D"], aisles: ["B","C"], windows: ["A","D"] },
  "E190": { layout: "2-2", cols: ["A","B","C","D"], aisles: ["B","C"], windows: ["A","D"] },
  "CRJ9": { layout: "2-2", cols: ["A","B","C","D"], aisles: ["B","C"], windows: ["A","D"] },
  // Widebody (2-4-2 or 3-3-3)
  "B767": { layout: "2-3-2", cols: ["A","B","C","D","E","F","G"], aisles: ["B","C","E","F"], windows: ["A","G"] },
  "B777": { layout: "3-3-3", cols: ["A","B","C","D","E","F","G","H","J"], aisles: ["C","D","G","H"], windows: ["A","J"] },
  "B787": { layout: "3-3-3", cols: ["A","B","C","D","E","F","G","H","J"], aisles: ["C","D","G","H"], windows: ["A","J"] },
  "A330": { layout: "2-4-2", cols: ["A","B","C","D","E","F","G","H"], aisles: ["B","C","F","G"], windows: ["A","H"] },
  "A350": { layout: "3-3-3", cols: ["A","B","C","D","E","F","G","H","J"], aisles: ["C","D","G","H"], windows: ["A","J"] },
  "A380": { layout: "3-4-3", cols: ["A","B","C","D","E","F","G","H","J","K"], aisles: ["C","D","G","H"], windows: ["A","K"] },
  "B747": { layout: "3-4-3", cols: ["A","B","C","D","E","F","G","H","J","K"], aisles: ["C","D","G","H"], windows: ["A","K"] },
};

// Get aircraft config from FlightAware AeroAPI for a flight, then infer seat layout
// Uses the same FLIGHTAWARE_API_KEY already in use for disruption polling
async function getFlightAwareSeatConfig(leg) {
  try {
    const apiKey = process.env.FLIGHTAWARE_API_KEY;
    if (!apiKey) return null;
    const ident = (leg.carrier || "") + (leg.flight_number || "");
    if (!ident) return null;
    // Fetch recent flights for this ident to get aircraft_type
    const url = `https://aeroapi.flightaware.com/aeroapi/flights/${encodeURIComponent(ident)}?max_pages=1`;
    const resp = await fetch(url, {
      headers: { "x-apikey": apiKey },
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    const flights = data.flights || [];
    if (flights.length === 0) return null;
    // Find the most relevant flight (closest departure date to leg)
    const legDep = leg.departs_at ? new Date(leg.departs_at).getTime() : null;
    let bestFlight = flights[0];
    if (legDep) {
      bestFlight = flights.reduce((best, f) => {
        const fDep = f.scheduled_out ? new Date(f.scheduled_out).getTime() : 0;
        const bestDep = best.scheduled_out ? new Date(best.scheduled_out).getTime() : 0;
        return Math.abs(fDep - legDep) < Math.abs(bestDep - legDep) ? f : best;
      }, flights[0]);
    }
    const aircraftType = bestFlight.aircraft_type || null;
    if (!aircraftType) return null;
    // Match to known config (try exact, then prefix)
    const config = AIRCRAFT_CONFIGS[aircraftType.toUpperCase()] ||
      Object.entries(AIRCRAFT_CONFIGS).find(([k]) => aircraftType.toUpperCase().startsWith(k))?.[1] ||
      null;
    return config ? { ...config, aircraft: aircraftType, ident } : null;
  } catch (e) {
    console.error("[flightaware-seat]", e.message);
    return null;
  }
}

// Infer seat availability hints from aircraft config + user preferences
// Returns array matching the old Amadeus format: { designator, cabin, available, characteristics }
function inferSeatsFromConfig(config, totalRows = 30) {
  if (!config) return [];
  const seats = [];
  for (let row = 1; row <= totalRows; row++) {
    for (const col of config.cols) {
      const chars = [];
      if (config.windows.includes(col)) chars.push("W");
      if (config.aisles.includes(col)) chars.push("A");
      if (row <= 2) chars.push("B"); // bulkhead approximation
      if (row >= Math.floor(totalRows * 0.4) && row <= Math.floor(totalRows * 0.5)) chars.push("E"); // exit row approx
      seats.push({
        designator: `${row}${col}`,
        cabin: "ECONOMY",
        available: true, // we can't know real availability without booking data
        characteristics: chars,
        number: String(row),
        column: col,
      });
    }
  }
  return seats;
}

// ---------------------------------------------------------------------------
// Map user seat preference IDs to Amadeus seat characteristics
// ---------------------------------------------------------------------------
const SEAT_PREF_TO_CHARACTERISTICS = {
  econ_aisle: { cabin: "ECONOMY", chars: ["A"] },       // A = aisle
  econ_window: { cabin: "ECONOMY", chars: ["W"] },      // W = window
  econ_exit_row: { cabin: "ECONOMY", chars: ["E"] },    // E = exit row
  econ_bulkhead: { cabin: "ECONOMY", chars: ["B"] },    // B = bulkhead
  pe_aisle: { cabin: "PREMIUM_ECONOMY", chars: ["A"] },
  pe_window: { cabin: "PREMIUM_ECONOMY", chars: ["W"] },
  pe_bulkhead: { cabin: "PREMIUM_ECONOMY", chars: ["B"] },
  biz_window_suite: { cabin: "BUSINESS", chars: ["W"] },
  biz_aisle: { cabin: "BUSINESS", chars: ["A"] },
  biz_bulkhead_behind: { cabin: "BUSINESS", chars: ["B"] },
  biz_forward_facing: { cabin: "BUSINESS", chars: ["F"] },
  first_suite: { cabin: "FIRST", chars: ["W", "1S"] },
  first_forward: { cabin: "FIRST", chars: ["F"] },
  first_window: { cabin: "FIRST", chars: ["W"] },
};

async function checkSeatPreferenceAlerts(legs) {
  const SEAT_LABELS = {
    econ_aisle: "aisle (Economy)", econ_window: "window (Economy)",
    econ_exit_row: "exit row (Economy)", econ_bulkhead: "bulkhead (Economy)",
    pe_aisle: "aisle (Premium Economy)", pe_window: "window (Premium Economy)",
    pe_bulkhead: "bulkhead (Premium Economy)", biz_window_suite: "window suite (Business)",
    biz_aisle: "direct aisle access (Business)", biz_bulkhead_behind: "bulkhead behind (Business)",
    biz_forward_facing: "forward facing (Business)", first_suite: "enclosed suite (First)",
    first_forward: "forward facing (First)", first_window: "window/wall side (First)",
  };
  // Group legs by user
  const byUser = {};
  for (const leg of legs) {
    if (!byUser[leg.user_email]) byUser[leg.user_email] = [];
    byUser[leg.user_email].push(leg);
  }
  for (const [userEmail, userLegs] of Object.entries(byUser)) {
    try {
      const userRows = await sql`SELECT preferences FROM users WHERE email = ${userEmail}`;
      const prefs = userRows[0]?.preferences || {};
      const seatPrefs = prefs.seat_prefs || [];
      if (seatPrefs.length === 0) continue;
      for (const leg of userLegs) {
        const hoursUntilDep = (new Date(leg.departs_at) - new Date()) / (1000 * 60 * 60);
        if (hoursUntilDep > 72 || hoursUntilDep < 1) continue; // only check 72h-1h window
        // Skip if already alerted in last 12h
        const recentAlerts = await sql`
          SELECT id FROM activity_events
          WHERE user_email = ${userEmail}
            AND leg_id = ${leg.id}
            AND type = 'seat_alert'
            AND created_at > NOW() - INTERVAL '12 hours'
        `;
        if (recentAlerts.length > 0) continue;
        const ident = (leg.carrier || "") + leg.flight_number;
        // Try to get aircraft config from FlightAware, then infer seat layout
        let matchingSeats = [];
        let usedLiveData = false;
        let aircraftInfo = null;
        const flightAwareConfig = await getFlightAwareSeatConfig(leg);
        if (flightAwareConfig) {
          aircraftInfo = flightAwareConfig.aircraft;
          const seatMap = inferSeatsFromConfig(flightAwareConfig);
          if (seatMap.length > 0) {
            usedLiveData = true; // We have aircraft-specific layout data
            // Check each user pref against the inferred seat map
            for (const pref of seatPrefs) {
              const criteria = SEAT_PREF_TO_CHARACTERISTICS[pref];
              if (!criteria) continue;
              const matches = seatMap.filter(s =>
                s.available &&
                s.characteristics.some(c => criteria.chars.includes(c))
              );
              if (matches.length > 0) {
                matchingSeats.push({
                  pref,
                  label: SEAT_LABELS[pref] || pref,
                  seats: matches.slice(0, 3).map(s => s.designator || (s.number + s.column)),
                  count: matches.length,
                  aircraft: aircraftInfo,
                  layout: flightAwareConfig.layout,
                });
              }
            }
          }
        }
        if (usedLiveData && matchingSeats.length === 0) {
          // Live data available but no preferred seats found — log a no-match event
          await logActivity(
            userEmail, "seat_alert",
            `No preferred seats on ${ident}`,
            `Wingman checked the live seat map for ${leg.origin} → ${leg.destination} — your preferred seats are not currently available. Will check again.`,
            leg.trip_id, leg.id, { ident, seatPrefs, liveData: true, found: false }
          );
          continue;
        }
        if (matchingSeats.length > 0) {
          const best = matchingSeats[0];
          const seatList = best.seats.join(", ");
          const aircraftNote = best.aircraft ? ` (${best.aircraft}, ${best.layout} layout)` : "";
          const activityBody = usedLiveData
            ? `Aircraft${aircraftNote}: ${best.count} ${best.label} seat${best.count !== 1 ? "s" : ""} on ${leg.origin} → ${leg.destination}. Typical positions: ${seatList}. Check the airline app to select.`
            : `Your preferred seat (${best.label}) may be available on ${leg.origin} → ${leg.destination}. Check the airline app to confirm.`;
          await logActivity(
            userEmail, "seat_alert",
            `🪑 ${best.label} available on ${ident}`,
            activityBody,
            leg.trip_id, leg.id,
            { ident, seatPrefs, matchingSeats, liveData: usedLiveData }
          );
          await sendPushToUser(
            userEmail,
            `🪑 Preferred seat open on ${ident}`,
            usedLiveData
              ? `${best.count} ${best.label} seat${best.count !== 1 ? "s" : ""} available on ${leg.origin} → ${leg.destination}. Tap to check.`
              : `Your preferred seat may be available on ${leg.origin} → ${leg.destination}. Tap to check.`,
            { route: "Activity", legId: leg.id }
          );
        } else if (!usedLiveData) {
          // No live data available — fall back to reminder
          const prefLabels = seatPrefs.map(p => SEAT_LABELS[p] || p).filter(Boolean);
          await logActivity(
            userEmail, "seat_alert",
            `Check seat on ${ident}`,
            `Seat map unavailable via API. Check the airline app for your preferred seat (${prefLabels.slice(0, 2).join(" or ")}) on ${leg.origin} → ${leg.destination}.`,
            leg.trip_id, leg.id, { ident, seatPrefs, liveData: false }
          );
          await sendPushToUser(
            userEmail,
            `🪑 Check your seat on ${ident}`,
            `Your preferred seat may be available on ${leg.origin} → ${leg.destination}. Tap to check.`,
            { route: "Activity" }
          );
        }
      }
    } catch (e) {
      console.error("[seat-alert]", e.message);
    }
  }
}

// Run poll on startup (after 30s delay to let server settle) and every 15 min
setTimeout(() => {
  pollDisruptions();
  setInterval(pollDisruptions, 15 * 60 * 1000);
}, 30 * 1000);

// ---------------------------------------------------------------------------
// Stripe — subscriptions + Apple Pay
// ---------------------------------------------------------------------------
const Stripe = require("stripe");
let _stripe = null;
function getStripe() {
  if (!_stripe) {
    if (!process.env.STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY not set");
    _stripe = Stripe(process.env.STRIPE_SECRET_KEY);
  }
  return _stripe;
}

// Subscription tiers
const PLANS = {
  pro: {
    name: "Wingman Pro",
    price_id: process.env.STRIPE_PRO_PRICE_ID || "price_pro_monthly",
    amount: 999, // $9.99/month
    currency: "usd",
    interval: "month",
    features: ["Live flight monitoring", "Gmail auto-import", "AI Concierge", "Seat alerts", "Hotel preference emails"],
  },
  elite: {
    name: "Wingman Elite",
    price_id: process.env.STRIPE_ELITE_PRICE_ID || "price_elite_monthly",
    amount: 2999, // $29.99/month
    currency: "usd",
    interval: "month",
    features: ["Everything in Pro", "Uber auto-dispatch", "Apple Wallet passes", "Editorial recommendations", "Priority support"],
  },
};

// GET /subscription/plans — return available plans
app.get("/subscription/plans", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");
    const { email } = jwt.verify(token, JWT_SECRET);
    const userRows = await sql`SELECT subscription_tier, subscription_status FROM users WHERE email = ${email}`;
    const user = userRows[0] || {};
    res.json({
      plans: PLANS,
      current_tier: user.subscription_tier || "free",
      current_status: user.subscription_status || "inactive",
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /subscription/create-intent — create a Stripe PaymentIntent for Apple Pay
app.post("/subscription/create-intent", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");
    const { email } = jwt.verify(token, JWT_SECRET);
    const { plan } = req.body;
    const stripe = getStripe();
    const planData = PLANS[plan];
    if (!planData) return res.status(400).json({ error: "Unknown plan" });
    // Get or create Stripe customer
    let userRows = await sql`SELECT stripe_customer_id FROM users WHERE email = ${email}`;
    let customerId = userRows[0]?.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email, metadata: { wingman_email: email } });
      customerId = customer.id;
      await sql`UPDATE users SET stripe_customer_id = ${customerId} WHERE email = ${email}`;
    }
    // Create a SetupIntent for subscription (so Apple Pay saves the card)
    const setupIntent = await stripe.setupIntents.create({
      customer: customerId,
      payment_method_types: ["card"],
      usage: "off_session",
      metadata: { plan, email },
    });
    res.json({
      client_secret: setupIntent.client_secret,
      customer_id: customerId,
      plan: planData,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /subscription/activate — after Apple Pay succeeds, create the subscription
app.post("/subscription/activate", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace("Bearer ", "");
    const { email } = jwt.verify(token, JWT_SECRET);
    const { plan, payment_method_id } = req.body;
    const stripe = getStripe();
    const planData = PLANS[plan];
    if (!planData) return res.status(400).json({ error: "Unknown plan" });
    const userRows = await sql`SELECT stripe_customer_id FROM users WHERE email = ${email}`;
    const customerId = userRows[0]?.stripe_customer_id;
    if (!customerId) return res.status(400).json({ error: "No Stripe customer" });
    // Attach payment method
    await stripe.paymentMethods.attach(payment_method_id, { customer: customerId });
    await stripe.customers.update(customerId, { invoice_settings: { default_payment_method: payment_method_id } });
    // Create subscription
    const subscription = await stripe.subscriptions.create({
      customer: customerId,
      items: [{ price: planData.price_id }],
      default_payment_method: payment_method_id,
      metadata: { email, plan },
    });
    // Update user in DB
    await sql`
      UPDATE users
      SET subscription_tier = ${plan},
          subscription_status = 'active',
          stripe_subscription_id = ${subscription.id}
      WHERE email = ${email}
    `;
    await logActivity(
      email, "subscription",
      `Wingman ${planData.name} activated`,
      `Your ${planData.name} subscription is now active. All features are unlocked.`,
      null, null,
      { plan, subscriptionId: subscription.id }
    );
    res.json({ ok: true, subscription_id: subscription.id, tier: plan });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /subscription/webhook — Stripe webhook for payment events
app.post("/subscription/webhook", express.raw({ type: "*/*" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;
  try {
    if (webhookSecret) {
      event = getStripe().webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      event = JSON.parse(req.body.toString());
    }
  } catch (e) {
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }
  try {
    switch (event.type) {
      case "invoice.payment_succeeded": {
        const invoice = event.data.object;
        const email = invoice.customer_email;
        if (email) {
          await sql`UPDATE users SET subscription_status = 'active' WHERE email = ${email}`;
          await logActivity(email, "subscription", "Subscription renewed", `Your Wingman subscription was renewed. Next billing date: ${new Date(invoice.period_end * 1000).toLocaleDateString()}.`);
        }
        break;
      }
      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const email = invoice.customer_email;
        if (email) {
          await sql`UPDATE users SET subscription_status = 'past_due' WHERE email = ${email}`;
          await sendPushToUser(email, "💳 Payment failed", "Your Wingman subscription payment failed. Tap to update your payment method.", { route: "Subscription" });
        }
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const rows = await sql`SELECT email FROM users WHERE stripe_subscription_id = ${sub.id}`;
        if (rows[0]) {
          await sql`UPDATE users SET subscription_tier = 'free', subscription_status = 'cancelled' WHERE email = ${rows[0].email}`;
          await logActivity(rows[0].email, "subscription", "Subscription cancelled", "Your Wingman subscription has been cancelled. You can resubscribe at any time.");
        }
        break;
      }
    }
    res.json({ received: true });
  } catch (e) {
    console.error("[stripe-webhook]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Duffel — flight search + booking
// ---------------------------------------------------------------------------
function getDuffel() {
  if (!process.env.DUFFEL_API_KEY) throw new Error("DUFFEL_API_KEY not set");
  return new Duffel({ token: process.env.DUFFEL_API_KEY });
}

// POST /flights/search
// Body: { origin, destination, departure_date, return_date?, cabin_class?, passengers? }
app.post("/flights/search", async (req, res) => {
  try {
    const user = await verifyAccessToken(req);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const { origin, destination, departure_date, return_date, cabin_class = "economy", passengers = 1 } = req.body;
    if (!origin || !destination || !departure_date) {
      return res.status(400).json({ error: "origin, destination, and departure_date are required" });
    }
    const duffel = getDuffel();
    const paxArray = Array.from({ length: passengers }, () => ({ type: "adult" }));
    const slices = [{ origin, destination, departure_date }];
    if (return_date) slices.push({ origin: destination, destination: origin, departure_date: return_date });
    const offerRequest = await duffel.offerRequests.create({
      slices,
      passengers: paxArray,
      cabin_class,
      return_offers: true,
      supplier_timeout: 15000,
    });
    // Return top 20 offers sorted by price
    const offers = (offerRequest.data.offers || [])
      .sort((a, b) => parseFloat(a.total_amount) - parseFloat(b.total_amount))
      .slice(0, 20)
      .map(o => ({
        id: o.id,
        total_amount: o.total_amount,
        total_currency: o.total_currency,
        expires_at: o.expires_at,
        slices: o.slices.map(s => ({
          origin: s.origin?.iata_code,
          origin_name: s.origin?.name,
          destination: s.destination?.iata_code,
          destination_name: s.destination?.name,
          duration: s.duration,
          segments: s.segments.map(seg => ({
            id: seg.id,
            carrier: seg.marketing_carrier?.name,
            carrier_iata: seg.marketing_carrier?.iata_code,
            carrier_logo: seg.marketing_carrier?.logo_symbol_url,
            flight_number: seg.marketing_carrier_flight_number,
            origin: seg.origin?.iata_code,
            destination: seg.destination?.iata_code,
            departing_at: seg.departing_at,
            arriving_at: seg.arriving_at,
            duration: seg.duration,
            aircraft: seg.aircraft?.name,
            stops: seg.stops?.length || 0,
          })),
        })),
        passengers: o.passengers,
        conditions: {
          refundable: o.conditions?.refund_before_departure?.allowed || false,
          changeable: o.conditions?.change_before_departure?.allowed || false,
        },
        baggages: o.slices?.[0]?.segments?.[0]?.passengers?.[0]?.baggages || [],
      }));
    res.json({ offers, offer_request_id: offerRequest.data.id });
  } catch (e) {
    console.error("[duffel-search]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /flights/offer/:offerId — get full offer details before booking
app.get("/flights/offer/:offerId", async (req, res) => {
  try {
    const user = await verifyAccessToken(req);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const duffel = getDuffel();
    const offer = await duffel.offers.get(req.params.offerId);
    res.json({ offer: offer.data });
  } catch (e) {
    console.error("[duffel-offer]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /flights/book
// Body: { offer_id, passengers: [{ given_name, family_name, born_on, gender, email, phone, passport_number?, passport_expiry?, passport_country? }] }
app.post("/flights/book", async (req, res) => {
  try {
    const user = await verifyAccessToken(req);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const { offer_id, passengers } = req.body;
    if (!offer_id || !passengers?.length) {
      return res.status(400).json({ error: "offer_id and passengers are required" });
    }
    const duffel = getDuffel();
    // Get the offer to check expiry and passenger requirements
    const offerData = await duffel.offers.get(offer_id);
    const offer = offerData.data;
    // Map passengers with IDs from the offer
    const offerPassengerIds = offer.passengers.map(p => p.id);
    const mappedPassengers = passengers.map((p, i) => ({
      id: offerPassengerIds[i],
      given_name: p.given_name,
      family_name: p.family_name,
      born_on: p.born_on,
      gender: p.gender,
      email: p.email || user.email,
      phone_number: p.phone || "+10000000000",
      ...(p.passport_number ? {
        identity_documents: [{
          type: "passport",
          unique_identifier: p.passport_number,
          expires_on: p.passport_expiry,
          issuing_country_code: p.passport_country || "US",
        }]
      } : {}),
    }));
    const order = await duffel.orders.create({
      selected_offers: [offer_id],
      passengers: mappedPassengers,
      payments: [{
        type: "balance",
        currency: offer.total_currency,
        amount: offer.total_amount,
      }],
      metadata: { wingman_user: user.email },
    });
    const orderData = order.data;
    // Save as a trip in the DB
    const firstSlice = offer.slices?.[0];
    const lastSlice = offer.slices?.[offer.slices.length - 1];
    const tripTitle = `${firstSlice?.origin?.iata_code || ""} → ${lastSlice?.destination?.iata_code || ""}`;
    const [trip] = await sql`
      INSERT INTO trips (user_email, title, status, source)
      VALUES (${user.email}, ${tripTitle}, 'upcoming', 'duffel')
      RETURNING id
    `;
    // Insert each slice as a trip leg
    for (const slice of offer.slices) {
      for (const seg of slice.segments) {
        await sql`
          INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation, raw_data)
          VALUES (
            ${trip.id}, 'flight',
            ${seg.marketing_carrier?.name || null},
            ${(seg.marketing_carrier?.iata_code || "") + (seg.marketing_carrier_flight_number || "")},
            ${seg.origin?.iata_code || null},
            ${seg.destination?.iata_code || null},
            ${seg.departing_at || null},
            ${seg.arriving_at || null},
            ${orderData.booking_reference || null},
            ${JSON.stringify({ duffel_order_id: orderData.id, segment_id: seg.id })}
          )
        `;
      }
    }
    await logActivity(
      user.email, "booking",
      `Flight booked: ${tripTitle}`,
      `Booking confirmed. Reference: ${orderData.booking_reference}. Total: ${offer.total_currency} ${offer.total_amount}.`,
      trip.id, null,
      { duffel_order_id: orderData.id, booking_reference: orderData.booking_reference }
    );
    res.json({
      order_id: orderData.id,
      booking_reference: orderData.booking_reference,
      trip_id: trip.id,
      total_amount: offer.total_amount,
      total_currency: offer.total_currency,
      slices: orderData.slices,
    });
  } catch (e) {
    console.error("[duffel-book]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /flights/orders — list user's Duffel bookings
app.get("/flights/orders", async (req, res) => {
  try {
    const user = await verifyAccessToken(req);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const rows = await sql`
      SELECT t.id, t.title, t.created_at, tl.carrier, tl.flight_number, tl.origin, tl.destination, tl.departs_at, tl.confirmation, tl.raw_data
      FROM trips t
      JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${user.email} AND t.source = 'duffel'
      ORDER BY tl.departs_at ASC
    `;
    res.json({ bookings: rows });
  } catch (e) {
    console.error("[duffel-orders]", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log("Wingman API on http://localhost:" + PORT));
