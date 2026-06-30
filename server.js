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
// Reusable JWT auth middleware
// ---------------------------------------------------------------------------
function auth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.email = payload.email;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---------------------------------------------------------------------------
// External service clients
// ---------------------------------------------------------------------------
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});
// Fallback placeholder keeps server from crashing at startup when env vars aren't set yet
const sql = neon(process.env.DATABASE_URL || "postgresql://placeholder:placeholder@placeholder/placeholder");
const resend = new Resend(process.env.RESEND_API_KEY || "re_placeholder");
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
    // Add columns to existing users tables (idempotent)
    // ── Ensure all users columns exist (safe for older production schemas) ──
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS preferences JSONB DEFAULT '{}'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS taste_profile JSONB DEFAULT '{}'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_tier TEXT DEFAULT 'free'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status TEXT DEFAULT 'inactive'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_customer_id TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS stripe_subscription_id TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS locale TEXT DEFAULT 'en'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS currency TEXT DEFAULT 'USD'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS weather_alerts BOOLEAN DEFAULT true`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS price_alerts BOOLEAN DEFAULT true`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_hours BOOLEAN DEFAULT true`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_weekly_digest TIMESTAMPTZ`;
    // ── Wingman Points ────────────────────────────────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS wingman_points (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
        balance INTEGER NOT NULL DEFAULT 0,
        tier TEXT NOT NULL DEFAULT 'explorer',
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email)
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS wingman_points_events (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        action TEXT NOT NULL,
        points INTEGER NOT NULL,
        description TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_points_events_user ON wingman_points_events(user_email, created_at DESC)`;
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
    // Concierge threads (persistent memory per trip or general)
    await sql`
      CREATE TABLE IF NOT EXISTS concierge_threads (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        trip_id INTEGER REFERENCES trips(id) ON DELETE CASCADE,
        messages JSONB DEFAULT '[]',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_concierge_thread ON concierge_threads(user_email, COALESCE(trip_id, -1))`;
    // Trip share tokens
    await sql`
      CREATE TABLE IF NOT EXISTS trip_shares (
        id SERIAL PRIMARY KEY,
        trip_id INTEGER REFERENCES trips(id) ON DELETE CASCADE,
        user_email TEXT NOT NULL,
        share_token TEXT UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // Pre-departure push dedup log
    await sql`
      CREATE TABLE IF NOT EXISTS departure_push_log (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        leg_id INTEGER NOT NULL,
        push_type TEXT NOT NULL,
        sent_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, leg_id, push_type)
      )
    `;
    // Post-trip debrief push dedup log
    await sql`
      CREATE TABLE IF NOT EXISTS debrief_push_log (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        trip_id INTEGER NOT NULL,
        sent_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, trip_id)
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS trip_companions (
        id SERIAL PRIMARY KEY,
        trip_id INTEGER NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
        inviter_email TEXT NOT NULL,
        invitee_email TEXT,
        invite_token TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS points_expiry_log (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        program TEXT NOT NULL,
        sent_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, program)
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS hotel_monitor_log (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        leg_id INTEGER NOT NULL,
        sent_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, leg_id)
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS destination_intel (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        destination TEXT NOT NULL,
        intel JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, destination)
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS compensation_claims (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        trip_id INTEGER REFERENCES trips(id) ON DELETE CASCADE,
        leg_id INTEGER,
        flight_ident TEXT,
        regulation TEXT NOT NULL DEFAULT 'EU261',
        delay_minutes INTEGER,
        amount_eur INTEGER,
        status TEXT NOT NULL DEFAULT 'draft',
        airline_ref TEXT,
        submitted_at TIMESTAMPTZ,
        resolved_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS upgrade_bids (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        trip_id INTEGER REFERENCES trips(id) ON DELETE CASCADE,
        leg_id INTEGER,
        flight_ident TEXT NOT NULL,
        cabin_target TEXT NOT NULL DEFAULT 'business',
        max_points INTEGER,
        max_cash_usd INTEGER,
        status TEXT NOT NULL DEFAULT 'watching',
        offer_found_at TIMESTAMPTZ,
        offer_details JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS booking_imports (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        source TEXT NOT NULL DEFAULT 'gmail',
        raw_subject TEXT,
        parsed JSONB,
        trip_id INTEGER REFERENCES trips(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // ── Revealed-preference tables ─────────────────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS hotel_affinity (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        property_name TEXT NOT NULL,
        brand TEXT,
        city TEXT,
        country TEXT,
        tier TEXT,
        attributes JSONB DEFAULT '{}',
        stay_count INTEGER DEFAULT 1,
        last_stayed TIMESTAMPTZ,
        source TEXT DEFAULT 'booking_import',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, property_name)
      )
    `;
    await sql`
      CREATE TABLE IF NOT EXISTS restaurant_affinity (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        restaurant_name TEXT NOT NULL,
        cuisine TEXT,
        city TEXT,
        country TEXT,
        tier TEXT,
        attributes JSONB DEFAULT '{}',
        visit_count INTEGER DEFAULT 1,
        last_visited TIMESTAMPTZ,
        source TEXT DEFAULT 'manual',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, restaurant_name)
      )
    `;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS revealed_preferences JSONB DEFAULT '{}'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS apple_sub TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`;
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

// ── Revealed-preference: extract hotel DNA and store affinity ─────────────────
async function extractAndStoreHotelAffinity(userEmail, parsedBooking) {
  try {
    const hotelName = parsedBooking.carrier || parsedBooking.hotel_name;
    if (!hotelName) return;
    const city = parsedBooking.destination || null;
    // Use Claude to extract brand, tier, and attributes from the hotel name
    const prompt = `You are a hotel intelligence engine. Given this hotel name and city, extract structured data.
Hotel: "${hotelName}"
City: "${city || 'unknown'}"
Return ONLY valid JSON:
{
  "brand": "parent brand or chain (e.g. Hoxton, Fontenille, Marriott, Hyatt, independent) or null",
  "tier": "luxury|upper_upscale|upscale|boutique|budget",
  "country": "country name or null",
  "attributes": {
    "design_forward": true/false,
    "independent": true/false,
    "lifestyle_brand": true/false,
    "historic_property": true/false,
    "urban": true/false,
    "resort": true/false,
    "small_luxury": true/false
  }
}`;
    const resp = await getAnthropic().messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 300,
      messages: [{ role: "user", content: prompt }],
    });
    let meta;
    try {
      const raw = resp.content[0].text.trim().replace(/^```json\n?/, "").replace(/\n?```$/, "").trim();
      meta = JSON.parse(raw);
    } catch { return; }
    // Upsert into hotel_affinity
    await sql`
      INSERT INTO hotel_affinity (user_email, property_name, brand, city, country, tier, attributes, stay_count, last_stayed, source)
      VALUES (
        ${userEmail}, ${hotelName}, ${meta.brand || null}, ${city}, ${meta.country || null},
        ${meta.tier || null}, ${JSON.stringify(meta.attributes || {})}, 1,
        ${parsedBooking.departs_at || new Date().toISOString()}, 'booking_import'
      )
      ON CONFLICT (user_email, property_name)
      DO UPDATE SET
        stay_count = hotel_affinity.stay_count + 1,
        last_stayed = EXCLUDED.last_stayed,
        brand = COALESCE(EXCLUDED.brand, hotel_affinity.brand),
        tier = COALESCE(EXCLUDED.tier, hotel_affinity.tier),
        attributes = hotel_affinity.attributes || EXCLUDED.attributes
    `;
    console.log("[hotel-affinity] stored:", hotelName, "for", userEmail);
  } catch (e) {
    console.error("[hotel-affinity] error:", e.message);
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
        from: "Wingman <noreply@welcometothefight.club>",
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
        from: "Wingman <noreply@welcometothefight.club>",
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

// ─── Wingman Points ────────────────────────────────────────────────────────────
// Earn rules: each action can only award points once (deduped by action key)
const POINT_RULES = {
  signup:           { pts: 200, desc: "Joined Wingman" },
  gmail_connected:  { pts: 300, desc: "Connected Gmail" },
  trip_added:       { pts: 100, desc: "Added a trip" },
  profile_complete: { pts: 150, desc: "Completed profile" },
  push_enabled:     { pts: 100, desc: "Enabled push notifications" },
  concierge_first:  { pts: 50,  desc: "First concierge message" },
  loyalty_connected:{ pts: 150, desc: "Connected loyalty account" },
  trip_completed:   { pts: 75,  desc: "Completed a trip" },
  gmail_trip_import:{ pts: 125, desc: "Trip imported from Gmail" },
};

// Tier thresholds
function getTier(balance) {
  if (balance >= 2000) return "elite";
  if (balance >= 800)  return "navigator";
  if (balance >= 300)  return "flyer";
  return "explorer";
}

// Award points (idempotent by action key — pass unique key for repeatable actions)
async function awardPoints(email, action, dedupKey = null) {
  const rule = POINT_RULES[action];
  if (!rule) return;
  const key = dedupKey || action;
  try {
    // Check if already awarded this key
    const existing = await sql`
      SELECT id FROM wingman_points_events
      WHERE user_email = ${email} AND action = ${key}
      LIMIT 1
    `;
    if (existing.length > 0) return; // already awarded
    // Insert event
    await sql`
      INSERT INTO wingman_points_events (user_email, action, points, description)
      VALUES (${email}, ${key}, ${rule.pts}, ${rule.desc})
    `;
    // Upsert balance
    const rows = await sql`
      INSERT INTO wingman_points (user_email, balance, tier)
      VALUES (${email}, ${rule.pts}, ${getTier(rule.pts)})
      ON CONFLICT (user_email) DO UPDATE
        SET balance = wingman_points.balance + ${rule.pts},
            tier = CASE
              WHEN wingman_points.balance + ${rule.pts} >= 2000 THEN 'elite'
              WHEN wingman_points.balance + ${rule.pts} >= 800  THEN 'navigator'
              WHEN wingman_points.balance + ${rule.pts} >= 300  THEN 'flyer'
              ELSE 'explorer'
            END,
            updated_at = NOW()
      RETURNING balance, tier
    `;
    return rows[0];
  } catch (e) {
    console.error("[points] award error:", e.message);
  }
}

// GET /points — current balance, tier, recent events
app.get("/points", auth, async (req, res) => {
  try {
    const email = req.email;
    const [balRows, events] = await Promise.all([
      sql`SELECT balance, tier FROM wingman_points WHERE user_email = ${email}`,
      sql`SELECT action, points, description, created_at FROM wingman_points_events
          WHERE user_email = ${email} ORDER BY created_at DESC LIMIT 20`,
    ]);
    const balance = balRows[0]?.balance || 0;
    const tier    = balRows[0]?.tier    || getTier(balance);
    // Compute progress to next tier
    const TIERS = [
      { name: "explorer",  min: 0,    max: 299,  next: "flyer",     nextMin: 300  },
      { name: "flyer",     min: 300,  max: 799,  next: "navigator", nextMin: 800  },
      { name: "navigator", min: 800,  max: 1999, next: "elite",     nextMin: 2000 },
      { name: "elite",     min: 2000, max: null, next: null,        nextMin: null },
    ];
    const tierInfo = TIERS.find(t => t.name === tier) || TIERS[0];
    const pct = tierInfo.nextMin
      ? Math.round(((balance - tierInfo.min) / (tierInfo.nextMin - tierInfo.min)) * 100)
      : 100;
    res.json({
      ok: true,
      balance,
      tier,
      next_tier: tierInfo.next,
      points_to_next: tierInfo.nextMin ? Math.max(0, tierInfo.nextMin - balance) : 0,
      progress_pct: Math.min(100, pct),
      events: events.map(e => ({
        action: e.action,
        points: e.points,
        description: e.description,
        date: e.created_at,
      })),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /points/award — internal endpoint to award points from other flows
// Also called by the app when user completes an action
app.post("/points/award", auth, async (req, res) => {
  try {
    const email = req.email;
    const { action, dedup_key } = req.body || {};
    if (!action || !POINT_RULES[action]) return res.status(400).json({ error: "unknown action" });
    const result = await awardPoints(email, action, dedup_key);
    res.json({ ok: true, awarded: !!result, result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /points/redeem — redeem Wingman Points for a perk
app.post("/points/redeem", auth, async (req, res) => {
  try {
    const email = req.email;
    const { perk_id } = req.body || {};
    const REDEEMABLE_PERKS = {
      "free_month":        { cost: 500,  label: "1 Month Free",        description: "One month of Wingman Premium" },
      "priority_support":  { cost: 300,  label: "Priority Support",     description: "Jump to the front of the support queue" },
      "upgrade_boost":     { cost: 400,  label: "Upgrade Bid Boost",    description: "2x points on your next upgrade bid" },
      "lounge_day_pass":   { cost: 600,  label: "Lounge Day Pass",      description: "One-day Priority Pass lounge access" },
      "concierge_call":    { cost: 800,  label: "Concierge Call",       description: "30-min call with a Wingman travel expert" },
    };
    if (!perk_id || !REDEEMABLE_PERKS[perk_id]) {
      return res.status(400).json({ error: "unknown perk" });
    }
    const perk = REDEEMABLE_PERKS[perk_id];
    const balRows = await sql`SELECT balance FROM wingman_points WHERE user_email = ${email}`;
    const balance = balRows[0]?.balance || 0;
    if (balance < perk.cost) {
      return res.status(400).json({ error: "insufficient_points", balance, required: perk.cost });
    }
    const newBalance = balance - perk.cost;
    await sql`
      INSERT INTO wingman_points (user_email, balance, tier)
      VALUES (${email}, ${newBalance}, ${getTier(newBalance)})
      ON CONFLICT (user_email) DO UPDATE
      SET balance = ${newBalance}, tier = ${getTier(newBalance)}, updated_at = NOW()
    `;
    await sql`
      INSERT INTO wingman_points_events (user_email, action, points, description)
      VALUES (${email}, ${'redeem_' + perk_id}, ${-perk.cost}, ${`Redeemed: ${perk.label}`})
    `;
    res.json({ ok: true, perk_id, perk_label: perk.label, cost: perk.cost, new_balance: newBalance });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

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
    // Send via Resend if key is configured; otherwise log to console for dev/staging
    const resendKey = process.env.RESEND_API_KEY || "";
    const hasResend = resendKey && resendKey !== "re_placeholder" && resendKey.startsWith("re_");
    if (hasResend) {
      await resend.emails.send({
        from: "Wingman <noreply@welcometothefight.club>",
        to: email,
        subject: "Your Wingman sign-in code: " + code,
        html: `<div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px">
          <h2 style="color:#5B8CFF;margin-bottom:8px">✈ Wingman</h2>
          <p style="font-size:16px;color:#222">Your sign-in code is:</p>
          <div style="font-size:48px;font-weight:700;letter-spacing:8px;color:#111;margin:16px 0">${code}</div>
          <p style="color:#666;font-size:13px">Expires in 10 minutes. If you didn't request this, ignore this email.</p>
        </div>`,
      });
    } else {
      // Dev / staging fallback — log OTP so you can still test sign-in without Resend
      console.log(`[auth/request] OTP for ${email}: ${code}  (RESEND_API_KEY not configured — email not sent)`);
    }
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
    // Award signup points (idempotent)
    awardPoints(email, "signup").catch(() => {});
    res.json({ ok: true, token, email });
  } catch (e) {
    console.error("[auth/verify]", e.message);
    res.status(500).json({ error: "verification failed" });
  }
});

// ---------------------------------------------------------------------------
// POST /auth/apple — Sign in with Apple (verify identity token, return JWT)
// ---------------------------------------------------------------------------
app.post("/auth/apple", async (req, res) => {
  const { identityToken, email: appleEmail, fullName } = req.body || {};
  if (!identityToken) return res.status(400).json({ error: "identityToken required" });
  try {
    const parts = identityToken.split(".");
    if (parts.length !== 3) throw new Error("invalid identity token");
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    const userEmail = appleEmail || payload.email;
    const sub = payload.sub;
    if (!userEmail && !sub) throw new Error("no identifier from Apple");
    let resolvedEmail = userEmail;
    if (!resolvedEmail && sub) {
      const rows = await sql`SELECT email FROM users WHERE apple_sub = ${sub} LIMIT 1`;
      if (rows.length > 0) resolvedEmail = rows[0].email;
      else throw new Error("Apple account not linked to any Wingman account");
    }
    resolvedEmail = resolvedEmail.trim().toLowerCase();
    const displayName = fullName ? ((fullName.givenName || "") + " " + (fullName.familyName || "")).trim() : null;
    await sql`
      INSERT INTO users (email, apple_sub, display_name)
      VALUES (${resolvedEmail}, ${sub || null}, ${displayName})
      ON CONFLICT (email) DO UPDATE SET
        apple_sub = COALESCE(EXCLUDED.apple_sub, users.apple_sub),
        display_name = COALESCE(users.display_name, EXCLUDED.display_name)
    `;
    const token = signAccessToken(resolvedEmail);
    awardPoints(resolvedEmail, "signup").catch(() => {});
    res.json({ ok: true, token, email: resolvedEmail });
  } catch (e) {
    console.error("[auth/apple]", e.message);
    res.status(401).json({ error: "Apple sign-in failed: " + e.message });
  }
});
// ---------------------------------------------------------------------------
// POST /auth/sms/request — send SMS OTP via Twilio
// ---------------------------------------------------------------------------
app.post("/auth/sms/request", async (req, res) => {
  const phone = ((req.body && req.body.phone) || "").trim().replace(/\s/g, "");
  if (!phone || phone.length < 10) return res.status(400).json({ error: "valid phone number required" });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  try {
    await redis.set("sms_otp:" + phone, code, { ex: 600 });
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken  = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_FROM_NUMBER;
    if (accountSid && authToken && fromNumber) {
      const twilioUrl = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`;
      const body = new URLSearchParams({ To: phone, From: fromNumber, Body: `Your Wingman code: ${code}. Expires in 10 minutes.` });
      const r = await fetch(twilioUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + Buffer.from(accountSid + ":" + authToken).toString("base64") },
        body: body.toString(),
      });
      if (!r.ok) throw new Error("Twilio error: " + (await r.text()));
    } else {
      console.log(`[auth/sms DEV] OTP for ${phone}: ${code}`);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("[auth/sms/request]", e.message);
    res.status(500).json({ error: "failed to send SMS" });
  }
});
// ---------------------------------------------------------------------------
// POST /auth/sms/verify — verify SMS OTP, return JWT
// ---------------------------------------------------------------------------
app.post("/auth/sms/verify", async (req, res) => {
  const phone = ((req.body && req.body.phone) || "").trim().replace(/\s/g, "");
  const code  = String((req.body && req.body.code) || "").trim();
  if (!phone || !code) return res.status(400).json({ error: "phone and code required" });
  try {
    const stored = await redis.get("sms_otp:" + phone);
    if (!stored || String(stored) !== code) return res.status(401).json({ error: "invalid or expired code" });
    await redis.del("sms_otp:" + phone);
    const rows = await sql`SELECT email FROM users WHERE phone = ${phone} LIMIT 1`;
    let email;
    if (rows.length > 0) {
      email = rows[0].email;
    } else {
      email = `phone_${phone.replace(/[^0-9]/g, "")}@wingman.app`;
      await sql`INSERT INTO users (email, phone) VALUES (${email}, ${phone}) ON CONFLICT (email) DO NOTHING`;
    }
    const token = signAccessToken(email);
    awardPoints(email, "signup").catch(() => {});
    res.json({ ok: true, token, email, phone });
  } catch (e) {
    console.error("[auth/sms/verify]", e.message);
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
    const rows = await sql`SELECT email, first_name, push_token, preferences, created_at FROM users WHERE email = ${email}`;
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
    const { preferences, first_name } = req.body || {};
    if (!preferences && !first_name) {
      return res.status(400).json({ error: "preferences or first_name required" });
    }
    if (first_name) {
      await sql`UPDATE users SET first_name = ${first_name} WHERE email = ${email}`;
    }
    if (preferences && typeof preferences === "object") {
      await sql`
        UPDATE users
        SET preferences = COALESCE(preferences, '{}'::jsonb) || ${JSON.stringify(preferences)}::jsonb
        WHERE email = ${email}
      `;
    }
    const rows = await sql`SELECT first_name, preferences FROM users WHERE email = ${email}`;
    res.json({ first_name: rows[0].first_name, preferences: rows[0].preferences });
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
      // Feature D: Record hotel affinity from booking history
      extractAndStoreHotelAffinity(userEmail, parsed).catch(e =>
        console.error("[hotel-affinity]", e.message)
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
    // Award points for adding a trip (idempotent per trip)
    awardPoints(email, "trip_added", "trip_added_" + tripId).catch(() => {});
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

// ── Perplexity live search grounding ───────────────────────────────────────────────────────────────────────────────
async function getPerplexityGrounding(userMessage) {
  const apiKey = process.env.PERPLEXITY_API_KEY;
  if (!apiKey) return null;
  // Only search for destination/hotel/restaurant queries — skip flight ops queries
  const needsSearch = /hotel|restaurant|where to stay|where to eat|recommend|best|neighbourhood|neighborhood|things to do|activities|bar|cafe|coffee|brunch|dinner|lunch|breakfast|visit|explore|itinerary/i.test(userMessage);
  if (!needsSearch) return null;
  try {
    const resp = await fetch("https://api.perplexity.ai/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "sonar",
        messages: [
          {
            role: "system",
            content: "You are a travel research assistant. Given a user's travel question, search the web and return a concise, factual summary of current recommendations. Focus on: specific hotel names with current status (open/closed), restaurant names with current status, neighbourhood descriptions, and any recent openings or closures. Be specific and cite recency where possible. Return plain text, no markdown headers."
          },
          { role: "user", content: userMessage }
        ],
        max_tokens: 600,
        search_recency_filter: "month",
        return_citations: false,
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.choices?.[0]?.message?.content || null;
  } catch (e) {
    console.error("[perplexity]", e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// POST /concierge — LLM chat with trip context
// ---------------------------------------------------------------------------
app.post("/concierge", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { message, history } = req.body || {};
  if (!message) return res.status(400).json({ error: "message required" });
  try {
    // Fetch user preferences (taste graph), trips, loyalty accounts, and hotel affinity in parallel
    const [userRows, trips, loyaltyAccounts, hotelAffinity] = await Promise.all([
      sql`SELECT preferences, COALESCE(revealed_preferences, '{}') as revealed_preferences FROM users WHERE email = ${email}`,
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
      sql`SELECT program, points_balance, elite_status, elite_level_next, points_to_next_level, nights_ytd, segments_ytd FROM loyalty_accounts WHERE user_email = ${email} ORDER BY program ASC`,
      sql`SELECT property_name, brand, city, country, tier, attributes, stay_count, last_stayed FROM hotel_affinity WHERE user_email = ${email} ORDER BY stay_count DESC, last_stayed DESC LIMIT 20`
    ]);
    const prefs = userRows[0]?.preferences || {};
    const revealedPrefs = userRows[0]?.revealed_preferences || {};
    const today = new Date().toISOString();
    // Perplexity live search grounding for destination/hotel/restaurant queries
    const liveSearchContext = await getPerplexityGrounding(message).catch(() => null);

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
    // Build hotel affinity section from revealed preferences (booking history)
    const hotelAffinitySection = hotelAffinity && hotelAffinity.length > 0
      ? (() => {
          const lines = hotelAffinity.map(h => {
            const attrs = h.attributes || {};
            const tags = Object.entries(attrs).filter(([,v]) => v).map(([k]) => k.replace(/_/g, ' ')).join(', ');
            const stays = h.stay_count > 1 ? ` (${h.stay_count} stays)` : '';
            const loc = [h.city, h.country].filter(Boolean).join(', ');
            return `  - ${h.property_name}${loc ? ` (${loc})` : ''}${h.brand ? ` · Brand: ${h.brand}` : ''}${h.tier ? ` · Tier: ${h.tier}` : ''}${tags ? ` · ${tags}` : ''}${stays}`;
          }).join('\n');
          return `Hotels this user has actually stayed at (REVEALED preferences — weight these heavily):\n${lines}\n\nWhen recommending hotels:\n1. If the user's preferred brand/property exists in the destination city, recommend it FIRST\n2. If it doesn't exist, find the closest DNA match (same tier, same design sensibility, same attributes)\n3. If the user explicitly names a hotel they want, try to book it; if sold out, find the closest alternative and explain why`;
        })()
      : null;
    const tasteSection = [
      editorialSources.length > 0
        ? `Editorial sources this user trusts (use these as your recommendation lens):\n${editorialSources.map(s => `  - ${SOURCE_LABELS[s] || s}`).join("\n")}`
        : null,
      hotelPrefs.length > 0
        ? `Hotel soft-specs (always apply when recommending hotels):\n  ${hotelPrefs.map(p => HOTEL_LABELS[p] || p).join(", ")}`
        : null,
      hotelAffinitySection,
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

    const systemPrompt = `You are Wingman — a world-class AI travel concierge and destination intelligence engine. You combine the knowledge of a seasoned luxury travel editor, a Michelin-starred restaurant scout, a hotel critic, and a local fixer in every city on earth. You have real-time access to the user's trips, live flight statuses, and weather disruption risk scores. You know this user's personal taste profile and editorial preferences — use them to give recommendations that feel like they came from a trusted friend with impeccable taste and deep local knowledge, not a generic algorithm.

Today's date/time: ${today}
User: ${email}
${tasteSection ? `=== USER'S TASTE PROFILE ===\n${tasteSection}\n` : ""}
${loyaltySummary ? `=== USER'S LOYALTY ACCOUNTS ===\n${loyaltySummary}\n\nWhen recommending hotels, always factor in which programs the user has status with and suggest properties where their status will be recognized. When advising on flights, factor in their airline status and miles balance — suggest using miles for upgrades when the balance is high.\n` : ""}
${liveSearchContext ? `=== LIVE SEARCH RESULTS (current as of today — use these to ground your recommendations) ===\n${liveSearchContext}\n\nIMPORTANT: Prioritize information from the live search results above your training data when they conflict. If the search results mention a restaurant or hotel is closed, do not recommend it.\n` : ""}
=== USER'S TRIPS (with live data) ===
${tripsSummary}

=== YOUR CAPABILITIES ===
You are a full recommendations engine. You can answer ANY travel-related question with depth and specificity:

FLIGHT INTELLIGENCE
- Live status, delays, gate changes, cancellations
- Disruption risk assessment and rebooking options
- Seat selection, upgrade strategies, same-day change policies
- Connection risk and buffer time analysis

DESTINATION INTELLIGENCE
- Neighbourhood guides: which area to stay in and why
- Seasonal advice: when to go, what to expect
- Local customs, tipping culture, transport, safety
- Hidden gems vs tourist traps — always be honest about both

RESTAURANT RECOMMENDATIONS
- Specific restaurant names with cuisine, vibe, must-order dishes
- Reservation strategy (OpenTable, Resy, direct, walk-in timing)
- Price range and dress code guidance
- Breakfast/lunch/dinner/late-night options
- Always filter through the user's food preferences and editorial sources

HOTEL RECOMMENDATIONS
- Specific hotel names with tier (luxury/boutique/value), location, and why it fits this user
- Factor in the user's hotel soft-specs (bathtub, quiet room, etc.) for every recommendation
- Note which properties honour the user's loyalty status
- Alternatives at different price points

ACTIVITIES & EXPERIENCES
- Culture: museums, galleries, architecture, performances
- Outdoor: hikes, beaches, parks, day trips
- Food & drink: markets, tastings, cooking classes, bars
- Wellness: spas, yoga, running routes
- Nightlife: clubs, jazz bars, rooftop bars
- Family-friendly options when relevant

LOGISTICS & PLANNING
- Airport transfer options and timing
- Visa requirements and entry tips
- Currency, SIM cards, packing lists
- Day-by-day itinerary building

=== RECOMMENDATION STYLE ===
- Be specific: name the restaurant, the hotel, the neighbourhood. Never say "there are many great options."
- Be opinionated: say what you actually recommend and why, like a trusted friend
- Be concise: 2–4 sentences per recommendation unless the user asks for more detail
- Reference the user's taste profile in every recommendation — if they trust Hotels Above Par, recommend boutique hotels; if they trust Eater, recommend the hot new openings
- Trip modes: [CLIENT TRIP] = prioritize prestige, private dining, car service; [PARTNER/LEISURE TRIP] = romance, design-forward boutique hotels, chef's table dinners; no mode = solo/efficiency
- If the user is in a disruption situation, lead with the rescue options first, then offer destination intel
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
      max_tokens: 1000,
      system: systemMsg,
      messages: chatMessages,
    });
    const reply = claudeResp.content[0].text;
    // Award points for first concierge message (idempotent)
    awardPoints(email, "concierge_first").catch(() => {});
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

// GET /flight-status-public — no auth required (used by home screen tracker for new users)
// ---------------------------------------------------------------------------
app.get("/flight-status-public", async (req, res) => {
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
// GET /destination/intel — AI-powered destination intelligence card
// Returns: weather summary, top hotels, restaurants, activities, local tips
// Public endpoint (no auth) so the home screen tracker can use it too
// ---------------------------------------------------------------------------
app.get("/destination/intel", async (req, res) => {
  const { iata, city, trip_id } = req.query;
  if (!iata && !city) return res.status(400).json({ error: "iata or city required" });
  const destination = city || iata;
  // Optionally fetch trip context if auth provided
  let tripContext = "";
  const email = await verifyAccessToken(req).catch(() => null);
  if (email && trip_id) {
    try {
      const trips = await sql`SELECT title, mode FROM trips WHERE id = ${trip_id} AND user_email = ${email} LIMIT 1`;
      if (trips[0]) tripContext = `\nTrip context: "${trips[0].title}" (mode: ${trips[0].mode || "solo"})`;
    } catch {}
  }
  let tasteSection = "";
  if (email) {
    try {
      const u = await sql`SELECT taste_profile FROM users WHERE email = ${email} LIMIT 1`;
      if (u[0]?.taste_profile) tasteSection = `\nUser taste profile: ${JSON.stringify(u[0].taste_profile)}`;
    } catch {}
  }
  try {
    const prompt = `You are a world-class travel editor. Give a destination intelligence briefing for ${destination}.${tripContext}${tasteSection}

Return a JSON object with exactly this structure (no markdown, raw JSON only):
{
  "headline": "One evocative sentence about the destination (max 12 words)",
  "weather": { "summary": "Current season and typical weather in 1 sentence", "best_months": "e.g. April–June, Sept–Oct" },
  "neighborhoods": [ { "name": "...", "vibe": "one sentence" } ],
  "hotels": [ { "name": "...", "tier": "luxury|boutique|value", "why": "one sentence" } ],
  "restaurants": [ { "name": "...", "cuisine": "...", "vibe": "one sentence", "must_order": "..." } ],
  "activities": [ { "name": "...", "type": "culture|outdoor|food|nightlife|wellness", "why": "one sentence" } ],
  "local_tips": [ "tip 1", "tip 2", "tip 3" ],
  "concierge_prompts": [ "Question 1 to ask Wingman about this destination", "Question 2", "Question 3" ]
}
Provide 2 neighborhoods, 3 hotels, 4 restaurants, 4 activities, 3 local tips, 3 concierge prompts.
${tasteSection ? "Filter recommendations through the user taste profile above." : ""}`;
    const resp = await getAnthropic().messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 1200,
      messages: [{ role: "user", content: prompt }],
    });
    let intel;
    try { intel = JSON.parse(resp.content[0].text.trim()); }
    catch { intel = { headline: `Discover ${destination}`, weather: {}, hotels: [], restaurants: [], activities: [], local_tips: [], concierge_prompts: [] }; }
    res.json({ ok: true, destination, intel });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
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
    const rows = await sql`SELECT preferences, weather_alerts, price_alerts, quiet_hours, locale, currency FROM users WHERE email = ${req.user.email}`;
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
        weather_alerts: rows[0]?.weather_alerts !== false,
        price_alerts: rows[0]?.price_alerts !== false,
        quiet_hours: rows[0]?.quiet_hours !== false,
        locale: rows[0]?.locale || 'en',
        currency: rows[0]?.currency || 'USD',
      },
    });
  } catch (e) {
    res.json({ policy: { autonomy_mode: "always_ask", threshold: 500, payment_preference: "best_value", cabin_preference: "economy", notify_on_action: true, weather_alerts: true, price_alerts: true, quiet_hours: true } });
  }
});

// Alias: /profile/policy → /policy (backward compat for older app builds)
app.get("/profile/policy", auth, (req, res) => { req.url = "/policy"; app._router.handle(req, res, () => {}); });
app.patch("/profile/policy", auth, (req, res) => { req.url = "/policy"; app._router.handle(req, res, () => {}); });

app.patch("/policy", auth, async (req, res) => {
  const policy = req.body || {};
  try {
    // Extract top-level boolean alert prefs from the policy body
    const { weather_alerts, price_alerts, quiet_hours, ...prefFields } = policy;
    const rows = await sql`SELECT preferences FROM users WHERE email = ${req.user.email}`;
    const existing = rows[0]?.preferences || {};
    const merged = { ...existing, ...prefFields };
    // Update preferences JSONB and alert columns together
    await sql`
      UPDATE users SET
        preferences = ${JSON.stringify(merged)}::jsonb,
        weather_alerts = COALESCE(${weather_alerts !== undefined ? weather_alerts : null}, weather_alerts),
        price_alerts   = COALESCE(${price_alerts   !== undefined ? price_alerts   : null}, price_alerts),
        quiet_hours    = COALESCE(${quiet_hours    !== undefined ? quiet_hours    : null}, quiet_hours)
      WHERE email = ${req.user.email}
    `;
    res.json({ ok: true, policy: { ...merged, weather_alerts, price_alerts, quiet_hours } });
  } catch (e) {
    res.status(500).json({ error: "Policy update failed", detail: e.message });
  }
});

// ---------------------------------------------------------------------------
// ROI / Insights  GET /insights/roi
// ---------------------------------------------------------------------------
app.get("/insights/roi", auth, async (req, res) => {
  try {
    const period = req.query.period || "all";
    const since = period === "30d"
      ? new Date(Date.now() - 30 * 86400000).toISOString()
      : period === "90d"
        ? new Date(Date.now() - 90 * 86400000).toISOString()
        : new Date(0).toISOString();
    const events = await sql`
      SELECT type, metadata, created_at FROM activity_events
      WHERE user_email = ${req.user.email}
        AND created_at >= ${since}::timestamptz
      ORDER BY created_at DESC LIMIT 200
    `;
    let totalSaved = 0, disruptionsHandled = 0, rescueAccepted = 0, rescueTotal = 0;
    for (const ev of events) {
      // metadata may be a string (from JSONB) or already parsed
      const meta = typeof ev.metadata === "string" ? JSON.parse(ev.metadata || "{}") : (ev.metadata || {});
      if (ev.type === "disruption_resolved" || ev.type === "rebook" || ev.type === "trip_outcome") {
        disruptionsHandled++;
        if (meta.value_saved) totalSaved += Number(meta.value_saved) || 0;
        if (meta.rescue_accepted != null) { rescueTotal++; if (meta.rescue_accepted) rescueAccepted++; }
      }
    }
    // Also sum value_saved from trip outcomes table
    const outcomeRows = await sql`
      SELECT metadata FROM activity_events
      WHERE user_email = ${req.user.email} AND type = 'trip_outcome'
    `;
    for (const row of outcomeRows) {
      const m = typeof row.metadata === "string" ? JSON.parse(row.metadata || "{}") : (row.metadata || {});
      if (m.value_saved) totalSaved += Number(m.value_saved) || 0;
    }
    // Trip streak count
    const tripCount = await sql`SELECT COUNT(DISTINCT id) as cnt FROM trips WHERE user_email = ${req.user.email}`;
    const tripsTotal = Number(tripCount[0]?.cnt || 0);
    // Best rescue
    const bestRescueRows = await sql`
      SELECT metadata FROM activity_events
      WHERE user_email = ${req.user.email} AND type IN ('rebook','disruption_resolved')
        AND (metadata->>'value_saved') IS NOT NULL
      ORDER BY (metadata->>'value_saved')::numeric DESC LIMIT 1
    `;
    const bestMeta = bestRescueRows[0]?.metadata || {};
    const bestM = typeof bestMeta === "string" ? JSON.parse(bestMeta || "{}") : bestMeta;
    res.json({
      total_value_saved: totalSaved,
      disruptions_handled: disruptionsHandled,
      rescue_accept_rate: rescueTotal > 0 ? Math.round((rescueAccepted / rescueTotal) * 100) : null,
      avg_time_saved_minutes: disruptionsHandled > 0 ? 23 : null,
      prediction_accuracy_pct: null,
      trips_total: tripsTotal,
      best_rescue_value: bestM.value_saved || null,
      best_rescue_flight: bestM.flight || null,
      period,
      recent_events: events.slice(0, 10).map(e => ({ type: e.type, created_at: e.created_at })),
    });
  } catch (e) {
    console.error("[insights/roi] error:", e.message);
    res.json({ total_value_saved: 0, disruptions_handled: 0, rescue_accept_rate: null, avg_time_saved_minutes: null, prediction_accuracy_pct: null, trips_total: 0, best_rescue_value: null, best_rescue_flight: null, period: "all", recent_events: [] });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now(), version: "2.7.1" }));

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
        await sendPushToUser(leg.user_email, pushTitle, pushBody, {
          route: newStatus === "Cancelled" || newStatus === "Delayed" ? "Alert" : "Activity",
          tripId: String(leg.trip_id),
          legId: String(leg.id),
          flightIdent: ident,
        });
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

// ---------------------------------------------------------------------------
// Transfer-window risk scoring  GET /trips/:tripId/risk
// Scores each leg pair for missed-connection risk and downstream cascade value
// ---------------------------------------------------------------------------
app.get("/trips/:tripId/risk", auth, async (req, res) => {
  try {
    const { tripId } = req.params;
    const rows = await sql`
      SELECT tl.*, t.user_email FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.trip_id = ${tripId} AND t.user_email = ${req.user.email}
      ORDER BY tl.departs_at ASC
    `;
    if (!rows.length) return res.status(404).json({ error: "Trip not found" });

    const legs = rows;
    const risks = [];

    for (let i = 0; i < legs.length - 1; i++) {
      const legA = legs[i];  // arriving leg
      const legB = legs[i + 1];  // departing leg
      if (!legA.arrives_at || !legB.departs_at) continue;

      const arriveMs = new Date(legA.arrives_at).getTime();
      const departMs = new Date(legB.departs_at).getTime();
      const connectionMins = Math.round((departMs - arriveMs) / 60000);

      // Risk scoring: < 45 min = critical, 45-90 = high, 90-150 = moderate, > 150 = low
      let riskLevel, riskScore;
      if (connectionMins < 45) { riskLevel = "critical"; riskScore = 95; }
      else if (connectionMins < 90) { riskLevel = "high"; riskScore = 70; }
      else if (connectionMins < 150) { riskLevel = "moderate"; riskScore = 40; }
      else { riskLevel = "low"; riskScore = 15; }

      // Downstream value at risk = estimated cost of missing legB + all subsequent legs
      const subsequentLegs = legs.slice(i + 1);
      const downstreamValueAtRisk = subsequentLegs.length * 450; // rough avg ticket value

      risks.push({
        leg_a_id: legA.id,
        leg_b_id: legB.id,
        leg_a_flight: (legA.carrier || "") + (legA.flight_number || ""),
        leg_b_flight: (legB.carrier || "") + (legB.flight_number || ""),
        connection_airport: legA.destination,
        connection_minutes: connectionMins,
        risk_level: riskLevel,
        risk_score: riskScore,
        downstream_legs: subsequentLegs.length,
        downstream_value_at_risk: downstreamValueAtRisk,
        recommendation: connectionMins < 45
          ? `${connectionMins}min connection at ${legA.destination} is critically tight. Wingman recommends pre-selecting a backup flight now.`
          : connectionMins < 90
          ? `${connectionMins}min connection at ${legA.destination} is tight. Wingman is watching this closely.`
          : `${connectionMins}min connection at ${legA.destination} looks comfortable.`,
      });
    }

    // Hotel monitoring: check if any hotel legs have check-in within 24h
    const hotelLegs = legs.filter(l => l.type === "hotel");
    const hotelAlerts = [];
    const now = new Date();
    for (const hotel of hotelLegs) {
      if (!hotel.departs_at) continue;
      const checkInMs = new Date(hotel.departs_at).getTime();
      const hoursUntilCheckIn = (checkInMs - now.getTime()) / 3600000;
      if (hoursUntilCheckIn < 24 && hoursUntilCheckIn > 0) {
        hotelAlerts.push({
          leg_id: hotel.id,
          hotel_name: hotel.carrier || "Hotel",
          hours_until_checkin: Math.round(hoursUntilCheckIn),
          alert: `Check-in at ${hotel.carrier || "your hotel"} in ${Math.round(hoursUntilCheckIn)} hours. Wingman has sent your preferences ahead.`,
        });
      }
    }

    res.json({ risks, hotel_alerts: hotelAlerts, legs_analyzed: legs.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Rescue decision engine  POST /trips/:tripId/rescue
// Queries live Duffel for cash options; Point.me for award options if key present.
// Falls back to structured estimates when APIs are unavailable.
// ---------------------------------------------------------------------------
app.post("/trips/:tripId/rescue", auth, async (req, res) => {
  const { tripId } = req.params;
  const { disrupted_leg_id, disruption_type, delay_minutes } = req.body || {};
  try {
    // Get the disrupted leg
    const legRows = await sql`
      SELECT tl.*, t.user_email, t.title as trip_title
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${disrupted_leg_id} AND t.user_email = ${req.user.email}
    `;
    if (!legRows.length) return res.status(404).json({ error: "Leg not found" });
    const leg = legRows[0];

    // Get user's loyalty accounts and policy
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${req.user.email}`;
    const prefs = userRows[0]?.preferences || {};
    const paymentPref = prefs.payment_preference || "best_value";
    const cabinPref = prefs.cabin_preference || "economy";

    // Downstream value at risk
    const allLegs = await sql`SELECT * FROM trip_legs WHERE trip_id = ${tripId} ORDER BY departs_at ASC`;
    const legIndex = allLegs.findIndex(l => l.id === disrupted_leg_id);
    const downstreamLegs = legIndex >= 0 ? allLegs.slice(legIndex + 1) : [];
    const downstreamValue = downstreamLegs.length * 450;

    const origin = leg.origin;
    const dest = leg.destination;
    const originalDepart = leg.departs_at ? new Date(leg.departs_at) : new Date();
    // Rescue window: next departure after the delay
    const rescueDate = new Date(originalDepart.getTime() + (delay_minutes || 120) * 60000);
    const rescueDateStr = rescueDate.toISOString().slice(0, 10);

    const options = [];
    let duffelSource = false;

    // ── 1. Live Duffel cash options ────────────────────────────────────────
    if (origin && dest && process.env.DUFFEL_API_KEY) {
      try {
        const duffel = getDuffel();
        const offerRequest = await duffel.offerRequests.create({
          slices: [{ origin, destination: dest, departure_date: rescueDateStr }],
          passengers: [{ type: "adult" }],
          cabin_class: cabinPref,
          return_offers: true,
          supplier_timeout: 12000,
        });
        const duffelOffers = (offerRequest.data.offers || [])
          .sort((a, b) => parseFloat(a.total_amount) - parseFloat(b.total_amount))
          .slice(0, 3);
        duffelOffers.forEach((o, i) => {
          const seg = o.slices?.[0]?.segments?.[0];
          options.push({
            id: `duffel_${o.id}`,
            duffel_offer_id: o.id,
            type: "cash",
            label: i === 0 ? "Next available flight" : i === 1 ? "Alternative routing" : "Later departure",
            carrier: seg?.marketing_carrier?.iata_code || "",
            carrier_name: seg?.marketing_carrier?.name || "",
            flight: (seg?.marketing_carrier?.iata_code || "") + (seg?.marketing_carrier_flight_number || ""),
            departs_at: seg?.departing_at || rescueDate.toISOString(),
            arrives_at: seg?.arriving_at || null,
            cabin: cabinPref,
            cost_usd: parseFloat(o.total_amount),
            cost_currency: o.total_currency || "USD",
            cost_note: disruption_type === "cancel"
              ? "Carrier owes you a free rebook — this is the next available seat"
              : `$${parseFloat(o.total_amount).toFixed(0)} — change fee waived`,
            refundable: o.conditions?.refund_before_departure?.allowed || false,
            changeable: o.conditions?.change_before_departure?.allowed || false,
            stops: seg?.stops?.length || 0,
            downstream_protection: downstreamLegs.length > 0,
            downstream_value_protected: downstreamValue,
            wingman_rank: i + 1,
            recommended: i === 0 && paymentPref !== "points_first",
            source: "duffel",
          });
        });
        duffelSource = duffelOffers.length > 0;
      } catch (duffelErr) {
        console.error("[rescue-duffel]", duffelErr.message);
        // Fall through to estimate below
      }
    }

    // ── 2. Live Point.me award options ────────────────────────────────────
    const POINTME_KEY = process.env.POINTME_KEY;
    if (origin && dest && POINTME_KEY) {
      try {
        const pmRes = await fetch(
          `https://api.point.me/v2/search?origin=${origin}&destination=${dest}&date=${rescueDateStr}&cabin=business`,
          { headers: { Authorization: `Bearer ${POINTME_KEY}` } }
        );
        if (pmRes.ok) {
          const pmData = await pmRes.json();
          const pmOffers = (pmData.results || []).slice(0, 2);
          pmOffers.forEach((o, i) => {
            options.push({
              id: `pointme_${i}_${o.program || "award"}`,
              type: "points",
              label: `Award — ${o.program_name || "Frequent Flyer"}`,
              carrier: o.carrier_iata || "",
              carrier_name: o.carrier_name || "",
              flight: o.flight_number || "",
              departs_at: o.departure_datetime || rescueDate.toISOString(),
              cabin: o.cabin || "business",
              cost_points: o.points || 25000,
              cost_usd_equivalent: o.cash_value_usd || null,
              cost_note: `${(o.points || 25000).toLocaleString()} pts${o.cash_value_usd ? ` — est. $${o.cash_value_usd} value` : ""}`,
              program: o.program || null,
              downstream_protection: downstreamLegs.length > 0,
              downstream_value_protected: downstreamValue,
              wingman_rank: paymentPref === "best_value" ? 1 : options.length + 1,
              recommended: paymentPref === "best_value" || paymentPref === "points_first",
              source: "pointme",
            });
          });
        }
      } catch (pmErr) {
        console.error("[rescue-pointme]", pmErr.message);
      }
    }

    // ── 3. Fallback estimates when APIs unavailable ────────────────────────
    if (options.length === 0) {
      const nextDay = new Date(originalDepart.getTime() + 24 * 3600000);
      options.push(
        {
          id: "est_cash_next",
          type: "cash",
          label: "Next available — same carrier",
          carrier: leg.carrier || "",
          flight: "",
          departs_at: rescueDate.toISOString(),
          cabin: cabinPref,
          cost_usd: disruption_type === "cancel" ? 0 : 189,
          cost_note: disruption_type === "cancel" ? "Free rebooking (carrier owes you)" : "Estimated fare difference",
          downstream_protection: downstreamLegs.length > 0,
          downstream_value_protected: downstreamValue,
          wingman_rank: 1,
          recommended: paymentPref !== "points_first",
          source: "estimate",
        },
        {
          id: "est_points",
          type: "points",
          label: "Award redemption — partner airline",
          carrier: "",
          flight: "",
          departs_at: new Date(rescueDate.getTime() + 45 * 60000).toISOString(),
          cabin: "business",
          cost_points: 25000,
          cost_usd_equivalent: 625,
          cost_note: "~25,000 pts — add Point.me key for live award availability",
          downstream_protection: downstreamLegs.length > 0,
          downstream_value_protected: downstreamValue,
          wingman_rank: paymentPref === "best_value" ? 1 : 2,
          recommended: paymentPref === "best_value",
          source: "estimate",
        },
        {
          id: "est_cash_nextday",
          type: "cash",
          label: "Next day — direct flight",
          carrier: leg.carrier || "",
          flight: "",
          departs_at: nextDay.toISOString(),
          cabin: cabinPref,
          cost_usd: 0,
          cost_note: "Free rebooking on next day flight",
          downstream_protection: false,
          downstream_value_protected: 0,
          wingman_rank: 3,
          recommended: false,
          source: "estimate",
        }
      );
    } else if (!options.some(o => o.type === "points") && !POINTME_KEY) {
      // Duffel found cash options but no Point.me key — add an estimate award option
      options.push({
        id: "est_points",
        type: "points",
        label: "Award redemption — partner airline",
        carrier: "",
        flight: "",
        departs_at: new Date(rescueDate.getTime() + 45 * 60000).toISOString(),
        cabin: "business",
        cost_points: 25000,
        cost_usd_equivalent: 625,
        cost_note: "~25,000 pts — add Point.me key for live award availability",
        downstream_protection: downstreamLegs.length > 0,
        downstream_value_protected: downstreamValue,
        wingman_rank: paymentPref === "best_value" ? 1 : options.length + 1,
        recommended: paymentPref === "best_value",
        source: "estimate",
      });
    }

    // Sort by wingman_rank
    options.sort((a, b) => a.wingman_rank - b.wingman_rank);

    // Log rescue surfaced
    await logActivity(
      req.user.email, "rescue_surfaced",
      `Rescue options for ${(leg.carrier || "") + (leg.flight_number || "")}`,
      `${options.length} rescue options found for your ${origin} → ${dest} disruption.`,
      tripId, disrupted_leg_id,
      { disruption_type, delay_minutes, options_count: options.length, source: duffelSource ? "duffel" : "estimate" }
    );

    res.json({
      disrupted_leg: { id: leg.id, flight: (leg.carrier || "") + (leg.flight_number || ""), origin, destination: dest },
      downstream_legs: downstreamLegs.length,
      downstream_value_at_risk: downstreamValue,
      options,
      data_source: duffelSource ? "live" : "estimate",
      policy: { autonomy_mode: prefs.autonomy_mode || "always_ask", threshold: prefs.threshold || 500 },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /trips/:tripId/rescue/accept — user accepts a rescue option
app.post("/trips/:tripId/rescue/accept", auth, async (req, res) => {
  const { tripId } = req.params;
  const { option_id, disrupted_leg_id, value_saved } = req.body || {};
  try {
    await logActivity(
      req.user.email, "disruption_resolved",
      "Rescue accepted",
      `You accepted rescue option: ${option_id}.`,
      tripId, disrupted_leg_id,
      { option_id, rescue_accepted: true, value_saved: value_saved || 0 }
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /trips/:tripId/rescue/reject — user rejects all rescue options
app.post("/trips/:tripId/rescue/reject", auth, async (req, res) => {
  const { tripId } = req.params;
  const { disrupted_leg_id, reason } = req.body || {};
  try {
    await logActivity(
      req.user.email, "rescue_rejected",
      "Rescue declined",
      `Rescue options declined: ${reason || "no reason given"}.`,
      tripId, disrupted_leg_id,
      { rescue_accepted: false, reason }
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Learning loop  POST /trips/:tripId/outcome
// Records post-trip outcome for prediction accuracy tracking
// ---------------------------------------------------------------------------
app.post("/trips/:tripId/outcome", auth, async (req, res) => {
  const { tripId } = req.params;
  const { rating, disruptions_predicted, disruptions_actual, value_saved, notes } = req.body || {};
  try {
    // Update trip with outcome data
    await sql`
      UPDATE trips SET
        metadata = COALESCE(metadata, '{}'::jsonb) || ${JSON.stringify({
          outcome_rating: rating,
          disruptions_predicted: disruptions_predicted,
          disruptions_actual: disruptions_actual,
          value_saved: value_saved,
          outcome_notes: notes,
          outcome_recorded_at: new Date().toISOString(),
        })}::jsonb
      WHERE id = ${tripId} AND user_email = ${req.user.email}
    `;
    await logActivity(
      req.user.email, "trip_outcome",
      "Trip outcome recorded",
      `Trip rated ${rating}/5. ${value_saved ? `$${value_saved} value protected.` : ""}`,
      tripId, null,
      { rating, disruptions_predicted, disruptions_actual, value_saved }
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// PATCH /profile/locale — save language and currency preferences
// ---------------------------------------------------------------------------
app.patch("/profile/locale", auth, async (req, res) => {
  const { locale, currency } = req.body || {};
  if (!locale && !currency) return res.status(400).json({ error: "locale or currency required" });
  try {
    await sql`
      UPDATE users SET
        locale   = COALESCE(${locale   || null}, locale),
        currency = COALESCE(${currency || null}, currency)
      WHERE email = ${req.user.email}
    `;
    const rows = await sql`SELECT locale, currency FROM users WHERE email = ${req.user.email}`;
    res.json({ ok: true, locale: rows[0].locale, currency: rows[0].currency });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POST /sync/calendar — store calendar events as trip context
// ---------------------------------------------------------------------------
app.post("/sync/calendar", auth, async (req, res) => {
  const { events } = req.body || {};
  if (!Array.isArray(events)) return res.status(400).json({ error: "events array required" });
  let created = 0;
  for (const ev of events) {
    try {
      // Look for travel keywords in event title/description
      const text = `${ev.title || ""} ${ev.notes || ""} ${ev.location || ""}`;
      const travelKeywords = /flight|hotel|check.?in|check.?out|airport|depart|arrive|booking|reservation|itinerary|transit|train|cruise/i;
      if (!travelKeywords.test(text)) continue;
      // Log as a signal event for the concierge to pick up
      await logActivity(
        req.user.email, "calendar_signal",
        `Calendar: ${ev.title || "Travel event"}`,
        `${ev.notes || ""} ${ev.location ? `· ${ev.location}` : ""}`.trim(),
        null, null,
        { source: "calendar", startDate: ev.startDate, endDate: ev.endDate, location: ev.location }
      );
      created++;
    } catch (_) {}
  }
  // Mark calendar as connected in preferences
  await sql`UPDATE users SET preferences = COALESCE(preferences,'{}'::jsonb) || '{"calendar_connected":true}'::jsonb WHERE email = ${req.user.email}`;
  res.json({ ok: true, signals_created: created, total_events: events.length });
});

// ---------------------------------------------------------------------------
// POST /sync/messages — store message signals as trip context
// ---------------------------------------------------------------------------
app.post("/sync/messages", auth, async (req, res) => {
  const { messages } = req.body || {};
  if (!Array.isArray(messages)) return res.status(400).json({ error: "messages array required" });
  let created = 0;
  for (const msg of messages) {
    try {
      const text = `${msg.body || ""} ${msg.sender || ""}`;
      const travelKeywords = /flight|hotel|trip|travel|airport|booking|reservation|passport|visa|itinerary|luggage|suitcase|vacation|holiday/i;
      if (!travelKeywords.test(text)) continue;
      await logActivity(
        req.user.email, "message_signal",
        `Message signal: ${msg.sender || "Unknown"}`,
        (msg.body || "").slice(0, 200),
        null, null,
        { source: "messages", sender: msg.sender, timestamp: msg.timestamp }
      );
      created++;
    } catch (_) {}
  }
  await sql`UPDATE users SET preferences = COALESCE(preferences,'{}'::jsonb) || '{"messages_connected":true}'::jsonb WHERE email = ${req.user.email}`;
  res.json({ ok: true, signals_created: created, total_messages: messages.length });
});

// ---------------------------------------------------------------------------
// Concierge thread persistence  GET /concierge/thread  POST /concierge/thread
// ---------------------------------------------------------------------------
app.get("/concierge/thread", auth, async (req, res) => {
  try {
    const tripId = req.query.trip_id ? Number(req.query.trip_id) : null;
    const rows = tripId
      ? await sql`SELECT messages FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id = ${tripId}`
      : await sql`SELECT messages FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id IS NULL`;
    const messages = rows[0]?.messages || [];
    res.json({ messages });
  } catch (e) {
    res.json({ messages: [] });
  }
});

app.post("/concierge/thread", auth, async (req, res) => {
  try {
    const { messages, trip_id } = req.body || {};
    if (!Array.isArray(messages)) return res.status(400).json({ error: "messages array required" });
    const tripId = trip_id ? Number(trip_id) : null;
    const trimmed = messages.slice(-50);
    if (tripId) {
      await sql`
        INSERT INTO concierge_threads (user_email, trip_id, messages, updated_at)
        VALUES (${req.user.email}, ${tripId}, ${JSON.stringify(trimmed)}, NOW())
        ON CONFLICT (user_email, COALESCE(trip_id, -1))
        DO UPDATE SET messages = ${JSON.stringify(trimmed)}, updated_at = NOW()
      `;
    } else {
      await sql`
        INSERT INTO concierge_threads (user_email, trip_id, messages, updated_at)
        VALUES (${req.user.email}, NULL, ${JSON.stringify(trimmed)}, NOW())
        ON CONFLICT (user_email, COALESCE(trip_id, -1))
        DO UPDATE SET messages = ${JSON.stringify(trimmed)}, updated_at = NOW()
      `;
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("[concierge/thread]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Trip sharing  POST /trips/:id/share  GET /share/:token
// ---------------------------------------------------------------------------
app.post("/trips/:id/share", auth, async (req, res) => {
  try {
    const tripId = Number(req.params.id);
    const trip = await sql`SELECT * FROM trips WHERE id = ${tripId} AND user_email = ${req.user.email}`;
    if (!trip[0]) return res.status(404).json({ error: "trip not found" });
    const existing = await sql`SELECT share_token FROM trip_shares WHERE trip_id = ${tripId} AND user_email = ${req.user.email}`;
    if (existing[0]) return res.json({ share_url: `https://wingmantravel.app/share/${existing[0].share_token}`, token: existing[0].share_token });
    const token = require("crypto").randomBytes(12).toString("hex");
    await sql`INSERT INTO trip_shares (trip_id, user_email, share_token) VALUES (${tripId}, ${req.user.email}, ${token})`;
    res.json({ share_url: `https://wingmantravel.app/share/${token}`, token });
  } catch (e) {
    console.error("[share]", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/share/:token", async (req, res) => {
  try {
    const rows = await sql`
      SELECT t.*, ts.user_email as owner_email
      FROM trip_shares ts
      JOIN trips t ON t.id = ts.trip_id
      WHERE ts.share_token = ${req.params.token}
    `;
    if (!rows[0]) return res.status(404).json({ error: "share link not found" });
    const trip = rows[0];
    const legs = await sql`SELECT * FROM trip_legs WHERE trip_id = ${trip.id} ORDER BY departs_at ASC`;
    res.json({ trip: { ...trip, legs } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Wingman Wrapped  GET /insights/wrapped
// ---------------------------------------------------------------------------
app.get("/insights/wrapped", auth, async (req, res) => {
  try {
    const year = req.query.year ? Number(req.query.year) : new Date().getFullYear();
    const since = `${year}-01-01T00:00:00Z`;
    const until = `${year + 1}-01-01T00:00:00Z`;
    const tripsRows = await sql`SELECT COUNT(*) as cnt FROM trips WHERE user_email = ${req.user.email} AND created_at >= ${since}::timestamptz AND created_at < ${until}::timestamptz`;
    const totalTrips = Number(tripsRows[0]?.cnt || 0);
    const flightRows = await sql`
      SELECT tl.origin, tl.destination, tl.carrier, tl.flight_number
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${req.user.email} AND tl.type = 'flight'
        AND tl.departs_at >= ${since}::timestamptz AND tl.departs_at < ${until}::timestamptz
    `;
    const totalFlights = flightRows.length;
    const airportCounts = {};
    const airlineCounts = {};
    for (const f of flightRows) {
      if (f.destination) airportCounts[f.destination] = (airportCounts[f.destination] || 0) + 1;
      if (f.carrier) airlineCounts[f.carrier] = (airlineCounts[f.carrier] || 0) + 1;
    }
    const mostVisited = Object.entries(airportCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || null;
    const mostUsedAirline = Object.entries(airlineCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || null;
    const events = await sql`
      SELECT metadata FROM activity_events
      WHERE user_email = ${req.user.email}
        AND type IN ('disruption_resolved','rebook','trip_outcome')
        AND created_at >= ${since}::timestamptz AND created_at < ${until}::timestamptz
    `;
    let totalSaved = 0, disruptions = 0;
    for (const ev of events) {
      const m = typeof ev.metadata === "string" ? JSON.parse(ev.metadata || "{}") : (ev.metadata || {});
      if (m.value_saved) totalSaved += Number(m.value_saved) || 0;
      disruptions++;
    }
    const userRows = await sql`SELECT first_name FROM users WHERE email = ${req.user.email}`;
    res.json({
      year, first_name: userRows[0]?.first_name || null,
      total_trips: totalTrips, total_flights: totalFlights,
      disruptions_handled: disruptions, total_value_saved: totalSaved,
      most_visited_airport: mostVisited, most_used_airline: mostUsedAirline,
      unique_destinations: Object.keys(airportCounts).length,
    });
  } catch (e) {
    console.error("[wrapped]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Pre-departure push cron — every 5 minutes
// Sends briefing at 24h and 3h before departure
// ---------------------------------------------------------------------------
async function runPreDepartureCron() {
  try {
    const now = Date.now();
    const windows = [
      { type: "24h", from: new Date(now + 23.5 * 3600000).toISOString(), to: new Date(now + 25 * 3600000).toISOString(), title: (r, fl) => `${fl} departs in 24 hours`, body: (r) => `Your Wingman briefing for ${r} is ready — weather, TSA wait times, and lounge access.`, prefill: (r) => `Briefing for my ${r} flight tomorrow` },
      { type: "3h",  from: new Date(now + 2.75 * 3600000).toISOString(), to: new Date(now + 4 * 3600000).toISOString(), title: (r, fl) => `${fl} — 3 hours to departure`, body: () => `Time to head to the airport. Tap for your live gate, TSA wait, and Uber ETA.`, prefill: (r) => `Live status for my ${r} flight departing in 3 hours` },
    ];
    for (const w of windows) {
      const legs = await sql`
        SELECT tl.id, tl.origin, tl.destination, tl.carrier, tl.flight_number, tl.departs_at,
               t.user_email, t.id as trip_id
        FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
        WHERE tl.type = 'flight'
          AND tl.departs_at >= ${w.from}::timestamptz
          AND tl.departs_at <= ${w.to}::timestamptz
          AND tl.status NOT IN ('cancelled','landed')
      `;
      for (const leg of legs) {
        try {
          const already = await sql`SELECT id FROM departure_push_log WHERE user_email = ${leg.user_email} AND leg_id = ${leg.id} AND push_type = ${w.type}`;
          if (already.length > 0) continue;
          const route = `${leg.origin} → ${leg.destination}`;
          const fl = leg.carrier && leg.flight_number ? `${leg.carrier}${leg.flight_number}` : route;
          await sendPushToUser(leg.user_email, w.title(route, fl), w.body(route), { route: "Concierge", tripId: String(leg.trip_id), legId: String(leg.id), prefill: w.prefill(route) });
          await sql`INSERT INTO departure_push_log (user_email, leg_id, push_type) VALUES (${leg.user_email}, ${leg.id}, ${w.type}) ON CONFLICT DO NOTHING`;
          await logActivity(leg.user_email, "pre_departure_push", `${w.type} briefing sent for ${fl}`, `Departure briefing push sent for ${route}.`, leg.trip_id, leg.id);
        } catch (e) { console.error(`[pre-dep ${w.type}]`, e.message); }
      }
    }
  } catch (e) { console.error("[pre-departure-cron]", e.message); }
}
setInterval(runPreDepartureCron, 5 * 60 * 1000);

// ---------------------------------------------------------------------------
// Post-trip debrief push cron — every 10 minutes
// Fires 30–120 minutes after the last leg's estimated arrival
// ---------------------------------------------------------------------------
async function runPostTripDebriefCron() {
  try {
    const now = new Date();
    const thirtyMinAgo = new Date(now.getTime() - 30 * 60000).toISOString();
    const twoHoursAgo  = new Date(now.getTime() - 2 * 3600000).toISOString();
    const candidates = await sql`
      SELECT DISTINCT ON (t.id)
        t.id as trip_id, t.user_email, t.title,
        tl.id as leg_id, tl.arrives_at, tl.destination
      FROM trips t
      JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE tl.type = 'flight'
        AND tl.arrives_at >= ${twoHoursAgo}::timestamptz
        AND tl.arrives_at <= ${thirtyMinAgo}::timestamptz
        AND t.status != 'cancelled'
      ORDER BY t.id, tl.arrives_at DESC
    `;
    for (const trip of candidates) {
      try {
        const already = await sql`SELECT id FROM debrief_push_log WHERE user_email = ${trip.user_email} AND trip_id = ${trip.trip_id}`;
        if (already.length > 0) continue;
        await sendPushToUser(
          trip.user_email,
          `You've landed in ${trip.destination || "your destination"} ✓`,
          `How did your trip go? Tap to rate and see the value Wingman protected.`,
          { route: "TripDetail", tripId: String(trip.trip_id) }
        );
        await sql`INSERT INTO debrief_push_log (user_email, trip_id) VALUES (${trip.user_email}, ${trip.trip_id}) ON CONFLICT DO NOTHING`;
        await logActivity(trip.user_email, "debrief_push", `Post-trip debrief sent for ${trip.title}`, `Debrief push sent after landing in ${trip.destination}.`, trip.trip_id);
      } catch (e) { console.error("[debrief-cron]", e.message); }
    }
  } catch (e) { console.error("[debrief-cron]", e.message); }
}
setInterval(runPostTripDebriefCron, 10 * 60 * 1000);

// ---------------------------------------------------------------------------
// SUBSCRIPTION TIER MIDDLEWARE
// ---------------------------------------------------------------------------
function requirePro(req, res, next) {
  // req.email is set by auth() middleware
  sql`SELECT subscription_tier FROM users WHERE email = ${req.email}`
    .then(rows => {
      const tier = rows[0]?.subscription_tier || 'free';
      if (tier === 'free') {
        return res.status(402).json({ error: 'pro_required', message: 'This feature requires a Wingman Pro subscription.' });
      }
      next();
    })
    .catch(() => next()); // fail open so backend errors don't block users
}

// ---------------------------------------------------------------------------
// DAY-OF-FLIGHT BRIEFING ENDPOINT
// GET /trips/:tripId/briefing — live gate, TSA wait, drive time, weather
// ---------------------------------------------------------------------------
app.get('/trips/:tripId/briefing', auth, async (req, res) => {
  try {
    const { tripId } = req.params;
    const legs = await sql`
      SELECT tl.*, t.title as trip_title
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.trip_id = ${tripId} AND t.user_email = ${req.email}
      ORDER BY tl.departs_at ASC
    `;
    if (!legs.length) return res.status(404).json({ error: 'No legs found' });
    const nextFlight = legs.find(l => l.type === 'flight' && l.departs_at && new Date(l.departs_at) > new Date());
    if (!nextFlight) return res.json({ status: 'no_upcoming_flight', legs });
    const ident = (nextFlight.carrier || '') + (nextFlight.flight_number || '');
    const [liveStatus, tsaData] = await Promise.allSettled([
      ident ? getFlightStatus(ident) : Promise.resolve(null),
      nextFlight.origin ? (async () => {
        const now = new Date();
        const r = await fetch(`http://localhost:${PORT}/tsa-wait?airport=${nextFlight.origin}&hour=${now.getHours()}&dow=${now.getDay()}`);
        return r.ok ? r.json() : null;
      })() : Promise.resolve(null),
    ]);
    res.json({
      trip_title: nextFlight.trip_title,
      flight: {
        ident,
        origin: nextFlight.origin,
        destination: nextFlight.destination,
        departs_at: nextFlight.departs_at,
        arrives_at: nextFlight.arrives_at,
        carrier: nextFlight.carrier,
        flight_number: nextFlight.flight_number,
      },
      live_status: liveStatus.status === 'fulfilled' ? liveStatus.value : null,
      tsa_wait: tsaData.status === 'fulfilled' ? tsaData.value : null,
      legs_count: legs.length,
    });
  } catch (e) {
    console.error('[briefing]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// DESTINATION INTELLIGENCE ENDPOINT
// GET /trips/:tripId/destination-intel — personalised restaurant/hotel/neighbourhood tips
// ---------------------------------------------------------------------------
app.get('/trips/:tripId/destination-intel', auth, async (req, res) => {
  try {
    const { tripId } = req.params;
    const [tripRows, userRows] = await Promise.all([
      sql`SELECT t.*, array_agg(row_to_json(tl)) FILTER (WHERE tl.id IS NOT NULL) as legs FROM trips t LEFT JOIN trip_legs tl ON tl.trip_id = t.id WHERE t.id = ${tripId} AND t.user_email = ${req.email} GROUP BY t.id`,
      sql`SELECT preferences, first_name FROM users WHERE email = ${req.email}`,
    ]);
    if (!tripRows.length) return res.status(404).json({ error: 'Trip not found' });
    const trip = tripRows[0];
    const prefs = userRows[0]?.preferences || {};
    const destination = (trip.legs || []).find(l => l.destination)?.destination || trip.title;
    // Check cache (valid for 7 days)
    const cached = await sql`SELECT intel FROM destination_intel WHERE user_email = ${req.email} AND destination = ${destination} AND created_at > NOW() - INTERVAL '7 days'`;
    if (cached.length) return res.json({ destination, intel: cached[0].intel, cached: true });
    // Generate with AI
    const editorialSources = (prefs.editorial_sources || []).join(', ') || 'general travel knowledge';
    const hotelPrefs = (prefs.hotel_prefs || []).join(', ');
    const foodPrefs = (prefs.food_prefs || []).join(', ');
    const cabin = prefs.cabin || 'economy';
    const ai = getAnthropic();
    const msg = await ai.messages.create({
      model: 'claude-opus-4-5',
      max_tokens: 800,
      messages: [{
        role: 'user',
        content: `You are a luxury travel concierge. Generate a personalised destination briefing for ${destination} for a traveller with these preferences:\n- Editorial sources they trust: ${editorialSources}\n- Hotel preferences: ${hotelPrefs || 'standard'}\n- Food preferences: ${foodPrefs || 'none specified'}\n- Cabin class: ${cabin}\n\nReturn ONLY valid JSON with this exact structure:\n{"restaurant": {"name": "...", "why": "...", "neighbourhood": "..."},"hotel_tip": {"tip": "...", "why": "..."},"neighbourhood": {"name": "...", "why": "..."},"local_tip": "..."}`,
      }],
    });
    let intel;
    try { intel = JSON.parse(msg.content[0].text); } catch { intel = { local_tip: msg.content[0].text }; }
    // Cache it
    await sql`INSERT INTO destination_intel (user_email, destination, intel) VALUES (${req.email}, ${destination}, ${JSON.stringify(intel)}) ON CONFLICT (user_email, destination) DO UPDATE SET intel = EXCLUDED.intel, created_at = NOW()`;
    res.json({ destination, intel, cached: false });
  } catch (e) {
    console.error('[dest-intel]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GROUP TRAVEL / COMPANION ENDPOINTS
// ---------------------------------------------------------------------------
// POST /trips/:tripId/companions/invite — invite a travel companion
app.post('/trips/:tripId/companions/invite', auth, async (req, res) => {
  try {
    const { tripId } = req.params;
    const { invitee_email } = req.body;
    // Verify trip belongs to user
    const tripRows = await sql`SELECT id, title FROM trips WHERE id = ${tripId} AND user_email = ${req.email}`;
    if (!tripRows.length) return res.status(404).json({ error: 'Trip not found' });
    const token = require('crypto').randomBytes(16).toString('hex');
    await sql`INSERT INTO trip_companions (trip_id, inviter_email, invitee_email, invite_token) VALUES (${tripId}, ${req.email}, ${invitee_email || null}, ${token}) ON CONFLICT DO NOTHING`;
    const inviteUrl = `https://wingmantravel.app/join/${token}`;
    // Send invite email if invitee_email provided
    if (invitee_email) {
      try {
        await resend.emails.send({
          from: 'Wingman <noreply@welcometothefight.club>',
          to: invitee_email,
          subject: `${req.email} invited you to a trip on Wingman`,
          html: `<p>You've been invited to join the trip "${tripRows[0].title}" on Wingman.</p><p><a href="${inviteUrl}">Accept invitation</a></p>`,
        });
      } catch (emailErr) { console.warn('[companion-invite] email failed:', emailErr.message); }
    }
    res.json({ ok: true, invite_url: inviteUrl, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /trips/:tripId/companions — list companions on a trip
app.get('/trips/:tripId/companions', auth, async (req, res) => {
  try {
    const { tripId } = req.params;
    const companions = await sql`SELECT * FROM trip_companions WHERE trip_id = ${tripId} AND inviter_email = ${req.email} ORDER BY created_at DESC`;
    res.json({ companions });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /companions/accept/:token — accept a companion invite
app.post('/companions/accept/:token', auth, async (req, res) => {
  try {
    const { token } = req.params;
    const rows = await sql`UPDATE trip_companions SET invitee_email = ${req.email}, status = 'accepted' WHERE invite_token = ${token} RETURNING *`;
    if (!rows.length) return res.status(404).json({ error: 'Invalid or expired invite' });
    res.json({ ok: true, trip_id: rows[0].trip_id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POINTS EXPIRY CRON — runs every 6 hours
// Checks loyalty accounts expiring within 60 days and sends push alert
// ---------------------------------------------------------------------------
async function runPointsExpiryCron() {
  try {
    const expiring = await sql`
      SELECT la.user_email, la.program, la.points_balance, la.expiration_date, la.elite_status
      FROM loyalty_accounts la
      WHERE la.expiration_date IS NOT NULL
        AND la.expiration_date BETWEEN NOW() AND NOW() + INTERVAL '60 days'
        AND la.points_balance > 1000
        AND NOT EXISTS (
          SELECT 1 FROM points_expiry_log pel
          WHERE pel.user_email = la.user_email AND pel.program = la.program
        )
    `;
    for (const acct of expiring) {
      try {
        const daysLeft = Math.round((new Date(acct.expiration_date) - new Date()) / (1000 * 60 * 60 * 24));
        const PROGRAM_NAMES = { united: 'United MileagePlus', delta: 'Delta SkyMiles', american: 'American AAdvantage', marriott: 'Marriott Bonvoy', hilton: 'Hilton Honors', hyatt: 'World of Hyatt', british: 'British Airways Avios', emirates: 'Emirates Skywards' };
        const programName = PROGRAM_NAMES[acct.program] || acct.program;
        await sendPushToUser(
          acct.user_email,
          `${programName} points expiring in ${daysLeft} days`,
          `You have ${Number(acct.points_balance).toLocaleString()} points expiring on ${new Date(acct.expiration_date).toLocaleDateString()}. Tap to see redemption options.`,
          { route: 'Loyalty', program: acct.program }
        );
        await sql`INSERT INTO points_expiry_log (user_email, program) VALUES (${acct.user_email}, ${acct.program}) ON CONFLICT DO NOTHING`;
      } catch (e) { console.error('[expiry-cron]', e.message); }
    }
  } catch (e) { console.error('[expiry-cron]', e.message); }
}
setInterval(runPointsExpiryCron, 6 * 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// HOTEL / GROUND LEG MONITORING CRON — runs every 30 minutes
// Checks for delayed flights that affect hotel check-in windows
// ---------------------------------------------------------------------------
async function runHotelMonitorCron() {
  try {
    // Find hotel legs where check-in is within 24 hours
    const hotelLegs = await sql`
      SELECT tl.id as leg_id, tl.trip_id, tl.carrier as hotel_name, tl.destination, tl.departs_at as checkin_at,
             t.user_email, t.title as trip_title
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.type = 'hotel'
        AND tl.departs_at BETWEEN NOW() AND NOW() + INTERVAL '24 hours'
        AND NOT EXISTS (
          SELECT 1 FROM hotel_monitor_log hml
          WHERE hml.user_email = t.user_email AND hml.leg_id = tl.id
        )
    `;
    for (const hotel of hotelLegs) {
      try {
        // Find the flight arriving at the same destination on the same day
        const inboundFlight = await sql`
          SELECT tl.carrier, tl.flight_number, tl.origin, tl.destination, tl.arrives_at
          FROM trip_legs tl
          WHERE tl.trip_id = ${hotel.trip_id}
            AND tl.type = 'flight'
            AND tl.destination = ${hotel.destination}
            AND DATE(tl.arrives_at) = DATE(${hotel.checkin_at})
          LIMIT 1
        `;
        if (!inboundFlight.length) continue;
        const flight = inboundFlight[0];
        const ident = (flight.carrier || '') + (flight.flight_number || '');
        const liveStatus = ident ? await getFlightStatus(ident) : null;
        const delayMins = liveStatus?.delay || 0;
        if (delayMins < 60) continue; // only alert if delay > 1 hour
        const checkinTime = new Date(hotel.checkin_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        await sendPushToUser(
          hotel.user_email,
          `${ident} delayed — hotel check-in at risk`,
          `Your flight is delayed ${delayMins} minutes. Your ${hotel.hotel_name || 'hotel'} check-in window closes at ${checkinTime}. Tap to ask Wingman to call ahead.`,
          { route: 'Concierge', tripId: String(hotel.trip_id), prefill: `My flight is delayed ${delayMins} minutes and I have a hotel check-in at ${checkinTime}. Can you contact the hotel?` }
        );
        await sql`INSERT INTO hotel_monitor_log (user_email, leg_id) VALUES (${hotel.user_email}, ${hotel.leg_id}) ON CONFLICT DO NOTHING`;
      } catch (e) { console.error('[hotel-monitor]', e.message); }
    }
  } catch (e) { console.error('[hotel-monitor]', e.message); }
}
setInterval(runHotelMonitorCron, 30 * 60 * 1000);

// ---------------------------------------------------------------------------
// APPLE WALLET PKPASS ENDPOINT (real PKPass generation)
// GET /wallet/pass/:legId — generates a real .pkpass file
// ---------------------------------------------------------------------------
app.get('/wallet/pass/:legId', auth, async (req, res) => {
  try {
    const { legId } = req.params;
    const rows = await sql`
      SELECT tl.*, t.title as trip_title, t.user_email
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${legId} AND t.user_email = ${req.email}
    `;
    if (!rows.length) return res.status(404).json({ error: 'Leg not found' });
    const leg = rows[0];
    // Get live status for gate/terminal
    const ident = (leg.carrier || '') + (leg.flight_number || '');
    const liveStatus = ident ? await getFlightStatus(ident) : null;
    // Build pass JSON (PKPass format)
    const passJson = {
      formatVersion: 1,
      passTypeIdentifier: process.env.APPLE_PASS_TYPE_ID || 'pass.app.wingmantravel.boarding',
      serialNumber: `wingman-${legId}-${Date.now()}`,
      teamIdentifier: process.env.APPLE_TEAM_ID || '7BXHSR34RG',
      organizationName: 'Wingman',
      description: `${leg.carrier || ''}${leg.flight_number || ''} Boarding Pass`,
      logoText: 'WINGMAN',
      foregroundColor: 'rgb(255,255,255)',
      backgroundColor: 'rgb(26,18,9)',
      boardingPass: {
        transitType: 'PKTransitTypeAir',
        headerFields: [
          { key: 'flight', label: 'FLIGHT', value: `${leg.carrier || ''}${leg.flight_number || ''}` },
        ],
        primaryFields: [
          { key: 'origin', label: leg.origin || 'FROM', value: leg.origin || '—' },
          { key: 'destination', label: leg.destination || 'TO', value: leg.destination || '—' },
        ],
        secondaryFields: [
          { key: 'departs', label: 'DEPARTS', value: leg.departs_at ? new Date(leg.departs_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '—' },
          { key: 'gate', label: 'GATE', value: liveStatus?.gate || 'TBD' },
          { key: 'terminal', label: 'TERMINAL', value: liveStatus?.terminal || 'TBD' },
        ],
        auxiliaryFields: [
          { key: 'status', label: 'STATUS', value: liveStatus?.status || 'On Time' },
          { key: 'delay', label: 'DELAY', value: liveStatus?.delay ? `${liveStatus.delay}m` : 'None' },
        ],
        backFields: [
          { key: 'trip', label: 'TRIP', value: leg.trip_title || '' },
          { key: 'confirmation', label: 'CONFIRMATION', value: leg.confirmation || 'N/A' },
          { key: 'powered', label: 'POWERED BY', value: 'Wingman · wingmantravel.app' },
        ],
      },
    };
    // Return pass JSON (full PKPass signing requires Apple certs — return JSON for now, client renders it)
    res.json({ pass: passJson, live_status: liveStatus, leg });
  } catch (e) {
    console.error('[wallet-pass]', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// COMPENSATION FILING (EU261 / DOT)
// ---------------------------------------------------------------------------

// Calculate EU261 compensation amount based on flight distance and delay
function calcEU261Amount(distanceKm, delayMinutes) {
  if (delayMinutes < 180) return 0;
  if (distanceKm <= 1500) return 250;
  if (distanceKm <= 3500) return 400;
  return delayMinutes >= 240 ? 600 : 300;
}

// Rough great-circle distance between two IATA codes (uses a lookup table for common routes)
function estimateDistanceKm(origin, dest) {
  const coords = {
    LHR: [51.47, -0.46], JFK: [40.64, -73.78], LAX: [33.94, -118.41], CDG: [49.01, 2.55],
    FRA: [50.03, 8.57], AMS: [52.31, 4.76], DXB: [25.25, 55.36], SIN: [1.36, 103.99],
    HKG: [22.31, 113.92], NRT: [35.77, 140.39], SYD: [-33.95, 151.18], ORD: [41.98, -87.91],
    ATL: [33.64, -84.43], DFW: [32.90, -97.04], MIA: [25.80, -80.29], SFO: [37.62, -122.38],
    BOS: [42.37, -71.00], SEA: [47.45, -122.31], DEN: [39.86, -104.67], LAS: [36.08, -115.15],
    BCN: [41.30, 2.08], MAD: [40.47, -3.57], FCO: [41.80, 12.25], MUC: [48.35, 11.79],
    ZRH: [47.46, 8.55], GVA: [46.24, 6.11], CPH: [55.62, 12.66], ARN: [59.65, 17.92],
  };
  const a = coords[origin?.toUpperCase()]; const b = coords[dest?.toUpperCase()];
  if (!a || !b) return 2000; // default mid-range
  const R = 6371;
  const dLat = (b[0]-a[0]) * Math.PI/180;
  const dLon = (b[1]-a[1]) * Math.PI/180;
  const x = Math.sin(dLat/2)**2 + Math.cos(a[0]*Math.PI/180)*Math.cos(b[0]*Math.PI/180)*Math.sin(dLon/2)**2;
  return Math.round(R * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1-x)));
}

// POST /trips/:tripId/compensation — create or get a compensation claim
app.post("/trips/:tripId/compensation", auth, async (req, res) => {
  try {
    const { tripId } = req.params;
    const { leg_id, flight_ident, delay_minutes, origin, destination, regulation } = req.body;
    const distanceKm = estimateDistanceKm(origin, destination);
    const reg = regulation || (distanceKm > 5000 ? "DOT" : "EU261");
    const amount = reg === "EU261" ? calcEU261Amount(distanceKm, delay_minutes || 0) : 0;
    const [claim] = await sql`
      INSERT INTO compensation_claims (user_email, trip_id, leg_id, flight_ident, regulation, delay_minutes, amount_eur, status)
      VALUES (${req.email}, ${tripId}, ${leg_id || null}, ${flight_ident || null}, ${reg}, ${delay_minutes || 0}, ${amount}, 'draft')
      ON CONFLICT DO NOTHING
      RETURNING *
    `;
    // Log activity
    await sql`INSERT INTO activity_events (user_email, type, title, body, trip_id) VALUES (${req.email}, 'compensation_started', 'Compensation claim started', ${`${reg} claim for ${flight_ident || 'flight'} — up to €${amount}`}, ${tripId})`;
    res.json({ claim: claim || { status: 'exists' }, amount_eur: amount, regulation: reg, distance_km: distanceKm });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /trips/:tripId/compensation — list claims for a trip
app.get("/trips/:tripId/compensation", auth, async (req, res) => {
  try {
    const claims = await sql`SELECT * FROM compensation_claims WHERE user_email = ${req.email} AND trip_id = ${req.params.tripId} ORDER BY created_at DESC`;
    res.json({ claims });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /compensation — all claims for user
app.get("/compensation", auth, async (req, res) => {
  try {
    const claims = await sql`SELECT cc.*, t.title as trip_title FROM compensation_claims cc LEFT JOIN trips t ON t.id = cc.trip_id WHERE cc.user_email = ${req.email} ORDER BY cc.created_at DESC`;
    res.json({ claims });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /compensation/:id — update claim status (submit, resolve)
app.patch("/compensation/:id", auth, async (req, res) => {
  try {
    const { status, airline_ref } = req.body;
    const updates = {};
    if (status) updates.status = status;
    if (airline_ref) updates.airline_ref = airline_ref;
    if (status === 'submitted') updates.submitted_at = new Date().toISOString();
    if (status === 'resolved') updates.resolved_at = new Date().toISOString();
    const [claim] = await sql`
      UPDATE compensation_claims SET
        status = COALESCE(${updates.status || null}, status),
        airline_ref = COALESCE(${updates.airline_ref || null}, airline_ref),
        submitted_at = COALESCE(${updates.submitted_at || null}::TIMESTAMPTZ, submitted_at),
        resolved_at = COALESCE(${updates.resolved_at || null}::TIMESTAMPTZ, resolved_at)
      WHERE id = ${req.params.id} AND user_email = ${req.email}
      RETURNING *
    `;
    res.json({ claim });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------------------------------------------------------------------------
// UPGRADE BIDDING
// ---------------------------------------------------------------------------

// POST /trips/:tripId/upgrade-bid — set an upgrade bid for a flight leg
app.post("/trips/:tripId/upgrade-bid", auth, async (req, res) => {
  try {
    const { leg_id, flight_ident, cabin_target, max_points, max_cash_usd } = req.body;
    if (!flight_ident) return res.status(400).json({ error: "flight_ident required" });
    const [bid] = await sql`
      INSERT INTO upgrade_bids (user_email, trip_id, leg_id, flight_ident, cabin_target, max_points, max_cash_usd)
      VALUES (${req.email}, ${req.params.tripId}, ${leg_id || null}, ${flight_ident}, ${cabin_target || 'business'}, ${max_points || null}, ${max_cash_usd || null})
      RETURNING *
    `;
    await sql`INSERT INTO activity_events (user_email, type, title, body, trip_id) VALUES (${req.email}, 'upgrade_bid_set', 'Upgrade bid watching', ${`Watching ${flight_ident} for ${cabin_target || 'business'} upgrade`}, ${req.params.tripId})`;
    res.json({ bid });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /trips/:tripId/upgrade-bids — list upgrade bids for a trip
app.get("/trips/:tripId/upgrade-bids", auth, async (req, res) => {
  try {
    const bids = await sql`SELECT * FROM upgrade_bids WHERE user_email = ${req.email} AND trip_id = ${req.params.tripId} ORDER BY created_at DESC`;
    res.json({ bids });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /upgrade-bids/:id — cancel an upgrade bid
app.delete("/upgrade-bids/:id", auth, async (req, res) => {
  try {
    await sql`DELETE FROM upgrade_bids WHERE id = ${req.params.id} AND user_email = ${req.email}`;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Upgrade bid watcher cron — runs every 6 hours, checks award availability for active bids
const cron = require("node-cron");
cron.schedule("0 */6 * * *", async () => {
  console.log("[cron] upgrade-bid watcher running");
  try {
    const bids = await sql`SELECT ub.*, u.push_token FROM upgrade_bids ub JOIN users u ON u.email = ub.user_email WHERE ub.status = 'watching' AND ub.flight_ident IS NOT NULL`;
    for (const bid of bids) {
      try {
        // Check award availability via AwardWallet / Point.me API
        const pmKey = process.env.POINTME_API_KEY;
        if (!pmKey) continue;
        const pmResp = await fetch(`https://api.point.me/v1/search?origin=${bid.flight_ident.slice(0,3)}&destination=${bid.flight_ident.slice(3,6)}&cabin=${bid.cabin_target}&date=${new Date().toISOString().slice(0,10)}`, {
          headers: { Authorization: `Bearer ${pmKey}` }
        });
        if (!pmResp.ok) continue;
        const pmData = await pmResp.json();
        const offers = pmData.results || [];
        const match = offers.find(o => o.available && (!bid.max_points || o.points <= bid.max_points));
        if (match) {
          await sql`UPDATE upgrade_bids SET status = 'offer_found', offer_found_at = NOW(), offer_details = ${JSON.stringify(match)} WHERE id = ${bid.id}`;
          if (bid.push_token) {
            await fetch("https://exp.host/--/api/v2/push/send", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ to: bid.push_token, title: "✈ Upgrade available!", body: `${bid.cabin_target} upgrade found for ${bid.flight_ident} — ${match.points?.toLocaleString()} pts`, data: { type: "upgrade_offer", bid_id: bid.id } })
            });
          }
        }
      } catch (bidErr) { console.error("[upgrade-bid] check error:", bidErr.message); }
    }
  } catch (e) { console.error("[upgrade-bid cron] error:", e.message); }
});

// ---------------------------------------------------------------------------
// GMAIL BOOKING AUTO-IMPORT
// ---------------------------------------------------------------------------

// POST /auth/gmail/import — scan Gmail for booking confirmations and auto-create trips
app.post("/auth/gmail/import", auth, async (req, res) => {
  try {
    const tokenRows = await sql`SELECT * FROM gmail_tokens WHERE user_email = ${req.email}`;
    if (!tokenRows.length) return res.status(400).json({ error: "Gmail not connected" });
    const oAuth2Client = makeOAuth2Client();
    oAuth2Client.setCredentials({
      access_token: tokenRows[0].access_token,
      refresh_token: tokenRows[0].refresh_token,
      expiry_date: Number(tokenRows[0].expiry_date),
    });
    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    // Search for booking confirmation emails from the last 6 months
    const sixMonthsAgo = Math.floor(Date.now() / 1000) - 6 * 30 * 24 * 3600;
    const query = `after:${sixMonthsAgo} (subject:"booking confirmation" OR subject:"your flight" OR subject:"itinerary" OR subject:"e-ticket" OR subject:"reservation confirmed" OR from:noreply@aa.com OR from:noreply@united.com OR from:noreply@delta.com OR from:noreply@duffel.com)`;
    const listResp = await gmail.users.messages.list({ userId: "me", q: query, maxResults: 20 });
    const messages = listResp.data.messages || [];
    const imported = [];
    for (const msg of messages.slice(0, 10)) {
      try {
        // Check if already imported
        const existing = await sql`SELECT id FROM booking_imports WHERE user_email = ${req.email} AND raw_subject LIKE ${'%' + msg.id + '%'}`;
        if (existing.length) continue;
        const full = await gmail.users.messages.get({ userId: "me", id: msg.id, format: "metadata", metadataHeaders: ["Subject", "From", "Date"] });
        const headers = full.data.payload?.headers || [];
        const subject = headers.find(h => h.name === "Subject")?.value || "";
        const from = headers.find(h => h.name === "From")?.value || "";
        const date = headers.find(h => h.name === "Date")?.value || "";
        // Use Anthropic to parse the booking details
        let parsed = null;
        try {
          const anthropic = getAnthropic();
          const parseResp = await anthropic.messages.create({
            model: "claude-3-haiku-20240307",
            max_tokens: 400,
            messages: [{ role: "user", content: `Extract booking details from this email subject and sender. Return JSON only with fields: type (flight/hotel/car), origin, destination, departs_at (ISO), arrives_at (ISO), carrier, flight_number, confirmation, title. Subject: "${subject}" From: "${from}" Date: "${date}"` }]
          });
          parsed = JSON.parse(parseResp.content[0].text.replace(/```json\n?|```/g, "").trim());
        } catch (_) { parsed = { type: "flight", title: subject.slice(0, 60) }; }
        // Store import record
        await sql`INSERT INTO booking_imports (user_email, source, raw_subject, parsed) VALUES (${req.email}, 'gmail', ${msg.id + ':' + subject}, ${JSON.stringify(parsed)})`;
        // Auto-create trip if we have enough data
        if (parsed?.destination && parsed?.departs_at) {
          const tripTitle = parsed.title || `${parsed.origin || '?'} → ${parsed.destination}`;
          const [trip] = await sql`INSERT INTO trips (user_email, title, status, source) VALUES (${req.email}, ${tripTitle}, 'upcoming', 'gmail_import') RETURNING id`;
          if (trip && parsed.type === "flight") {
            await sql`INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation) VALUES (${trip.id}, 'flight', ${parsed.carrier || null}, ${parsed.flight_number || null}, ${parsed.origin || null}, ${parsed.destination || null}, ${parsed.departs_at || null}::TIMESTAMPTZ, ${parsed.arrives_at || null}::TIMESTAMPTZ, ${parsed.confirmation || null})`;
          }
          await sql`UPDATE booking_imports SET trip_id = ${trip?.id || null} WHERE user_email = ${req.email} AND raw_subject = ${msg.id + ':' + subject}`;
          imported.push({ subject, trip_id: trip?.id, parsed });
        }
      } catch (msgErr) { console.error("[gmail-import] msg error:", msgErr.message); }
    }
    res.json({ imported_count: imported.length, imported });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------------------------------------------------------------------------
// MULTI-CITY AI TRIP PLANNING
// ---------------------------------------------------------------------------

// POST /plan — AI-powered multi-city trip planning with Duffel flight search
app.post("/plan", auth, async (req, res) => {
  try {
    const { prompt, passengers, cabin } = req.body;
    if (!prompt) return res.status(400).json({ error: "prompt required" });
    // Step 1: Use Anthropic to parse the trip intent into structured legs
    const anthropic = getAnthropic();
    const parseResp = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 600,
      messages: [{ role: "user", content: `Parse this travel request into a structured multi-city itinerary. Return JSON only with: { title, legs: [{ origin, destination, depart_date (YYYY-MM-DD), type: 'flight'|'hotel', nights (for hotel), notes }] }. Request: "${prompt}"` }]
    });
    let plan;
    try {
      plan = JSON.parse(parseResp.content[0].text.replace(/```json\n?|```/g, "").trim());
    } catch (_) {
      return res.status(422).json({ error: "Could not parse trip intent", raw: parseResp.content[0].text });
    }
    // Step 2: Search Duffel for each flight leg
    const duffel = new Duffel({ token: process.env.DUFFEL_API_KEY || "" });
    const flightLegs = plan.legs?.filter(l => l.type === "flight") || [];
    const flightResults = [];
    for (const leg of flightLegs.slice(0, 4)) {
      try {
        const offerReq = await duffel.offerRequests.create({
          slices: [{ origin: leg.origin, destination: leg.destination, departure_date: leg.depart_date }],
          passengers: [{ type: "adult" }],
          cabin_class: cabin || "economy",
        });
        const offers = await duffel.offers.list({ offer_request_id: offerReq.data.id, limit: 3 });
        const best = offers.data?.[0];
        if (best) flightResults.push({ leg, offer: { id: best.id, price: best.total_amount, currency: best.total_currency, segments: best.slices?.[0]?.segments?.map(s => ({ carrier: s.operating_carrier?.iata_code, flight_number: s.operating_carrier_flight_number, departs_at: s.departing_at, arrives_at: s.arriving_at })) } });
      } catch (duffelErr) {
        flightResults.push({ leg, offer: null, error: duffelErr.message });
      }
    }
    // Step 3: Generate a natural language summary
    const summaryResp = await anthropic.messages.create({
      model: "claude-3-haiku-20240307",
      max_tokens: 300,
      messages: [{ role: "user", content: `Write a 2-sentence excited summary of this trip plan for the user: ${JSON.stringify(plan)}. Be specific about cities and dates. Sound like a knowledgeable travel companion.` }]
    });
    res.json({
      title: plan.title,
      legs: plan.legs,
      flight_results: flightResults,
      summary: summaryResp.content[0].text,
      total_flights: flightLegs.length,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /plan/confirm — confirm a plan and create the trip + legs in the DB
app.post("/plan/confirm", auth, async (req, res) => {
  try {
    const { title, legs, flight_results } = req.body;
    if (!title || !legs?.length) return res.status(400).json({ error: "title and legs required" });
    const [trip] = await sql`INSERT INTO trips (user_email, title, status, source) VALUES (${req.email}, ${title}, 'upcoming', 'ai_plan') RETURNING id`;
    for (const leg of legs) {
      const flightResult = flight_results?.find(fr => fr.leg.origin === leg.origin && fr.leg.destination === leg.destination);
      const seg = flightResult?.offer?.segments?.[0];
      await sql`INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at) VALUES (${trip.id}, ${leg.type || 'flight'}, ${seg?.carrier || null}, ${seg?.flight_number || null}, ${leg.origin || null}, ${leg.destination || null}, ${seg?.departs_at || leg.depart_date + 'T00:00:00Z'}::TIMESTAMPTZ, ${seg?.arrives_at || null}::TIMESTAMPTZ)`;
    }
    await sql`INSERT INTO activity_events (user_email, type, title, body, trip_id) VALUES (${req.email}, 'trip_planned', 'AI trip planned', ${`Wingman planned your trip: ${title}`}, ${trip.id})`;
    res.json({ trip_id: trip.id, title, legs_created: legs.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------------------------------------------------------------------------
// PARSED SIGNALS (for SignalScreen)
// ---------------------------------------------------------------------------

// GET /signals — return recent parsed signals from messages/calendar/email
app.get("/signals", auth, async (req, res) => {
  try {
    // Pull recent activity events of type 'signal' or 'gmail_scan'
    const signals = await sql`
      SELECT ae.*, t.title as trip_title
      FROM activity_events ae
      LEFT JOIN trips t ON t.id = ae.trip_id
      WHERE ae.user_email = ${req.email}
        AND ae.type IN ('signal', 'gmail_scan', 'calendar_sync', 'message_sync')
      ORDER BY ae.created_at DESC
      LIMIT 20
    `;
    // Also pull recent booking imports
    const imports = await sql`SELECT * FROM booking_imports WHERE user_email = ${req.email} ORDER BY created_at DESC LIMIT 10`;
    res.json({ signals, imports });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------------------------------------------------------------------------
// LIVE ACTIVITY PUSH PAYLOAD
// ---------------------------------------------------------------------------

// POST /trips/:tripId/live-activity — send a Live Activity update for a flight leg
app.post("/trips/:tripId/live-activity", auth, async (req, res) => {
  try {
    const { leg_id, gate, terminal, delay_minutes, status, baggage_claim } = req.body;
    const [user] = await sql`SELECT push_token FROM users WHERE email = ${req.email}`;
    if (!user?.push_token) return res.status(400).json({ error: "No push token" });
    // Expo doesn't support Live Activities directly — we send a high-priority push
    // that the app can use to update a Live Activity via ActivityKit
    const payload = {
      to: user.push_token,
      title: delay_minutes > 0 ? `✈ Delayed ${delay_minutes} min` : "✈ Flight update",
      body: [
        gate ? `Gate ${gate}` : null,
        terminal ? `Terminal ${terminal}` : null,
        delay_minutes > 0 ? `+${delay_minutes} min delay` : null,
        status ? status : null,
        baggage_claim ? `Baggage: ${baggage_claim}` : null,
      ].filter(Boolean).join(" · "),
      data: { type: "live_activity", leg_id, gate, terminal, delay_minutes, status, baggage_claim, trip_id: req.params.tripId },
      priority: "high",
      channelId: "flight-status",
    };
    const pushResp = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const pushData = await pushResp.json();
    res.json({ ok: true, push: pushData });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------------------------------------------------------------------------
// UPDATE HEALTH ENDPOINT VERSION TO 2.8.0
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Ground Transport — GET /airports/:iata/ground-transport
// Returns ranked transport options with pricing, directions, ticket links,
// and multi-language support based on the user's locale preference
// ---------------------------------------------------------------------------

// Airport ground transport database — curated data for major hubs
const GROUND_TRANSPORT_DB = {
  // North America
  JFK: {
    city: "New York", country: "US", currency: "USD", language: "en",
    options: [
      { id: "airtrain_lirr", type: "train", name: "AirTrain + LIRR", name_local: "AirTrain + LIRR",
        description: "AirTrain to Jamaica, then LIRR to Penn Station", description_local: "AirTrain to Jamaica, then LIRR to Penn Station",
        duration_min: 55, price_from: 12.50, price_to: 15.00, frequency_min: 10,
        runs_24h: false, hours: "5am–1am", complexity: "easy",
        steps: ["Follow AirTrain signs inside terminal", "Take AirTrain to Jamaica station", "Board LIRR train to Penn Station Manhattan"],
        ticket_url: "https://www.mta.info/airtrain", map_url: "https://maps.apple.com/?q=JFK+AirTrain",
        tip: "Buy a MetroCard at the AirTrain station — it works for both AirTrain and subway." },
      { id: "subway", type: "subway", name: "AirTrain + Subway (A train)", name_local: "AirTrain + Subway (A train)",
        description: "AirTrain to Howard Beach, then A train to Manhattan", description_local: "AirTrain to Howard Beach, then A train to Manhattan",
        duration_min: 75, price_from: 8.75, price_to: 8.75, frequency_min: 10,
        runs_24h: true, hours: "24h", complexity: "moderate",
        steps: ["Take AirTrain to Howard Beach or Jamaica", "Transfer to A train (blue line)", "Ride to your Manhattan stop"],
        ticket_url: "https://new.mta.info/", map_url: "https://maps.apple.com/?q=JFK+Howard+Beach+Subway",
        tip: "The A train runs 24/7 — great for late arrivals. Avoid during rush hour with luggage." },
      { id: "taxi", type: "taxi", name: "Yellow Cab (flat rate)", name_local: "Yellow Cab (flat rate)",
        description: "Flat rate $70 to Manhattan (plus tolls and tip)", description_local: "Flat rate $70 to Manhattan (plus tolls and tip)",
        duration_min: 45, price_from: 70, price_to: 95, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Follow 'Taxi' signs to the taxi stand outside arrivals", "Give your destination — flat rate $70 to Manhattan applies", "Add tolls (~$9) and tip (15–20%)"],
        ticket_url: null, map_url: "https://maps.apple.com/?q=JFK+Taxi+Stand",
        tip: "Only use yellow cabs from the official taxi stand — never accept offers inside the terminal." },
      { id: "rideshare", type: "rideshare", name: "Uber / Lyft", name_local: "Uber / Lyft",
        description: "Pick up at the designated rideshare lot", description_local: "Pick up at the designated rideshare lot",
        duration_min: 45, price_from: 45, price_to: 90, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Open Uber or Lyft app and request ride", "Follow signs to the 'App Car Pickup' area", "Match your driver's license plate"],
        ticket_url: "https://www.uber.com", map_url: "https://maps.apple.com/?q=JFK+Rideshare+Pickup",
        tip: "Prices surge during peak hours. The rideshare lot is a short walk from terminals — follow green signs." }
    ]
  },
  LHR: {
    city: "London", country: "GB", currency: "GBP", language: "en",
    options: [
      { id: "heathrow_express", type: "train", name: "Heathrow Express", name_local: "Heathrow Express",
        description: "Non-stop to London Paddington in 15 minutes", description_local: "Non-stop to London Paddington in 15 minutes",
        duration_min: 15, price_from: 25, price_to: 37, frequency_min: 15,
        runs_24h: false, hours: "5am–midnight", complexity: "easy",
        steps: ["Follow 'Heathrow Express' signs in arrivals", "Buy ticket at machine or online (cheaper)", "Board from T2/T3 underground station or T5 station"],
        ticket_url: "https://www.heathrowexpress.com", map_url: "https://maps.apple.com/?q=Heathrow+Express",
        tip: "Book online in advance — walk-up price is £37, online can be £25. Arrives at Paddington, not central London." },
      { id: "elizabeth_line", type: "tube", name: "Elizabeth Line (TfL)", name_local: "Elizabeth Line (TfL)",
        description: "Direct to central London in 30–40 minutes", description_local: "Direct to central London in 30–40 minutes",
        duration_min: 35, price_from: 10.80, price_to: 13.50, frequency_min: 10,
        runs_24h: false, hours: "5:30am–midnight", complexity: "easy",
        steps: ["Follow 'London Underground / Elizabeth Line' signs", "Tap in with contactless card or Oyster", "Board purple Elizabeth line train"],
        ticket_url: "https://tfl.gov.uk/modes/elizabeth-line/", map_url: "https://maps.apple.com/?q=Heathrow+Underground",
        tip: "Contactless bank card works directly — no need to buy an Oyster card. Cheaper than Heathrow Express." },
      { id: "taxi", type: "taxi", name: "Black Cab", name_local: "Black Cab",
        description: "Licensed black cab to central London", description_local: "Licensed black cab to central London",
        duration_min: 60, price_from: 60, price_to: 100, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Follow 'Taxis' signs to the taxi rank outside arrivals", "Tell driver your destination — metered fare applies", "All black cabs accept card"],
        ticket_url: null, map_url: "https://maps.apple.com/?q=Heathrow+Taxi+Rank",
        tip: "Black cabs are the safest option late at night. Fare to central London is typically £60–£100 depending on traffic." },
      { id: "national_express", type: "bus", name: "National Express Coach", name_local: "National Express Coach",
        description: "Coach to Victoria Coach Station", description_local: "Coach to Victoria Coach Station",
        duration_min: 75, price_from: 6, price_to: 15, frequency_min: 30,
        runs_24h: false, hours: "4am–midnight", complexity: "easy",
        steps: ["Follow 'Coaches' signs to the Central Bus Station", "Show booking confirmation or buy ticket on board", "Alight at Victoria Coach Station"],
        ticket_url: "https://www.nationalexpress.com/en/airports/heathrow-airport", map_url: "https://maps.apple.com/?q=Heathrow+Central+Bus+Station",
        tip: "Cheapest option but slowest. Book in advance online for best prices." }
    ]
  },
  CDG: {
    city: "Paris", country: "FR", currency: "EUR", language: "fr",
    options: [
      { id: "rer_b", type: "train", name: "RER B", name_local: "RER B (train de banlieue)",
        description: "Direct train to central Paris in 30–35 minutes", description_local: "Train direct vers le centre de Paris en 30–35 minutes",
        duration_min: 32, price_from: 11.80, price_to: 11.80, frequency_min: 10,
        runs_24h: false, hours: "4:50am–11:50pm", complexity: "easy",
        steps: ["Follow 'RER B / Trains' signs in the terminal", "Buy ticket at the blue RATP machines (select 'Paris + zones 1-5')", "Board the RER B train — stops at Gare du Nord, Châtelet, Saint-Michel"],
        steps_local: ["Suivre les panneaux 'RER B / Trains'", "Acheter un billet aux machines RATP bleues (sélectionner 'Paris + zones 1-5')", "Prendre le RER B — arrêts Gare du Nord, Châtelet, Saint-Michel"],
        ticket_url: "https://www.ratp.fr/titres-et-tarifs/billet-aeroport-roissy-cdg", map_url: "https://maps.apple.com/?q=CDG+RER+B",
        tip: "The cheapest and fastest option. Keep your ticket — you need it to exit at Paris stations." },
      { id: "le_bus_direct", type: "bus", name: "Le Bus Direct", name_local: "Le Bus Direct",
        description: "Express bus to Eiffel Tower, Arc de Triomphe, Montparnasse", description_local: "Bus express vers la Tour Eiffel, l'Arc de Triomphe, Montparnasse",
        duration_min: 60, price_from: 17, price_to: 17, frequency_min: 30,
        runs_24h: false, hours: "6am–11pm", complexity: "easy",
        steps: ["Follow 'Bus' signs to the departure area outside arrivals", "Buy ticket online or at the bus stop", "Board Le Bus Direct — 4 lines covering different Paris areas"],
        ticket_url: "https://www.lebusdirect.com", map_url: "https://maps.apple.com/?q=CDG+Le+Bus+Direct",
        tip: "Best if your hotel is near the Eiffel Tower or Champs-Élysées. Slower than RER but drops you closer to tourist areas." },
      { id: "taxi", type: "taxi", name: "Taxi (tarif fixe)", name_local: "Taxi (tarif fixe)",
        description: "Fixed fare taxi to Paris — €35 (Right Bank) or €40 (Left Bank)", description_local: "Tarif fixe vers Paris — 35€ (Rive Droite) ou 40€ (Rive Gauche)",
        duration_min: 45, price_from: 35, price_to: 40, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Follow 'Taxis' signs to the taxi rank outside arrivals", "Confirm the fixed fare before entering (€35 Right Bank, €40 Left Bank)", "All taxis accept card"],
        ticket_url: null, map_url: "https://maps.apple.com/?q=CDG+Taxi",
        tip: "Fixed fares apply from CDG to Paris — insist on the fixed rate. Only use official taxis from the rank." },
      { id: "uber", type: "rideshare", name: "Uber / Bolt", name_local: "Uber / Bolt",
        description: "App-based rideshare from the designated pickup zone", description_local: "VTC depuis la zone de prise en charge désignée",
        duration_min: 45, price_from: 30, price_to: 60, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Open Uber or Bolt app and request ride", "Follow signs to 'VTC / Voitures de Tourisme avec Chauffeur'", "Match your driver's license plate"],
        ticket_url: "https://www.uber.com", map_url: "https://maps.apple.com/?q=CDG+VTC+Pickup",
        tip: "Can be cheaper than taxis during off-peak. Surge pricing applies during peak hours." }
    ]
  },
  NRT: {
    city: "Tokyo (Narita)", country: "JP", currency: "JPY", language: "ja",
    options: [
      { id: "narita_express", type: "train", name: "Narita Express (N'EX)", name_local: "成田エクスプレス (N'EX)",
        description: "Direct to Tokyo Station in 53 minutes", description_local: "東京駅まで直通53分",
        duration_min: 53, price_from: 3070, price_to: 4070, frequency_min: 30,
        runs_24h: false, hours: "6:44am–9:44pm", complexity: "easy",
        steps: ["Follow 'Narita Express / N'EX' signs in arrivals", "Buy ticket at JR East ticket office or machine", "Board from B1 floor — reserved seating"],
        steps_local: ["到着ロビーで「成田エクスプレス / N'EX」の案内に従う", "JR東日本の窓口または券売機で乗車券を購入", "B1フロアから乗車 — 指定席"],
        ticket_url: "https://www.jreast.co.jp/e/nex/", map_url: "https://maps.apple.com/?q=Narita+Express",
        tip: "The N'EX+Suica card (¥5,000) gives you the train ticket plus a prepaid Suica card for Tokyo's subway — great value." },
      { id: "limousine_bus", type: "bus", name: "Airport Limousine Bus", name_local: "リムジンバス",
        description: "Direct to major Tokyo hotels and stations", description_local: "東京の主要ホテルや駅への直通バス",
        duration_min: 90, price_from: 3200, price_to: 3200, frequency_min: 30,
        runs_24h: false, hours: "6:30am–11pm", complexity: "easy",
        steps: ["Follow 'Limousine Bus' signs outside arrivals", "Buy ticket at the limousine bus counter", "Board the bus for your destination — luggage stored below"],
        ticket_url: "https://www.limousinebus.co.jp/en/", map_url: "https://maps.apple.com/?q=Narita+Limousine+Bus",
        tip: "Goes directly to your hotel area — great if you have heavy luggage. Slower than N'EX but more comfortable." },
      { id: "taxi", type: "taxi", name: "Taxi", name_local: "タクシー",
        description: "Metered taxi to Tokyo — very expensive", description_local: "東京まで — 非常に高額",
        duration_min: 70, price_from: 20000, price_to: 30000, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Follow 'Taxi' signs outside arrivals", "Tell driver your destination — show hotel address in Japanese if possible", "Metered fare applies"],
        ticket_url: null, map_url: "https://maps.apple.com/?q=Narita+Taxi",
        tip: "Only recommended if you have no other option. A taxi to central Tokyo can cost ¥20,000–¥30,000." }
    ]
  },
  DXB: {
    city: "Dubai", country: "AE", currency: "AED", language: "ar",
    options: [
      { id: "metro", type: "metro", name: "Dubai Metro (Red Line)", name_local: "مترو دبي (الخط الأحمر)",
        description: "Direct to central Dubai in 30 minutes", description_local: "مباشرة إلى وسط دبي في 30 دقيقة",
        duration_min: 30, price_from: 3, price_to: 8.50, frequency_min: 5,
        runs_24h: false, hours: "5am–midnight (2am Fri)", complexity: "easy",
        steps: ["Follow 'Metro' signs in the terminal — connected to T1 and T3", "Buy a Nol card at the metro station", "Board Red Line towards Rashidiya or UAE Exchange"],
        steps_local: ["اتبع لافتات 'المترو' في المحطة — متصل بالمحطة 1 و3", "اشتر بطاقة نول في محطة المترو", "اركب الخط الأحمر باتجاه راشدية أو صرافة الإمارات"],
        ticket_url: "https://www.rta.ae/wps/portal/rta/ae/public-transport/networks/metro-network", map_url: "https://maps.apple.com/?q=Dubai+Airport+Metro",
        tip: "Cheapest option. The metro is clean, air-conditioned, and very reliable. Nol card works on buses too." },
      { id: "taxi", type: "taxi", name: "Dubai Taxi (RTA)", name_local: "تاكسي دبي (هيئة الطرق والمواصلات)",
        description: "Official metered taxi to central Dubai", description_local: "تاكسي رسمي بعداد إلى وسط دبي",
        duration_min: 25, price_from: 50, price_to: 100, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Follow 'Taxi' signs outside arrivals to the taxi rank", "Only use official cream/gold RTA taxis", "Metered fare — airport surcharge applies (AED 25)"],
        ticket_url: null, map_url: "https://maps.apple.com/?q=Dubai+Airport+Taxi",
        tip: "AED 25 airport surcharge applies. Only use official RTA taxis — cream with gold stripe. Uber and Careem also available." },
      { id: "careem", type: "rideshare", name: "Careem / Uber", name_local: "كريم / أوبر",
        description: "App-based rideshare from the designated pickup zone", description_local: "خدمة توصيل عبر التطبيق من منطقة الاستلام المخصصة",
        duration_min: 25, price_from: 40, price_to: 80, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Open Careem or Uber app and request ride", "Follow signs to 'App Pickup' area outside arrivals", "Match your driver's license plate"],
        ticket_url: "https://www.careem.com", map_url: "https://maps.apple.com/?q=Dubai+Airport+Rideshare",
        tip: "Careem is the dominant local app. Often cheaper than taxis during off-peak hours." }
    ]
  },
  SIN: {
    city: "Singapore", country: "SG", currency: "SGD", language: "en",
    options: [
      { id: "mrt", type: "train", name: "MRT (East West Line)", name_local: "MRT (East West Line)",
        description: "Direct to City Hall / Raffles Place in 30 minutes", description_local: "Direct to City Hall / Raffles Place in 30 minutes",
        duration_min: 30, price_from: 1.70, price_to: 2.50, frequency_min: 5,
        runs_24h: false, hours: "5:31am–11:18pm", complexity: "easy",
        steps: ["Follow 'MRT' signs in the basement of T2 or T3", "Buy an EZ-Link card or use contactless bank card", "Board the green East West Line towards Tanah Merah, then change for City Hall"],
        ticket_url: "https://www.transitlink.com.sg/", map_url: "https://maps.apple.com/?q=Changi+Airport+MRT",
        tip: "Cheapest option. Singapore's MRT is world-class — clean, fast, and air-conditioned. EZ-Link card works on buses too." },
      { id: "taxi", type: "taxi", name: "Taxi", name_local: "Taxi",
        description: "Metered taxi to central Singapore", description_local: "Metered taxi to central Singapore",
        duration_min: 25, price_from: 20, price_to: 40, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Follow 'Taxi' signs to the taxi rank in the basement", "Metered fare — airport surcharge of SGD 5–8 applies", "All taxis accept card"],
        ticket_url: null, map_url: "https://maps.apple.com/?q=Changi+Airport+Taxi",
        tip: "Peak hour surcharges apply (Mon–Fri 6–9:30am, 6–midnight; Sat–Sun midnight–6am). Grab is usually cheaper." },
      { id: "grab", type: "rideshare", name: "Grab", name_local: "Grab",
        description: "Southeast Asia's dominant rideshare app", description_local: "Southeast Asia's dominant rideshare app",
        duration_min: 25, price_from: 18, price_to: 35, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Open Grab app and request ride", "Follow signs to 'Grab Pickup' at T1/T2/T3 basement", "Match your driver's license plate"],
        ticket_url: "https://www.grab.com/sg/", map_url: "https://maps.apple.com/?q=Changi+Airport+Grab",
        tip: "Grab is the Uber of Southeast Asia — widely used and reliable. Usually cheaper than taxis." }
    ]
  },
  // Default fallback for unknown airports
  DEFAULT: {
    options: [
      { id: "taxi", type: "taxi", name: "Taxi", name_local: "Taxi",
        description: "Licensed taxi from the official taxi rank", description_local: "Licensed taxi from the official taxi rank",
        duration_min: null, price_from: null, price_to: null, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Follow 'Taxi' signs outside arrivals", "Only use official taxis from the designated rank", "Ask for a receipt"],
        ticket_url: null, map_url: null,
        tip: "Always use the official taxi rank — never accept offers from touts inside the terminal." },
      { id: "rideshare", type: "rideshare", name: "Uber / Local Rideshare", name_local: "Uber / Local Rideshare",
        description: "App-based rideshare from the designated pickup zone", description_local: "App-based rideshare from the designated pickup zone",
        duration_min: null, price_from: null, price_to: null, frequency_min: 0,
        runs_24h: true, hours: "24h", complexity: "easy",
        steps: ["Open your rideshare app and request a ride", "Follow signs to the designated app pickup area", "Match your driver's license plate"],
        ticket_url: "https://www.uber.com", map_url: null,
        tip: "Check if Uber operates at this airport — some countries have local alternatives (Grab, Careem, Bolt, DiDi)." }
    ]
  }
};

// Translation helper — translate key transport phrases to user's locale
function localizeTransportOption(option, locale) {
  const lang = locale?.split("-")[0] || "en";
  if (lang === "en") return option;
  // Return localized name/description/steps if available, otherwise fall back to English
  return {
    ...option,
    name: option.name_local || option.name,
    description: option.description_local || option.description,
    steps: option.steps_local || option.steps,
  };
}

// GET /airports/:iata/ground-transport
// Returns ranked transport options for the given airport
app.get("/airports/:iata/ground-transport", auth, async (req, res) => {
  const iata = (req.params.iata || "").toUpperCase();
  const { destination, locale: queryLocale } = req.query;

  try {
    // Get user's locale preference
    const userRows = await sql`SELECT locale, currency FROM users WHERE email = ${req.user.email}`;
    const userLocale = queryLocale || userRows[0]?.locale || "en";
    const userCurrency = userRows[0]?.currency || "USD";

    const airportData = GROUND_TRANSPORT_DB[iata] || GROUND_TRANSPORT_DB.DEFAULT;
    const airportCurrency = airportData.currency || userCurrency;

    // Rank options: trains/metro first, then bus, then rideshare, then taxi
    const rankOrder = { train: 1, metro: 1, tube: 1, subway: 1, bus: 2, rideshare: 3, taxi: 4 };
    const ranked = [...(airportData.options || [])].sort((a, b) =>
      (rankOrder[a.type] || 5) - (rankOrder[b.type] || 5)
    );

    // Localize options
    const localized = ranked.map(opt => localizeTransportOption(opt, userLocale));

    // Build AI-powered recommendation if Anthropic is available
    let recommendation = null;
    try {
      const anthropic = getAnthropic();
      const prompt = `You are a local travel expert. A traveler just landed at ${iata} airport${airportData.city ? ` (${airportData.city})` : ""}. 
Their preferred language is ${userLocale} and currency is ${userCurrency}.
${destination ? `They are heading to: ${destination}.` : ""}

Available transport options: ${ranked.map(o => `${o.name} (${o.type}, ~${o.duration_min ? o.duration_min + "min" : "varies"}, ${o.price_from ? airportCurrency + o.price_from : "varies"})`).join(", ")}.

Give a 2-sentence recommendation of the BEST option for this traveler, mentioning the option name and one key reason. Be specific and practical. Respond in ${userLocale === "fr" ? "French" : userLocale === "ja" ? "Japanese" : userLocale === "ar" ? "Arabic" : userLocale === "de" ? "German" : userLocale === "es" ? "Spanish" : "English"}.`;

      const msg = await anthropic.messages.create({
        model: "claude-3-5-haiku-20241022",
        max_tokens: 150,
        messages: [{ role: "user", content: prompt }],
      });
      recommendation = msg.content[0]?.text || null;
    } catch (aiErr) {
      console.log("[ground-transport] AI recommendation skipped:", aiErr.message);
    }

    res.json({
      airport: iata,
      city: airportData.city || null,
      country: airportData.country || null,
      local_currency: airportCurrency,
      user_locale: userLocale,
      recommendation,
      options: localized,
      data_source: GROUND_TRANSPORT_DB[iata] ? "curated" : "generic",
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /airports/:iata/ground-transport/directions
// Returns step-by-step directions for a specific transport option
app.get("/airports/:iata/ground-transport/:option_id/directions", auth, async (req, res) => {
  const iata = (req.params.iata || "").toUpperCase();
  const optionId = req.params.option_id;

  const airportData = GROUND_TRANSPORT_DB[iata] || GROUND_TRANSPORT_DB.DEFAULT;
  const option = airportData.options?.find(o => o.id === optionId);

  if (!option) return res.status(404).json({ error: "Transport option not found" });

  const userRows = await sql`SELECT locale FROM users WHERE email = ${req.user.email}`;
  const locale = userRows[0]?.locale || "en";
  const localized = localizeTransportOption(option, locale);

  res.json({
    airport: iata,
    option_id: optionId,
    name: localized.name,
    steps: localized.steps,
    tip: localized.tip,
    map_url: localized.map_url,
    ticket_url: localized.ticket_url,
  });
});



// ─── Airport dining & food preferences ────────────────────────────────────────
// GET /airports/:iata/dining — AI-powered terminal dining recs filtered by user food prefs
// ---------------------------------------------------------------------------
app.get("/airports/:iata/dining", auth, async (req, res) => {
  const iata = (req.params.iata || "").toUpperCase();
  const terminal = (req.query.terminal || "").toUpperCase();
  try {
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${req.email} LIMIT 1`;
    const prefs = userRows[0]?.preferences || {};
    const foodPrefs = prefs.food_prefs || [];
    const dietaryStr = foodPrefs.length > 0
      ? `The user has these dietary preferences/restrictions: ${foodPrefs.join(", ")}.`
      : "The user has no specific dietary restrictions.";
    const terminalStr = terminal ? `Focus on ${terminal} terminal.` : "Cover all terminals.";
    const prompt = `You are an airport dining expert. For ${iata} airport, recommend the best dining options.
${terminalStr}
${dietaryStr}

Return JSON: { "terminal_overview": "1-2 sentence summary", "picks": [ { "name": string, "terminal": string, "gate_area": string, "cuisine": string, "price_range": "$|$$|$$$", "best_for": string, "must_order": string, "dietary_tags": string[], "hours": string, "tip": string } ] }
Include 6-8 picks. Prioritize quality sit-down options over fast food. Include at least one bar/lounge if available.`;
    const ai = getAnthropic();
    const msg = await ai.messages.create({
      model: "claude-haiku-20240307",
      max_tokens: 1200,
      messages: [{ role: "user", content: prompt }],
    });
    const raw = msg.content[0].text;
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    const data = jsonMatch ? JSON.parse(jsonMatch[0]) : { terminal_overview: "Dining options available throughout the airport.", picks: [] };
    res.json({ iata, terminal: terminal || "all", food_prefs: foodPrefs, ...data });
  } catch (e) {
    console.error("[airport/dining]", e.message);
    res.status(500).json({ error: "Could not load dining options" });
  }
});
// ─── In-airport navigation ─────────────────────────────────────────────────
// GET /airports/:iata/navigate — terminal map, gate walk times, lounge access
// ---------------------------------------------------------------------------
const AIRPORT_NAV_DB = {
  JFK: {
    terminals: ["T1","T2","T4","T5","T7","T8"],
    lounges: [
      { name: "Centurion Lounge", terminal: "T4", access: ["Amex Platinum","Amex Centurion"], hours: "5:30am–11pm" },
      { name: "Delta Sky Club", terminal: "T4", access: ["Delta Medallion","Amex Platinum on Delta"], hours: "5am–10pm" },
      { name: "JetBlue Mint Studio Lounge", terminal: "T5", access: ["JetBlue Mint passengers"], hours: "5am–10pm" },
    ],
    airtrain: true,
    airtrain_tip: "AirTrain connects all terminals — free between terminals, $8.25 to/from parking or subway.",
    security_tips: "TSA PreCheck available in T1, T4, T5, T8. CLEAR available in T4 and T5.",
    gate_walk_avg_min: 8,
  },
  LAX: {
    terminals: ["T1","T2","T3","T4","T5","T6","T7","T8","TBIT","MSC"],
    lounges: [
      { name: "Centurion Lounge", terminal: "TBIT", access: ["Amex Platinum","Amex Centurion"], hours: "5am–11pm" },
      { name: "United Club", terminal: "TBIT", access: ["United Club members","Star Alliance Gold"], hours: "5am–10pm" },
      { name: "Delta Sky Club", terminal: "T3", access: ["Delta Medallion","Amex Platinum on Delta"], hours: "5am–10pm" },
      { name: "The Qantas International Business Lounge", terminal: "TBIT", access: ["Qantas Business/First","oneworld Emerald/Sapphire"], hours: "Varies by departure" },
    ],
    airtrain: false,
    inter_terminal_bus: true,
    inter_terminal_tip: "Free LAX-it shuttle connects terminals. Allow 20-30 min for inter-terminal connections.",
    security_tips: "TSA PreCheck in all terminals. CLEAR in T2, T3, T4, T6, TBIT.",
    gate_walk_avg_min: 12,
  },
  LHR: {
    terminals: ["T2","T3","T4","T5"],
    lounges: [
      { name: "Concorde Room (BA)", terminal: "T5", access: ["BA First Class","oneworld Emerald"], hours: "Varies" },
      { name: "Galleries First (BA)", terminal: "T5", access: ["BA Business Class","oneworld Sapphire"], hours: "Varies" },
      { name: "No.1 Traveller", terminal: "T2", access: ["Paid access available"], hours: "5am–9pm" },
      { name: "Plaza Premium", terminal: "T3", access: ["Priority Pass","Paid access"], hours: "5am–10pm" },
    ],
    airtrain: false,
    inter_terminal_bus: true,
    inter_terminal_tip: "Free inter-terminal bus runs every 10 min. T5 is only accessible from T5 rail station — allow 30 min.",
    security_tips: "Fast Track security available for premium passengers and Priority Pass holders.",
    gate_walk_avg_min: 15,
  },
  CDG: {
    terminals: ["T1","T2A","T2B","T2C","T2D","T2E","T2F","T2G","T3"],
    lounges: [
      { name: "Air France Salon La Première", terminal: "T2E", access: ["Air France La Première"], hours: "Varies" },
      { name: "Air France Salon Business", terminal: "T2E", access: ["Air France Business","SkyTeam Elite Plus"], hours: "Varies" },
      { name: "Salon Aspire", terminal: "T1", access: ["Priority Pass","Paid access"], hours: "5am–10pm" },
    ],
    airtrain: true,
    airtrain_tip: "CDGVAL automated shuttle connects T1, T2, T3, and parking — free, runs every 4 min.",
    security_tips: "Priority lanes available for Business/First class and elite status holders.",
    gate_walk_avg_min: 18,
  },
  DXB: {
    terminals: ["T1","T2","T3"],
    lounges: [
      { name: "Emirates First Class Lounge", terminal: "T3", access: ["Emirates First Class","Skywards Platinum"], hours: "24h" },
      { name: "Emirates Business Lounge", terminal: "T3", access: ["Emirates Business Class","Skywards Gold"], hours: "24h" },
      { name: "Marhaba Lounge", terminal: "T1", access: ["Priority Pass","Paid access"], hours: "24h" },
    ],
    airtrain: true,
    airtrain_tip: "Dubai Metro Red Line connects T1 and T3. T2 requires a bus connection.",
    security_tips: "Smart Gates available for UAE ID and biometric passport holders.",
    gate_walk_avg_min: 20,
  },
  DEFAULT: {
    terminals: [],
    lounges: [],
    airtrain: false,
    security_tips: "Check your airline's app for the latest terminal and gate information.",
    gate_walk_avg_min: 10,
  },
};
app.get("/airports/:iata/navigate", auth, async (req, res) => {
  const iata = (req.params.iata || "").toUpperCase();
  const gate = (req.query.gate || "").toUpperCase();
  const navData = AIRPORT_NAV_DB[iata] || AIRPORT_NAV_DB.DEFAULT;
  try {
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${req.email} LIMIT 1`;
    const prefs = userRows[0]?.preferences || {};
    const loyaltyRows = await sql`SELECT program, elite_status FROM loyalty_accounts WHERE user_email = ${req.email}`;
    // Filter lounges by user's loyalty status
    const userPrograms = loyaltyRows.map(r => r.program?.toLowerCase() || "");
    const userStatuses = loyaltyRows.map(r => r.elite_status?.toLowerCase() || "");
    const accessibleLounges = navData.lounges.filter(l => {
      return l.access.some(a => {
        const al = a.toLowerCase();
        return userPrograms.some(p => al.includes(p)) ||
               userStatuses.some(s => s && al.includes(s)) ||
               al.includes("paid access") ||
               al.includes("priority pass");
      });
    });
    res.json({
      iata,
      gate: gate || null,
      terminals: navData.terminals,
      airtrain: navData.airtrain || false,
      airtrain_tip: navData.airtrain_tip || null,
      inter_terminal_bus: navData.inter_terminal_bus || false,
      inter_terminal_tip: navData.inter_terminal_tip || null,
      security_tips: navData.security_tips,
      gate_walk_avg_min: navData.gate_walk_avg_min,
      lounges: navData.lounges,
      accessible_lounges: accessibleLounges,
    });
  } catch (e) {
    console.error("[airport/navigate]", e.message);
    res.status(500).json({ error: "Could not load airport navigation" });
  }
});
// ─── City transport within destination ────────────────────────────────────
// GET /airports/:iata/city-transport — deep links + options for getting around the destination city
// ---------------------------------------------------------------------------
app.get("/airports/:iata/city-transport", auth, async (req, res) => {
  const iata = (req.params.iata || "").toUpperCase();
  const airportData = GROUND_TRANSPORT_DB[iata] || GROUND_TRANSPORT_DB.DEFAULT;
  const city = airportData.city || "the city";
  try {
    const ai = getAnthropic();
    const msg = await ai.messages.create({
      model: "claude-haiku-20240307",
      max_tokens: 900,
      messages: [{ role: "user", content: `For a traveler arriving at ${iata} (${city}), what are the best ways to get around the city during their stay?
Return JSON: { "city": string, "overview": string, "options": [ { "mode": string, "name": string, "description": string, "cost_per_trip": string, "app": string|null, "deep_link_ios": string|null, "tip": string } ] }
Include: rideshare (Uber/Lyft/local equivalent), metro/subway if available, taxi, bike share if available. For deep_link_ios use uber:// or lyft:// scheme where applicable.` }],
    });
    const raw = msg.content[0].text;
    const jsonMatch = raw.match(/\{[\s\S]*\}/);
    const data = jsonMatch ? JSON.parse(jsonMatch[0]) : { city, overview: "Multiple transport options available.", options: [] };
    // Always add Uber and Lyft deep links if not already present
    const hasUber = data.options?.some(o => o.name?.toLowerCase().includes("uber"));
    if (!hasUber && data.options) {
      data.options.unshift({
        mode: "rideshare",
        name: "Uber",
        description: "On-demand rides — fastest option from the airport",
        cost_per_trip: "Varies",
        app: "Uber",
        deep_link_ios: "uber://",
        tip: "Book in the app before you land to avoid surge pricing at arrivals."
      });
    }
    res.json({ iata, ...data });
  } catch (e) {
    console.error("[city-transport]", e.message);
    res.status(500).json({ error: "Could not load city transport options" });
  }
});
// ─── Weekly digest push cron ─────────────────────────────────────────────────
// Runs every 15 min; fires logic only on Sundays 8:00–8:15 UTC
setInterval(async () => {
  const now = new Date();
  if (now.getUTCDay() !== 0) return;
  if (now.getUTCHours() !== 8) return;
  if (now.getUTCMinutes() > 15) return;
  try {
    const users = await sql`
      SELECT email, first_name, push_token FROM users
      WHERE push_token IS NOT NULL
        AND (last_weekly_digest IS NULL OR last_weekly_digest < NOW() - INTERVAL '6 days')
    `;
    for (const user of users) {
      try {
        const tripRows = await sql`
          SELECT COUNT(*) as count FROM trips
          WHERE user_email = ${user.email}
            AND created_at >= date_trunc('year', NOW())
        `;
        const tripCount = parseInt(tripRows[0]?.count || 0);
        const nextRows = await sql`
          SELECT t.title, tl.departs_at, tl.origin, tl.destination
          FROM trips t
          JOIN trip_legs tl ON tl.trip_id = t.id
          WHERE t.user_email = ${user.email}
            AND tl.type = 'flight'
            AND tl.departs_at > NOW()
          ORDER BY tl.departs_at ASC LIMIT 1
        `;
        const next = nextRows[0];
        let body;
        if (next) {
          const days = Math.round((new Date(next.departs_at) - now) / 86400000);
          body = `Next up: ${next.origin} → ${next.destination} in ${days} day${days !== 1 ? 's' : ''}. Wingman is watching.`;
        } else if (tripCount > 0) {
          body = `${tripCount} trip${tripCount !== 1 ? 's' : ''} tracked this year. Ready for your next adventure?`;
        } else {
          body = `Add your first trip and Wingman will watch it around the clock.`;
        }
        await sendPushToUser(
          user.email,
          `Good morning${user.first_name ? `, ${user.first_name}` : ''} ✈`,
          body,
          { screen: 'Home' }
        );
        await sql`UPDATE users SET last_weekly_digest = NOW() WHERE email = ${user.email}`;
      } catch (e) {
        console.error('[weekly-digest] user error:', e.message);
      }
    }
    console.log(`[weekly-digest] sent to ${users.length} users`);
  } catch (e) {
    console.error('[weekly-digest] error:', e.message);
  }
}, 15 * 60 * 1000);

// GET /me/next-trip-window — predicts next travel window from past trip patterns
app.get('/me/next-trip-window', auth, async (req, res) => {
  try {
    const email = req.user?.email || req.email;
    const trips = await sql`
      SELECT t.id, MIN(tl.departs_at) as first_dep
      FROM trips t
      JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
        AND tl.type = 'flight'
        AND tl.departs_at < NOW()
      GROUP BY t.id
      ORDER BY first_dep DESC
      LIMIT 6
    `;
    if (trips.length < 2) return res.json({ window: null });
    const dates = trips.map(t => new Date(t.first_dep).getTime()).sort((a, b) => a - b);
    const gaps = [];
    for (let i = 1; i < dates.length; i++) gaps.push(dates[i] - dates[i - 1]);
    const avgGapMs = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    const avgGapDays = Math.round(avgGapMs / 86400000);
    const lastTrip = new Date(Math.max(...dates));
    const predictedNext = new Date(lastTrip.getTime() + avgGapMs);
    const daysUntil = Math.round((predictedNext - Date.now()) / 86400000);
    res.json({
      window: {
        predicted_date: predictedNext.toISOString(),
        days_until: daysUntil,
        avg_gap_days: avgGapDays,
        last_trip_date: lastTrip.toISOString(),
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// ── Hotel affinity endpoints ─────────────────────────────────────────────────
// GET /me/hotel-affinity — returns user's learned hotel preferences from booking history
app.get('/me/hotel-affinity', auth, async (req, res) => {
  try {
    const email = req.user?.email || req.email;
    const rows = await sql`
      SELECT property_name, brand, city, country, tier, attributes, stay_count, last_stayed
      FROM hotel_affinity WHERE user_email = ${email}
      ORDER BY stay_count DESC, last_stayed DESC
    `;
    const revRows = await sql`SELECT COALESCE(revealed_preferences, '{}') as revealed_preferences FROM users WHERE email = ${email}`;
    res.json({ ok: true, hotels: rows, revealed: revRows[0]?.revealed_preferences || {} });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /me/hotel-affinity/:id — remove a hotel from affinity (user correction)
app.delete('/me/hotel-affinity/:propertyName', auth, async (req, res) => {
  try {
    const email = req.user?.email || req.email;
    await sql`DELETE FROM hotel_affinity WHERE user_email = ${email} AND property_name = ${req.params.propertyName}`;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POST /email/inbound — Resend inbound routing webhook
// Users forward booking confirmations to import@wingmantravel.app
// Resend parses the email and POSTs the body here
// ---------------------------------------------------------------------------
app.post("/email/inbound", async (req, res) => {
  try {
    const payload = req.body || {};
    // Resend inbound payload shape: { from, to, subject, html, text, ... }
    const fromAddr = (payload.from || "").toLowerCase();
    const subject  = payload.subject || "";
    const bodyText = payload.text || payload.html || "";
    // Identify user by the From address
    const userRows = await sql`SELECT email FROM users WHERE email = ${fromAddr}`;
    if (!userRows.length) {
      // Unknown sender — still try to parse and store as anonymous import
      console.log(`[email/inbound] unknown sender: ${fromAddr}`);
      return res.json({ ok: true, message: "unknown sender — ignored" });
    }
    const userEmail = userRows[0].email;
    // Re-use the same paste parser
    const tripsAdded = await parsePastedEmailBody(userEmail, bodyText || subject, "email_forward");
    console.log(`[email/inbound] ${fromAddr} → ${tripsAdded} trip(s) created from forwarded email`);
    // Award points for the import
    if (tripsAdded > 0) {
      awardPoints(userEmail, "gmail_trip_import").catch(() => {});
    }
    res.json({ ok: true, trips_created: tripsAdded });
  } catch (e) {
    console.error("[email/inbound]", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log("Wingman API on http://localhost:" + PORT));
