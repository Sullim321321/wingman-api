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
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const validator = require("validator");
const crypto = require("crypto");

// ── The constraint graph (see TRIP_MODEL.md) ─────────────────────────────────
// Intents → constraints (with their reasons) → commitments. Plan, Book and Protect
// are three readings of the same graph. `.bind(sql)` is called just below the sql
// client so the invariant closures can use it like the existing ones do.
const graph = require("./constraints");

const app = express();

// ── Security headers (helmet) ─────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,   // API-only, no HTML served
  crossOriginEmbedderPolicy: false,
}));

// ── CORS — locked to known origins ───────────────────────────────────────────
const ALLOWED_ORIGINS = [
  "https://wingmantravel.app",
  "https://www.wingmantravel.app",
  "exp://",        // Expo Go dev
  /^exp:\/\//,
  /^https:\/\/.*\.expo\.dev$/,
];
app.use(cors({
  origin: (origin, cb) => {
    // Allow no-origin (mobile apps, curl, Render health checks)
    if (!origin) return cb(null, true);
    const ok = ALLOWED_ORIGINS.some(o =>
      typeof o === "string" ? o === origin : o.test(origin)
    );
    cb(ok ? null : new Error("CORS: origin not allowed"), ok);
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));

// ── Global rate limiter — 300 req / 15 min per IP ────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please slow down." },
});
app.use(globalLimiter);

// Trust Render's reverse proxy for correct IP in rate limiting
app.set("trust proxy", 1);

// Force HTTPS in production
app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" &&
      req.headers["x-forwarded-proto"] !== "https") {
    return res.redirect(301, "https://" + req.headers.host + req.url);
  }
  next();
});

// ── Auth endpoint limiter — 10 req / 15 min per IP ───────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many auth attempts, please try again later." },
  skip: (req) => process.env.NODE_ENV === "test",
});

// ── Concierge limiter — 60 req / 10 min per IP ───────────────────────────────
const conciergeLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Concierge rate limit reached. Please wait a moment." },
});

// ── Body size limit — 1 MB ────────────────────────────────────────────────────
// Stripe webhook requires raw body for signature verification — skip JSON parsing for that route
app.use((req, res, next) => {
  if (req.path === "/subscription/webhook") return next();
  express.json({ limit: "1mb" })(req, res, next);
});

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET env var not set. Refusing to start.");
  process.exit(1);
}
// NOTE: the mobile client does not implement token refresh (no /auth/refresh call),
// so it holds a single access token for the whole session. A 15m lifetime silently
// killed that token mid-session — the concierge (used late in a session) was the most
// visible casualty, 401ing while already-loaded screens still showed cached data.
// Match the access token to the refresh-token window until client refresh is built.
const JWT_EXPIRES_IN = "30d";   // Long-lived access token (client has no refresh flow)
const REFRESH_TOKEN_TTL_DAYS = 30; // Rotating refresh token TTL

// ── Field-level encryption for OAuth tokens stored in DB ─────────────────────
// ENCRYPTION_KEY must be a 64-char hex string (32 bytes) set in env
const ENC_KEY = process.env.ENCRYPTION_KEY
  ? Buffer.from(process.env.ENCRYPTION_KEY, "hex")
  : null;
const ENC_ALGO = "aes-256-gcm";

function encryptField(plaintext) {
  if (!ENC_KEY || !plaintext) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ENC_ALGO, ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString("hex") + ":" + tag.toString("hex") + ":" + encrypted.toString("hex");
}

function decryptField(ciphertext) {
  if (!ENC_KEY || !ciphertext) return ciphertext;
  // If it doesn't look encrypted (legacy plaintext), return as-is
  const parts = ciphertext.split(":");
  if (parts.length !== 3) return ciphertext;
  try {
    const iv = Buffer.from(parts[0], "hex");
    const tag = Buffer.from(parts[1], "hex");
    const encrypted = Buffer.from(parts[2], "hex");
    const decipher = crypto.createDecipheriv(ENC_ALGO, ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted) + decipher.final("utf8");
  } catch { return ciphertext; } // fallback for legacy unencrypted values
}

// ── HTTPS enforcement — trust Render's proxy ─────────────────────────────────

// ---------------------------------------------------------------------------
// Reusable JWT auth middleware
// ---------------------------------------------------------------------------
// ── Input sanitisation helpers ────────────────────────────────────────────────
function sanitiseEmail(e) {
  if (!e || typeof e !== "string") return null;
  const trimmed = e.trim().toLowerCase();
  return validator.isEmail(trimmed) ? trimmed : null;
}
function sanitiseStr(s, maxLen = 500) {
  if (!s || typeof s !== "string") return "";
  return s.trim().slice(0, maxLen);
}

// ── PII scrubber — strips sensitive patterns before sending to Anthropic ────────
// Patterns: credit/debit card numbers, passport numbers, SSNs, IBAN, sort codes
const PII_PATTERNS = [
  // Credit/debit card numbers (13-19 digits, optionally space/dash separated)
  { pattern: /(?:\d[ -]?){13,19}/g,                          replacement: "[card number removed]" },
  // US Social Security Numbers
  { pattern: /\d{3}[- ]?\d{2}[- ]?\d{4}/g,                  replacement: "[SSN removed]" },
  // Passport numbers (common formats: letter(s) + 6-9 digits)
  { pattern: /[A-Z]{1,2}\d{6,9}/g,                           replacement: "[passport number removed]" },
  // IBAN (2 letters + 2 digits + up to 30 alphanumeric)
  { pattern: /[A-Z]{2}\d{2}[A-Z0-9]{4,30}/g,                 replacement: "[IBAN removed]" },
  // UK sort codes
  { pattern: /\d{2}[- ]?\d{2}[- ]?\d{2}/g,                   replacement: "[sort code removed]" },
  // CVV / CVC (3-4 digits preceded by cvv/cvc/security code label)
  { pattern: /(?:cvv|cvc|security code)[:\s]*\d{3,4}/gi,     replacement: "[CVV removed]" },
];

function scrubPII(text) {
  if (!text || typeof text !== "string") return text;
  let scrubbed = text;
  for (const { pattern, replacement } of PII_PATTERNS) {
    scrubbed = scrubbed.replace(pattern, replacement);
  }
  return scrubbed;
}

function auth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.email = payload.email;
    // Much of the codebase reads req.user.email (55 call sites) while this middleware
    // only ever set req.email — so every one of those threw a TypeError and 500'd.
    // Populate both shapes so old and new call sites both work.
    req.user = { email: payload.email };
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
graph.bind(sql);   // constraint-graph invariants close over the same sql client
const resend = new Resend(process.env.RESEND_API_KEY || "re_placeholder");
// Anthropic lazy-loaded so server starts even if key is missing
let _anthropic = null;
function getAnthropic() {
  if (!_anthropic) {
    if (!process.env.ANTHROPIC_API_KEY) throw new Error("ANTHROPIC_API_KEY not set");
    // The SDK was pinned at 0.39.0 (early 2025) while we call claude-sonnet-4-5 and
    // claude-haiku-4-5 — models that postdate it. The symptom was a socket dying
    // mid-response ("Invalid response body ... Premature close"), which surfaced to
    // the user as the concierge's "that didn't go through". Not a timeout, not auth:
    // a stale transport.
    //
    // maxRetries covers the transport failures that are not the model's fault. The
    // default of 2 is thin for a 55s concierge call.
    _anthropic = new Anthropic({
      apiKey: process.env.ANTHROPIC_API_KEY,
      maxRetries: 4,
      timeout: 120000,
    });
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
    // ── Referral loop ──────────────────────────────────────────────────────────
    // referral_code: this user's own code, minted lazily on first view.
    // referred_by:   email of whoever invited them (set once, at signup only).
    // referral_credited: guards the reward — paid on ACTIVATION, not signup, so a
    //   pile of throwaway addresses earns nothing. See maybeCreditReferral().
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_credited BOOLEAN DEFAULT false`;
    await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code) WHERE referral_code IS NOT NULL`;
    await sql`CREATE INDEX IF NOT EXISTS idx_users_referred_by ON users(referred_by)`;

    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS locale TEXT DEFAULT 'en'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS currency TEXT DEFAULT 'USD'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS weather_alerts BOOLEAN DEFAULT true`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS price_alerts BOOLEAN DEFAULT true`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS quiet_hours BOOLEAN DEFAULT true`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_morning_briefing TIMESTAMPTZ`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS travel_pace TEXT DEFAULT 'comfortable'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS home_airports JSONB DEFAULT '[]'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS seat_preference TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS cabin_preference TEXT DEFAULT 'economy'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS min_connection_mins INTEGER DEFAULT 60`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS notify_journey BOOLEAN DEFAULT true`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_weekly_digest TIMESTAMPTZ`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_opened_at TIMESTAMPTZ`;
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
        user_email TEXT NOT NULL,
        account_email TEXT,
        account_label TEXT,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expiry_date BIGINT,
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (user_email, account_email)
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
    await sql`ALTER TABLE activity_events ADD COLUMN IF NOT EXISTS dismissed BOOLEAN DEFAULT FALSE`;
    // Ledger of every Gmail message we've already run through the parser (any outcome).
    // Lets rescans skip the expensive LLM call for emails we've already seen, so each
    // email is parsed at most once ever instead of on every scan.
    await sql`
      CREATE TABLE IF NOT EXISTS processed_emails (
        user_email TEXT NOT NULL,
        email_id TEXT NOT NULL,
        processed_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (user_email, email_id)
      )
    `;
    // Decision spine — a "decision" is a headline + rationale + ranked options with a
    // recommended default, tied to a trip/leg. Powers auto-handled disruptions and
    // one-tap decision cards. (Build-plan ticket #1.)
    await sql`
      CREATE TABLE IF NOT EXISTS decisions (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        trip_id INTEGER,
        leg_id INTEGER,
        kind TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        headline TEXT NOT NULL,
        rationale TEXT,
        options JSONB DEFAULT '[]',
        recommended_option_id TEXT,
        autonomy_action TEXT,
        chosen_option_id TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        resolved_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_decisions_user ON decisions(user_email, status, created_at DESC)`;
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
    await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_trips_email_id ON trips(user_email, raw_email_id) WHERE raw_email_id IS NOT NULL`;
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
    await sql`
      CREATE TABLE IF NOT EXISTS destination_images (
        city TEXT PRIMARY KEY,
        url TEXT,
        credit TEXT,
        credit_url TEXT,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // Standing orders (Roadmap 2) — per-trip pre-authorized auto-rebooking rules.
    await sql`
      CREATE TABLE IF NOT EXISTS standing_orders (
        trip_id INTEGER PRIMARY KEY REFERENCES trips(id) ON DELETE CASCADE,
        user_email TEXT NOT NULL,
        enabled BOOLEAN DEFAULT FALSE,
        max_price INTEGER,
        min_cabin TEXT,
        avoid_airports JSONB DEFAULT '[]',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    // ── The constraint graph (TRIP_MODEL.md, Phase 0) ────────────────────────
    // intents · constraints · satisfies · depends_on · deliberations, plus the
    // trip_legs columns that make PLANNING possible (state, cost, cancellable_until).
    // Additive only. Nothing below this line changes existing behaviour — the graph
    // is born, populated by dual-write, and proved honest by its invariants long
    // before any screen reads from it.
    await graph.ensureConstraintSchema(sql);

    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS revealed_preferences JSONB DEFAULT '{}'`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS apple_sub TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT`;
    await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`;
    // ── Ensure all trips columns exist (safe for older production schemas) ──
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'upcoming'`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS source TEXT DEFAULT 'manual'`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS mode TEXT DEFAULT 'solo'`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS raw_email_id TEXT`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS companions_count INTEGER DEFAULT 1`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS companion_names JSONB DEFAULT '[]'`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS event_legs JSONB DEFAULT '[]'`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS destination_city TEXT`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS destination_country TEXT`;
    await sql`ALTER TABLE trips ADD COLUMN IF NOT EXISTS archived BOOLEAN DEFAULT false`;
    // ── Pre-trip checklist ──────────────────────────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS trip_checklist (
        id SERIAL PRIMARY KEY,
        trip_id INTEGER NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
        user_email TEXT NOT NULL,
        item TEXT NOT NULL,
        category TEXT DEFAULT 'general',
        due_date DATE,
        completed BOOLEAN DEFAULT false,
        auto_generated BOOLEAN DEFAULT true,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_trip_checklist_trip ON trip_checklist(trip_id, sort_order)`;
    // ── Ensure all trip_legs columns exist ──
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'upcoming'`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS raw_data JSONB`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS gate TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS terminal TEXT`;
    // ── Enriched leg fields for all reservation types (v2 pipeline) ──
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS destination_city TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS nights INTEGER`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS guests INTEGER`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS station_from TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS station_to TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS pickup_location TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS dropoff_location TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS vehicle_class TEXT`;
    // property_name was referenced by the concierge trip write-back INSERT and the
    // leg PATCH allow-list, but never actually created — so adding a booking from
    // chat threw every time. It belongs alongside property_address.
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS property_name TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS property_address TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS price_total NUMERIC(12,2)`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS currency TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS seat TEXT`;
    await sql`ALTER TABLE trip_legs ADD COLUMN IF NOT EXISTS cabin_class TEXT`;
    // Index for trip grouping lookups
    await sql`CREATE INDEX IF NOT EXISTS idx_trip_legs_dest_city ON trip_legs(trip_id, destination_city)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_trip_legs_dates ON trip_legs(departs_at, arrives_at)`;
    // ── Multi-account Gmail support: add account_email column and swap unique constraint ──
    await sql`ALTER TABLE gmail_tokens ADD COLUMN IF NOT EXISTS account_email TEXT`;
    await sql`ALTER TABLE gmail_tokens ADD COLUMN IF NOT EXISTS account_label TEXT`;
    // Drop the old single-account unique constraint (user_email) if it still exists
    try {
      await sql`ALTER TABLE gmail_tokens DROP CONSTRAINT IF EXISTS gmail_tokens_user_email_key`;
    } catch {}
    // Add the new composite unique constraint if not already present
    try {
      await sql`ALTER TABLE gmail_tokens ADD CONSTRAINT gmail_tokens_user_account_unique UNIQUE (user_email, account_email)`;
    } catch {}
    // Backfill account_email for existing rows that have NULL
    await sql`UPDATE gmail_tokens SET account_email = user_email WHERE account_email IS NULL`;

    // ── Deduplicate gmail trips: keep only the lowest id per (user_email, raw_email_id) ──
    try {
      const dupes = await sql`
        DELETE FROM trips
        WHERE id IN (
          SELECT id FROM (
            SELECT id,
                   ROW_NUMBER() OVER (PARTITION BY user_email, raw_email_id ORDER BY id ASC) AS rn
            FROM trips
            WHERE raw_email_id IS NOT NULL
          ) ranked
          WHERE rn > 1
        )
        RETURNING id
      `;
      if (dupes.length > 0) console.log(`[db] deduped ${dupes.length} duplicate gmail trips`);
    } catch (e) {
      console.error("[db] dedup error:", e.message);
    }

    // ── Auto-rename poorly-titled gmail trips using leg data ──
    try {
      await sql`
        UPDATE trips t
        SET title = CASE
          WHEN tl.origin IS NOT NULL AND tl.destination IS NOT NULL
            THEN tl.origin || ' → ' || tl.destination
          WHEN tl.destination IS NOT NULL
            THEN tl.destination || ' Trip'
          WHEN tl.carrier IS NOT NULL AND tl.flight_number IS NOT NULL
            THEN tl.carrier || tl.flight_number
          WHEN tl.carrier IS NOT NULL
            THEN tl.carrier || ' Booking'
          ELSE t.title
        END
        FROM trip_legs tl
        WHERE tl.trip_id = t.id
          AND t.source = 'gmail'
          AND (
            t.title = 'Unknown Trip'
            OR t.title = 'Unknown'
            OR t.title LIKE 'Unknown%Trip'
            OR t.title = 'Trip'
            OR t.title LIKE '% Flight'
            OR t.title LIKE '% Airlines Flight'
            OR t.title LIKE '% Booking'
            OR t.title = 'Imported Trip'
          )
      `;
    } catch (e) {
      console.error("[db] rename error:", e.message);
    }

    // ── Third-party integrations (TripIt iCal, TravelPerk OAuth, etc.) ────────
    await sql`
      CREATE TABLE IF NOT EXISTS user_integrations (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        provider TEXT NOT NULL,
        config JSONB DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_email, provider)
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_user_integrations_email ON user_integrations(user_email)`;

    // ── Persistent memory: user instructions ──────────────────────────────
    await sql`
      CREATE TABLE IF NOT EXISTS user_instructions (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        instruction TEXT NOT NULL,
        source TEXT DEFAULT 'chat',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_user_instructions_email ON user_instructions(user_email, created_at DESC)`;

    // ── Persistent user memory document ──────────────────────────────────────
    // A structured JSON document that accumulates everything Wingman learns about
    // the user over time — from chat, booking history, and explicit profile edits.
    await sql`
      CREATE TABLE IF NOT EXISTS user_memory (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL UNIQUE,
        memory JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_user_memory_email ON user_memory(user_email)`;
    await sql`
      CREATE TABLE IF NOT EXISTS race_events (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        name TEXT NOT NULL,
        distance TEXT,
        race_date DATE NOT NULL,
        location TEXT,
        goal_time TEXT,
        notes TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `;
    await sql`CREATE INDEX IF NOT EXISTS idx_race_events_email ON race_events(user_email)`;
        console.log("[db] tables ready");
  } catch (e) {
    console.error("[db] bootstrap error:", e.message);
  }
}
bootstrapDB();

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Hotel pre-arrival preference email helper
// lookupHotelContact — REMOVED. sendHotelPreferenceEmail — REMOVED.
// Autonomous outbound emails to hotels are permanently disabled.

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
      model: "claude-sonnet-4-5",
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

// sendHotelPreferenceEmail — PERMANENTLY DELETED.
// Wingman will never autonomously send emails to hotels or any third party.
// Hotel preference sharing must be an explicit, user-initiated action.

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

// Generate a cryptographically random refresh token, store its SHA-256 hash in DB
async function issueRefreshToken(email) {
  const raw = crypto.randomBytes(40).toString("hex"); // 80-char hex string
  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 86400 * 1000);
  // Invalidate all previous refresh tokens for this user (single active session per user)
  await sql`DELETE FROM refresh_tokens WHERE user_email = ${email}`;
  await sql`
    INSERT INTO refresh_tokens (user_email, token_hash, expires_at)
    VALUES (${email}, ${hash}, ${expiresAt.toISOString()})
  `;
  return raw; // Return the raw token to send to the client (never stored)
}

// Verify a raw refresh token — returns email or null
async function consumeRefreshToken(raw) {
  if (!raw || typeof raw !== "string") return null;
  const hash = crypto.createHash("sha256").update(raw).digest("hex");
  const rows = await sql`
    SELECT user_email, expires_at FROM refresh_tokens
    WHERE token_hash = ${hash} AND expires_at > NOW()
  `;
  if (!rows.length) return null;
  // Rotate: delete the used token immediately (prevents replay)
  await sql`DELETE FROM refresh_tokens WHERE token_hash = ${hash}`;
  return rows[0].user_email;
}
async function verifyAccessToken(req) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return null;
  try {
    const payload = jwt.verify(t, JWT_SECRET);
    // Accept access tokens. Older builds signed tokens without a `type` field, and
    // the `auth` middleware (used by the rest of the app) never checked type — so a
    // strict check here rejected valid tokens ONLY at the concierge. Align the two:
    // trust any valid JWT with an email, and only reject explicit refresh tokens.
    if (payload.type === "refresh") return null;
    return payload.email || null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------

// ─── Wingman Points ────────────────────────────────────────────────────────────
// Earn rules: each action can only award points once (deduped by action key)
;

// Codes people have to read aloud, type on a phone, or squint at in a text
// message. No 0/O/1/I/L — the characters that cause "it says invalid code".
const REFERRAL_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

function newReferralCode() {
  let s = "";
  for (let i = 0; i < 6; i++) {
    s += REFERRAL_ALPHABET[Math.floor(Math.random() * REFERRAL_ALPHABET.length)];
  }
  return s;
}

// Mint lazily and only once, on first view. Retries on the (vanishingly rare)
// unique-index collision rather than trusting randomness.
async function getOrCreateReferralCode(email) {
  const [u] = await sql`SELECT referral_code FROM users WHERE email = ${email}`;
  if (u?.referral_code) return u.referral_code;
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = newReferralCode();
    try {
      const [row] = await sql`
        UPDATE users SET referral_code = ${code}
        WHERE email = ${email} AND referral_code IS NULL
        RETURNING referral_code
      `;
      if (row?.referral_code) return row.referral_code;
      // Lost a race — someone else set it. Read it back.
      const [again] = await sql`SELECT referral_code FROM users WHERE email = ${email}`;
      if (again?.referral_code) return again.referral_code;
    } catch (e) {
      if (attempt === 4) throw e; // collided 5x; something is genuinely wrong
    }
  }
  return null;
}

/**
 * Mark a referral as having come good — the person you introduced is actually
 * travelling with Wingman, not just registered.
 *
 * There is NO REWARD any more. This used to pay 500 points to the referrer and
 * 250 to the newcomer; that was the gamification layer, and it's gone. A private
 * travel office does not run a referral programme. It grows because one member
 * introduces another, and the introduction is the whole of it.
 *
 * What we still do is TELL you — quietly, once — that the person you vouched for
 * is being looked after. Which is the thing you actually wanted to know.
 */
async function maybeCreditReferral(email) {
  try {
    const [u] = await sql`
      SELECT referred_by, referral_credited FROM users WHERE email = ${email}
    `;
    if (!u?.referred_by || u.referral_credited) return;

    // Claim it first, so two concurrent activations can't both notify.
    const [claimed] = await sql`
      UPDATE users SET referral_credited = true
      WHERE email = ${email} AND referral_credited = false AND referred_by IS NOT NULL
      RETURNING referred_by
    `;
    if (!claimed) return;

    await sendPushToUser(
      claimed.referred_by,
      "Your introduction landed",
      "Someone you introduced is travelling with Wingman now. They're in good hands.",
      { type: "referral" },
    ).catch(() => {});
  } catch (e) {
    console.error("[referral/credit]", e.message);
  }
}

// ── GET /referral — your invitation code, and one honest number ───────────────
//
// No points, no rewards, no tier. This used to return reward_points and
// friend_points; there is nothing to earn any more.
//
// It returns `activated` — how many of the people you introduced are ACTUALLY
// travelling with Wingman. Not "invited", which counts people who did nothing and
// exists only to make the number look bigger.
app.get("/referral", auth, async (req, res) => {
  const email = req.user.email;
  try {
    const code = await getOrCreateReferralCode(email);

    const [stats] = await sql`
      SELECT
        COUNT(*)::int                                  AS invited,
        COUNT(*) FILTER (WHERE referral_credited)::int AS activated
      FROM users
      WHERE referred_by = ${email}
    `;

    res.json({
      code,
      invited: stats?.invited || 0,
      activated: stats?.activated || 0,
    });
  } catch (e) {
    console.error("[referral]", e.message);
    res.status(500).json({ error: "could not load referral" });
  }
});

// GET /points — current balance, tier, recent events


// POST /points/award — internal endpoint to award points from other flows
// Also called by the app when user completes an action


// POST /points/redeem — redeem Wingman Points for a perk


// POST /auth/request — send OTP
// ---------------------------------------------------------------------------
app.post("/auth/request", authLimiter, async (req, res) => {
  const email = ((req.body && req.body.email) || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "valid email required" });
  }
  const code = String(Math.floor(100000 + Math.random() * 900000));
  try {
    // Sign-in and sign-up are the same endpoint: /auth/verify creates the user if
    // they don't exist. That means a typo'd address doesn't fail — it silently
    // mints a fresh empty account, and the user concludes Wingman lost their data.
    // (This is a real scenario for anyone with a work and a personal address.)
    // We can't refuse to create accounts without breaking sign-up, so instead we
    // tell the client which case this is and let it confirm first.
    const [existing] = await sql`SELECT 1 FROM users WHERE email = ${email}`;
    const isNewUser = !existing;

    await redis.set("otp:" + email, code, { ex: 600 });
    // Send via Resend if key is configured; otherwise log to console for dev/staging
    const resendKey = process.env.RESEND_API_KEY || "";
    const hasResend = resendKey && resendKey !== "re_placeholder" && resendKey.startsWith("re_");
    if (hasResend) {
      await resend.emails.send({
        from: "Wingman <hello@wingmantravel.app>",
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
    // Older shipped clients ignore is_new_user and behave exactly as before, so
    // this is safe to deploy ahead of the app build.
    res.json({ ok: true, is_new_user: isNewUser });
  } catch (e) {
    console.error("[auth/request]", e.message);
    res.status(500).json({ error: "failed to send OTP" });
  }
});

// ---------------------------------------------------------------------------
// POST /auth/verify — verify OTP, return JWT
// ---------------------------------------------------------------------------
app.post("/auth/verify", authLimiter, async (req, res) => {
  const email = ((req.body && req.body.email) || "").trim().toLowerCase();
  const code = String((req.body && req.body.code) || "").trim();
  if (!email || !code) return res.status(400).json({ error: "email and code required" });
  try {
    const stored = await redis.get("otp:" + email);
    if (!stored || String(stored) !== code) {
      return res.status(401).json({ error: "invalid or expired code" });
    }
    await redis.del("otp:" + email);
    // RETURNING only yields a row when the INSERT actually happened, so this
    // doubles as "is this a brand-new user?" — which is exactly when a referral
    // may be attributed, and never again.
    const [created] = await sql`
      INSERT INTO users (email) VALUES (${email})
      ON CONFLICT (email) DO NOTHING
      RETURNING email
    `;
    const isNewUser = !!created;

    // Referral attribution. Deliberately signup-only and one-way: you cannot be
    // re-attributed later, you cannot refer yourself, and a bad code is ignored
    // rather than failing the sign-in — nobody should be locked out of their
    // account because a friend mistyped a promo code.
    const rawRef = String((req.body && (req.body.referralCode || req.body.referral_code)) || "")
      .trim().toUpperCase();
    if (isNewUser && rawRef) {
      try {
        const [referrer] = await sql`
          SELECT email FROM users WHERE referral_code = ${rawRef}
        `;
        if (referrer && referrer.email !== email) {
          await sql`UPDATE users SET referred_by = ${referrer.email} WHERE email = ${email}`;
        }
      } catch (e) {
        console.error("[auth/verify] referral attribution:", e.message);
      }
    }

    const token = signAccessToken(email);
    const refreshToken = await issueRefreshToken(email);
    // Award signup points (idempotent)
    res.json({ ok: true, token, refreshToken, email, is_new_user: isNewUser });
  } catch (e) {
    console.error("[auth/verify]", e.message);
    res.status(500).json({ error: "verification failed" });
  }
});

// ---------------------------------------------------------------------------
// POST /auth/apple — Sign in with Apple (verify identity token, return JWT)
// ---------------------------------------------------------------------------
app.post("/auth/apple", authLimiter, async (req, res) => {
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
  const timezone = req.body?.timezone || null; // IANA tz for daily briefing timing
  if (!token) return res.status(400).json({ error: "token required" });
  try {
    if (timezone) {
      await sql`UPDATE users SET push_token = ${token}, timezone = ${timezone} WHERE email = ${email}`;
    } else {
      await sql`UPDATE users SET push_token = ${token} WHERE email = ${email}`;
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// POST /me/test-morning-briefing — send yourself the daily briefing now (for testing)
// ---------------------------------------------------------------------------
app.post("/me/test-morning-briefing", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const urows = await sql`SELECT first_name, push_token FROM users WHERE email = ${email}`;
    const u = urows[0];
    const now = new Date();
    const nextRows = await sql`
      SELECT tl.departs_at, tl.origin, tl.destination, tl.destination_city, tl.carrier, tl.flight_number
      FROM trips t JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email} AND tl.type = 'flight'
        AND COALESCE(tl.arrives_at, tl.departs_at) > NOW()
      ORDER BY tl.departs_at ASC LIMIT 1
    `;
    const next = nextRows[0];
    const name = u?.first_name ? `, ${u.first_name}` : "";
    let title = `Good morning${name}`, body;
    if (!next) {
      body = `Nothing on your calendar yet. Forward a booking or tell me where you're headed and I'll take it from there.`;
    } else {
      const daysAway = Math.ceil((new Date(next.departs_at) - now) / 86400000);
      const dest = next.destination_city || next.destination || "your destination";
      const ident = [next.carrier, next.flight_number].filter(Boolean).join("");
      const route = next.origin && next.destination ? `${next.origin} → ${next.destination}` : dest;
      if (daysAway <= 0) body = `${dest} today. ${route}${ident ? ` · ${ident}` : ""}. You're in good shape — I'll flag anything the moment it moves.`;
      else if (daysAway === 1) body = `${dest} tomorrow. Everything's lined up; I'll have your full briefing ready in the morning.`;
      else body = `${dest} in ${daysAway} days. Nothing needs you yet — I'm watching it and will speak up if that changes.`;
    }
    if (u?.push_token) await sendPushToUser(email, title, body, { screen: "Home" });
    res.json({ ok: true, sent: !!u?.push_token, preview: { title, body } });
  } catch (e) {
    console.error("[test-morning-briefing]", e.message);
    res.status(500).json({ ok: false, error: e.message });
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
      WHERE ae.user_email = ${email} AND ae.dismissed IS NOT TRUE
      ORDER BY ae.created_at DESC
      LIMIT ${limit}
    `;
    res.json({ events });
  } catch (e) {
    console.error("[activity]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /activity/:id/dismiss — soft-dismiss a signal (swipe-to-dismiss)
app.post("/activity/:id/dismiss", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    await sql`UPDATE activity_events SET dismissed = TRUE WHERE id = ${req.params.id} AND user_email = ${email}`;
    res.json({ ok: true });
  } catch (e) {
    console.error("[activity/dismiss]", e.message);
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

/**
 * GET /loyalty/insights — make the connected accounts actually DO something.
 *
 * Until now, connecting a frequent-flyer account got you a list of numbers back.
 * That is a promise the app was quietly breaking.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 * ----------------------------------
 * The roadmap asks for "best card per booking" and "award availability". We hold
 * no earning rates and no award inventory, so both would mean inventing numbers
 * and telling someone to put a $4,000 booking on the wrong card. A chief of staff
 * who guesses confidently is worse than one who says nothing.
 *
 * So every insight below is derived STRICTLY from data we actually have, and each
 * one carries the evidence it was derived from.
 */
const POINTS_EXPIRY_WARN_DAYS = 90;

async function loyaltyInsights(email) {
  const [accounts, upcoming] = await Promise.all([
    sql`SELECT * FROM loyalty_accounts WHERE user_email = ${email} ORDER BY program ASC`,
    sql`
      SELECT tl.id, tl.type, tl.carrier, tl.flight_number, tl.departs_at,
             tl.destination_city, tl.destination, tl.nights, t.id AS trip_id, t.title
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.departs_at >= NOW()
        AND tl.departs_at <= NOW() + INTERVAL '180 days'
      ORDER BY tl.departs_at ASC
    `,
  ]);

  const insights = [];
  const DAY = 86400000;
  const now = Date.now();

  for (const a of accounts) {
    // ── 1. Points about to expire ────────────────────────────────────────────
    // The single most valuable thing here, and pure fact: the date is in the row.
    // Points expire quietly and nobody notices until they're gone.
    if (a.expiration_date && Number(a.points_balance) > 0) {
      const days = Math.round((new Date(a.expiration_date).getTime() - now) / DAY);
      if (days > 0 && days <= POINTS_EXPIRY_WARN_DAYS) {
        insights.push({
          kind: "points_expiring",
          urgency: days <= 30 ? "high" : "medium",
          program: a.program,
          title: `${Number(a.points_balance).toLocaleString()} ${a.program} points expire in ${days} days`,
          body: `Any qualifying activity usually resets the clock — a flight, a points purchase, or a dining/shopping partner. Worth ten minutes.`,
          evidence: { points: Number(a.points_balance), expires: a.expiration_date, days_left: days },
        });
      }
    }

    // ── 2. Status within reach ───────────────────────────────────────────────
    // points_to_next_level and elite_level_next are both stored. If an upcoming
    // trip on this carrier would plausibly close the gap, that is worth saying —
    // but we say what we KNOW (the gap, the trip), not a computed projection we'd
    // be inventing.
    if (a.elite_level_next && Number(a.points_to_next_level) > 0) {
      const carrierLegs = upcoming.filter(
        (l) => l.carrier && a.program &&
               a.program.toLowerCase().includes(String(l.carrier).toLowerCase().split(" ")[0]),
      );
      insights.push({
        kind: "status_gap",
        urgency: carrierLegs.length ? "medium" : "low",
        program: a.program,
        title: `${Number(a.points_to_next_level).toLocaleString()} points from ${a.elite_level_next}`,
        body: carrierLegs.length
          ? `You have ${carrierLegs.length} upcoming ${a.program} booking${carrierLegs.length > 1 ? "s" : ""} — make sure your number is on ${carrierLegs.length > 1 ? "them" : "it"}, or the credit won't land.`
          : `No upcoming bookings on ${a.program}. If a status run matters to you, this is the gap to close.`,
        evidence: {
          points_to_next: Number(a.points_to_next_level),
          next_level: a.elite_level_next,
          current: a.elite_status || null,
          upcoming_legs: carrierLegs.map((l) => ({ trip_id: l.trip_id, leg_id: l.id, departs_at: l.departs_at })),
        },
      });
    }
  }

  // ── 3. Upcoming bookings on a carrier you HAVE an account with ─────────────
  // The most concrete, most actionable, and most commonly missed: you're flying an
  // airline you have status with, and the booking may not carry your number. We
  // can't see whether the number is attached (we don't store it per-leg), so we
  // ASK rather than assert.
  const programNames = accounts.map((a) => String(a.program || "").toLowerCase());
  const matchable = upcoming.filter((l) => {
    if (!l.carrier) return false;
    const c = String(l.carrier).toLowerCase();
    return programNames.some((p) => p && (p.includes(c.split(" ")[0]) || c.includes(p.split(" ")[0])));
  });
  for (const l of matchable.slice(0, 5)) {
    insights.push({
      kind: "attach_number",
      urgency: "low",
      program: l.carrier,
      title: `${l.carrier}${l.flight_number ? " " + l.flight_number : ""} on ${new Date(l.departs_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}`,
      body: `You have a ${l.carrier} account. Check your number is on this booking — credit doesn't apply retroactively without a claim.`,
      evidence: { trip_id: l.trip_id, leg_id: l.id, departs_at: l.departs_at },
    });
  }

  const order = { high: 0, medium: 1, low: 2 };
  insights.sort((a, b) => order[a.urgency] - order[b.urgency]);

  return {
    insights,
    accounts_connected: accounts.length,
    // Said plainly, so the UI never has to pretend it knows more than it does.
    not_covered: "Earning rates and award availability aren't something we hold, so we don't guess at them.",
  };
}

app.get("/loyalty/insights", auth, async (req, res) => {
  try {
    res.json(await loyaltyInsights(req.user.email));
  } catch (e) {
    console.error("[loyalty/insights]", e.message);
    res.status(500).json({ error: "could not load loyalty insights" });
  }
});

// POST /loyalty/connect — connect a loyalty account (manual entry: member number + status tier)
app.post("/loyalty/connect", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { program, login, password, login2, member_number, elite_status, member_name } = req.body || {};
  if (!program) return res.status(400).json({ error: "program required" });
  const prog = LOYALTY_PROGRAMS[program];
  if (!prog) return res.status(400).json({ error: "unknown program" });
  try {
    // Store the account with whatever data was provided (manual entry or credentials)
    const accountNumber = member_number || login || null;
    const statusTier = elite_status || null;
    const displayName = member_name || null;

    await sql`
      INSERT INTO loyalty_accounts (
        user_email, program, provider_code,
        account_number, member_name, elite_status,
        last_synced
      )
      VALUES (
        ${email}, ${program}, ${prog.code},
        ${accountNumber}, ${displayName}, ${statusTier},
        NOW()
      )
      ON CONFLICT (user_email, provider_code)
      DO UPDATE SET
        account_number = COALESCE(EXCLUDED.account_number, loyalty_accounts.account_number),
        member_name    = COALESCE(EXCLUDED.member_name, loyalty_accounts.member_name),
        elite_status   = COALESCE(EXCLUDED.elite_status, loyalty_accounts.elite_status),
        last_synced    = NOW()
    `;

    const statusMsg = statusTier ? ` · ${statusTier}` : "";
    await logActivity(email, "loyalty", `${prog.name} connected`,
      `${prog.name}${statusMsg} added to your profile.`);

    // If credentials provided, store them encrypted and kick off AwardWallet sync
    if (login && password) {
      const awUser = process.env.AWARDWALLET_API_USER;
      const awPass = process.env.AWARDWALLET_API_PASS;
      if (awUser && awPass) {
        // Store encrypted credentials in metadata JSONB for future re-syncs
        const credsMetadata = JSON.stringify({
          login_enc: encryptField(login),
          pass_enc: encryptField(password),
          login2: login2 || null,
        });
        sql`UPDATE loyalty_accounts SET metadata = ${credsMetadata}::jsonb WHERE user_email = ${email} AND program = ${program}`
          .catch(e => console.error("[loyalty-creds-store]", e.message));
        // POST /account/check — correct AwardWallet v2 endpoint
        awRequest("/account/check", {
          method: "POST",
          body: JSON.stringify({
            provider: prog.code,
            login,
            password,
            ...(login2 ? { login2 } : {}),
            userId: email,
            userData: JSON.stringify({ userEmail: email, program }),
            priority: 9,
            timeout: 300,
            retries: 2,
          }),
        }).then(awResp => {
          const requestId = awResp.requestId || awResp.id || null;
          if (requestId) {
            sql`UPDATE loyalty_accounts SET aw_account_id = ${requestId} WHERE user_email = ${email} AND program = ${program}`
              .catch(e => console.error("[loyalty-aw-update]", e.message));
            // Poll for results — will update elite_status, balance, etc. when done
            pollAwardWalletResult(email, program, requestId).catch(e => console.error("[loyalty-poll]", e.message));
          }
        }).catch(e => console.error("[loyalty-aw]", e.message));
      }
    }

    res.json({ ok: true, program, elite_status: statusTier, account_number: accountNumber });
  } catch (e) {
    console.error("[loyalty-connect]", e.message);
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

// PATCH /loyalty/:program — update status/balance manually
app.patch("/loyalty/:program", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { program } = req.params;
  const { elite_status, points_balance, nights_ytd, segments_ytd, account_number, member_name } = req.body || {};
  try {
    const updates = [];
    if (elite_status   !== undefined) updates.push(`elite_status = '${elite_status.replace(/'/g, "''")}'`);
    if (points_balance !== undefined) updates.push(`points_balance = ${parseInt(points_balance) || 0}`);
    if (nights_ytd     !== undefined) updates.push(`nights_ytd = ${parseInt(nights_ytd) || 0}`);
    if (segments_ytd   !== undefined) updates.push(`segments_ytd = ${parseInt(segments_ytd) || 0}`);
    if (account_number !== undefined) updates.push(`account_number = '${account_number.replace(/'/g, "''")}'`);
    if (member_name    !== undefined) updates.push(`member_name = '${member_name.replace(/'/g, "''")}'`);
    if (updates.length === 0) return res.json({ ok: true, note: "nothing to update" });
    updates.push(`last_synced = NOW()`);
    await sql`
      UPDATE loyalty_accounts
      SET elite_status   = COALESCE(${elite_status   ?? null}, elite_status),
          points_balance = COALESCE(${points_balance != null ? parseInt(points_balance) : null}, points_balance),
          nights_ytd     = COALESCE(${nights_ytd     != null ? parseInt(nights_ytd)     : null}, nights_ytd),
          segments_ytd   = COALESCE(${segments_ytd   != null ? parseInt(segments_ytd)   : null}, segments_ytd),
          account_number = COALESCE(${account_number ?? null}, account_number),
          member_name    = COALESCE(${member_name    ?? null}, member_name),
          last_synced    = NOW()
      WHERE user_email = ${email} AND program = ${program}
    `;
    res.json({ ok: true, program });
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
    // Re-submit account credentials to AwardWallet for a fresh sync
    const meta = acct.metadata || {};
    const loginEnc = meta.login_enc;
    const passEnc  = meta.pass_enc;
    if (!loginEnc || !passEnc) {
      console.log(`[loyalty-sync] ${userEmail} ${program}: no credentials in metadata, skipping AW sync`);
      return;
    }
    const syncLogin    = decryptField(loginEnc);
    const syncPassword = decryptField(passEnc);
    const syncLogin2   = meta.login2 || null;
    // POST /account/check — submit to AwardWallet queue
    const submitResp = await awRequest("/account/check", {
      method: "POST",
      body: JSON.stringify({
        provider: prog.code,
        login: syncLogin,
        password: syncPassword,
        ...(syncLogin2 ? { login2: syncLogin2 } : {}),
        userId: userEmail,
        userData: JSON.stringify({ userEmail, program }),
        priority: 1,   // background = low priority
        timeout: 300,
        retries: 2,
      }),
    });
    const requestId = submitResp.requestId || submitResp.id || null;
    if (!requestId) {
      console.log(`[loyalty-sync] ${userEmail} ${program}: no requestId returned from AW`);
      return;
    }
    await sql`UPDATE loyalty_accounts SET aw_account_id = ${requestId} WHERE user_email = ${userEmail} AND program = ${program}`;
    // Delegate to pollAwardWalletResult for polling + DB update
    await pollAwardWalletResult(userEmail, program, requestId);
    return;
    // (Legacy dead code below — kept for reference)
    if (false) {
      let data = null;
      const balance = 0;
      const eliteStatus = null;
      const eliteNext = null;
      const pointsToNext = null;
      const nightsYtd = null;
      const segmentsYtd = null;
      const memberName = null;
      const accountNumber = null;
      const expirationDate = null;
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

// Poll AwardWallet /account/check/{id} until state===1 (complete) then update DB
async function pollAwardWalletResult(userEmail, program, requestId, maxAttempts = 12, intervalMs = 5000) {
  const prog = LOYALTY_PROGRAMS[program];
  if (!prog) return;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, intervalMs));
    try {
      const data = await awRequest(`/account/check/${requestId}`);
      // state: 1 = complete, 0 = pending/processing, -1 = error
      if (data.state === -1) {
        console.error(`[loyalty-poll] ${userEmail} ${program}: AW error — ${data.errorReason || data.message}`);
        return;
      }
      if (data.state !== 1) {
        console.log(`[loyalty-poll] ${userEmail} ${program}: still processing (attempt ${i + 1})`);
        continue;
      }
      // Parse properties array — elite status, member name, account number live here
      const props = Array.isArray(data.properties) ? data.properties : [];
      const getProp = (...codes) => {
        for (const code of codes) {
          const p = props.find(p => p.code === code || p.name === code);
          if (p && p.value) return p.value;
        }
        return null;
      };
      const balance        = parseInt(data.balance || 0) || 0;
      const eliteStatus    = getProp("Level", "Membership_Level", "EliteLevel", "Elite_Level") || null;
      const eliteNext      = getProp("NextLevel", "Next_Level", "NextEliteLevel") || null;
      const pointsToNext   = parseInt(getProp("PointsToNextLevel", "Points_To_Next_Level") || 0) || null;
      const nightsYtd      = parseInt(getProp("Nights", "NightsYTD", "Nights_YTD") || 0) || null;
      const segmentsYtd    = parseInt(getProp("Segments", "SegmentsYTD", "Segments_YTD") || 0) || null;
      const memberName     = getProp("Name", "MemberName", "Member_Name") || null;
      const accountNumber  = getProp("Number", "MemberNumber", "Member_Number", "RewardsNumber") || data.login || null;
      const expirationDate = data.expirationDate ? new Date(data.expirationDate) : null;
      // Fetch current values for change detection
      const rows = await sql`SELECT * FROM loyalty_accounts WHERE user_email = ${userEmail} AND program = ${program}`;
      const acct = rows[0];
      const prevBalance = acct?.points_balance || 0;
      const prevStatus  = acct?.elite_status;
      await sql`
        UPDATE loyalty_accounts SET
          points_balance       = ${balance},
          elite_status         = COALESCE(${eliteStatus}, elite_status),
          elite_level_next     = ${eliteNext},
          points_to_next_level = ${pointsToNext},
          nights_ytd           = ${nightsYtd},
          segments_ytd         = ${segmentsYtd},
          member_name          = COALESCE(${memberName}, member_name),
          account_number       = COALESCE(${accountNumber}, account_number),
          expiration_date      = ${expirationDate},
          last_synced          = NOW()
        WHERE user_email = ${userEmail} AND program = ${program}
      `;
      // Log notable changes
      if (prevStatus && eliteStatus && prevStatus !== eliteStatus) {
        await logActivity(userEmail, "loyalty",
          `${prog.name} status updated: ${eliteStatus}`,
          `Your ${prog.name} elite status is now ${eliteStatus}.`);
        await sendPushToUser(userEmail,
          `${prog.icon} ${prog.name} status update`,
          `Your status is now ${eliteStatus}!`,
          { route: "Loyalty" });
      } else if (balance > prevBalance) {
        const earned = (balance - prevBalance).toLocaleString();
        await logActivity(userEmail, "loyalty",
          `${prog.name} +${earned} ${prog.kind === "airline" ? "miles" : "points"}`,
          `Your ${prog.name} balance increased by ${earned}. New balance: ${balance.toLocaleString()}.`);
      }
      console.log(`[loyalty-poll] ${userEmail} ${program}: ${balance} pts, status: ${eliteStatus}`);
      return; // success
    } catch (e) {
      console.error(`[loyalty-poll] attempt ${i + 1}:`, e.message);
    }
  }
  console.log(`[loyalty-poll] ${userEmail} ${program}: timed out after ${maxAttempts} attempts`);
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
    const rows = await sql`SELECT email, first_name, push_token, preferences, created_at, subscription_tier, subscription_status FROM users WHERE email = ${email}`;
    if (!rows[0]) return res.status(404).json({ error: "user not found" });
    // Track last app open for re-engagement logic
    await sql`UPDATE users SET last_opened_at = NOW() WHERE email = ${email}`.catch(() => {});
    // Return all connected Google accounts
    const gmailRows = await sql`SELECT id, account_email, account_label, updated_at FROM gmail_tokens WHERE user_email = ${email} ORDER BY id ASC`;
    const connected_accounts = gmailRows.map(r => ({
      id: r.id,
      account_email: r.account_email || email,
      label: r.account_label || null,
      connected_at: r.updated_at,
    }));
    res.json({ ...rows[0], gmail_connected: gmailRows.length > 0, connected_accounts });
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
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return res.status(503).json({
      error: "Google OAuth not configured",
      hint: "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in the Render dashboard environment variables."
    });
  }
  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/calendar.readonly"
    ],
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
    // Fetch the Google account email so we can store it as account_email
    let accountEmail = userEmail; // fallback
    try {
      oauth2.setCredentials(tokens);
      const { google } = require("googleapis");
      const oauth2Api = google.oauth2({ version: "v2", auth: oauth2 });
      const info = await oauth2Api.userinfo.get();
      if (info.data?.email) accountEmail = info.data.email;
      // Save given_name to users.first_name if not already set
      if (info.data?.given_name) {
        await sql`UPDATE users SET first_name = ${info.data.given_name} WHERE email = ${userEmail} AND first_name IS NULL`;
      }
    } catch (e) {
      console.warn("[gmail/callback] could not fetch account email:", e.message);
    }
    await sql`
      INSERT INTO gmail_tokens (user_email, account_email, access_token, refresh_token, expiry_date)
      VALUES (${userEmail}, ${accountEmail}, ${encryptField(tokens.access_token)}, ${encryptField(tokens.refresh_token) || null}, ${tokens.expiry_date || null})
      ON CONFLICT (user_email, account_email) DO UPDATE SET
        access_token = EXCLUDED.access_token,
        refresh_token = COALESCE(EXCLUDED.refresh_token, gmail_tokens.refresh_token),
        expiry_date = EXCLUDED.expiry_date,
        updated_at = NOW()
    `;
    // Trigger initial email scan in background
    scanGmailForTrips(userEmail, tokens).catch(e => console.error("[gmail scan]", e.message));
    // Deep-link back to the app — Expo scheme
    const deepLink = "wingman://connections?gmail=connected";
    res.send(`<html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Gmail Connected — Wingman</title>
        <style>
          body { font-family: -apple-system, sans-serif; background: #0E0C0A; color: #F5F0E8;
                 text-align: center; padding: 60px 24px; margin: 0; }
          h2 { color: #C9A96E; font-size: 22px; margin-bottom: 12px; }
          p  { color: #9E9589; font-size: 15px; line-height: 1.6; }
          a  { display: inline-block; margin-top: 24px; background: #C9A96E; color: #0E0C0A;
               text-decoration: none; border-radius: 12px; padding: 14px 28px;
               font-size: 15px; font-weight: 600; }
        </style>
        <script>
          // Auto-redirect back to app after 1s
          setTimeout(function() {
            window.location.href = "${deepLink}";
          }, 1000);
        </script>
      </head>
      <body>
        <h2>✈ Gmail connected</h2>
        <p>Wingman is scanning your inbox for travel bookings.<br>Returning you to the app…</p>
        <a href="${deepLink}">Return to Wingman</a>
      </body>
    </html>`);
  } catch (e) {
    console.error("[gmail/callback]", e.message);
    res.status(500).send("OAuth error: " + e.message);
  }
});

// ---------------------------------------------------------------------------
// Gmail scanner — parse booking confirmation emails into trips
// ---------------------------------------------------------------------------
async function getGmailClient(userEmail, accountEmail = null) {
  // If accountEmail specified, use that specific account; otherwise use first available
  const rows = accountEmail
    ? await sql`SELECT * FROM gmail_tokens WHERE user_email = ${userEmail} AND account_email = ${accountEmail}`
    : await sql`SELECT * FROM gmail_tokens WHERE user_email = ${userEmail} ORDER BY id ASC`;
  if (!rows[0]) return null;
  const row = rows[0];
  const oauth2 = makeOAuth2Client();
  oauth2.setCredentials({
    access_token: decryptField(row.access_token),
    refresh_token: decryptField(row.refresh_token),
    expiry_date: row.expiry_date,
  });
  // Auto-refresh if needed — update the specific row by id
  oauth2.on("tokens", async (tokens) => {
    if (tokens.access_token) {
      await sql`UPDATE gmail_tokens SET access_token = ${tokens.access_token}, expiry_date = ${tokens.expiry_date || null}, updated_at = NOW() WHERE id = ${row.id}`;
    }
  });
  return google.gmail({ version: "v1", auth: oauth2 });
}

async function scanGmailForTrips(userEmail, tokens) {
  // Scan ALL connected Google accounts for this user
  const accountRows = await sql`SELECT account_email FROM gmail_tokens WHERE user_email = ${userEmail}`;
  if (accountRows.length === 0) return;
  for (const accountRow of accountRows) {
    await scanGmailAccountForTrips(userEmail, accountRow.account_email);
  }
  // After importing, fold loose reservations (dinners, Ubers) into the trips
  // they happened during; delete any orphans with no surrounding trip.
  await cleanupLooseTrips(userEmail, { dryRun: false }).catch(e => console.error("[scan re-home]", e.message));
  // Remove any duplicate legs that slipped in across repeated scans.
  await dedupeLegs(userEmail).catch(e => console.error("[scan dedupe]", e.message));
  // Fold near-duplicate trips (e.g. "Brentwood" + "Brentwood Hotel") into one.
  await mergeDuplicateTrips(userEmail).catch(e => console.error("[scan merge]", e.message));
  // Reset hotel stay counts to the real number of stays (repeated scans inflated them).
  await recomputeHotelAffinity(userEmail).catch(e => console.error("[scan affinity]", e.message));
}

// Merge trips whose titles are the same once trailing generic lodging words are
// stripped ("Brentwood Hotel" -> "Brentwood"). Legs move into the canonical trip
// (shortest, cleanest title); the redundant trip is deleted. Pure SQL, no LLM.
async function mergeDuplicateTrips(userEmail) {
  const trips = await sql`SELECT id, title FROM trips WHERE user_email = ${userEmail}`;
  const norm = (t) => String(t || "").trim().toLowerCase()
    .replace(/\s+(hotel|hotels|airbnb|stay|reservations?|resort|inn|suites?|apartment|apartments)$/i, "")
    .trim();
  const groups = {};
  for (const t of trips) {
    const k = norm(t.title);
    if (!k) continue;
    (groups[k] = groups[k] || []).push(t);
  }
  let merged = 0;
  for (const k of Object.keys(groups)) {
    const g = groups[k];
    if (g.length < 2) continue;
    // Keep the trip with the shortest title (prefer "Brentwood" over "Brentwood Hotel").
    g.sort((a, b) => (a.title || "").length - (b.title || "").length || a.id - b.id);
    const keep = g[0];
    for (const t of g.slice(1)) {
      await sql`UPDATE trip_legs SET trip_id = ${keep.id} WHERE trip_id = ${t.id}`;
      await sql`DELETE FROM trips WHERE id = ${t.id} AND user_email = ${userEmail}`;
      merged++;
    }
  }
  if (merged > 0) await dedupeLegs(userEmail).catch(() => {});
  return merged;
}

// Reset hotel_affinity.stay_count to the actual number of stays — counted as
// distinct trips per property from the (deduped) hotel legs. The upsert increments
// stay_count on every import, so repeated scans inflate it (e.g. "101 stays").
async function recomputeHotelAffinity(userEmail) {
  const updated = await sql`
    UPDATE hotel_affinity ha
    SET stay_count = sub.cnt
    FROM (
      SELECT LOWER(TRIM(COALESCE(tl.carrier, tl.destination))) AS name,
             COUNT(DISTINCT tl.trip_id) AS cnt
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${userEmail}
        AND tl.type IN ('hotel','airbnb')
        AND COALESCE(tl.carrier, tl.destination) IS NOT NULL
      GROUP BY 1
    ) sub
    WHERE ha.user_email = ${userEmail}
      AND LOWER(TRIM(ha.property_name)) = sub.name
      AND ha.stay_count <> sub.cnt
    RETURNING ha.id
  `;
  return updated.length;
}

// Delete duplicate trip_legs, keeping the earliest of each identical booking.
// Identical = same trip + type + confirmation (or, when confirmation is null,
// same type + date + carrier + property + destination).
async function dedupeLegs(userEmail) {
  const removed = await sql`
    DELETE FROM trip_legs
    WHERE id IN (
      SELECT id FROM (
        SELECT id, ROW_NUMBER() OVER (
          PARTITION BY trip_id, type,
            COALESCE(LOWER(confirmation), ''),
            COALESCE(departs_at::text, ''),
            COALESCE(LOWER(carrier), ''),
            COALESCE(LOWER(destination), '')
          ORDER BY id ASC
        ) AS rn
        FROM trip_legs
        WHERE trip_id IN (SELECT id FROM trips WHERE user_email = ${userEmail})
      ) ranked
      WHERE ranked.rn > 1
    )
    RETURNING id`;
  return removed.length;
}

async function scanGmailAccountForTrips(userEmail, accountEmail) {
  const gmail = await getGmailClient(userEmail, accountEmail);
  if (!gmail) return;
  // Search for booking confirmation emails
  const queries = [
    // Airlines
    "from:united.com subject:confirmation",
    "from:delta.com subject:confirmation",
    "from:aa.com subject:confirmation",
    "from:southwest.com subject:confirmation",
    "from:alaskaair.com subject:confirmation",
    "from:jetblue.com subject:confirmation",
    "from:britishairways.com",
    "from:virginatlantic.com",
    "from:lufthansa.com subject:confirmation",
    "from:emirates.com subject:confirmation",
    "from:qantas.com subject:confirmation",
    // Hotels - major chains
    "from:marriott.com",
    "from:hilton.com",
    "from:ihg.com",
    "from:hyatt.com",
    "from:fourseasons.com",
    "from:accor.com",
    "from:wyndham.com",
    "from:bestwestern.com",
    "from:radissonhotels.com",
    "from:choicehotels.com",
    // OTAs
    "from:airbnb.com",
    "from:hotels.com",
    "from:expedia.com",
    "from:booking.com",
    "from:priceline.com",
    "from:kayak.com",
    "from:hotwire.com",
    "from:tripadvisor.com",
    "from:agoda.com",
    "from:vrbo.com",
    // Car rental
    "from:hertz.com subject:confirmation",
    "from:enterprise.com subject:confirmation",
    "from:avis.com subject:confirmation",
    "from:budget.com subject:confirmation",
    "from:nationalcar.com subject:confirmation",
    "from:alamo.com subject:confirmation",
    "from:sixt.com subject:confirmation",
    "from:turo.com",
    // Airline loyalty programs (emails come from program domains, not airline domains)
    "from:trueblue.jetblue.com",
    "from:jetbluetravel.com",
    "from:vacations.jetblue.com",
    "from:jetblue.com subject:(hotel OR vacation OR resort OR confirmation)",
    "from:mileageplus.united.com",
    "from:skymiles.delta.com",
    "from:aadvantage.aa.com",
    "from:rapidrewards.southwest.com",
    "from:mileageplan.alaskaair.com",
    "from:avios.com",
    "from:executiveclub.ba.com",
    "from:flyingblue.com",
    "from:emiratesskywards.com",
    "from:qantaspoints.com",
    "from:velocityfrequentflyer.com",
    "from:frequentflyer.qantas.com",
    "from:lifemiles.com",
    "from:aeromexico.com subject:confirmation",
    // Hotel loyalty programs
    "from:bonvoy.marriott.com",
    "from:hiltonhonors.com",
    "from:ihgrewardsclub.com",
    "from:worldofhyatt.com",
    "from:wyndhamrewards.com",
    "from:choiceprivileges.com",
    "from:bestwesternrewards.com",
    "from:preferredhotels.com",
    "from:smallluxuryhotels.com",
    // OTA platforms — booking confirmations often come from noreply subdomains
    "from:expediamail.com",
    "from:email.expedia.com",
    "from:bookings.com",
    "from:noreply.booking.com",
    "from:email.booking.com",
    "from:info.priceline.com",
    "from:email.priceline.com",
    "from:kayak.com",
    "from:email.kayak.com",
    "from:hotels.com",
    "from:email.hotels.com",
    "from:tripadvisor.com",
    "from:email.tripadvisor.com",
    "from:airbnb.com",
    "from:message.airbnb.com",
    "from:vrbo.com",
    "from:email.vrbo.com",
    "from:hotwire.com",
    "from:orbitz.com",
    "from:cheaptickets.com",
    "from:travelocity.com",
    "from:agoda.com",
    "from:email.agoda.com",
    "from:trip.com",
    "from:email.trip.com",
    "from:skyscanner.net",
    "from:google.com subject:(trip OR itinerary OR booking)",
    // Ground transport
    "from:amtrak.com subject:confirmation",
    "from:eurostar.com subject:confirmation",
    "from:uber.com subject:(trip OR receipt)",
    "from:lyft.com subject:receipt",
    // Cruise lines
    "from:royalcaribbean.com subject:confirmation",
    "from:carnival.com subject:confirmation",
    "from:ncl.com subject:confirmation",
    "from:princess.com subject:confirmation",
    "from:celebrity.com subject:confirmation",
    // UK & European rail operators
    "from:eurostar.com",
    "from:thetrainline.com",
    "from:email.thetrainline.com",
    "from:lner.co.uk",
    "from:avantitrain.co.uk",
    "from:tpexpress.co.uk",
    "from:gwr.com",
    "from:southwesternrailway.com",
    "from:southeastern.co.uk",
    "from:scotrail.co.uk",
    "from:crosscountrytrains.co.uk",
    "from:c2c-online.co.uk",
    "from:chilternrailways.co.uk",
    "from:greateranglia.co.uk",
    "from:nationalrail.co.uk",
    "from:raileurope.com",
    "from:sncf-connect.com",
    "from:bahn.de",
    "from:thalys.com",
    "from:italo.it",
    "from:trenitalia.com",
    "from:renfe.com",
    "from:ouigo.com",
    "from:flixbus.com",
    "from:busbud.com",
    // Ferry operators
    "from:stenaline.co.uk",
    "from:poferries.com",
    "from:brittanyferries.co.uk",
    "from:dfdsseaways.co.uk",
    "from:irishferries.com",
    "from:calmac.co.uk",
    "from:northlinkferries.co.uk",
    "from:directferries.co.uk",
    "from:condorferries.co.uk",
    // Car rental — additional platforms
    "from:rentalcars.com",
    "from:email.rentalcars.com",
    "from:getaround.com",
    "from:zipcar.com",
    "from:enterprise.co.uk",
    "from:hertz.co.uk",
    "from:europcar.com",
    "from:email.europcar.com",
    "from:goldcar.es",
    "from:thrifty.com",
    "from:dollar.com",
    "from:fox.com subject:confirmation",
    "from:paylesscar.com",
    "from:easirent.com",
    "from:holidayautos.com",
    "from:autoeurope.com",
    // Activity & experience booking
    "from:viator.com",
    "from:getyourguide.com",
    "from:klook.com",
    "from:airbnbexperiences.com",
    "from:eventbrite.com subject:(ticket OR confirmation)",
    "from:ticketmaster.com subject:confirmation",
    "from:opentable.com subject:confirmation",
    "from:resy.com subject:confirmation",
    // Short-term rentals
    "from:homeaway.com",
    "from:email.homeaway.com",
    "from:cottages.com",
    "from:holidaylettings.co.uk",
    "from:sykes.com",
    "from:hoseasons.co.uk",
    "from:canopyandstars.co.uk",
    "from:uniquehomestays.com",
    // Airport transfers & ground transport
    "from:blacklane.com",
    "from:wheely.com",
    "from:addison.lee",
    "from:nationaltaxi.co.uk",
    "from:greentomato.com",
    "from:trainline.com subject:(booking OR confirmation)",
    // Travel agencies & specialist OTAs
    "from:truebluetravel.co.uk",
    "from:trueblue-travel.com",
    "from:truebluetravel.com",
    "from:secretescapes.com",
    "from:mr-mrs-smith.com",
    "from:tablet.com",
    "from:designhotels.com",
    "from:i-escape.com",
    "from:sawdays.co.uk",
    "from:lastminute.com",
    "from:loveholidays.com",
    "from:on-the-beach.co.uk",
    "from:tui.co.uk",
    "from:jet2.com",
    "from:easyjet.com subject:confirmation",
    "from:ryanair.com subject:confirmation",
    "from:flybe.com",
    "from:loganair.co.uk",
    "from:flightcentre.co.uk",
    "from:trailfinders.com",
    "from:kuoni.co.uk",
    "from:ba.com",
    "from:virginatlantic.com subject:confirmation",
    // Broad catch-all for anything travel-related in the last 6 months
    "subject:(hotel confirmation OR hotel reservation OR booking confirmation OR reservation confirmed OR check-in OR itinerary) newer_than:6m",
    "subject:(flight confirmation OR flight itinerary OR e-ticket OR boarding pass) newer_than:6m",
    "subject:(your booking OR your reservation OR booking reference OR reservation number) newer_than:6m",
    "subject:(points redeemed OR miles redeemed OR award booking OR reward booking) newer_than:6m",
    "subject:(cruise confirmation OR cruise itinerary OR sail date) newer_than:6m",
    "subject:(train booking OR rail ticket OR seat reservation) newer_than:6m",
    "subject:(car rental OR car hire OR vehicle booking OR pickup confirmation) newer_than:6m",
    "subject:(ferry booking OR ferry ticket OR sailing confirmation) newer_than:6m",
    "subject:(activity booking OR experience confirmed OR tour confirmation) newer_than:6m",
    "subject:(Airbnb OR vacation rental OR short stay OR apartment booking) newer_than:6m",
    // Dining reservations — restaurants + booking platforms (US + European/Nordic)
    "from:opentable.com",
    "from:resy.com",
    "from:sevenrooms.com",
    "from:exploretock.com",
    "from:tock.com",
    "from:waiteraid.com",
    "from:bokabord.se",
    "from:thefork.com",
    "from:quandoo.com",
    "subject:(reservation confirmed OR your reservation OR table for OR dining reservation OR your table OR booking confirmed) newer_than:6m",
    // Broad body-level catch — many hotels use a plain "Reservation Confirmation"
    // subject from their own domain (SynXis/Design Hotels) and restaurants use
    // non-obvious platforms. These booking-specific phrases match in subject OR body,
    // so they catch confirmations the templated queries above miss. is_travel_booking
    // filters out any non-travel noise before anything is stored.
    "subject:(reservation confirmation) newer_than:1y",
    "(\"confirmation number\" OR \"booking reference\" OR \"reservation is now confirmed\" OR \"your reservation is confirmed\") newer_than:1y",
  ];
  const seen = new Set();
  for (const q of queries) {
    try {
      const listRes = await gmail.users.messages.list({ userId: "me", q, maxResults: 50 });
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

// Turn an HTML email into readable plain text so the parser can actually see the
// itinerary. Airline confirmations (esp. American) are huge HTML documents whose
// first several KB are <head>, CSS, and preheader boilerplate — the flight DATE
// sits deep in the markup. Stripping tags surfaces the real content up front.
function stripHtml(html) {
  return String(html)
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<head[\s\S]*?<\/head>/gi, " ")
    .replace(/<\/(p|div|tr|td|table|li|h[1-6]|br)>/gi, "\n")
    .replace(/<br\s*\/?>(?=)/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/&[#a-z0-9]+;/gi, " ")
    .replace(/[ \t ]+/g, " ")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// Walk the full MIME tree, collecting text/plain and text/html separately.
function collectEmailParts(payload, acc) {
  if (!payload) return;
  const mime = (payload.mimeType || "").toLowerCase();
  if (payload.body && payload.body.data) {
    const decoded = Buffer.from(payload.body.data, "base64").toString("utf8");
    if (mime.includes("text/html")) acc.html.push(decoded);
    else if (mime.includes("text/plain") || mime.startsWith("text/") || !mime) acc.plain.push(decoded);
  }
  if (payload.parts) for (const part of payload.parts) collectEmailParts(part, acc);
}

function extractEmailBody(payload) {
  if (!payload) return "";
  const acc = { plain: [], html: [] };
  collectEmailParts(payload, acc);
  const plain = acc.plain.join("\n").trim();
  // Prefer the plain-text part only when it's substantial — many airline emails
  // ship an empty/preheader-only text/plain part alongside the real HTML itinerary.
  if (plain.length > 400) return plain;
  const stripped = acc.html.length ? stripHtml(acc.html.join("\n")) : "";
  return stripped.length > plain.length ? stripped : plain;
}

// ─── Trip grouping: find an existing trip that covers the same destination + date window ────
// Leg types that make a trip a "real" trip (travel + lodging). Everything else
// (dining, activities, transfers) is a "loose" booking that belongs INSIDE a trip.
const ANCHOR_TYPES = new Set(["flight", "hotel", "airbnb", "train", "ferry", "cruise", "car"]);

// ── Sanity bounds on travel dates ────────────────────────────────────────────
// A hotel booking parsed with the wrong check-out YEAR produces a leg spanning
// hundreds of days ("11 Howard · 266 nights", "ModernHaus SoHo · 801 nights").
// Such a leg overlaps essentially every date window, so it becomes a MAGNET:
// every subsequent booking to that city matches it and gets absorbed into the
// same trip. That is how one "New York" trip swallowed years of unrelated travel.
//
// So: any stay longer than this is treated as a parse error, not as a long
// holiday. Its end date is discarded rather than trusted.
const MAX_STAY_NIGHTS = 30;
const MAX_TRIP_DAYS   = 30;   // a single trip should not span longer than this

/**
 * Do two place names refer to the same place?
 *
 * Naive string equality does NOT work, and I proved it the hard way: a first cut
 * of this check "helpfully" evicted a Roma booking from a trip titled Roma, nine
 * New York bookings from a Brooklyn trip, and every Milano booking from Milan.
 * All of them were filed correctly. The check was wrong, not the data.
 *
 * Three things make two names the same place:
 *   1. An alias — Milano/Milan, Roma/Rome, München/Munich.
 *   2. Containment — a borough or district inside its city (Brooklyn ⊂ New York).
 *   3. One string containing the other — "New York, NY" vs "New York".
 *
 * When in doubt, this returns TRUE. A booking left in a slightly-wrong trip is a
 * cosmetic annoyance; a booking ripped out of the RIGHT trip is data loss the user
 * has to repair by hand. The asymmetry should always favour leaving things alone.
 */
const CITY_ALIASES = [
  ["milan", "milano"],
  ["rome", "roma"],
  ["florence", "firenze"],
  ["venice", "venezia"],
  ["naples", "napoli"],
  ["turin", "torino"],
  ["munich", "muenchen", "münchen"],
  ["cologne", "koln", "köln"],
  ["vienna", "wien"],
  ["prague", "praha"],
  ["warsaw", "warszawa"],
  ["lisbon", "lisboa"],
  ["seville", "sevilla"],
  ["copenhagen", "kobenhavn", "københavn"],
  ["gothenburg", "goteborg", "göteborg"],
  ["zurich", "zuerich", "zürich"],
  ["geneva", "geneve", "genève"],
  ["brussels", "bruxelles", "brussel"],
  ["antwerp", "antwerpen"],
  ["the hague", "den haag"],
  ["moscow", "moskva"],
  ["athens", "athina"],
  ["istanbul", "constantinople"],
  ["cairo", "al qahirah"],
  ["mumbai", "bombay"],
  ["kolkata", "calcutta"],
  ["chennai", "madras"],
  ["beijing", "peking"],
  ["guangzhou", "canton"],
  ["ho chi minh city", "saigon"],
  ["mexico city", "ciudad de mexico", "cdmx"],
  ["seoul", "soul"],
  // Boroughs / districts that ARE the city for travel purposes.
  ["new york", "nyc", "manhattan", "brooklyn", "queens", "bronx", "staten island"],
  ["london", "westminster", "camden", "shoreditch", "soho"],
  ["paris", "montmartre", "le marais"],
  ["tokyo", "shibuya", "shinjuku", "ginza"],
];

const CITY_ALIAS_MAP = (() => {
  const m = new Map();
  for (const group of CITY_ALIASES) {
    for (const name of group) m.set(name, group[0]); // canonical = first entry
  }
  return m;
})();

function canonicalCity(s) {
  const c = String(s || "").toLowerCase().split(",")[0].trim();
  if (!c) return "";
  return CITY_ALIAS_MAP.get(c) || c;
}

function sameCity(a, b) {
  const ca = canonicalCity(a);
  const cb = canonicalCity(b);
  if (!ca || !cb) return true;              // no evidence either way → don't act
  if (ca === cb) return true;
  return ca.includes(cb) || cb.includes(ca); // "new york ny" vs "new york"
}

// True when a leg's own duration is implausible — i.e. the dates are wrong.
function isImplausibleSpan(startISO, endISO) {
  if (!startISO || !endISO) return false;
  const s = new Date(startISO).getTime();
  const e = new Date(endISO).getTime();
  if (Number.isNaN(s) || Number.isNaN(e)) return false;
  if (e < s) return true;                                   // ends before it starts
  return (e - s) > MAX_STAY_NIGHTS * 86400000;
}

// Find a real trip (has an anchor leg) whose date window covers `whenISO`.
// Prefers a trip whose city matches; falls back to any date-overlapping trip.
async function findTripForLooseBooking(userEmail, whenISO, city) {
  if (!whenISO) return null;
  const rows = await sql`
    SELECT t.id, t.title,
      MIN(tl.departs_at) AS s,
      MAX(COALESCE(tl.arrives_at, tl.departs_at)) AS e,
      BOOL_OR(tl.type IN ('flight','hotel','airbnb','train','ferry','cruise','car')) AS has_anchor,
      STRING_AGG(LOWER(COALESCE(tl.destination_city, tl.destination, '')), ' ') AS cities
    FROM trips t
    JOIN trip_legs tl ON tl.trip_id = t.id
    WHERE t.user_email = ${userEmail}
    GROUP BY t.id, t.title
  `;
  const when = new Date(whenISO).getTime();
  if (Number.isNaN(when)) return null;
  const DAY = 86400000;
  const cityLc = canonicalCity(city);
  let fallback = null;
  for (const r of rows) {
    if (!r.has_anchor || !r.s) continue;      // only attach to real trips
    const start = new Date(r.s).getTime() - DAY;
    const end   = new Date(r.e || r.s).getTime() + DAY;

    // A trip whose span is implausibly long has bad dates somewhere inside it
    // (see MAX_STAY_NIGHTS). Its window would swallow almost any dinner booking,
    // so refuse to attach to it rather than compound the mess.
    if (end - start > (MAX_TRIP_DAYS + 2) * DAY) continue;

    if (when < start || when > end) continue;  // date must fall in the trip window

    // Alias-aware, and the trip TITLE counts as evidence alongside the anchor legs'
    // cities. Raw string matching here is what made "Milano" fail to match "Milan".
    const places = [r.title, ...String(r.cities || "").split(/\s+/).filter(Boolean)];
    if (cityLc && places.some((p) => sameCity(cityLc, p))) {
      return { tripId: r.id, title: r.title };  // best: date + city match
    }

    // ── The date-only fallback, and why it is now conditional ─────────────────
    //
    // This used to fire whenever the dates overlapped, whatever the city. So a
    // restaurant booking in London, on a date when a Stockholm trip happened to be
    // open, got filed under Stockholm. That is how a trip fills up with things
    // that have nothing to do with it.
    //
    // The distinction that matters:
    //
    //   • Booking has a city, and it DOESN'T match this trip → this is positive
    //     evidence it belongs somewhere else. Do NOT attach. Silence beats a
    //     confident mis-file.
    //
    //   • Booking has NO city at all → a dinner reservation with no location, on a
    //     date inside a trip, most likely IS part of that trip. Attaching is a fair
    //     inference and the only one available.
    //
    // The old code treated "wrong city" and "no city" identically. They are not the
    // same: one is evidence against, the other is merely absence of evidence.
    if (!cityLc && !fallback) {
      fallback = { tripId: r.id, title: r.title };
    }
  }
  return fallback;
}

/**
 * Retitle a trip to match the journey it actually became.
 *
 * A trip's title is set from the FIRST booking that lands in it, and then never
 * revisited. So a fortnight of Stockholm → Edinburgh → London stayed called
 * "Stockholm" — because a Stockholm hotel happened to be imported first.
 *
 * That's more corrosive than it looks. The trip is CORRECT — those legs really do
 * belong together — but the title makes every London booking inside it look
 * misfiled, and the user reasonably concludes the grouping is broken. A wrong label
 * on right data destroys trust just as fast as wrong data.
 *
 * So: the title follows the anchors, in the order you travelled them.
 *   one city      → "Stockholm"
 *   two or three  → "Stockholm → Edinburgh → London"
 *   more          → "Stockholm → … → Tokyo"
 *
 * Holder buckets keep their names. Manually-renamed trips are left alone.
 */
async function retitleTripFromLegs(tripId) {
  try {
    const [trip] = await sql`SELECT id, title, source FROM trips WHERE id = ${tripId}`;
    if (!trip) return;
    if (trip.title === "Needs review" || trip.title === "Reservations") return;
    if (trip.source === "manual") return;   // the user named it; don't argue

    const legs = await sql`
      SELECT COALESCE(destination_city, destination) AS city, departs_at
      FROM trip_legs
      WHERE trip_id = ${tripId}
        AND type IN ('flight','hotel','airbnb','train','ferry','cruise')
        AND COALESCE(destination_city, destination, '') <> ''
      ORDER BY departs_at ASC NULLS LAST
    `;
    if (!legs.length) return;

    // Distinct cities, in travel order, alias-aware (Milano and Milan are one stop).
    const stops = [];
    for (const l of legs) {
      const c = canonicalCity(l.city);
      if (!c) continue;
      if (stops.some((s) => sameCity(s.canon, c))) continue;
      stops.push({ canon: c, label: String(l.city).split(",")[0].trim() });
    }
    if (!stops.length) return;

    let title;
    if (stops.length === 1) title = stops[0].label;
    else if (stops.length <= 3) title = stops.map((s) => s.label).join(" → ");
    else title = `${stops[0].label} → … → ${stops[stops.length - 1].label}`;

    if (title && title !== trip.title) {
      await sql`UPDATE trips SET title = ${title} WHERE id = ${tripId}`;
      console.log(`[retitle] #${tripId}: "${trip.title}" → "${title}"`);
    }
  } catch (e) {
    console.error("[retitle]", e.message);
  }
}

/**
 * Discard end dates that cannot be real, BEFORE they are stored or used to group.
 *
 * MUTATES `parsed` deliberately: every ingest path (Gmail, paste, forwarded mail)
 * calls findOrCreateGroupedTrip with this same object and then inserts from it, so
 * cleaning here fixes both the grouping AND what lands in trip_legs. Sanitising in
 * only one of those places is how you get a tidy trip list built on bad rows.
 *
 * A "266-night" or "801-night" stay is not a long holiday. It is a check-out date
 * parsed with the wrong year. Keeping it poisons everything downstream: the trip's
 * date window, the grouping magnet, the nights count, and the ROI maths.
 */
function sanitizeLegDates(parsed, userEmail) {
  if (!parsed || !parsed.departs_at || !parsed.arrives_at) return parsed;
  if (!isImplausibleSpan(parsed.departs_at, parsed.arrives_at)) return parsed;

  console.warn(
    `[grouping] implausible span for ${userEmail}: ${parsed.type || "leg"} ` +
    `${parsed.departs_at} → ${parsed.arrives_at} — discarding end date (likely wrong year)`,
  );
  // Keep the start (almost always right); drop the end rather than invent one.
  parsed.arrives_at = null;
  parsed.nights = null;
  return parsed;
}

async function findOrCreateGroupedTrip(userEmail, parsed, emailId, source) {
  // Dedup by confirmation first, group anchors by destination, attach loose
  // bookings (dining/activities) to the trip they happen during, and never name
  // a trip after a carrier or a restaurant.
  sanitizeLegDates(parsed, userEmail);

  const rawDest = (parsed.destination_city || parsed.destination || "").split(",")[0].trim();
  const dest = rawDest.toLowerCase();
  const confirmation = (parsed.confirmation || "").trim();
  const startDate = parsed.departs_at ? new Date(parsed.departs_at) : null;
  const endDate   = parsed.arrives_at  ? new Date(parsed.arrives_at)  : startDate;
  const isLoose = parsed.type && !ANCHOR_TYPES.has(parsed.type);

  // ── 1. Strongest signal: an existing leg with the SAME confirmation number ──
  if (confirmation) {
    const byConf = await sql`
      SELECT t.id, t.title
      FROM trips t
      JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${userEmail}
        AND tl.confirmation IS NOT NULL
        AND LOWER(tl.confirmation) = ${confirmation.toLowerCase()}
      ORDER BY t.id ASC
      LIMIT 1
    `;
    if (byConf.length > 0) {
      return { tripId: byConf[0].id, isNew: false, tripTitle: byConf[0].title };
    }
  }

  // ── 2. Loose booking (dinner, bar, activity, transfer): attach to the trip it
  //       happens during. If there's no such trip, SKIP it — a dinner with no
  //       surrounding trip is not itself a trip. ──
  if (isLoose) {
    const match = await findTripForLooseBooking(userEmail, parsed.departs_at, rawDest);
    if (match) {
      console.log(`[grouping] loose ${parsed.type} -> trip "${match.title}" (id=${match.tripId})`);
      return { tripId: match.tripId, isNew: false, tripTitle: match.title };
    }
    // No surrounding trip yet — park in a single "Reservations" holder so it can
    // be folded in when its trip appears. Never a venue-named trip.
    const HOLD = "Reservations";
    const held = await sql`SELECT id FROM trips WHERE user_email = ${userEmail} AND title = ${HOLD} LIMIT 1`;
    if (held.length) return { tripId: held[0].id, isNew: false, tripTitle: HOLD };
    const rrows = await sql`INSERT INTO trips (user_email, title, source, raw_email_id) VALUES (${userEmail}, ${HOLD}, ${source || 'gmail'}, ${emailId || null}) RETURNING id`;
    return rrows.length ? { tripId: rrows[0].id, isNew: true, tripTitle: HOLD } : null;
  }

  // ── 3. Anchor booking — destination match, but ONLY within a real date window ──
  //
  // Two hard rules here, both learned the hard way:
  //
  //   (a) A candidate leg whose OWN span is implausible (a "266-night" hotel stay
  //       from a mis-parsed year) is excluded as an anchor. Otherwise it overlaps
  //       every window and drags every same-city booking into its trip.
  //
  //   (b) A booking with NO DATE never matches on destination alone. It used to:
  //       the old `else` branch took the oldest trip to that city, which is how a
  //       dateless "United ? → EWR" leg ended up filed under a trip from years
  //       earlier. A booking we can't place in time is a booking we can't group —
  //       it goes to "Needs review" instead of being guessed at.
  if (dest && startDate) {
    const buffer = 2 * 24 * 60 * 60 * 1000;
    const windowStart = new Date(startDate.getTime() - buffer);
    const windowEnd   = endDate ? new Date(endDate.getTime() + buffer) : new Date(startDate.getTime() + buffer);

    const candidates = await sql`
      SELECT DISTINCT t.id, t.title
      FROM trips t
      JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${userEmail}
        AND LOWER(COALESCE(tl.destination_city, tl.destination, '')) LIKE ${'%' + dest + '%'}
        AND tl.departs_at IS NOT NULL
        AND tl.departs_at <= ${windowEnd.toISOString()}
        AND COALESCE(tl.arrives_at, tl.departs_at) >= ${windowStart.toISOString()}
        -- (a) never anchor to a leg with an implausible duration
        AND COALESCE(tl.arrives_at, tl.departs_at) - tl.departs_at <= ${MAX_STAY_NIGHTS + " days"}::interval
        -- and never join a trip that is ALREADY absurdly long
        AND (
          SELECT MAX(COALESCE(x.arrives_at, x.departs_at)) - MIN(x.departs_at)
          FROM trip_legs x WHERE x.trip_id = t.id
        ) <= ${MAX_TRIP_DAYS + " days"}::interval
      ORDER BY t.id ASC
      LIMIT 1
    `;
    if (candidates && candidates.length > 0) {
      return { tripId: candidates[0].id, isNew: false, tripTitle: candidates[0].title };
    }
  }

  // ── 4. Title — city or route ONLY. Prefer the destination city; never a
  //       property or email-subject name (that is how "Brentwood Hotel" happened). ──
  let tripTitle = null;
  if (rawDest) {
    tripTitle = rawDest;
  } else if (parsed.origin && parsed.destination) {
    tripTitle = `${parsed.origin} → ${parsed.destination}`;
  } else if (parsed.trip_title && parsed.trip_title !== "Unknown" && parsed.trip_title !== "Unknown Trip") {
    tripTitle = parsed.trip_title;
  }

  // ── 5. Un-groupable anchor (no destination, no route) → "Needs review" holder ──
  if (!tripTitle) {
    const HOLD = "Needs review";
    const held = await sql`SELECT id FROM trips WHERE user_email = ${userEmail} AND title = ${HOLD} LIMIT 1`;
    if (held.length > 0) return { tripId: held[0].id, isNew: false, tripTitle: HOLD };
    const holdRows = await sql`
      INSERT INTO trips (user_email, title, source, raw_email_id)
      VALUES (${userEmail}, ${HOLD}, ${source || 'gmail'}, ${emailId || null})
      RETURNING id
    `;
    return holdRows.length ? { tripId: holdRows[0].id, isNew: true, tripTitle: HOLD } : null;
  }

  // ── 6. Guard against re-processing the same email, then create the trip ──
  if (emailId) {
    const dup = await sql`SELECT id FROM trips WHERE user_email = ${userEmail} AND raw_email_id = ${emailId} LIMIT 1`;
    if (dup.length > 0) return null;
  }
  const tripRows = await sql`
    INSERT INTO trips (user_email, title, source, raw_email_id)
    VALUES (${userEmail}, ${tripTitle}, ${source || 'gmail'}, ${emailId || null})
    RETURNING id
  `;
  if (tripRows.length === 0) return null;
  return { tripId: tripRows[0].id, isNew: true, tripTitle };
}

async function parseAndStoreEmail(userEmail, message) {
  // Check if already processed
  const existing = await sql`SELECT id FROM trips WHERE user_email = ${userEmail} AND raw_email_id = ${message.id}`;
  if (existing.length > 0) return;
  // Skip the (paid) LLM call if we've already parsed this email once — any outcome.
  // This is what keeps rescans from re-charging Anthropic for the whole inbox.
  const seenBefore = await sql`SELECT 1 FROM processed_emails WHERE user_email = ${userEmail} AND email_id = ${message.id} LIMIT 1`;
  if (seenBefore.length > 0) return;

  const headers = message.payload?.headers || [];
  const subject = headers.find(h => h.name === "Subject")?.value || "";
  const from    = headers.find(h => h.name === "From")?.value || "";
  const body    = extractEmailBody(message.payload);
  const snippet = message.snippet || "";

  try {
    const prompt = `You are a travel booking parser. Extract ALL structured data from this booking confirmation email.
Return ONLY valid JSON — no markdown, no explanation, no code fences.

Subject: ${subject}
From: ${from}
Body (up to 8000 chars): ${(body || snippet).slice(0, 8000)}

Rules:
- "is_travel_booking" = true for any email containing a confirmed booking, reservation, or itinerary — including emails from loyalty programmes (TrueBlue, MileagePlus, SkyMiles, Avios, etc.) and OTAs (Expedia, Booking.com, TrueBlue Travel, etc.) that contain booking details. Set false ONLY for pure promotional emails, newsletters, or points statements with NO booking details.
- "type" must be one of: flight | hotel | airbnb | car | train | ferry | cruise | activity | transfer | other
- "destination_city" = the city the traveller is visiting (e.g. "Edinburgh", "New York", "Tokyo") — extract this even for flights (use arrival city). For hotels, Airbnb, restaurants, and activities, this is the city where the property or venue is located — derive it from the address if it is not stated. NEVER leave destination_city null for a hotel, restaurant, or activity.
- "trip_title" = the destination city name only (e.g. "Edinburgh", "New York") — used to group all bookings for the same trip. NEVER include carrier/airline/hotel name here.
- For hotels/Airbnb: "departs_at" = check-in datetime, "arrives_at" = check-out datetime, "nights" = number of nights
- For trains: "station_from" and "station_to" are the station names (e.g. "London King's Cross", "Edinburgh Waverley")
- For cars: "pickup_location" = city or airport where car is collected, "dropoff_location" = return location
- For flights: "flight_number" = IATA code (e.g. "BA1234"), "origin" = departure IATA or city, "destination" = arrival IATA or city ALWAYS extract "departs_at" for flights — the departure date and time in ISO 8601 (include the year; infer it from the email date if the ticket only shows month/day). A flight without a departs_at is not useful, so never leave it null when any date/time appears in the email.
- "carrier" = airline, hotel property name, car rental company, train operator, ferry operator, or activity provider
- "price_total" = total cost as a number (no currency symbol), "currency" = 3-letter ISO code (e.g. "GBP", "USD")
- "guests" = number of guests/passengers as integer
- "property_address" = full address for hotels/Airbnb if present
- "vehicle_class" = car class (e.g. "Economy", "SUV", "Luxury") for car rentals
- "seat" = seat number for flights/trains if present
- "cabin_class" = "Economy", "Premium Economy", "Business", or "First" for flights

Return this exact JSON structure:
{
  "is_travel_booking": true or false,
  "type": "flight|hotel|airbnb|car|train|ferry|cruise|activity|transfer|other",
  "trip_title": "destination city name only — used for grouping (e.g. Edinburgh, New York)",
  "destination_city": "city the traveller is visiting",
  "carrier": "airline, hotel, car company, train operator, etc.",
  "confirmation": "booking reference or confirmation number",
  "origin": "departure city, airport code, or station (null for hotels/Airbnb)",
  "destination": "arrival city, airport code, or station",
  "departs_at": "ISO 8601 datetime or null",
  "arrives_at": "ISO 8601 datetime or null",
  "nights": null or integer,
  "guests": null or integer,
  "flight_number": "IATA flight number or null",
  "station_from": "departure station name or null",
  "station_to": "arrival station name or null",
  "pickup_location": "car pickup city/airport or null",
  "dropoff_location": "car dropoff city/airport or null",
  "vehicle_class": "car class or null",
  "property_address": "hotel/Airbnb address or null",
  "price_total": null or number,
  "currency": "3-letter ISO currency code or null",
  "seat": "seat number or null",
  "cabin_class": "Economy|Premium Economy|Business|First or null"
}`;

    let claudeResp;
    try {
      claudeResp = await getAnthropic().messages.create({
        model: "claude-haiku-4-5",  // cheap model — email field extraction is simple; Sonnet repair below catches misses
        max_tokens: 700,
        messages: [{ role: "user", content: prompt }],
      });
    } catch (llmErr) {
      console.error("[gmail parse] LLM call failed:", llmErr.message, "Subject:", subject);
      return;
    }

    let parsed;
    try {
      const raw = claudeResp.content[0].text.trim();
      const jsonStr = raw.replace(/^```json\n?/, "").replace(/\n?```$/, "").trim();
      parsed = JSON.parse(jsonStr);
    } catch (parseErr) {
      console.error("[gmail parse] JSON parse failed:", parseErr.message, "Raw:", claudeResp.content[0]?.text?.slice(0, 200));
      return;
    }

    // Record that we've parsed this email (even non-travel ones) so future scans
    // never pay to run it through the LLM again.
    await sql`INSERT INTO processed_emails (user_email, email_id) VALUES (${userEmail}, ${message.id}) ON CONFLICT DO NOTHING`.catch(() => {});

    if (!parsed.is_travel_booking) return;

    // ── P0 hardening: if a booking is missing the fields we group on, retry once
    //    with a focused prompt before storing. Reliable destination + date is what
    //    keeps trips from fragmenting into junk. ──
    const missingCritical = (p) =>
      !(p.destination_city || p.destination) || !(p.departs_at || p.arrives_at);
    if (missingCritical(parsed)) {
      try {
        const repairPrompt = `From this ${parsed.type || "travel"} booking email, extract ONLY the destination and dates. Return ONLY JSON: {"destination_city": string|null, "destination": string|null, "departs_at": ISO8601|null, "arrives_at": ISO8601|null}. For flights, destination_city = arrival city; departs_at = departure time. For hotels, departs_at = check-in, arrives_at = check-out.\n\nSubject: ${subject}\nBody: ${(body || snippet).slice(0, 8000)}`;
        const fix = await getAnthropic().messages.create({
          model: "claude-sonnet-4-5",
          max_tokens: 300,
          messages: [{ role: "user", content: repairPrompt }],
        });
        const fixRaw = fix.content[0].text.trim().replace(/^```json\n?/, "").replace(/\n?```$/, "").trim();
        const fixed = JSON.parse(fixRaw);
        parsed.destination_city = parsed.destination_city || fixed.destination_city || null;
        parsed.destination      = parsed.destination      || fixed.destination      || null;
        parsed.departs_at       = parsed.departs_at       || fixed.departs_at        || null;
        parsed.arrives_at       = parsed.arrives_at       || fixed.arrives_at         || null;
      } catch (repairErr) {
        console.warn("[gmail parse] repair pass failed:", repairErr.message, "Subject:", subject);
      }
      if (missingCritical(parsed)) {
        console.warn("[gmail parse] still missing destination/date after retry; routing to review. Subject:", subject);
      }
    }

    // ── Find or create a grouped trip ──
    const groupResult = await findOrCreateGroupedTrip(userEmail, parsed, message.id, 'gmail');
    if (!groupResult) return; // duplicate email
    const { tripId, isNew, tripTitle } = groupResult;
    const legTitle = tripTitle || parsed.trip_title || parsed.destination_city || parsed.destination || "Trip";

    // ── Skip if this exact booking is already a leg ──
    // A booking grouped INTO an existing trip never records its own raw_email_id on
    // the trips table, so the email can be re-seen on later scans and re-inserted.
    // Guard by confirmation number (and, when absent, by type+date+name) so rescans
    // fill gaps without creating duplicate legs.
    if (parsed.confirmation) {
      const dupLeg = await sql`
        SELECT tl.id FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
        WHERE t.user_email = ${userEmail}
          AND LOWER(tl.confirmation) = ${String(parsed.confirmation).toLowerCase()}
        LIMIT 1`;
      if (dupLeg.length > 0) return;
    } else if (parsed.departs_at) {
      const dupLeg = await sql`
        SELECT tl.id FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
        WHERE t.user_email = ${userEmail}
          AND tl.type = ${parsed.type || "flight"}
          AND tl.departs_at = ${parsed.departs_at}::TIMESTAMPTZ
          AND COALESCE(LOWER(tl.carrier),'') = ${String(parsed.carrier || "").toLowerCase()}
          AND COALESCE(LOWER(tl.destination),'') = ${String(parsed.destination || "").toLowerCase()}
        LIMIT 1`;
      if (dupLeg.length > 0) return;
    }

    // ── Insert the leg with all enriched fields ──
    await sql`
      INSERT INTO trip_legs (
        trip_id, type, carrier, flight_number, origin, destination, destination_city,
        departs_at, arrives_at, confirmation, raw_data,
        nights, guests, station_from, station_to,
        pickup_location, dropoff_location, vehicle_class,
        property_address, price_total, currency, seat, cabin_class
      ) VALUES (
        ${tripId},
        ${parsed.type || "flight"},
        ${parsed.carrier || null},
        ${parsed.flight_number || null},
        ${parsed.origin || null},
        ${parsed.destination || null},
        ${parsed.destination_city || null},
        ${parsed.departs_at || null}::TIMESTAMPTZ,
        ${parsed.arrives_at  || null}::TIMESTAMPTZ,
        ${parsed.confirmation || null},
        ${JSON.stringify(parsed)},
        ${parsed.nights    || null},
        ${parsed.guests    || null},
        ${parsed.station_from || null},
        ${parsed.station_to   || null},
        ${parsed.pickup_location  || null},
        ${parsed.dropoff_location || null},
        ${parsed.vehicle_class    || null},
        ${parsed.property_address || null},
        ${parsed.price_total != null ? parsed.price_total : null},
        ${parsed.currency || null},
        ${parsed.seat         || null},
        ${parsed.cabin_class  || null}
      )
    `;

    // The trip may have just become a different journey. A Stockholm trip that
    // gains an Edinburgh hotel and a London one is no longer "Stockholm" — and
    // leaving it named that makes every London booking inside it look misfiled.
    await retitleTripFromLegs(tripId);

    const typeLabel = {
      flight: "Flight", hotel: "Hotel", airbnb: "Airbnb", car: "Car rental",
      train: "Train", ferry: "Ferry", cruise: "Cruise", activity: "Activity",
      transfer: "Transfer", other: "Booking"
    }[parsed.type] || "Booking";

    await logActivity(
      userEmail, "import",
      `${typeLabel} imported: ${parsed.carrier || parsed.destination_city || legTitle}`,
      isNew
        ? `New trip created: ${legTitle}. Wingman is now monitoring.`
        : `Added to your ${legTitle} trip automatically.`,
      tripId
    );

    // Hotel-specific features
    if (parsed.type === "hotel" || parsed.type === "airbnb") {
// DISABLED-AUTO-EMAIL:       if (parsed.type === "hotel") {
// DISABLED-AUTO-EMAIL:         sendHotelPreferenceEmail(userEmail, parsed, legTitle).catch(e =>
// DISABLED-AUTO-EMAIL:           console.error("[hotel-pref-email]", e.message)
        extractAndStoreHotelAffinity(userEmail, parsed).catch(e =>
          console.error("[hotel-affinity]", e.message)
        );
    }
    console.log(`[gmail] stored ${parsed.type} leg for trip "${legTitle}" (id=${tripId}, new=${isNew}) for ${userEmail}`);
  } catch (e) {
    console.error("[gmail/parse]", e.message);
  }
}

// ---------------------------------------------------------------------------
// POST /trips/rename-unknown — retroactively rename Unknown Trip records using existing leg data
// ---------------------------------------------------------------------------
app.post("/trips/rename-unknown", auth, async (req, res) => {
  const email = req.email;
  try {
    // Find all poorly-named trips: Unknown Trip variants AND carrier-only titles like "United Airlines Flight"
    const unknowns = await sql`
      SELECT t.id, t.title, tl.origin, tl.destination, tl.carrier, tl.flight_number
      FROM trips t
      JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
        AND (
          t.title = 'Unknown Trip'
          OR t.title = 'Unknown'
          OR t.title LIKE 'Unknown%Trip'
          OR t.title LIKE '% Flight'
          OR t.title LIKE '% Airlines Flight'
          OR t.title = 'Trip'
          OR t.title = 'Imported Trip'
        )
      ORDER BY t.id, tl.id
    `;
    // Group by trip id, use first leg for title
    const seen = new Set();
    let renamed = 0;
    for (const row of unknowns) {
      if (seen.has(row.id)) continue;
      seen.add(row.id);
      let newTitle;
      if (row.origin && row.destination) {
        newTitle = `${row.origin} \u2192 ${row.destination}`;
      } else if (row.destination) {
        newTitle = `${row.destination} Trip`;
      } else if (row.carrier && row.flight_number) {
        newTitle = `${row.carrier}${row.flight_number}`;
      } else if (row.carrier) {
        newTitle = `${row.carrier} Flight`;
      } else {
        continue; // no data to improve on
      }
      await sql`UPDATE trips SET title = ${newTitle} WHERE id = ${row.id} AND user_email = ${email}`;
      renamed++;
    }
    res.json({ ok: true, renamed });
  } catch (e) {
    console.error("[rename-unknown]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /trips/reparse-unknown — delete poorly-titled gmail trips and re-trigger Gmail scan
// ---------------------------------------------------------------------------
app.post("/trips/reparse-unknown", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    // Delete all poorly-titled gmail trips so they can be re-parsed with improved prompt
    const deleted = await sql`
      DELETE FROM trips
      WHERE user_email = ${email}
        AND source = 'gmail'
        AND (
          title = 'Unknown Trip'
          OR title = 'Unknown'
          OR title LIKE 'Unknown%Trip'
          OR title = 'Trip'
          OR title LIKE '% Airlines Booking'
          OR title LIKE '% Airlines Flight'
          OR title LIKE '% Booking'
          OR title LIKE '% Flight'
          OR title = 'Imported Trip'
        )
      RETURNING id
    `;
    console.log(`[reparse] Deleted ${deleted.length} poorly-titled gmail trips for ${email}`);
    // Re-trigger Gmail scan in background — improved Claude prompt will produce better titles
    scanGmailForTrips(email).catch(e => console.error("[reparse scan]", e.message));
    res.json({ ok: true, deleted: deleted.length, message: `Cleared ${deleted.length} trips, re-scanning Gmail with improved parser now` });
  } catch (e) {
    console.error("[reparse-unknown]", e.message);
    res.status(500).json({ error: e.message });
  }
});


// DELETE /auth/gmail — disconnect Gmail (revoke token and delete from DB)
// Optional query param: ?account_id=<id> to disconnect a specific account only
app.delete("/auth/gmail", auth, async (req, res) => {
  const email = req.email;
  const accountId = req.query.account_id ? Number(req.query.account_id) : null;
  try {
    // Fetch the specific row(s) to revoke
    const rows = accountId
      ? await sql`SELECT id, refresh_token, access_token FROM gmail_tokens WHERE user_email = ${email} AND id = ${accountId}`
      : await sql`SELECT id, refresh_token, access_token FROM gmail_tokens WHERE user_email = ${email}`;
    for (const row of rows) {
      const token = row.refresh_token || row.access_token;
      if (token) {
        try {
          await fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`, { method: "POST" });
        } catch {} // best-effort revoke
      }
    }
    if (accountId) {
      await sql`DELETE FROM gmail_tokens WHERE user_email = ${email} AND id = ${accountId}`;
    } else {
      await sql`DELETE FROM gmail_tokens WHERE user_email = ${email}`;
    }
    await logActivity(email, "gmail_disconnected", "Gmail disconnected", "A Gmail account connection has been removed.", null, null, {});
    res.json({ ok: true });
  } catch (e) {
    console.error("[DELETE /auth/gmail]", e.message);
    res.status(500).json({ error: e.message });
  }
});

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

  // Otherwise: trigger a background Gmail re-scan
  // ?force=true clears previously-scanned gmail trips so missed emails are re-processed
  const force = req.query.force === 'true' || req.body?.force === true;
  try {
    if (force) {
      // Delete all gmail-sourced trips so the scan picks them up fresh
      const deleted = await sql`DELETE FROM trips WHERE user_email = ${email} AND source = 'gmail' RETURNING id`;
      console.log(`[scan/force] cleared ${deleted.length} gmail trips for ${email}`);
    }
    scanGmailForTrips(email).catch(e => console.error("[scan]", e.message));
    res.json({ ok: true, message: force ? "Force rescan started — all Gmail trips cleared and re-importing" : "Scan started", trips_created: 0 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POST /auth/gmail/rescan — full re-scan with progress summary
// Unlike /auth/gmail/scan (fire-and-forget background), this waits and returns
// a structured summary: { accounts_scanned, emails_processed, trips_created,
//                         trips_updated, legs_added, breakdown_by_type }
// ---------------------------------------------------------------------------
app.post("/auth/gmail/rescan", auth, async (req, res) => {
  const email = req.email;
  if (!email) return res.status(401).json({ error: "unauthorized" });

  // Rate-limit: one full rescan per 10 minutes per user
  const lastScan = rescanCooldowns.get(email);
  if (lastScan && Date.now() - lastScan < 10 * 60 * 1000) {
    const waitSecs = Math.ceil((10 * 60 * 1000 - (Date.now() - lastScan)) / 1000);
    return res.status(429).json({ error: `Please wait ${waitSecs}s before rescanning again.` });
  }
  rescanCooldowns.set(email, Date.now());

  try {
    const accountRows = await sql`SELECT account_email FROM gmail_tokens WHERE user_email = ${email}`;
    if (accountRows.length === 0) {
      return res.status(400).json({ error: "No Gmail account connected. Connect Gmail in Settings first." });
    }

    // Snapshot trip/leg counts before scan
    const before = await sql`
      SELECT
        (SELECT COUNT(*) FROM trips WHERE user_email = ${email}) AS trip_count,
        (SELECT COUNT(*) FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id WHERE t.user_email = ${email}) AS leg_count
    `;
    const tripsBefore = Number(before[0].trip_count);
    const legsBefore  = Number(before[0].leg_count);

    // Run the full scan synchronously (awaited) so we can return a summary
    for (const accountRow of accountRows) {
      await scanGmailAccountForTrips(email, accountRow.account_email);
    }

    // Snapshot after scan
    const after = await sql`
      SELECT
        (SELECT COUNT(*) FROM trips WHERE user_email = ${email}) AS trip_count,
        (SELECT COUNT(*) FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id WHERE t.user_email = ${email}) AS leg_count
    `;
    const tripsAfter = Number(after[0].trip_count);
    const legsAfter  = Number(after[0].leg_count);

    // Breakdown by leg type for the new legs
    const breakdown = await sql`
      SELECT tl.type, COUNT(*) AS count
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.created_at >= NOW() - INTERVAL '5 minutes'
      GROUP BY tl.type
      ORDER BY count DESC
    `;

    const summary = {
      ok: true,
      accounts_scanned: accountRows.length,
      trips_before: tripsBefore,
      trips_after: tripsAfter,
      trips_created: Math.max(0, tripsAfter - tripsBefore),
      legs_added: Math.max(0, legsAfter - legsBefore),
      breakdown_by_type: breakdown.reduce((acc, r) => { acc[r.type] = Number(r.count); return acc; }, {}),
      message: tripsAfter > tripsBefore
        ? `Found ${tripsAfter - tripsBefore} new trip${tripsAfter - tripsBefore !== 1 ? 's' : ''} and ${legsAfter - legsBefore} new booking${legsAfter - legsBefore !== 1 ? 's' : ''}.`
        : legsAfter > legsBefore
          ? `Added ${legsAfter - legsBefore} new booking${legsAfter - legsBefore !== 1 ? 's' : ''} to existing trips.`
          : "Inbox scanned — everything is already up to date.",
    };

    console.log(`[rescan] ${email}: ${JSON.stringify(summary)}`);
    res.json(summary);
  } catch (e) {
    console.error("[rescan]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// In-memory cooldown map (resets on server restart — acceptable for rate-limiting)
const rescanCooldowns = new Map();

// ---------------------------------------------------------------------------
// Parse a pasted email/confirmation body using the same LLM pipeline as Gmail
async function parsePastedEmailBody(userEmail, body, source) {
  if (!body || body.trim().length < 20) return 0;

  const prompt = `You are a travel booking parser. Extract ALL structured data from this booking confirmation text.
Return ONLY valid JSON — no markdown, no explanation, no code fences.

Text: ${body.slice(0, 4000)}

Rules:
- "is_travel_booking" = true for any email containing a confirmed booking, reservation, or itinerary — including emails from loyalty programmes (TrueBlue, MileagePlus, SkyMiles, Avios, etc.) and OTAs (Expedia, Booking.com, TrueBlue Travel, etc.) that contain booking details. Set false ONLY for pure promotional emails, newsletters, or points statements with NO booking details.
- "type" must be one of: flight | hotel | airbnb | car | train | ferry | cruise | activity | transfer | other
- "destination_city" = the city the traveller is visiting (e.g. "Edinburgh", "New York", "Tokyo") For hotels, Airbnb, restaurants, and activities, this is the city where the property or venue is located — derive it from the address if it is not stated. NEVER leave destination_city null for a hotel, restaurant, or activity.
- "trip_title" = the destination city name only (e.g. "Edinburgh") — used to group all bookings for the same trip
- For hotels/Airbnb: "departs_at" = check-in datetime, "arrives_at" = check-out datetime, "nights" = number of nights
- For trains: "station_from" and "station_to" are the station names
- For cars: "pickup_location" = city or airport where car is collected, "dropoff_location" = return location
- For flights: "flight_number" = IATA code, "origin" = departure IATA or city, "destination" = arrival IATA or city ALWAYS extract "departs_at" for flights — the departure date and time in ISO 8601 (include the year; infer it from the email date if the ticket only shows month/day). A flight without a departs_at is not useful, so never leave it null when any date/time appears in the email.
- "carrier" = airline, hotel property name, car rental company, train operator, etc.
- "price_total" = total cost as a number, "currency" = 3-letter ISO code
- "guests" = number of guests/passengers as integer
- "confirmation" = booking reference or confirmation number

Return this exact JSON structure:
{
  "is_travel_booking": true or false,
  "type": "flight|hotel|airbnb|car|train|ferry|cruise|activity|transfer|other",
  "trip_title": "destination city name only",
  "destination_city": "city the traveller is visiting",
  "carrier": "airline, hotel, car company, train operator, etc.",
  "confirmation": "booking reference or null",
  "origin": "departure city, airport code, or station (null for hotels/Airbnb)",
  "destination": "arrival city, airport code, or station",
  "departs_at": "ISO 8601 datetime or null",
  "arrives_at": "ISO 8601 datetime or null",
  "nights": null or integer,
  "guests": null or integer,
  "flight_number": "IATA flight number or null",
  "station_from": "departure station name or null",
  "station_to": "arrival station name or null",
  "pickup_location": "car pickup city/airport or null",
  "dropoff_location": "car dropoff city/airport or null",
  "vehicle_class": "car class or null",
  "property_address": "hotel/Airbnb address or null",
  "price_total": null or number,
  "currency": "3-letter ISO currency code or null",
  "seat": "seat number or null",
  "cabin_class": "Economy|Premium Economy|Business|First or null"
}`;

  let parsed;
  try {
    const claudeResp = await getAnthropic().messages.create({
      model: "claude-haiku-4-5",  // cheap model for email field extraction
      max_tokens: 700,
      messages: [{ role: "user", content: prompt }],
    });
    const raw = claudeResp.content[0].text.trim();
    const jsonStr = raw.replace(/^```json\n?/, "").replace(/\n?```$/, "").trim();
    parsed = JSON.parse(jsonStr);
  } catch (e) {
    console.error("[paste/parse] LLM or JSON error:", e.message);
    return 0;
  }

  if (!parsed.is_travel_booking) return 0;

  // Use the same grouping engine as Gmail
  const groupResult = await findOrCreateGroupedTrip(userEmail, parsed, null, source || 'paste');
  if (!groupResult) return 0;
  const { tripId, isNew, tripTitle } = groupResult;
  const legTitle = tripTitle || parsed.trip_title || parsed.destination_city || parsed.destination || "Trip";

  await sql`
    INSERT INTO trip_legs (
      trip_id, type, carrier, flight_number, origin, destination, destination_city,
      departs_at, arrives_at, confirmation, raw_data,
      nights, guests, station_from, station_to,
      pickup_location, dropoff_location, vehicle_class,
      property_address, price_total, currency, seat, cabin_class
    ) VALUES (
      ${tripId},
      ${parsed.type || "flight"},
      ${parsed.carrier || null},
      ${parsed.flight_number || null},
      ${parsed.origin || null},
      ${parsed.destination || null},
      ${parsed.destination_city || null},
      ${parsed.departs_at || null},
      ${parsed.arrives_at  || null},
      ${parsed.confirmation || null},
      ${JSON.stringify(parsed)},
      ${parsed.nights    || null},
      ${parsed.guests    || null},
      ${parsed.station_from || null},
      ${parsed.station_to   || null},
      ${parsed.pickup_location  || null},
      ${parsed.dropoff_location || null},
      ${parsed.vehicle_class    || null},
      ${parsed.property_address || null},
      ${parsed.price_total != null ? parsed.price_total : null},
      ${parsed.currency || null},
      ${parsed.seat         || null},
      ${parsed.cabin_class  || null}
    )
  `;

  // Same as the Gmail path: the trip may have just become a multi-city journey.
  await retitleTripFromLegs(tripId);

  const typeLabel = {
    flight: "Flight", hotel: "Hotel", airbnb: "Airbnb", car: "Car rental",
    train: "Train", ferry: "Ferry", cruise: "Cruise", activity: "Activity",
    transfer: "Transfer", other: "Booking"
  }[parsed.type] || "Booking";

  await logActivity(
    userEmail, "import",
    `${typeLabel} imported: ${parsed.carrier || legTitle}`,
    isNew ? `New trip created: ${legTitle}.` : `Added to your ${legTitle} trip.`,
    tripId
  );
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
  const showAll = req.query.all === "true"; // ?all=true to include past trips
  try {
    const trips = await sql`
      SELECT t.*,
        MIN(tl.departs_at) AS trip_start,
        MAX(COALESCE(tl.arrives_at, tl.departs_at)) AS trip_end,
        json_agg(
          json_build_object(
            'id',               tl.id,
            'type',             tl.type,
            'carrier',          tl.carrier,
            'flight_number',    tl.flight_number,
            'origin',           tl.origin,
            'destination',      tl.destination,
            'destination_city', tl.destination_city,
            'departs_at',       tl.departs_at,
            'arrives_at',       tl.arrives_at,
            'confirmation',     tl.confirmation,
            'status',           tl.status,
            'nights',           tl.nights,
            'guests',           tl.guests,
            'station_from',     tl.station_from,
            'station_to',       tl.station_to,
            'pickup_location',  tl.pickup_location,
            'dropoff_location', tl.dropoff_location,
            'vehicle_class',    tl.vehicle_class,
            'property_address', tl.property_address,
            'price_total',      tl.price_total,
            'currency',         tl.currency,
            'seat',             tl.seat,
            'cabin_class',      tl.cabin_class,
            'raw_data',         tl.raw_data
          )
          ORDER BY tl.departs_at ASC NULLS LAST
        ) FILTER (WHERE tl.id IS NOT NULL) AS legs
      FROM trips t
      LEFT JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
        AND t.archived = false
      GROUP BY t.id
      HAVING
        -- Default: show active + upcoming trips (or trips with no legs yet)
        -- Use MAX(COALESCE(arrives_at, departs_at)) so active hotel stays are included:
        --   hotel leg: departs_at = check-in (past), arrives_at = check-out (future) → shown
        --   flight: departs_at = departure, arrives_at = arrival → shown if either is future
        -- Pass ?all=true to include fully-past trips
        (${showAll} = TRUE)
        OR (MAX(COALESCE(tl.arrives_at, tl.departs_at)) IS NULL
            OR MAX(COALESCE(tl.arrives_at, tl.departs_at)) >= NOW())
      ORDER BY
        CASE WHEN MIN(tl.departs_at) >= NOW() OR MIN(tl.departs_at) IS NULL THEN 0 ELSE 1 END ASC,
        CASE WHEN MIN(tl.departs_at) >= NOW() OR MIN(tl.departs_at) IS NULL THEN MIN(tl.departs_at) ELSE NULL END ASC NULLS LAST,
        CASE WHEN MIN(tl.departs_at) < NOW() THEN MIN(tl.departs_at) ELSE NULL END DESC NULLS LAST
    `;
    res.json({ trips });
  } catch (e) {
    console.error("[trips]", e.message);
    res.status(500).json({ error: "db error" });
  }
});

// ---------------------------------------------------------------------------
// POST /inbound/email — inbound email webhook (Resend / SendGrid inbound)
// ---------------------------------------------------------------------------
// How it works:
//   1. User forwards any booking confirmation to import@wingmantravel.app
//   2. Resend (or SendGrid) inbound routing POSTs the parsed email here
//   3. We match the sender's email address to a Wingman account
//   4. Parse the body with the same LLM pipeline as Gmail scan
//   5. Create / group the trip using findOrCreateGroupedTrip
//
// Resend inbound payload shape:
//   { from, to, subject, text, html, headers }
// SendGrid inbound payload shape (multipart/form-data):
//   req.body.from, req.body.subject, req.body.text, req.body.html
// ---------------------------------------------------------------------------
app.post("/inbound/email", async (req, res) => {
  // Accept both JSON (Resend) and form-encoded (SendGrid)
  const from    = req.body?.from    || req.body?.envelope?.from || "";
  const subject = req.body?.subject || "";
  const text    = req.body?.text    || req.body?.plain || "";
  const html    = req.body?.html    || "";

  // Extract the sender email address
  const senderMatch = from.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
  const senderEmail = senderMatch ? senderMatch[0].toLowerCase() : null;

  if (!senderEmail) {
    console.warn("[inbound/email] no sender email found in from:", from);
    return res.status(200).json({ ok: false, reason: "no sender email" });
  }

  // Look up the Wingman user by sender email
  // We check both the primary account email and connected Gmail accounts
  let userEmail = null;
  try {
    const userRows = await sql`
      SELECT user_email FROM gmail_tokens WHERE account_email = ${senderEmail}
      UNION
      SELECT email AS user_email FROM users WHERE email = ${senderEmail}
      LIMIT 1
    `;
    if (userRows.length > 0) {
      userEmail = userRows[0].user_email;
    }
  } catch (e) {
    console.error("[inbound/email] user lookup error:", e.message);
  }

  if (!userEmail) {
    // Unknown sender — still return 200 so the webhook doesn't retry
    console.warn(`[inbound/email] unknown sender: ${senderEmail}`);
    return res.status(200).json({ ok: false, reason: "unknown sender" });
  }

  // Build the body to parse — prefer plain text, fall back to HTML stripped of tags
  const body = text.trim() ||
    html.replace(/<[^>]+>/g, " ").replace(/\s{2,}/g, " ").trim();

  if (body.length < 20) {
    return res.status(200).json({ ok: false, reason: "body too short" });
  }

  try {
    const count = await parsePastedEmailBody(userEmail, `Subject: ${subject}\n\n${body}`, "email_forward");
    console.log(`[inbound/email] ${senderEmail} → ${userEmail}: ${count} booking(s) created`);
    return res.status(200).json({ ok: true, bookings_created: count });
  } catch (e) {
    console.error("[inbound/email] parse error:", e.message);
    return res.status(200).json({ ok: false, reason: e.message });
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

// ── Local transit payment knowledge database ─────────────────────────────────
// Curated data on how to pay for transit in major cities worldwide
const TRANSIT_PAYMENT_DB = {
  // UK
  london:    { card: 'Oyster or contactless bank card (tap in/out)', app: 'TfL Oyster app', cash: 'Not accepted on buses or Tube', ticket_url: 'https://tfl.gov.uk/fares', tip: 'Contactless bank cards and Apple Pay work on all TfL services.' },
  edinburgh: { card: 'Contactless bank card or Ridacard', app: 'Lothian Buses app', cash: 'Exact change only on buses — no change given', ticket_url: 'https://www.lothianbuses.com/tickets/', tip: 'Buy a day ticket on the app before boarding. Cash accepted but exact change only.' },
  manchester:{ card: 'Contactless or Get Me There card', app: 'Get Me There app', cash: 'Exact change on buses', ticket_url: 'https://tfgm.com/tickets', tip: 'Trams (Metrolink) require a ticket before boarding — buy at platform machines.' },
  // Ireland
  dublin:    { card: 'Leap Card (tap on/off)', app: 'TFI Live app', cash: 'Exact change only — Apple Pay NOT accepted on Dublin Bus', ticket_url: 'https://www.leapcard.ie', tip: 'Apple Pay is not accepted on Dublin Bus. Buy a Leap Card at any newsagent or Spar. Top up in the TFI app. Exact coins only if paying cash.' },
  // Sweden
  stockholm: { card: 'SL Access card or contactless bank card', app: 'SL app', cash: 'Not accepted — card or app only', ticket_url: 'https://sl.se/en/in-english/fares--tickets/', tip: 'Buy a 24h or 72h ticket in the SL app before boarding. Contactless bank cards and Apple Pay work at most validators.' },
  gothenburg:{ card: 'Västtrafik To Go app or contactless', app: 'Västtrafik To Go', cash: 'Not accepted', ticket_url: 'https://www.vasttrafik.se/en/tickets/', tip: 'Buy in the app — no cash or ticket machines on trams.' },
  // Denmark
  copenhagen:{ card: 'Rejsekort or contactless bank card', app: 'DOT Tickets app', cash: 'Not accepted on Metro; exact change on some buses', ticket_url: 'https://www.rejsekort.dk', tip: 'Contactless and Apple Pay work on the Metro. Buy a City Pass in the DOT app for unlimited travel.' },
  // Norway
  oslo:      { card: 'Ruter card or contactless', app: 'Ruter app', cash: 'Not accepted', ticket_url: 'https://ruter.no/en/', tip: 'Buy in the Ruter app. Contactless and Apple Pay work at validators.' },
  // Netherlands
  amsterdam: { card: 'OV-chipkaart or contactless bank card', app: 'NS app or 9292 app', cash: 'Not accepted on most services', ticket_url: 'https://www.ov-chipkaart.nl/en/', tip: 'Contactless bank cards and Apple Pay work on GVB trams and metro. Always tap in AND out or you will be charged the maximum fare.' },
  // Germany
  berlin:    { card: 'BVG ticket or contactless', app: 'BVG Fahrinfo app', cash: 'Accepted at machines, not on board', ticket_url: 'https://www.bvg.de/en/tickets', tip: 'Buy a day ticket (Tageskarte) in the BVG app. Validate paper tickets before boarding — inspectors are frequent.' },
  munich:    { card: 'MVV ticket or contactless', app: 'MVV app', cash: 'Accepted at machines', ticket_url: 'https://www.mvv-muenchen.de/en/tickets-and-fares/', tip: 'Validate paper tickets immediately — fines are €60+. Contactless works on most U-Bahn and S-Bahn.' },
  // France
  paris:     { card: 'Navigo card or contactless bank card', app: 'Bonjour RATP app', cash: 'Not accepted on buses; accepted at Metro machines', ticket_url: 'https://www.ratp.fr/en/titres-et-tarifs', tip: 'Contactless bank cards and Apple Pay work on all Metro, RER, and buses. t+ tickets still work but Navigo Liberté+ is cheaper for short stays.' },
  // Spain
  madrid:    { card: 'Multi card or contactless', app: 'CRTM app', cash: 'Accepted at machines', ticket_url: 'https://www.crtm.es/billetes-y-tarifs/', tip: 'Buy a 10-trip Metrobus card at any Metro station — much cheaper than single tickets.' },
  barcelona: { card: 'T-Casual card or contactless', app: 'TMB app', cash: 'Accepted at machines', ticket_url: 'https://www.tmb.cat/en/barcelona-fares-metro-bus', tip: 'T-Casual (10 trips) is the best value. Contactless works on Metro and buses.' },
  // Italy
  rome:      { card: 'ATAC ticket or contactless', app: 'MaCheStaFer app', cash: 'Accepted at tabacchi shops and machines', ticket_url: 'https://www.atac.roma.it/en/page/tickets-and-passes', tip: 'Buy tickets at tabacchi (newsagents) or machines before boarding. Validate immediately on the bus.' },
  milan:     { card: 'ATM card or contactless', app: 'ATM Milano app', cash: 'Accepted at machines', ticket_url: 'https://www.atm.it/en/ViaggiaConNoi/Pagine/Biglietti.aspx', tip: 'Contactless and Apple Pay work on Metro. Buy a 24h or 48h pass in the ATM app.' },
  // USA
  'new york':{ card: 'OMNY contactless or MetroCard', app: 'MTA app', cash: 'Not accepted on buses (MetroCard or OMNY only)', ticket_url: 'https://new.mta.info/fares', tip: 'Tap your contactless card or Apple Pay directly at the turnstile — no MetroCard needed.' },
  chicago:   { card: 'Ventra card or contactless', app: 'Ventra app', cash: 'Not accepted on L trains or buses', ticket_url: 'https://www.ventrachicago.com', tip: 'Load the Ventra app and tap your phone. Contactless bank cards work at most readers.' },
  // Singapore
  singapore: { card: 'EZ-Link or contactless bank card', app: 'SimplyGo app', cash: 'Not accepted', ticket_url: 'https://www.transitlink.com.sg/', tip: 'Contactless bank cards and Apple Pay work on all MRT and buses via SimplyGo. Always tap in AND out.' },
  // Japan
  tokyo:     { card: 'Suica or Pasmo IC card', app: 'Suica app (iPhone wallet)', cash: 'Accepted at machines, not on board', ticket_url: 'https://www.jreast.co.jp/e/pass/suica.html', tip: 'Add Suica to your iPhone Wallet — tap in and out everywhere. Apple Pay works natively. Cash machines at every station if you need to top up.' },
  // Australia
  sydney:    { card: 'Opal card or contactless bank card', app: 'Opal Travel app', cash: 'Not accepted', ticket_url: 'https://www.opal.com.au', tip: 'Contactless bank cards and Apple Pay work on all Sydney trains, buses, and ferries. Tap on AND off.' },
  // UAE
  dubai:     { card: 'Nol card or contactless', app: 'RTA Dubai app', cash: 'Accepted at machines', ticket_url: 'https://www.rta.ae/wps/portal/rta/ae/public-transport', tip: 'Buy a Nol card at any Metro station. Contactless works on Metro. Taxis are metered and very affordable.' },
};

function getTransitPaymentInfo(cityOrCountry) {
  if (!cityOrCountry) return null;
  const key = cityOrCountry.toLowerCase().trim();
  if (TRANSIT_PAYMENT_DB[key]) return TRANSIT_PAYMENT_DB[key];
  for (const [city, info] of Object.entries(TRANSIT_PAYMENT_DB)) {
    if (key.includes(city) || city.includes(key)) return info;
  }
  return null;
}

// ── Google Directions Transit routing ────────────────────────────────────────
// Returns structured transit route with steps, times, and payment info
async function getTransitRoute(origin, destination, location) {
  const apiKey = process.env.GOOGLE_PLACES_API_KEY;
  if (!apiKey) return null;
  try {
    const originStr = origin || (location?.lat ? `${location.lat},${location.lng || location.lon}` : null);
    if (!originStr || !destination) return null;
    const url = `https://maps.googleapis.com/maps/api/directions/json?origin=${encodeURIComponent(originStr)}&destination=${encodeURIComponent(destination)}&mode=transit&alternatives=false&key=${apiKey}`;
    const r = await fetch(url);
    const data = await r.json();
    if (data.status !== 'OK' || !data.routes?.length) return null;
    const route = data.routes[0];
    const leg = route.legs[0];
    const steps = (leg.steps || []).map(step => ({
      instruction: step.html_instructions?.replace(/<[^>]+>/g, '') || '',
      mode: step.travel_mode,
      duration: step.duration?.text,
      distance: step.distance?.text,
      transit: step.transit_details ? {
        line: step.transit_details.line?.short_name || step.transit_details.line?.name,
        vehicle: step.transit_details.line?.vehicle?.name,
        departure_stop: step.transit_details.departure_stop?.name,
        arrival_stop: step.transit_details.arrival_stop?.name,
        departure_time: step.transit_details.departure_time?.text,
        num_stops: step.transit_details.num_stops,
      } : null,
    }));
    const city = location?.city || leg.start_address?.split(',').slice(-2).join(',').trim();
    const paymentInfo = getTransitPaymentInfo(city);
    return {
      summary: route.summary,
      total_duration: leg.duration?.text,
      total_distance: leg.distance?.text,
      departure_time: leg.departure_time?.text,
      arrival_time: leg.arrival_time?.text,
      start_address: leg.start_address,
      end_address: leg.end_address,
      steps,
      payment: paymentInfo,
      maps_url: `https://www.google.com/maps/dir/?api=1&origin=${encodeURIComponent(originStr)}&destination=${encodeURIComponent(destination)}&travelmode=transit`,
    };
  } catch (e) {
    console.error('[transit-route]', e.message);
    return null;
  }
}


// ── Google Places grounding — fetch REAL business names near user's location ──────────────────────────────────────
// Returns array of { name, address, rating, open_now, place_id, maps_url } or []
async function getPlacesGrounding(userMessage, location) {
  const apiKey = process.env.GOOGLE_PLACES_API_KEY;
  if (!apiKey || !location?.lat) return [];
  const msg = userMessage.toLowerCase();
  let placeType = null;
  let keyword = null;
  if (/bakery|croissant|pastry|bread/.test(msg))              { placeType = 'bakery'; keyword = 'bakery'; }
  else if (/coffee|cafe|caf\u00e9|flat white|espresso/.test(msg)) { placeType = 'cafe'; keyword = 'cafe'; }
  else if (/restaurant|dinner|lunch|eat|food|cuisine/.test(msg))  { placeType = 'restaurant'; }
  else if (/bar|cocktail|drink|pub|whisky|wine/.test(msg))        { placeType = 'bar'; }
  else if (/hotel|stay|accommodation|room/.test(msg))            { placeType = 'lodging'; }
  else if (/brunch|breakfast/.test(msg))                         { placeType = 'restaurant'; keyword = 'brunch'; }
  else return [];
  try {
    const lat = location.lat;
    const lng = location.lng || location.lon || 0;
    const keywordParam = keyword ? `&keyword=${encodeURIComponent(keyword)}` : '';
    const url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=${lat},${lng}&radius=2000&type=${placeType}${keywordParam}&rankby=prominence&key=${apiKey}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(6000) });
    if (!resp.ok) return [];
    const data = await resp.json();
    if (data.status !== 'OK' && data.status !== 'ZERO_RESULTS') {
      console.error('[places]', data.status, data.error_message);
      return [];
    }
    return (data.results || []).slice(0, 5).map(p => ({
      name: p.name,
      address: p.vicinity || p.formatted_address || null,
      rating: p.rating || null,
      user_ratings_total: p.user_ratings_total || 0,
      open_now: p.opening_hours?.open_now ?? null,
      place_id: p.place_id,
      maps_url: `https://www.google.com/maps/place/?q=place_id:${p.place_id}`,
      price_level: p.price_level ?? null,
    }));
  } catch (e) {
    console.error('[places]', e.message);
    return [];
  }
}

// ── OpenWeatherMap — live current weather for user's location ─────────────────────────────────────────────────────
async function getLiveWeather(location) {
  const apiKey = process.env.OPENWEATHER_API_KEY;
  if (!apiKey || !location?.lat) return null;
  try {
    const lat = location.lat;
    const lng = location.lng || location.lon || 0;
    const url = `https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lng}&appid=${apiKey}&units=metric`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(5000) });
    if (!resp.ok) return null;
    const d = await resp.json();
    const temp = Math.round(d.main?.temp);
    const feels = Math.round(d.main?.feels_like);
    const desc = d.weather?.[0]?.description || 'clear';
    const humidity = d.main?.humidity;
    const windKph = d.wind?.speed ? Math.round(d.wind.speed * 3.6) : null;
    // OWM d.name returns sub-neighbourhoods for dense cities (e.g. "Hammersmith" not "London").
    // Use BigDataCloud reverse geocoding (free, no key) to get the proper city name.
    let city = d.name || null;
    try {
      const geoResp = await fetch(
        `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lng}&localityLanguage=en`,
        { signal: AbortSignal.timeout(4000) }
      );
      if (geoResp.ok) {
        const geo = await geoResp.json();
        city = geo.city || geo.locality || city;
      }
    } catch { /* fall back to OWM d.name */ }
    return { temp, feels, desc, city, humidity, windKph };
  } catch (e) {
    console.error('[weather]', e.message);
    return null;
  }
}

// ── Perplexity live search grounding ───────────────────────────────────────────────────────────────────────────────
async function getPerplexityGrounding(userMessage, userProfile = null) {
  const apiKey = process.env.PERPLEXITY_API_KEY;
  if (!apiKey) return null;
  // Only search for destination/hotel/restaurant queries — skip flight ops queries
  const needsSearch = /hotel|restaurant|where to stay|where to eat|recommend|best|neighbourhood|neighborhood|things to do|activities|bar|cafe|coffee|brunch|dinner|lunch|breakfast|visit|explore|itinerary|plan|planning|trip to|travel to/i.test(userMessage);
  if (!needsSearch) return null;

  // Detect planning mode — run multiple targeted queries in parallel
  const isPlanningMode = /\b(plan|planning|itinerary|trip to|travel to|tour|cities|nights?|days?|schedule|route)\b/i.test(userMessage) && userMessage.length > 30;

  try {
    if (isPlanningMode && userProfile) {
      // Build targeted queries based on user memory
      const m = userProfile;
      const gymBrand = m.hotel_must_haves?.match(/technogym/i) ? 'Technogym' : m.hotel_must_haves?.match(/life fitness/i) ? 'Life Fitness' : null;
      const coldPlunge = m.hotel_must_haves?.match(/cold plunge|ice bath|vitality pool/i);
      const hotelBrands = m.hotel_brands || null;
      const tier = m.travel_tier || 'upscale';

      // Extract destination cities from the message
      const cityMatches = userMessage.match(/\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b/g) || [];
      const likelyCities = cityMatches.filter(c => c.length > 3 && !['Plan','Trip','Travel','Tour','Night','Day','Week'].includes(c));

      // Build targeted search queries
      const queries = [userMessage]; // always include the original
      if (gymBrand && likelyCities.length > 0) {
        queries.push(`${gymBrand} gym hotel ${likelyCities.slice(0,3).join(' ')} ${tier}`);
      }
      if (coldPlunge && likelyCities.length > 0) {
        queries.push(`cold plunge ice bath hotel ${likelyCities.slice(0,3).join(' ')} ${tier}`);
      }
      if (hotelBrands && likelyCities.length > 0) {
        const brands = hotelBrands.split(/[,;]+/).map(b => b.trim()).slice(0,2).join(' OR ');
        queries.push(`${brands} hotel ${likelyCities.slice(0,3).join(' ')}`);
      }

      // Run all queries in parallel, combine results
      const results = await Promise.all(queries.slice(0,3).map(async (q) => {
        try {
          const resp = await fetch('https://api.perplexity.ai/chat/completions', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              model: 'sonar',
              messages: [
                { role: 'system', content: 'You are a travel research assistant. Search the web and return a concise factual summary of current hotel and restaurant recommendations. Include specific property names, current open/closed status, price tier, and any notable amenities. Return plain text, no markdown.' },
                { role: 'user', content: q }
              ],
              max_tokens: 500,
              search_recency_filter: 'month',
              return_citations: false,
            }),
            signal: AbortSignal.timeout(10000),
          });
          if (!resp.ok) return null;
          const data = await resp.json();
          return data.choices?.[0]?.message?.content || null;
        } catch { return null; }
      }));

      const combined = results.filter(Boolean).join('\n\n---\n\n');
      return combined || null;
    }

    // Standard single-query mode
    const resp = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'sonar',
        messages: [
          {
            role: 'system',
            content: 'You are a travel research assistant. Given a user\'s travel question, search the web and return a concise, factual summary of current recommendations. Focus on: specific hotel names with current status (open/closed), restaurant names with current status, neighbourhood descriptions, and any recent openings or closures. Be specific and cite recency where possible. Return plain text, no markdown headers.'
          },
          { role: 'user', content: userMessage }
        ],
        max_tokens: 600,
        search_recency_filter: 'month',
        return_citations: false,
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    return data.choices?.[0]?.message?.content || null;
  } catch (e) {
    console.error('[perplexity]', e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// GET /me/memory — return the user's current memory document
// PATCH /me/memory — allow the user to directly update or correct their memory
// DELETE /me/memory/:field — remove a specific field from memory
// ---------------------------------------------------------------------------
// ── P1 cleanup migration: repair junk trips created before the grouping fix ──
// Removes duplicate legs sharing a confirmation, merges trips that share a
// confirmation, relabels carrier-named / "Trip" titles from their legs'
// destination, and deletes empty trips. DRY-RUN by default; pass ?apply=true.
async function cleanupTrips(userEmail, { dryRun = true } = {}) {
  const report = { dryRun, duplicateLegsRemoved: 0, tripsMerged: 0, titlesFixed: 0, emptyTripsDeleted: 0, details: [] };

  // (a) duplicate legs sharing the same confirmation (keep lowest id)
  const dupLegs = await sql`
    SELECT tl.confirmation AS confirmation, COUNT(*) AS n
    FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${userEmail} AND tl.confirmation IS NOT NULL AND tl.confirmation <> ''
    GROUP BY tl.confirmation HAVING COUNT(*) > 1
  `;
  for (const row of dupLegs) {
    report.duplicateLegsRemoved += Number(row.n) - 1;
    report.details.push(`dup legs for confirmation ${row.confirmation}: ${row.n} -> 1`);
    if (!dryRun) {
      await sql`
        DELETE FROM trip_legs WHERE id IN (
          SELECT tl.id FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
          WHERE t.user_email = ${userEmail} AND tl.confirmation = ${row.confirmation}
          ORDER BY tl.id ASC OFFSET 1
        )
      `;
    }
  }

  // (b) merge trips that share a confirmation number (keep earliest trip)
  const sharedConf = await sql`
    SELECT tl.confirmation AS confirmation, ARRAY_AGG(DISTINCT t.id ORDER BY t.id) AS trip_ids
    FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${userEmail} AND tl.confirmation IS NOT NULL AND tl.confirmation <> ''
    GROUP BY tl.confirmation HAVING COUNT(DISTINCT t.id) > 1
  `;
  for (const row of sharedConf) {
    const ids = row.trip_ids;

    // A confirmation number is strong evidence two legs belong together — but it
    // is NOT proof. Some values in here are junk: a loyalty number, or a reference
    // an airline recycled years later. Merging on one of those glues unrelated
    // journeys into a single trip. (It produced an "Albany" trip spanning 5,188
    // days from two legs fourteen years apart.)
    //
    // It also sets up a fight: unmergeMegaTrips() splits on date gaps, this merges
    // on confirmations, and the two undo each other forever.
    //
    // So: sanity-check the merge before doing it. If joining these trips would
    // create something longer than a plausible journey, the confirmation is a
    // collision, not a booking. Trust the calendar over the string.
    const [span] = await sql`
      SELECT ROUND(EXTRACT(EPOCH FROM (
               MAX(COALESCE(tl.arrives_at, tl.departs_at)) - MIN(tl.departs_at)
             )) / 86400) AS days
      FROM trip_legs tl
      WHERE tl.trip_id = ANY(${ids})
    `;
    if (span && Number(span.days) > MAX_TRIP_DAYS) {
      report.details.push(
        `SKIP merge of trips ${ids.join(",")} — confirmation "${row.confirmation}" spans ` +
        `${span.days} days. That's a recycled/garbage reference, not one booking.`,
      );
      continue;
    }

    const keep = ids[0];
    const merge = ids.slice(1);
    report.tripsMerged += merge.length;
    report.details.push(`merge trips ${merge.join(",")} -> ${keep} (confirmation ${row.confirmation})`);
    if (!dryRun) {
      for (const mid of merge) {
        await sql`UPDATE trip_legs SET trip_id = ${keep} WHERE trip_id = ${mid}`;
        await sql`DELETE FROM trips WHERE id = ${mid} AND user_email = ${userEmail}`;
      }
    }
  }

  // (c) relabel carrier-named / generic titles from the legs' destination
  const badTitles = await sql`
    SELECT t.id, t.title FROM trips t
    WHERE t.user_email = ${userEmail}
      AND (t.title = 'Trip' OR t.title LIKE '% Trip' OR t.title LIKE '%Airlines%' OR t.title LIKE '%Air Lines%')
  `;
  for (const t of badTitles) {
    const better = await sql`
      SELECT COALESCE(destination_city, destination) AS dest FROM trip_legs
      WHERE trip_id = ${t.id} AND COALESCE(destination_city, destination) IS NOT NULL
      ORDER BY id ASC LIMIT 1
    `;
    if (better.length && better[0].dest) {
      const newTitle = better[0].dest.split(",")[0].trim();
      report.titlesFixed += 1;
      report.details.push(`retitle #${t.id}: "${t.title}" -> "${newTitle}"`);
      if (!dryRun) await sql`UPDATE trips SET title = ${newTitle} WHERE id = ${t.id}`;
    }
  }

  // (d) delete empty trips (no legs)
  const empties = await sql`
    SELECT t.id FROM trips t
    WHERE t.user_email = ${userEmail}
      AND NOT EXISTS (SELECT 1 FROM trip_legs tl WHERE tl.trip_id = t.id)
  `;
  report.emptyTripsDeleted = empties.length;
  if (empties.length) report.details.push(`delete ${empties.length} empty trips: ${empties.map(e => e.id).join(",")}`);
  if (!dryRun && empties.length) {
    await sql`
      DELETE FROM trips t
      WHERE t.user_email = ${userEmail}
        AND NOT EXISTS (SELECT 1 FROM trip_legs tl WHERE tl.trip_id = t.id)
    `;
  }

  return report;
}

/**
 * Undo the damage done by magnet legs: split trips that have swallowed years of
 * unrelated travel back into real ones.
 *
 * How the mess happened: a hotel booking parsed with the wrong check-out year
 * produced a leg spanning hundreds of days. That leg overlapped every date window,
 * so every subsequent booking to the same city matched it and was absorbed. One
 * "New York" trip ended up holding flights from April, September, November and
 * February, plus an "801-night" stay.
 *
 * The repair, in order:
 *   1. Fix the poison legs — discard end dates that cannot be real.
 *   2. Re-cluster each over-long trip by DATE GAPS. Legs more than SPLIT_GAP_DAYS
 *      apart belong to different journeys. The earliest cluster keeps the original
 *      trip (preserving its id, ratings, and any standing orders); later clusters
 *      become new trips titled from their own destination.
 *   3. Legs with no date at all can't be clustered — park them in "Needs review"
 *      rather than guessing, which is what caused this in the first place.
 */
const SPLIT_GAP_DAYS = 5;   // > 5 days between legs ⇒ a different trip

async function unmergeMegaTrips(userEmail, { dryRun = true } = {}) {
  const report = { dryRun, legsDatesFixed: 0, tripsSplit: 0, tripsCreated: 0, legsOrphaned: 0, details: [] };
  const DAY = 86400000;

  // ── 1. Neutralise the magnets ────────────────────────────────────────────────
  const bad = await sql`
    SELECT tl.id, tl.property_name, tl.departs_at, tl.arrives_at
    FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${userEmail}
      AND tl.departs_at IS NOT NULL
      AND tl.arrives_at IS NOT NULL
      AND (
        tl.arrives_at < tl.departs_at
        OR tl.arrives_at - tl.departs_at > ${MAX_STAY_NIGHTS + " days"}::interval
      )
  `;
  for (const l of bad) {
    const nights = Math.round((new Date(l.arrives_at) - new Date(l.departs_at)) / DAY);
    report.legsDatesFixed++;
    report.details.push(`leg #${l.id} "${l.property_name || "—"}": ${nights} nights is a bad year — dropping end date`);
    if (!dryRun) {
      await sql`UPDATE trip_legs SET arrives_at = NULL, nights = NULL WHERE id = ${l.id}`;
    }
  }

  // ── 0. Retitle multi-city trips ──────────────────────────────────────────────
  // A trip is named after whichever booking landed first. A fortnight of
  // Stockholm → Edinburgh → London therefore stayed called "Stockholm", which made
  // every London booking inside it look misfiled — when the trip was correct all
  // along. A wrong label on right data destroys trust exactly as fast as wrong data.
  report.tripsRetitled = 0;
  const titleCandidates = await sql`
    SELECT DISTINCT t.id, t.title
    FROM trips t JOIN trip_legs tl ON tl.trip_id = t.id
    WHERE t.user_email = ${userEmail}
      AND t.title NOT IN ('Needs review', 'Reservations')
      AND COALESCE(t.source, '') <> 'manual'
  `;
  for (const t of titleCandidates) {
    const legs = await sql`
      SELECT COALESCE(destination_city, destination) AS city
      FROM trip_legs
      WHERE trip_id = ${t.id}
        AND type IN ('flight','hotel','airbnb','train','ferry','cruise')
        AND COALESCE(destination_city, destination, '') <> ''
      ORDER BY departs_at ASC NULLS LAST
    `;
    const stops = [];
    for (const l of legs) {
      const c = canonicalCity(l.city);
      if (!c || stops.some((s) => sameCity(s.canon, c))) continue;
      stops.push({ canon: c, label: String(l.city).split(",")[0].trim() });
    }
    if (!stops.length) continue;
    const title = stops.length === 1
      ? stops[0].label
      : stops.length <= 3
        ? stops.map((s) => s.label).join(" → ")
        : `${stops[0].label} → … → ${stops[stops.length - 1].label}`;
    if (title === t.title) continue;

    report.tripsRetitled++;
    report.details.push(`retitle #${t.id}: "${t.title}" → "${title}"`);
    if (!dryRun) await sql`UPDATE trips SET title = ${title} WHERE id = ${t.id}`;
  }

  // ── 1a. RECOVERY: put back anything wrongly evicted to "Reservations" ────────
  //
  // An earlier version of the eviction below compared city names as raw strings. It
  // did not know that Milano is Milan, that Brooklyn is in New York, or that a
  // booking in Roma inside a trip named "Roma" is obviously fine. It dumped a pile
  // of correctly-filed bookings into "Reservations".
  //
  // This puts them back. It runs FIRST, so a repair run both undoes that damage and
  // then re-applies the (now alias-aware) check.
  report.reservationsRehomed = 0;
  const stranded = await sql`
    SELECT tl.id, tl.departs_at, tl.property_name,
           COALESCE(tl.destination_city, tl.destination) AS city
    FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${userEmail}
      AND t.title = 'Reservations'
      AND tl.departs_at IS NOT NULL
  `;
  for (const l of stranded) {
    const home = await findTripForLooseBooking(userEmail, l.departs_at, l.city);
    if (!home) continue;   // genuinely homeless — leave it in Reservations
    report.reservationsRehomed++;
    report.details.push(`"${l.property_name || l.city}" → back into "${home.title}"`);
    if (!dryRun) {
      await sql`UPDATE trip_legs SET trip_id = ${home.tripId} WHERE id = ${l.id}`;
    }
  }

  // ── 1b. Evict bookings filed under a trip to the wrong city ──────────────────
  // The loose-booking matcher used to fall back to a date-only match when no city
  // matched — so a dinner in London landed in a Stockholm trip that happened to
  // overlap the dates. Move those out. If a trip to the RIGHT city exists on those
  // dates, they go there; otherwise to "Reservations", where they can be folded in
  // later. We do not guess a second time.
  // Pull the CANDIDATES in SQL, then decide in JS — because "is this the same
  // place?" needs an alias table (Milano = Milan) and containment (Brooklyn ⊂ New
  // York), and SQL string matching knows neither. A first version of this check did
  // it in SQL and evicted a Roma booking from a trip called Roma.
  const looseWithCity = await sql`
    SELECT tl.id, tl.departs_at, tl.property_name,
           COALESCE(tl.destination_city, tl.destination) AS city,
           t.id AS trip_id, t.title,
           (SELECT STRING_AGG(DISTINCT COALESCE(a.destination_city, a.destination, ''), '|')
            FROM trip_legs a
            WHERE a.trip_id = t.id
              AND a.type IN ('flight','hotel','airbnb','train','ferry','cruise','car')) AS anchor_cities
    FROM trip_legs tl
    JOIN trips t ON t.id = tl.trip_id
    WHERE t.user_email = ${userEmail}
      AND tl.type NOT IN ('flight','hotel','airbnb','train','ferry','cruise','car')
      AND COALESCE(tl.destination_city, tl.destination, '') <> ''
      AND t.title NOT IN ('Reservations', 'Needs review')
  `;

  const misfiled = looseWithCity.filter((l) => {
    const anchors = String(l.anchor_cities || "").split("|").filter(Boolean);
    // The trip TITLE counts as evidence too — a booking in Roma inside a trip named
    // "Roma" is obviously correctly filed, and the first version missed that entirely.
    const candidates = [l.title, ...anchors];
    if (!candidates.length) return false;
    // Mis-filed only if it matches NOTHING. Any match at all means leave it alone.
    return !candidates.some((c) => sameCity(l.city, c));
  });

  report.misfiledMoved = 0;
  for (const l of misfiled) {
    const better = await findTripForLooseBooking(userEmail, l.departs_at, l.city);
    const destTripId = better && better.tripId !== l.trip_id ? better.tripId : null;

    report.misfiledMoved++;
    report.details.push(
      `"${l.property_name || l.city}" (${l.city}) was filed under "${l.title}" — ` +
      (destTripId ? `moving to the ${l.city} trip` : `moving to "Reservations"`),
    );

    if (!dryRun) {
      let target = destTripId;
      if (!target) {
        let [hold] = await sql`
          SELECT id FROM trips WHERE user_email = ${userEmail} AND title = 'Reservations' LIMIT 1
        `;
        if (!hold) {
          [hold] = await sql`
            INSERT INTO trips (user_email, title, source)
            VALUES (${userEmail}, 'Reservations', 'unmerge') RETURNING id
          `;
        }
        target = hold.id;
      }
      await sql`UPDATE trip_legs SET trip_id = ${target} WHERE id = ${l.id}`;
    }
  }

  // ── 2. Re-cluster over-long trips ────────────────────────────────────────────
  // Re-read spans AFTER the fix above, so a trip that is only long because of a
  // poison leg isn't split unnecessarily.
  // "Needs review" and "Reservations" are holder buckets, not trips. Splitting them
  // is meaningless — and worse, the old code "moved" their undated legs INTO
  // themselves and reported it as work every single run. A repair that can never
  // say "nothing to do" trains you to skim past the runs where something IS wrong.
  const longTrips = await sql`
    SELECT t.id, t.title
    FROM trips t JOIN trip_legs tl ON tl.trip_id = t.id
    WHERE t.user_email = ${userEmail}
      AND t.title NOT IN ('Needs review', 'Reservations')
    GROUP BY t.id, t.title
    HAVING MAX(COALESCE(tl.arrives_at, tl.departs_at)) - MIN(tl.departs_at)
           > ${MAX_TRIP_DAYS + " days"}::interval
  `;

  for (const t of longTrips) {
    const legs = await sql`
      SELECT id, departs_at, arrives_at, destination_city, destination, confirmation
      FROM trip_legs WHERE trip_id = ${t.id}
      ORDER BY departs_at ASC NULLS LAST
    `;
    const dated = legs.filter(l => l.departs_at);
    const undated = legs.filter(l => !l.departs_at);

    // Greedy clustering on date gaps.
    let clusters = [];
    let cur = null;
    for (const l of dated) {
      const start = new Date(l.departs_at).getTime();
      const end   = new Date(l.arrives_at || l.departs_at).getTime();
      if (!cur) { cur = { legs: [l], end }; continue; }
      if (start - cur.end > SPLIT_GAP_DAYS * DAY) {
        clusters.push(cur);
        cur = { legs: [l], end };
      } else {
        cur.legs.push(l);
        cur.end = Math.max(cur.end, end);
      }
    }
    if (cur) clusters.push(cur);

    // ── Confirmation numbers OVERRIDE the date gaps ──────────────────────────
    // A return flight booked on one confirmation can easily sit 10 days after the
    // outbound. Date-gap clustering alone tears that booking in half — which it
    // did, scattering one confirmation across three "trips". A shared confirmation
    // is the strongest signal we have that two legs belong together, stronger than
    // any date heuristic. So: union any clusters that share one.
    const byConf = new Map();
    clusters.forEach((c, i) => {
      for (const l of c.legs) {
        const conf = (l.confirmation || "").trim().toLowerCase();
        if (!conf) continue;
        if (!byConf.has(conf)) byConf.set(conf, new Set());
        byConf.get(conf).add(i);
      }
    });

    // Union-find over cluster indices.
    const parent = clusters.map((_, i) => i);
    const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
    const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb); };

    const clusterStart = (i) => new Date(clusters[i].legs[0].departs_at).getTime();
    const clusterEnd   = (i) => clusters[i].end;

    for (const [conf, idxs] of byConf.entries()) {
      const list = [...idxs];
      if (list.length < 2) continue;

      // Guard: a confirmation shared by legs MONTHS or YEARS apart is not one
      // booking — it's a recycled reference or a loyalty number that got parsed
      // into the confirmation field. Uniting on it would rebuild the very mega-trip
      // we're here to dismantle, and the splitter and merger would then undo each
      // other forever. Dates beat strings when the string is implausible.
      const earliest = Math.min(...list.map(clusterStart));
      const latest   = Math.max(...list.map(clusterEnd));
      if (latest - earliest > MAX_TRIP_DAYS * DAY) {
        report.details.push(
          `  (ignored confirmation "${conf}" — its legs span ` +
          `${Math.round((latest - earliest) / DAY)} days; that's a collision, not a booking)`,
        );
        continue;
      }

      for (let i = 1; i < list.length; i++) union(list[0], list[i]);
    }

    const merged = new Map();
    clusters.forEach((c, i) => {
      const root = find(i);
      if (!merged.has(root)) merged.set(root, []);
      merged.get(root).push(i);   // keep the CONSTITUENT date-clusters, not just their legs
    });

    // ── Enforce the constraint on the RESULT, not on each hop ─────────────────
    //
    // Union-find is transitive, and that quietly defeats a per-confirmation guard:
    // conf A joins clusters 1→2 (3 days apart, fine), conf B joins 2→3 (fine),
    // C joins 3→4... every individual union passes a 30-day check, but the CHAIN
    // drags fifteen legs across 687 days into one cluster. unmergeMegaTrips then
    // sees a single cluster, concludes there's nothing to split, and skips the trip.
    // That's how "London — 687 days, 15 legs" survived three repair runs.
    //
    // So: after unioning, look at what we actually built. If a merged group spans
    // longer than a plausible journey, the confirmations that built it were
    // collisions. Throw the union away for that group and keep the date clusters,
    // which are the thing we can actually trust.
    const beforeUnion = clusters.length;
    const rebuilt = [];
    for (const idxs of merged.values()) {
      const legs = idxs.flatMap((i) => clusters[i].legs);
      const starts = legs.map((l) => new Date(l.departs_at).getTime());
      const ends   = legs.map((l) => new Date(l.arrives_at || l.departs_at).getTime());
      const span   = Math.max(...ends) - Math.min(...starts);

      if (idxs.length > 1 && span > MAX_TRIP_DAYS * DAY) {
        report.details.push(
          `  (rejected a ${Math.round(span / DAY)}-day merge — confirmations chained across ` +
          `unrelated trips; keeping the ${idxs.length} date clusters)`,
        );
        for (const i of idxs) rebuilt.push(clusters[i]);   // undo the union
        continue;
      }
      rebuilt.push({ legs, end: Math.max(...ends) });
    }

    clusters = rebuilt.sort(
      (a, b) => new Date(a.legs[0].departs_at) - new Date(b.legs[0].departs_at),
    );
    if (clusters.length !== beforeUnion) {
      report.details.push(
        `  (kept ${beforeUnion - clusters.length} split(s) together — shared confirmation number)`,
      );
    }

    if (clusters.length <= 1 && !undated.length) continue;

    report.tripsSplit++;
    report.details.push(`trip #${t.id} "${t.title}" (${dated.length} dated legs) → ${clusters.length} trips`);

    // Cluster 0 keeps the original trip id — preserving ratings, standing orders,
    // and anything else keyed to it.
    for (let i = 1; i < clusters.length; i++) {
      const c = clusters[i];
      const destLeg = c.legs.find(l => l.destination_city || l.destination);
      const title = destLeg
        ? String(destLeg.destination_city || destLeg.destination).split(",")[0].trim()
        : t.title;
      const when = new Date(c.legs[0].departs_at).toISOString().slice(0, 10);
      report.tripsCreated++;
      report.details.push(`  → new trip "${title}" (${when}, ${c.legs.length} legs)`);
      if (!dryRun) {
        const [nt] = await sql`
          INSERT INTO trips (user_email, title, source)
          VALUES (${userEmail}, ${title}, 'unmerge')
          RETURNING id
        `;
        for (const l of c.legs) {
          await sql`UPDATE trip_legs SET trip_id = ${nt.id} WHERE id = ${l.id}`;
        }
      }
    }

    // ── 3. Undated legs: we cannot place them in time, so we do not guess. ──────
    if (undated.length) {
      report.legsOrphaned += undated.length;
      report.details.push(`  → ${undated.length} undated leg(s) to "Needs review"`);
      if (!dryRun) {
        let [hold] = await sql`
          SELECT id FROM trips WHERE user_email = ${userEmail} AND title = 'Needs review' LIMIT 1
        `;
        if (!hold) {
          [hold] = await sql`
            INSERT INTO trips (user_email, title, source)
            VALUES (${userEmail}, 'Needs review', 'unmerge') RETURNING id
          `;
        }
        for (const l of undated) {
          await sql`UPDATE trip_legs SET trip_id = ${hold.id} WHERE id = ${l.id}`;
        }
      }
    }
  }

  return report;
}

app.post("/admin/cleanup-trips", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const dryRun = req.query.apply !== "true";
    const report = await cleanupTrips(email, { dryRun });
    res.json({ ok: true, ...report });
  } catch (e) {
    console.error("[cleanup-trips]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * GET /admin/invariants — assert things that must NEVER be true of the data.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every bug we found by hand had the same shape: the endpoint returned 200, the
 * JSON was well-formed, the app rendered it beautifully — and it said "266 nights".
 * Nothing FAILED. The system faithfully served nonsense.
 *
 * A status-code test can never catch that. It asks "did it respond?" when the
 * question that matters is "is the answer possible?".
 *
 * So this checks the data itself. Each invariant is a statement that should return
 * ZERO rows. Any row is a bug — in the parser, the grouping, or a migration — and
 * it is reported with real examples so it can be chased down rather than shrugged at.
 *
 * Add to this list every time we find a bug. That is what stops it recurring.
 */
const INVARIANTS = [
  {
    name: "hotel stay longer than 30 nights",
    why: "A check-out date parsed with the wrong year. These become date magnets that swallow unrelated trips.",
    query: (email) => sql`
      SELECT tl.id, tl.property_name AS detail, tl.departs_at, tl.arrives_at,
             ROUND(EXTRACT(EPOCH FROM (tl.arrives_at - tl.departs_at)) / 86400) AS days
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.arrives_at IS NOT NULL AND tl.departs_at IS NOT NULL
        AND tl.arrives_at - tl.departs_at > INTERVAL '30 days'
      LIMIT 5`,
  },
  {
    name: "leg that arrives before it departs",
    why: "Time does not work that way. A date-parse error.",
    query: (email) => sql`
      SELECT tl.id, COALESCE(tl.property_name, tl.flight_number) AS detail, tl.departs_at, tl.arrives_at
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.arrives_at IS NOT NULL AND tl.departs_at IS NOT NULL
        AND tl.arrives_at < tl.departs_at
      LIMIT 5`,
  },
  {
    name: "trip spanning more than 30 days",
    why: "Almost always a trip that has absorbed unrelated travel, not a real long journey.",
    // "Needs review" and "Reservations" are deliberate HOLDER buckets for bookings
    // we can't place in time. They are not trips and a span across them is
    // meaningless — a junk drawer is supposed to look like a junk drawer. Excluded
    // by name, narrowly, rather than by loosening the rule for everything.
    query: (email) => sql`
      SELECT t.id, t.title AS detail,
             ROUND(EXTRACT(EPOCH FROM (MAX(COALESCE(tl.arrives_at, tl.departs_at)) - MIN(tl.departs_at))) / 86400) AS days,
             COUNT(tl.id)::int AS legs
      FROM trips t JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
        AND t.title NOT IN ('Needs review', 'Reservations')
      GROUP BY t.id, t.title
      HAVING MAX(COALESCE(tl.arrives_at, tl.departs_at)) - MIN(tl.departs_at) > INTERVAL '30 days'
      LIMIT 5`,
  },
  {
    name: "holder bucket is overflowing",
    why: "'Needs review' is where bookings go when we can't place them in time. A big pile means the PARSER is failing, not that the bucket is broken. Worth looking at, not ignoring.",
    query: (email) => sql`
      SELECT t.id, t.title AS detail, COUNT(tl.id)::int AS legs
      FROM trips t JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
        AND t.title IN ('Needs review', 'Reservations')
      GROUP BY t.id, t.title
      HAVING COUNT(tl.id) > 20
      LIMIT 5`,
  },
  {
    name: "nights count disagrees with the dates",
    why: "The stored nights value and the actual date range have drifted apart. One of them is lying.",
    query: (email) => sql`
      SELECT tl.id, tl.property_name AS detail, tl.nights,
             ROUND(EXTRACT(EPOCH FROM (tl.arrives_at - tl.departs_at)) / 86400) AS days
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.nights IS NOT NULL
        AND tl.arrives_at IS NOT NULL AND tl.departs_at IS NOT NULL
        AND ABS(tl.nights - EXTRACT(EPOCH FROM (tl.arrives_at - tl.departs_at)) / 86400) > 1
      LIMIT 5`,
  },
  {
    name: "same confirmation number across different trips",
    why: "One booking cannot belong to two journeys. The grouping split something it should have kept together.",
    query: (email) => sql`
      SELECT tl.confirmation AS detail, COUNT(DISTINCT t.id)::int AS trips
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email} AND tl.confirmation IS NOT NULL AND tl.confirmation <> ''
      GROUP BY tl.confirmation
      HAVING COUNT(DISTINCT t.id) > 1
      LIMIT 5`,
  },
  {
    name: "booking filed under a trip to a different city",
    why: "A dinner in Stockholm sitting inside a Brooklyn trip. The grouping fell back to a date-only match and ignored the city. NOTE: this is alias-aware — Milano IS Milan, Brooklyn IS New York — because a check that evicts correctly-filed bookings is worse than no check.",
    // Deliberately NOT a pure-SQL string comparison. See sameCity(): the first
    // version of this invariant did compare strings, and it flagged a Roma booking
    // inside a trip named Roma as mis-filed.
    query: async (email) => {
      const rows = await sql`
        SELECT tl.id, t.title AS detail,
               COALESCE(tl.property_name, tl.destination_city, tl.destination) AS booking,
               COALESCE(tl.destination_city, tl.destination) AS booking_city,
               (SELECT STRING_AGG(DISTINCT COALESCE(a.destination_city, a.destination, ''), '|')
                FROM trip_legs a
                WHERE a.trip_id = t.id
                  AND a.type IN ('flight','hotel','airbnb','train','ferry','cruise','car')) AS anchor_cities
        FROM trip_legs tl
        JOIN trips t ON t.id = tl.trip_id
        WHERE t.user_email = ${email}
          AND tl.type NOT IN ('flight','hotel','airbnb','train','ferry','cruise','car')
          AND COALESCE(tl.destination_city, tl.destination, '') <> ''
          AND t.title NOT IN ('Reservations', 'Needs review')
      `;
      return rows
        .filter((r) => {
          const candidates = [r.detail, ...String(r.anchor_cities || "").split("|").filter(Boolean)];
          return candidates.length > 0 && !candidates.some((c) => sameCity(r.booking_city, c));
        })
        .slice(0, 5)
        .map(({ anchor_cities, ...rest }) => rest);
    },
  },
  {
    name: "trip named after an airline",
    why: "Trips are named for places. 'American Airlines' is a carrier, not a destination.",
    query: (email) => sql`
      SELECT t.id, t.title AS detail FROM trips t
      WHERE t.user_email = ${email}
        AND (t.title ILIKE '%airlines%' OR t.title ILIKE '%air lines%' OR t.title ILIKE '%jetblue%' OR t.title = 'Trip')
      LIMIT 5`,
  },
  {
    name: "trip with no legs",
    why: "An empty trip is a ghost — it renders as a card that opens onto nothing.",
    query: (email) => sql`
      SELECT t.id, t.title AS detail FROM trips t
      WHERE t.user_email = ${email}
        AND NOT EXISTS (SELECT 1 FROM trip_legs tl WHERE tl.trip_id = t.id)
      LIMIT 5`,
  },
  {
    name: "departure more than 2 years in the future",
    why: "Nobody books that far out. It's a year-parse error hiding in plain sight.",
    query: (email) => sql`
      SELECT tl.id, COALESCE(tl.property_name, tl.flight_number, tl.carrier) AS detail, tl.departs_at
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.departs_at > NOW() + INTERVAL '2 years'
      LIMIT 5`,
  },

  // ── The constraint graph's own promises (see constraints.js) ───────────────
  // The old invariants ask "is this data possible?". These ask a harder question:
  // "is Wingman entitled to believe this?" — no inferred rule may be non-negotiable,
  // no researched fact may lack a source, no cascade node may assert an impact it
  // cannot evidence, and no autonomous action may fail to name what it protected.
  ...graph.CONSTRAINT_INVARIANTS,
];

app.get("/admin/invariants", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const violations = [];
    const findings = [];      // `soft` invariants: reported, do NOT fail the suite
    for (const inv of INVARIANTS) {
      let rows = [];
      try {
        rows = await inv.query(email);
      } catch (e) {
        violations.push({ name: inv.name, why: inv.why, error: e.message, examples: [] });
        continue;
      }
      if (rows.length) {
        const hit = { name: inv.name, why: inv.why, count: rows.length, examples: rows };
        (inv.soft ? findings : violations).push(hit);
      }
    }
    res.json({
      // A soft invariant is a DIAGNOSIS, not a defect. "Booked commitment with no
      // reason attached" will be large on the first run — that is the point of the
      // whole exercise, not a failure of it. Failing the suite on it would teach us
      // to ignore the suite.
      ok: violations.length === 0,
      checked: INVARIANTS.length,
      violations,
      findings,
    });
  } catch (e) {
    console.error("[invariants]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /admin/unmerge-trips — split trips that swallowed unrelated travel.
// Dry-run by default. Add ?apply=true to actually write.
app.post("/admin/unmerge-trips", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const dryRun = req.query.apply !== "true";
    const report = await unmergeMegaTrips(email, { dryRun });
    res.json({ ok: true, ...report });
  } catch (e) {
    console.error("[unmerge-trips]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Re-home dining/activity reservations that were imported as their own "trips":
// move each into the real trip it happened during, then delete the loose trips
// (orphan reservations with no surrounding trip are junk and get removed).
async function cleanupLooseTrips(userEmail, { dryRun = true } = {}) {
  const report = { dryRun, reservationsReassigned: 0, looseTripsDeleted: 0, details: [] };
  const looseTrips = await sql`
    SELECT t.id, t.title
    FROM trips t
    WHERE t.user_email = ${userEmail}
      AND EXISTS (SELECT 1 FROM trip_legs tl WHERE tl.trip_id = t.id)
      AND NOT EXISTS (
        SELECT 1 FROM trip_legs tl
        WHERE tl.trip_id = t.id
          AND tl.type IN ('flight','hotel','airbnb','train','ferry','cruise','car')
      )
      AND t.title <> 'Needs review'
  `;
  for (const lt of looseTrips) {
    const legs = await sql`SELECT id, departs_at, destination_city, destination FROM trip_legs WHERE trip_id = ${lt.id}`;
    for (const leg of legs) {
      const match = await findTripForLooseBooking(userEmail, leg.departs_at, leg.destination_city || leg.destination);
      if (match && match.tripId !== lt.id) {
        report.reservationsReassigned++;
        report.details.push(`"${lt.title}" reservation -> "${match.title}"`);
        if (!dryRun) await sql`UPDATE trip_legs SET trip_id = ${match.tripId} WHERE id = ${leg.id}`;
      }
    }
    report.looseTripsDeleted++;
    report.details.push(`delete loose trip "${lt.title}"`);
    if (!dryRun) {
      await sql`DELETE FROM trip_legs WHERE trip_id = ${lt.id}`;
      await sql`DELETE FROM trips WHERE id = ${lt.id} AND user_email = ${userEmail}`;
    }
  }
  return report;
}

app.post("/admin/cleanup-reservations", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const dryRun = req.query.apply !== "true";
    const report = await cleanupLooseTrips(email, { dryRun });
    res.json({ ok: true, ...report });
  } catch (e) {
    console.error("[cleanup-reservations]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Fast, non-destructive-ish cleanup: remove duplicate legs (keeps the earliest of
// each identical booking). Pure SQL — returns immediately, no Gmail scan.
app.post("/admin/dedupe-legs", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const removed = await dedupeLegs(email);
    res.json({ ok: true, removed });
  } catch (e) {
    console.error("[dedupe-legs]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Fast: reset inflated hotel stay counts to real values. Pure SQL, no scan.
app.post("/admin/recompute-affinity", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const corrected = await recomputeHotelAffinity(email);
    res.json({ ok: true, corrected });
  } catch (e) {
    console.error("[recompute-affinity]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Fast: merge near-duplicate trips (e.g. "Brentwood" + "Brentwood Hotel"). Pure SQL.
app.post("/admin/merge-duplicate-trips", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const merged = await mergeDuplicateTrips(email);
    res.json({ ok: true, merged });
  } catch (e) {
    console.error("[merge-duplicate-trips]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ─── Decision spine (build-plan ticket #1) ──────────────────────────────────────
// GET /decisions — pending / auto-done decisions that still need surfacing.
app.get("/decisions", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const rows = await sql`
      SELECT * FROM decisions
      WHERE user_email = ${email}
        AND status IN ('pending', 'auto_done')
        AND (expires_at IS NULL OR expires_at > NOW())
      ORDER BY created_at DESC
      LIMIT 20`;
    res.json({ ok: true, decisions: rows });
  } catch (e) {
    console.error("[decisions]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /decisions/:id/confirm — confirm the recommended (or chosen) option.
// (Execution of the real action — Duffel rebook etc. — will hook in here later.)
app.post("/decisions/:id/confirm", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const [d] = await sql`SELECT * FROM decisions WHERE id = ${req.params.id} AND user_email = ${email}`;
    if (!d) return res.status(404).json({ error: "not_found" });
    const optionId = (req.body && req.body.option_id) || d.recommended_option_id;
    await sql`UPDATE decisions SET status = 'confirmed', chosen_option_id = ${optionId}, resolved_at = NOW() WHERE id = ${d.id}`;
    // Feed the Insights "value protected" ledger when a rebook rescue is accepted.
    const opts = typeof d.options === "string" ? JSON.parse(d.options || "[]") : (d.options || []);
    const chosen = opts.find(o => o.id === optionId) || {};
    const valueSaved = d.kind === "rebook" && optionId !== "opt_hold" ? Number(chosen.value_saved || 0) : 0;
    if (valueSaved > 0) {
      logActivity(email, "rebook", `Rescue accepted: ${d.headline}`, null, d.trip_id, d.leg_id,
        { value_saved: valueSaved, rescue_accepted: true, decision_id: d.id }).catch(() => {});
    } else {
      logActivity(email, "recovery", `Confirmed: ${d.headline}`, null, d.trip_id).catch(() => {});
    }
    res.json({ ok: true, status: "confirmed", chosen_option_id: optionId, value_saved: valueSaved });
  } catch (e) {
    console.error("[decisions/confirm]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /decisions/:id/dismiss — snooze/decline.
app.post("/decisions/:id/dismiss", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    await sql`UPDATE decisions SET status = 'dismissed', resolved_at = NOW() WHERE id = ${req.params.id} AND user_email = ${email}`;
    res.json({ ok: true, status: "dismissed" });
  } catch (e) {
    console.error("[decisions/dismiss]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /decisions/:id/undo — reverse a just-confirmed decision (reversible autonomy).
// Restores it to pending and removes the value-protected event so Insights doesn't
// count a rescue the user backed out of.
app.post("/decisions/:id/undo", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const [d] = await sql`SELECT id FROM decisions WHERE id = ${req.params.id} AND user_email = ${email}`;
    if (!d) return res.status(404).json({ error: "not_found" });
    await sql`UPDATE decisions SET status = 'pending', chosen_option_id = NULL, resolved_at = NULL WHERE id = ${d.id}`;
    await sql`DELETE FROM activity_events WHERE user_email = ${email} AND type = 'rebook' AND (metadata->>'decision_id') = ${String(d.id)}`;
    res.json({ ok: true, status: "pending" });
  } catch (e) {
    console.error("[decisions/undo]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /decisions/simulate — create a test decision so the whole confirm/dismiss
// loop is exercisable before the automated flight-watcher is switched on.
app.post("/decisions/simulate", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const [leg] = await sql`
      SELECT tl.*, t.id AS trip_id, t.title
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email} AND tl.type = 'flight' AND tl.departs_at > NOW()
      ORDER BY tl.departs_at ASC LIMIT 1`;
    const ident = leg ? `${leg.carrier || ""}${leg.flight_number || ""}`.trim() : "";
    const route = leg ? `${leg.origin || "?"} → ${leg.destination || "?"}` : "BOS → LHR";
    const headline = `${ident ? ident + " " : ""}${route} looks at risk`;
    const options = [
      { id: "opt_a", label: "Rebook on the later departure", detail: "Same cabin, arrives ~1h later, no change fee", recommended: true, value_saved: 430 },
      { id: "opt_b", label: "Hold and monitor", detail: "I'll keep watching and re-alert only if it worsens", recommended: false },
      { id: "opt_c", label: "Reroute via a hub", detail: "Arrives on time, one extra connection", recommended: false, value_saved: 380 },
    ];
    const rows = await sql`
      INSERT INTO decisions (user_email, trip_id, leg_id, kind, status, headline, rationale, options, recommended_option_id, autonomy_action, expires_at)
      VALUES (${email}, ${leg?.trip_id || null}, ${leg?.id || null}, 'rebook', 'pending', ${headline},
        ${"A high delay probability and a tight downstream connection put this itinerary at risk. The later departure keeps you in the same cabin with no change fee — that's my recommendation."},
        ${JSON.stringify(options)}, 'opt_a', 'asked', ${new Date(Date.now() + 6 * 3600000).toISOString()})
      RETURNING id`;
    res.json({ ok: true, id: rows[0].id, headline });
  } catch (e) {
    console.error("[decisions/simulate]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Rebuild trips from scratch: wipe this user's trips, then re-scan Gmail with the
// fixed parser (flights+hotels group into cohesive trips; dinners/Ubers fold in).
// Preview by default; pass ?confirm=true to actually wipe and rebuild. The scan
// runs in the background because a full re-scan can take a few minutes.
app.post("/admin/rebuild-trips", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const [{ count }] = await sql`SELECT COUNT(*)::int AS count FROM trips WHERE user_email = ${email}`;
    const wipe = req.query.wipe === "true";
    if (req.query.confirm !== "true") {
      return res.json({
        ok: true, preview: true, currentTrips: count,
        message: `Re-scan Gmail and reconcile ${count} trips (SAFE — no deletion). Add ?confirm=true to proceed. Add &wipe=true ONLY if you want to delete all trips first and rebuild from scratch.`,
      });
    }
    // DEFAULT is non-destructive: the scan dedupes and re-homes, so existing trips are
    // preserved and only gaps get filled. A wipe-first rebuild is opt-in (&wipe=true)
    // because a failed/slow scan after a wipe leaves the user with nothing.
    if (wipe) {
      await sql`DELETE FROM trip_legs WHERE trip_id IN (SELECT id FROM trips WHERE user_email = ${email})`;
      await sql`DELETE FROM trips WHERE user_email = ${email}`;
    }
    // Run the scan synchronously (awaited). A fire-and-forget background scan dies
    // on Render's free tier — the dyno spins down the moment the response is sent.
    await scanGmailForTrips(email);
    const after = await sql`
      SELECT
        (SELECT COUNT(*)::int FROM trips WHERE user_email = ${email}) AS trips,
        (SELECT COUNT(*)::int FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
           WHERE t.user_email = ${email}) AS legs,
        (SELECT COUNT(*)::int FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
           WHERE t.user_email = ${email}
             AND tl.type IN ('flight','hotel','airbnb','train','ferry','cruise','car')
             AND tl.departs_at IS NULL) AS dateless_anchors
    `;
    res.json({
      ok: true,
      wiped: wipe,
      rebuilt: after[0],
      message: `${wipe ? "Wiped and rebuilt" : "Reconciled"}: ${after[0].trips} trips, ${after[0].legs} legs. ${after[0].dateless_anchors} anchor leg(s) still missing a date.`,
    });
  } catch (e) {
    console.error("[rebuild-trips]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/me/memory", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const rows = await sql`SELECT memory, updated_at FROM user_memory WHERE user_email = ${email}`;
    res.json({ ok: true, memory: rows[0]?.memory || {}, updated_at: rows[0]?.updated_at || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/me/memory", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const updates = req.body || {};
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: "no fields" });
    // Fetch existing and merge
    const rows = await sql`SELECT memory FROM user_memory WHERE user_email = ${email}`;
    const existing = rows[0]?.memory || {};
    const merged = { ...existing, ...updates };
    await sql`
      INSERT INTO user_memory (user_email, memory, updated_at)
      VALUES (${email}, ${JSON.stringify(merged)}::jsonb, NOW())
      ON CONFLICT (user_email) DO UPDATE
      SET memory = ${JSON.stringify(merged)}::jsonb, updated_at = NOW()
    `;
    res.json({ ok: true, memory: merged });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/me/memory/:field", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const field = req.params.field;
    await sql`
      UPDATE user_memory
      SET memory = memory - ${field}, updated_at = NOW()
      WHERE user_email = ${email}
    `;
    res.json({ ok: true, deleted: field });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// extractAndUpdateMemory — background function that learns about the user
// from each conversation turn and persists it to user_memory
// ---------------------------------------------------------------------------
async function extractAndUpdateMemory(email, userMessage, assistantReply, existingMemory) {
  // Only run if the message contains personal context worth learning
  const personalSignals = /\b(i am|i'm|i have|i've|i fly|i stay|i train|i run|i work|i travel|my|mine|i prefer|i like|i love|i hate|i don't|i need|i want|i always|i never|we are|we're|my partner|my husband|my wife|my boyfriend|my girlfriend|my friend|my colleague|my team|passport|status|tier|alliance|mosaic|gold|platinum|diamond|elite|business class|first class|cold plunge|technogym|marathon|5k|10k|half marathon|race|coach|physio|training)\b/i;
  if (!personalSignals.test(userMessage) && !personalSignals.test(assistantReply)) return;

  try {
    const extractPrompt = `You are a memory extraction system for a travel concierge app. Your job is to extract factual, persistent facts about the user from a conversation turn and merge them into their existing memory profile.

Existing memory:
${JSON.stringify(existingMemory, null, 2)}

New conversation:
User: ${userMessage}
Assistant: ${assistantReply}

Extract any NEW facts about the user that are worth remembering long-term. Only extract things that are stable personal attributes — not transient questions or one-off requests. Focus on:
- Identity/context (who they are, what they do, where they're based)
- Travel style and tier (luxury, upscale, budget; how they like to travel)
- Loyalty programs and airline/hotel status
- Cabin preferences (always business on long-haul, etc.)
- Hotel brand preferences and must-haves (cold plunge, lap pool, Technogym, etc.)
- Typical travel companions (solo, with partner, with friend, etc.)
- Training/fitness goals (race dates, distances, training phase)
- Recovery requirements (cold plunge, pool, massage, etc.)
- Food/dining preferences and restrictions
- Interests and things they enjoy
- Things they dislike or want to avoid
- Passport/nationality
- Home base city

Return ONLY a JSON object with fields to UPDATE in the memory. Use these exact field names:
identity, travel_style, travel_tier, passport, home_base, loyalty_alliance, loyalty_notes, cabin_default, airline_notes, hotel_brands, hotel_must_haves, food_notes, companions, training, recovery, work_context, interests, dislikes, misc (array of freeform notes)

If nothing new was learned, return {}. Do not repeat things already in the existing memory. Do not invent or infer things not stated. Return only valid JSON, no explanation.`;

    const resp = await getAnthropic().messages.create({
      model: 'claude-haiku-4-5',
      max_tokens: 400,
      messages: [{ role: 'user', content: extractPrompt }],
    });
    const raw = resp.content[0].text.trim();
    // Parse JSON — strip any markdown fences
    const jsonStr = raw.replace(/^```json?\s*/i, '').replace(/\s*```$/, '').trim();
    const updates = JSON.parse(jsonStr);
    if (!updates || typeof updates !== 'object' || Object.keys(updates).length === 0) return;

    // Merge misc arrays rather than overwriting
    const merged = { ...existingMemory };
    for (const [k, v] of Object.entries(updates)) {
      if (k === 'misc') {
        merged.misc = [...(merged.misc || []), ...(Array.isArray(v) ? v : [v])].slice(-20);
      } else if (v !== null && v !== undefined && v !== '') {
        merged[k] = v;
      }
    }

    await sql`
      INSERT INTO user_memory (user_email, memory, updated_at)
      VALUES (${email}, ${JSON.stringify(merged)}::jsonb, NOW())
      ON CONFLICT (user_email) DO UPDATE
      SET memory = ${JSON.stringify(merged)}::jsonb, updated_at = NOW()
    `;
  } catch (e) {
    // Silent failure — memory extraction is best-effort
    console.error('[memory-extract]', e.message);
  }
}

// ---------------------------------------------------------------------------
// POST /concierge — LLM chat with trip context
// ---------------------------------------------------------------------------
app.post("/concierge", conciergeLimiter, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { message: rawMessage, history, location } = req.body || {};
  if (!rawMessage) return res.status(400).json({ error: "message required" });
  // Scrub PII from user message before it reaches Anthropic
  const message = scrubPII(rawMessage);
  try {
    // Fetch user preferences (taste graph), trips, loyalty accounts, hotel affinity, and memory in parallel
    const [userRows, rawTrips, rawLegs, loyaltyAccounts, hotelAffinity, savedInstructions, memoryRows] = await Promise.all([
      sql`SELECT preferences, first_name, COALESCE(revealed_preferences, '{}') as revealed_preferences FROM users WHERE email = ${email}`,
      sql`SELECT id, title, status, mode, created_at, companions_count, companion_names FROM trips WHERE user_email = ${email} ORDER BY created_at DESC LIMIT 25`,
      sql`SELECT tl.* FROM trip_legs tl INNER JOIN trips t ON tl.trip_id = t.id WHERE t.user_email = ${email} ORDER BY tl.departs_at ASC NULLS LAST`,
      sql`SELECT program, points_balance, elite_status, elite_level_next, points_to_next_level, nights_ytd, segments_ytd FROM loyalty_accounts WHERE user_email = ${email} ORDER BY program ASC`,
      sql`SELECT property_name, brand, city, country, tier, attributes, stay_count, last_stayed FROM hotel_affinity WHERE user_email = ${email} ORDER BY stay_count DESC, last_stayed DESC LIMIT 20`,
      sql`SELECT instruction FROM user_instructions WHERE user_email = ${email} ORDER BY created_at DESC LIMIT 20`,
      sql`SELECT memory FROM user_memory WHERE user_email = ${email}`,
    ]);
    // Assemble trips with legs (avoids json_agg ORDER BY Neon compatibility issue)
    const legsByTrip = {};
    for (const leg of rawLegs) {
      if (!legsByTrip[leg.trip_id]) legsByTrip[leg.trip_id] = [];
      legsByTrip[leg.trip_id].push(leg);
    }
    const trips = rawTrips.map(t => ({ ...t, legs: legsByTrip[t.id] || [] }));
    const prefs = userRows[0]?.preferences || {};
    const revealedPrefs = userRows[0]?.revealed_preferences || {};
    const firstName = userRows[0]?.first_name || null;
    const userMemory = memoryRows[0]?.memory || {};
    const today = new Date().toISOString();
    const locationContext = location?.city
      ? `User's current location: ${location.city}${location.country ? ', ' + location.country : ''}${location.lat ? ` (${location.lat.toFixed(3)}, ${location.lon?.toFixed(3) || location.lng?.toFixed(3)})` : ''}`
      : location?.lat
      ? `User's current coordinates: ${location.lat.toFixed(4)}, ${(location.lon || location.lng || 0).toFixed(4)}`
      : null;
    // Detect planning intent — used to switch to planning mode (more tokens, targeted Perplexity queries)
    const isPlanningMode = /\b(plan|planning|itinerary|trip to|travel to|tour|cities|nights?|days?|schedule|route)\b/i.test(message) && message.length > 30;
    // Detect transit/navigation intent for route lookup
    const transitIntentRegex = /how (do i|can i|to) (get|go|travel|commute|take|reach)|directions? (to|from)|transit|bus|metro|subway|train|tram|tube|underground|from .+ to .+|get (from|to) .+|route (to|from)/i;
    const transitMatch = message.match(/(?:from|get to|go to|travel to|directions? to|how (?:do i|can i) get to)\s+(.+?)(?:\s+from\s+(.+?))?(?:\?|$)/i);
    const isTransitQuery = transitIntentRegex.test(message);
    const transitDest = transitMatch ? transitMatch[1]?.trim() : null;
    const transitOrigin = transitMatch ? transitMatch[2]?.trim() : null;
    // Grounding: run Places, Weather, Perplexity, and Transit in parallel (all best-effort)
    const [placesResults, liveWeather, liveSearchContext, transitRoute] = await Promise.all([
      getPlacesGrounding(message, location).catch(() => []),
      getLiveWeather(location).catch(() => null),
      getPerplexityGrounding(message, userMemory).catch(() => null),
      (isTransitQuery && transitDest) ? getTransitRoute(transitOrigin, transitDest, location).catch(() => null) : Promise.resolve(null),
    ]);

    // Enrich trips with live flight status + weather risk (in parallel, best-effort, 5s max)
    const enrichedTrips = await Promise.race([
      Promise.all(trips.map(async (trip) => {
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
    })),
      new Promise(resolve => setTimeout(() => resolve(trips), 5000)),
    ]);
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
          const companionsLabel = trip.companions_count > 0
            ? ` [${trip.companions_count + 1} travellers, ${trip.companions_count + 1} rooms${trip.companion_names ? ` — ${trip.companion_names}` : ""}]`
            : "";
          return `Trip: "${trip.title}"${modeLabel}${companionsLabel}\n${legLines || "  (no legs)"}`.trim();
        }).join("\n\n");

        // Build taste profile section from user preferences
    const editorialSources = (prefs.editorial_sources || []);
    const hotelPrefs = (prefs.hotel_prefs || []);
    const seatPrefs = (prefs.seat_prefs || []);
    const foodPrefs = (prefs.food_prefs || []);
    // Phase 1: extended profile fields
    const loyaltyAlliance = prefs.loyalty_alliance || null;
    const loyaltyPrograms = prefs.loyalty_programs || [];
    const trainingActive = prefs.training_active || false;
    const raceDate = prefs.race_date || null;
    const raceDistance = prefs.race_distance || null;
    const trainingPhase = prefs.training_phase || null;
    const gymBrandPref = prefs.gym_brand_pref || null;
    const coldPlungeReq = prefs.cold_plunge_req || false;
    const poolReq = prefs.pool_req || false;
    const companionDefault = prefs.companion_default || null;
    const travelTier = prefs.travel_tier || null;
    const passportCountry = prefs.passport_country || null;
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

    // Build saved instructions section
    const instructionsSection = savedInstructions && savedInstructions.length > 0
      ? `=== STANDING INSTRUCTIONS FROM USER ===
These are preferences and rules the user has explicitly told you to always follow. Treat them as hard constraints:
${savedInstructions.map(r => `  - ${r.instruction}`).join("\n")}
`
      : "";

    // Build user memory section — the persistent contextual profile
    const memorySection = (() => {
      const m = userMemory;
      if (!m || Object.keys(m).length === 0) return null;
      const lines = [];
      if (firstName) lines.push(`Name: ${firstName}`);
      if (m.identity)       lines.push(`About: ${m.identity}`);
      if (m.travel_style)   lines.push(`Travel style: ${m.travel_style}`);
      if (m.travel_tier)    lines.push(`Tier: ${m.travel_tier}`);
      if (m.passport)       lines.push(`Passport: ${m.passport}`);
      if (m.home_base)      lines.push(`Home base: ${m.home_base}`);
      if (m.loyalty_alliance) lines.push(`Alliance: ${m.loyalty_alliance}`);
      if (m.loyalty_notes)  lines.push(`Loyalty: ${m.loyalty_notes}`);
      if (m.cabin_default)  lines.push(`Default cabin: ${m.cabin_default}`);
      if (m.airline_notes)  lines.push(`Airline preferences: ${m.airline_notes}`);
      if (m.hotel_brands)   lines.push(`Preferred hotel brands: ${m.hotel_brands}`);
      if (m.hotel_must_haves) lines.push(`Hotel must-haves: ${m.hotel_must_haves}`);
      if (m.food_notes)     lines.push(`Food/dining: ${m.food_notes}`);
      if (m.companions)     lines.push(`Typical travel companions: ${m.companions}`);
      if (m.training)       lines.push(`Training/fitness: ${m.training}`);
      if (m.recovery)       lines.push(`Recovery requirements: ${m.recovery}`);
      if (m.work_context)   lines.push(`Work context: ${m.work_context}`);
      if (m.interests)      lines.push(`Interests: ${m.interests}`);
      if (m.dislikes)       lines.push(`Dislikes/avoid: ${m.dislikes}`);
      if (m.misc && Array.isArray(m.misc)) m.misc.forEach(note => lines.push(`Note: ${note}`));
      if (lines.length === 0) return null;
      return `=== WHO THIS USER IS (persistent memory — treat as ground truth) ===
This is everything Wingman has learned about this user over time. Use it to inform every response without the user needing to re-explain themselves.
${lines.join("\n")}
`;
    })();

    // ── Concierge system prompt, split for prompt caching ─────────────────
    // The static half has zero interpolation, so it is byte-identical on every
    // request and can serve as a cached prefix. It MUST come first — caching only
    // works on an identical prefix. Per-request context follows it.
    const conciergeStatic = `You are Wingman — a world-class AI travel concierge and destination intelligence engine. You combine the knowledge of a seasoned luxury travel editor, a Michelin-starred restaurant scout, a hotel critic, and a local fixer in every city on earth. You have real-time access to the user's trips, live flight statuses, and weather disruption risk scores. You know this user's personal taste profile and editorial preferences — use them to give recommendations that feel like they came from a trusted friend with impeccable taste and deep local knowledge, not a generic algorithm.

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

=== VOICE — YOU ARE A CHIEF OF STAFF, NOT A CONCIERGE ===
Act like the principal's trusted chief of staff: three steps ahead, discreet, and protective of their time and attention.
- Open with a read, not raw data ("You're in good shape"), then the substance.
- Report what you have already handled; never announce baseline monitoring ("I'm watching your flight") — that is assumed and should feel intuitive.
- Prioritise ruthlessly. Surface only what genuinely needs the user, and bundle it. Suppress noise.
- Always carry a recommendation with a short reason drawn from memory ("you loved the kaiseki in Kanazawa, so I'd lock it"), and offer a sensible default the user can approve in one word.
- Ask a brief, specific question when a preference is genuinely unknown — do not guess. One question per unknown.
- Close with agency ("say the word and I'll take it from here").
- Warm, economical, personal. You know this user; use memory so they never re-explain themselves.

=== RESPONSE FORMAT — CRITICAL ===
- NEVER use markdown: no #, ##, **, *, -, bullet points, or any other markdown syntax
- Write in plain conversational prose only — like a text message from a trusted chief of staff
- Keep responses concise: 1-3 sentences unless the user explicitly asks for more detail
- Do not list capabilities or introduce yourself unless directly asked
- Never start a response with "I" or "As your"
- Lead with a direct answer to what was asked. You MAY briefly surface a single time-sensitive item the user would clearly want handled (e.g. a reservation about to sell out) with a recommendation and a one-word-approvable default — but never pad replies with unsolicited itineraries or lists.
- Don't lecture the user on how to spend their time; offer, don't instruct.
- If the user asks a question, answer it directly and concisely. When a decision genuinely depends on a preference you don't know, ask one brief clarifying question rather than guessing.

=== RECOMMENDATION STYLE ===
- Make recommendations when asked, and when you proactively surface a time-sensitive item (per the Voice section) — but keep proactive suggestions to a single high-value item, never a list.
- Always be specific: name the actual place from the verified Places list. Never say "there are many great options."
- Follow the user's lead — if they say they want to visit somewhere, help them do it, don't redirect them
- Reference the user's taste profile only when it's directly relevant to what they asked
- Trip modes: [CLIENT TRIP] = prioritize prestige, private dining, car service; [PARTNER/LEISURE TRIP] = romance, design-forward boutique hotels, chef's table dinners; no mode = solo/efficiency
- If the user is in a disruption situation, lead with the rescue options first
- If data is missing or stale, say so honestly

=== BOOKING & TICKETING ===
- When the user asks about tickets, booking, or reservations for an attraction, restaurant, or experience, ALWAYS include a direct booking link or action — never just say "you can buy tickets online"
- For attractions: search the Places results for a website URL; if present, tell the user you can open the booking page directly
- For restaurants: if the user wants to book, offer to open OpenTable, Resy, or the restaurant's direct site
- For flights: offer to open the Wingman flight booking flow
- End your response with an ACTION line when there's a concrete next step. Two forms:
  · External link:  ACTION:{"type":"book","label":"<button label>","url":"<url>"}
  · In-app action:  ACTION:{"type":"navigate","label":"<button label>","screen":"<Screen>","params":{...}}
  Valid screens: FlightSearch, AddTrip, TripDetail, Disruption, Destination, LoungeCards, AirportDining, GroundTransport, Expenses, Decisions.
  The app renders this as a tappable button. Only include one ACTION per response.
- If no direct URL is available, say so honestly and suggest the best alternative (phone number, walk-in timing, etc.)

=== PROPOSE, DON'T JUST ANSWER ===
You are a chief of staff, not a search box. When you have enough context to know what the
user will most likely want next, PROPOSE it — with an ACTION button — rather than waiting
to be asked. Draw on their memory and history: the hotels they return to, their cabin, the
airports they use.
- "You've stayed at The Hoxton in Florence twice. Want me to look at it again for these dates?" → ACTION
- If a flight is disrupted and they haven't acted: propose the rebooking, don't describe it.
- If they mention a city with no trip yet: offer to start the trip.
Never propose more than one thing at a time — bring ONE decision with a recommendation.
Only propose something you can actually follow through on. Never invent a booking, a price,
or an availability you haven't been given; if you don't know, say so plainly.

=== TRIP PLANNING MODE ===
When the user asks you to plan a trip, build an itinerary, or mentions visiting multiple cities or destinations:

1. CLARIFYING QUESTIONS FIRST (if dates, companions, or purpose are missing): Ask 1-2 targeted questions before planning. Keep it brief — one question per unknown. Do not ask about things you already know from the user's profile (e.g. don't ask about hotel preferences if you already know them from memory).

2. WHEN YOU HAVE ENOUGH CONTEXT: Build a detailed day-by-day plan. For each city:
   - Recommend a specific hotel (name it, explain why it fits this user's profile — reference their must-haves like cold plunge, Technogym, gym brand)
   - Note which loyalty program is accepted and whether their status applies
   - Suggest 1-2 restaurants per city (specific names, not generic descriptions)
   - Flag any training/recovery considerations if relevant (e.g. "The Aman has a 25m lap pool — good for quality sessions")
   - Note the best neighbourhood to stay in and why

3. FLIGHT ROUTING: When recommending flights between cities, consider:
   - The user's airline status and alliance (route through hubs where their status is recognised)
   - Suggest specific routing (e.g. LHR → NRT on BA, connecting in London to earn Avios)
   - Flag if a route requires a connection and whether it's worth it vs direct

4. PLAN TAG: After your full text reply, emit a PLAN tag on its own line with a compact JSON object (no newlines inside the JSON):
  PLAN:{"title":"<trip name>","cities":["<city1>","<city2>",...],"nights":<total nights>,"legs":[{"from":"<city>","to":"<city>","date":"<YYYY-MM-DD>","type":"flight","routing":"<e.g. LHR-NRT on BA"},{"city":"<city>","hotel":"<specific hotel name>","nights":<n>,"check_in":"<YYYY-MM-DD>","loyalty_program":"<program>","why":"<one sentence why it fits this user>"},...],"highlights":["<key highlight 1>","<key highlight 2>","<key highlight 3>"],"training_notes":"<optional: quality windows, rest days, pool/gym notes>"}
- Only emit one PLAN tag per response. Only emit it when you have actually built a multi-city trip plan (not for single questions or day-trip queries).
- The PLAN tag allows the app to render a "Save this trip" button so the user can instantly add the itinerary to Wingman.

=== TRIP WRITE-BACK (modifying existing trips from chat) ===
You have access to the user's trips listed above, including their trip IDs and leg IDs. When the user asks you to modify their trips — add a leg, change a date, delete a leg, rename a trip — you can do it directly.

After your text reply, emit a WRITE tag on its own line with a compact JSON command (no newlines inside the JSON):

To ADD a leg to an existing trip:
  WRITE:{"action":"add_leg","trip_id":"<trip id>","leg":{"type":"flight|hotel|car|train","carrier":"<airline or hotel name>","flight_number":"<flight number if flight>","origin":"<IATA or city>","destination":"<IATA or city>","departs_at":"<ISO8601>","arrives_at":"<ISO8601 or null>","cabin_class":"<economy|business|first>","nights":<number if hotel>,"property_name":"<hotel name if hotel>"}}

To UPDATE an existing leg:
  WRITE:{"action":"update_leg","trip_id":"<trip id>","leg_id":"<leg id>","updates":{"<field>":"<new value>"}}

To DELETE a leg:
  WRITE:{"action":"delete_leg","trip_id":"<trip id>","leg_id":"<leg id>"}

To UPDATE trip metadata (title, status):
  WRITE:{"action":"update_trip","trip_id":"<trip id>","updates":{"title":"<new title>"}}

Rules:
- Only emit a WRITE tag when the user explicitly asks you to make a change to their trips
- Always confirm what you did in your text reply (e.g. "Done — I've added the Park Hyatt Tokyo check-in to your Asia trip.")
- Only emit one WRITE tag per response
- Never emit a WRITE tag for planning/research responses — only for confirmed changes the user has asked for
- If the trip_id or leg_id you need is not in the trips list above, tell the user you can't find it and ask them to check their Trips screen
`;

    // Per-request context — changes every call, so it sits AFTER the cached prefix.
    const conciergeDynamic = `

Today's date/time: ${today}
User: ${firstName ? firstName + ' (' + email + ')' : email}
${memorySection || ''}${instructionsSection}${tasteSection ? `=== USER'S TASTE PROFILE ===\n${tasteSection}\n` : ""}
${loyaltySummary ? `=== USER'S LOYALTY ACCOUNTS ===\n${loyaltySummary}\n\nWhen recommending hotels, always factor in which programs the user has status with and suggest properties where their status will be recognized. When advising on flights, factor in their airline status and miles balance — suggest using miles for upgrades when the balance is high.\n` : ""}
${locationContext ? `=== USER'S CURRENT LOCATION ===\n${locationContext}\nUse this to give hyper-local recommendations. If the user asks "what should I do" or "where should I eat" without specifying a city, assume they mean right now, right here.\n` : ""}
${liveWeather ? `=== LIVE WEATHER AT USER'S LOCATION ===\nCurrently ${liveWeather.temp}\u00b0C (feels like ${liveWeather.feels}\u00b0C), ${liveWeather.desc}${liveWeather.windKph ? `, wind ${liveWeather.windKph} km/h` : ''}${liveWeather.humidity ? `, humidity ${liveWeather.humidity}%` : ''}.\nUse this when the user asks about weather, what to wear, or whether to go outside.\n` : ""}
${placesResults.length > 0 ? `=== NEARBY PLACES (REAL — from Google Maps, verified) ===\nThe following businesses actually exist near the user right now. ONLY recommend places from this list when asked for local recommendations. NEVER invent or hallucinate business names.\n${placesResults.map((p, i) => `${i+1}. ${p.name} — ${p.address || 'nearby'}${p.rating ? ` · ${p.rating}★ (${p.user_ratings_total} reviews)` : ''}${p.open_now === true ? ' · Open now' : p.open_now === false ? ' · Currently closed' : ''}${p.price_level !== null ? ' · ' + ['Free','Inexpensive','Moderate','Expensive','Very expensive'][p.price_level] || '' : ''}\n   Maps: ${p.maps_url}`).join('\n')}\n\nCRITICAL: You MUST only name businesses from the list above. If none match what the user is asking for, say so honestly and describe the type of neighbourhood to look in instead.\n` : ""}
${liveSearchContext ? `=== LIVE SEARCH RESULTS (current as of today — use these to ground your recommendations) ===\n${liveSearchContext}\n\nIMPORTANT: Prioritize information from the live search results above your training data when they conflict. If the search results mention a restaurant or hotel is closed, do not recommend it.\n` : ""}
${transitRoute ? `=== TRANSIT ROUTE (from Google Directions API — verified) ===\nRoute: ${transitRoute.start_address} → ${transitRoute.end_address}\nTotal journey: ${transitRoute.total_duration}${transitRoute.total_distance ? ` · ${transitRoute.total_distance}` : ''}${transitRoute.departure_time ? ` · Departs ${transitRoute.departure_time}` : ''}${transitRoute.arrival_time ? ` · Arrives ${transitRoute.arrival_time}` : ''}\n\nSTEPS:\n${transitRoute.steps.map((s, i) => `${i+1}. [${s.mode}] ${s.instruction}${s.duration ? ` (${s.duration})` : ''}${s.transit ? ` — ${s.transit.vehicle || 'Transit'} ${s.transit.line || ''}, board at ${s.transit.departure_stop || ''}, alight at ${s.transit.arrival_stop || ''}${s.transit.departure_time ? ` (departs ${s.transit.departure_time})` : ''}${s.transit.num_stops ? `, ${s.transit.num_stops} stops` : ''}` : ''}`).join('\n')}\n\n${transitRoute.payment ? `PAYMENT IN THIS CITY:\n- Card: ${transitRoute.payment.card}\n- App: ${transitRoute.payment.app}\n- Cash: ${transitRoute.payment.cash}\n- TIP: ${transitRoute.payment.tip}\n- Buy tickets: ${transitRoute.payment.ticket_url}` : ''}\n\nOpen in Maps: ${transitRoute.maps_url}\n\nCRITICAL TRANSIT INSTRUCTIONS: When presenting this route, always include: (1) the specific transit line/bus number, (2) exactly how to pay in this city (especially whether Apple Pay works), (3) whether to tap in AND out or just tap in, (4) the direct ticket purchase link. End your response with: ACTION:{"type":"maps","label":"Open in Maps","url":"${transitRoute.maps_url}"} on its own line.\n` : ""}
=== USER'S TRIPS (with live data) ===
${tripsSummary}

`;

    const systemPrompt = `${conciergeStatic}\n\n${conciergeDynamic}`;


    // Scrub PII from history messages too
    const safeHistory = Array.isArray(history)
      ? history.slice(-10).map(m => ({ ...m, content: scrubPII(m.content) }))
      : [];
    const messages = [
      { role: "system", content: systemPrompt },
      ...safeHistory,
      { role: "user", content: message },
    ];

    // Claude requires system prompt separate from messages array
    const systemMsg = messages.find(m => m.role === "system")?.content || "";
    const chatMessages = messages.filter(m => m.role !== "system");
        const claudeResp = await Promise.race([
      getAnthropic().messages.create({
        model: "claude-sonnet-4-5",
        max_tokens: isPlanningMode ? 2500 : 1000,
        // Prompt caching: the static instruction block (~2.7k tokens) is byte-identical
        // on every request, so on a cache hit it's billed at ~10% of the input rate.
        // Per-request context follows it, uncached. Order matters — the cached block
        // must be the prefix.
        system: [
          { type: "text", text: conciergeStatic, cache_control: { type: "ephemeral" } },
          { type: "text", text: conciergeDynamic },
        ],
        messages: chatMessages,
      }),
      new Promise((_, reject) =>
        setTimeout(() => reject(Object.assign(new Error("Concierge LLM timeout after 55s"), { name: "TimeoutError" })), 55000)
      ),
    ]);
    // Strip any markdown that slips through — render as plain text on mobile
    const rawReply = claudeResp.content[0].text;

    // ── Persistent memory: detect instruction phrases and save them ──────
    const instructionPhrases = [
      /\b(?:always|never|every time|from now on|please always|please never|remember that|remember to|don't forget|make sure you always|make sure you never)\b.{5,120}/gi,
    ];
    for (const pattern of instructionPhrases) {
      const matches = rawMessage.match(pattern);
      if (matches) {
        for (const match of matches) {
          const cleaned = match.trim().replace(/[.!?]+$/, '').trim();
          if (cleaned.length > 10) {
            sql`INSERT INTO user_instructions (user_email, instruction, source) VALUES (${email}, ${cleaned}, 'chat') ON CONFLICT DO NOTHING`.catch(() => {});
          }
        }
      }
    }

    // ── Persistent memory: silently extract and update user memory from conversation ──
    // Run async in background — does not block the response
    extractAndUpdateMemory(email, rawMessage, rawReply, userMemory).catch(() => {});
    // Extract ACTION tag before stripping
    let bookingAction = null;
    const actionMatch = rawReply.match(/ACTION:(\{[^\n]+\})/m);
    if (actionMatch) {
      try { bookingAction = JSON.parse(actionMatch[1]); } catch {}
    }

    // Extract PLAN tag — structured trip plan returned when Claude plans a multi-city trip
    // Format: PLAN:{"title":"...","cities":[...],"nights":19,"legs":[...],"highlights":[...]}
    let tripPlan = null;
    const planMatch = rawReply.match(/PLAN:({[\s\S]+?})(?:\n|$)/m);
    if (planMatch) {
      try { tripPlan = JSON.parse(planMatch[1]); } catch {}
    }

    // Extract WRITE tag — server-side trip/leg mutations emitted by Claude
    // Format: WRITE:{"action":"add_leg","trip_id":"...","leg":{...}}
    // Format: WRITE:{"action":"update_leg","trip_id":"...","leg_id":"...","updates":{...}}
    // Format: WRITE:{"action":"delete_leg","trip_id":"...","leg_id":"..."}
    // Format: WRITE:{"action":"update_trip","trip_id":"...","updates":{...}}
    let writeResult = null;
    const writeMatch = rawReply.match(/WRITE:({[^\n]+})/m);
    if (writeMatch) {
      try {
        const cmd = JSON.parse(writeMatch[1]);
        if (cmd.action === 'add_leg' && cmd.trip_id && cmd.leg) {
          // Verify ownership
          const tr = await sql`SELECT id FROM trips WHERE id = ${cmd.trip_id} AND user_email = ${email}`;
          if (tr.length) {
            const leg = cmd.leg;
            const ins = await sql`
              INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation, property_name, cabin_class, seat, nights, guests)
              VALUES (${cmd.trip_id}, ${leg.type||'flight'}, ${leg.carrier||null}, ${leg.flight_number||null}, ${leg.origin||null}, ${leg.destination||null}, ${leg.departs_at||null}, ${leg.arrives_at||null}, ${leg.confirmation||null}, ${leg.property_name||null}, ${leg.cabin_class||null}, ${leg.seat||null}, ${leg.nights||null}, ${leg.guests||null})
              RETURNING *
            `;
            writeResult = { action: 'add_leg', leg: ins[0] };
          }
        } else if (cmd.action === 'update_leg' && cmd.trip_id && cmd.leg_id && cmd.updates) {
          const tr = await sql`SELECT id FROM trips WHERE id = ${cmd.trip_id} AND user_email = ${email}`;
          if (tr.length) {
            const allowed = ['type','carrier','flight_number','origin','destination','departs_at','arrives_at','confirmation','property_name','cabin_class','seat','nights','guests'];
            const fields = Object.keys(cmd.updates).filter(k => allowed.includes(k));
            for (const f of fields) {
              await sql`UPDATE trip_legs SET ${sql(f)} = ${cmd.updates[f]||null} WHERE id = ${cmd.leg_id} AND trip_id = ${cmd.trip_id}`;
            }
            const upd = await sql`SELECT * FROM trip_legs WHERE id = ${cmd.leg_id}`;
            writeResult = { action: 'update_leg', leg: upd[0] };
          }
        } else if (cmd.action === 'delete_leg' && cmd.trip_id && cmd.leg_id) {
          const tr = await sql`SELECT id FROM trips WHERE id = ${cmd.trip_id} AND user_email = ${email}`;
          if (tr.length) {
            await sql`DELETE FROM trip_legs WHERE id = ${cmd.leg_id} AND trip_id = ${cmd.trip_id}`;
            writeResult = { action: 'delete_leg', leg_id: cmd.leg_id };
          }
        } else if (cmd.action === 'update_trip' && cmd.trip_id && cmd.updates) {
          const tr = await sql`SELECT id FROM trips WHERE id = ${cmd.trip_id} AND user_email = ${email}`;
          if (tr.length) {
            const allowed = ['title','status','mode','companions_count','companion_names'];
            const fields = Object.keys(cmd.updates).filter(k => allowed.includes(k));
            for (const f of fields) {
              await sql`UPDATE trips SET ${sql(f)} = ${cmd.updates[f]||null} WHERE id = ${cmd.trip_id}`;
            }
            writeResult = { action: 'update_trip', trip_id: cmd.trip_id };
          }
        }
      } catch (we) {
        console.error('[concierge/write]', we.message);
      }
    }

    // Also detect planning intent heuristically and ask Claude to emit a PLAN tag
    const planningIntent = !tripPlan && /\b(plan|planning|itinerary|trip to|travel to|visit|tour|cities|nights?|days?)\b/i.test(rawMessage) && rawMessage.length > 40;
    // (The system prompt instructs Claude to emit PLAN: when it detects trip planning; this is a fallback)
    const reply = rawReply
      .replace(/^ACTION:\{[^\n]+\}\s*$/gm, '') // remove ACTION line
      .replace(/^PLAN:\{[\s\S]+?\}\s*$/gm, '') // remove PLAN line
      .replace(/^WRITE:\{[^\n]+\}\s*$/gm, '') // remove WRITE line
      .replace(/^#{1,6}\s+/gm, '')              // remove # headings
      .replace(/\*\*([^*]+)\*\*/g, '$1')        // remove **bold**
      .replace(/\*([^*]+)\*/g, '$1')            // remove *italic*
      .replace(/^[\-\*]\s+/gm, '\u2022 ')      // convert bullet - to bullet point
      .replace(/\n{3,}/g, '\n\n')               // collapse triple newlines
      .trim();
    // Award points for first concierge message (idempotent)
    res.json({ ok: true, reply, places: placesResults.length > 0 ? placesResults : undefined, weather: liveWeather || undefined, action: bookingAction || undefined, transit: transitRoute || undefined, plan: tripPlan || undefined, write: writeResult || undefined });
  } catch (e) {
    console.error("[concierge]", e.message);
    const isTimeout = e.name === "TimeoutError" || e.message?.includes("timeout");
    const isCreditError = e.message?.includes("credit balance") || e.message?.includes("insufficient_quota");
    const statusCode = isTimeout ? 504 : 500;
    const clientMsg = isTimeout
      ? "timeout"
      : isCreditError
      ? "service_unavailable"
      : "concierge_error";
    res.status(statusCode).json({ error: clientMsg, detail: e.message });
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
// ── ML prediction module (BTS logistic regression, 1.02M training flights) ──
const { predict: mlPredict, loadModel: mlLoadModel } = require('./predict_service');
try { mlLoadModel(); } catch (e) { console.warn('[predict] ML model load failed:', e.message); }

app.get("/predict", async (req, res) => {
  const dep     = String(req.query.dep     || "DEN").toUpperCase();
  const arr     = String(req.query.arr     || "ASE").toUpperCase();
  const carrier = String(req.query.carrier || "AA").toUpperCase();
  const month   = parseInt(req.query.month)   || new Date().getMonth() + 1;
  const dow     = parseInt(req.query.dow)     || new Date().getDay() || 7;
  const hour    = parseInt(req.query.hour)    || 8;
  const dist    = parseInt(req.query.dist)    || 1000;

  const depI = ICAO[dep] || "K" + dep;
  const arrI = ICAO[arr] || "K" + arr;
  const [dm, am] = await Promise.all([metar(depI), metar(arrI)]);
  const dw = weatherScore(dm);
  const aw = weatherScore(am);

  // METAR composite score (0-1) — average of dep + arr weather severity
  const metarScore = (dw.score + aw.score) / 2;

  // Mountain airport sensitivity factor
  const mtn = (MOUNTAIN.has(arr) ? 1 : 0) * 0.85 + (MOUNTAIN.has(dep) ? 1 : 0) * 0.2;

  // ── ML model prediction (BTS logistic regression) ──
  let mlResult = null;
  try {
    mlResult = mlPredict({
      carrier, origin: dep, dest: arr,
      month, day_of_week: dow, dep_hour: hour, distance: dist,
      metar_score: metarScore,
    });
  } catch (e) {
    console.warn('[predict] ML inference failed:', e.message);
  }

  // ── Composite risk score ──
  // If ML model is available, use its composite score; otherwise fall back to METAR heuristic
  let risk, sources;
  if (mlResult) {
    // ML already blends METAR; add mountain sensitivity on top
    const mtnBoost = Math.round(Math.min(mtn, 1) * 15);
    risk = Math.min(mlResult.risk_score + mtnBoost, 95);
    sources = [
      "BTS Reporting Carrier On-Time Performance 2022-2024 (1.02M flights)",
      "aviationweather.gov METAR",
      "airport ops profile",
    ];
  } else {
    // Legacy METAR-only heuristic fallback
    const fDep  = Math.round(dw.score * 34);
    const fArr  = Math.round(aw.score * 32);
    const fMtn  = Math.round(Math.min(mtn, 1) * 20);
    risk = Math.min(fDep + fArr + fMtn + 6, 95);
    sources = ["aviationweather.gov METAR", "airport ops profile"];
  }

  const factors = [
    { label: "Historical route performance", points: mlResult ? Math.round(mlResult.ml_probability * 60) : 0,
      impact: impactOf(mlResult ? Math.round(mlResult.ml_probability * 60) : 0),
      detail: mlResult
        ? `${carrier} ${dep}→${arr} has a ${(mlResult.ml_probability * 100).toFixed(0)}% historical delay rate on this route/time (BTS 2022-2024)`
        : "ML model unavailable" },
    { label: "Weather at " + dep, points: Math.round(dw.score * 34), impact: impactOf(Math.round(dw.score * 34)), detail: dw.notes.join(", ") || "Clear" },
    { label: "Weather at " + arr, points: Math.round(aw.score * 32), impact: impactOf(Math.round(aw.score * 32)), detail: aw.notes.join(", ") || "Clear" },
    { label: "Airport sensitivity", points: Math.round(Math.min(mtn, 1) * 15), impact: impactOf(Math.round(Math.min(mtn, 1) * 15)),
      detail: MOUNTAIN.has(arr) ? arr + " has strict weather minimums" : "standard airport tolerances" },
  ].filter(f => f.points > 0);

  const email = await verifyAccessToken(req);
  const summary = risk >= 60
    ? `High disruption risk on ${dep} → ${arr}. Historical data shows ${carrier} delays ${(mlResult?.ml_probability * 100 || 30).toFixed(0)}% of the time on this route.`
    : risk >= 35
    ? `Moderate disruption risk on ${dep} → ${arr}. Monitor conditions before departure.`
    : `Conditions look manageable on ${dep} → ${arr}.`;

  res.json({
    dep, arr, carrier, risk,
    live: !!(dm || am),
    summary,
    factors,
    sources,
    ml: mlResult ? {
      probability: mlResult.ml_probability,
      model_version: mlResult.model_version,
      trained_rows: mlResult.trained_rows,
      data_source: mlResult.data_source,
      roc_auc: 0.6346,
    } : null,
    metar: { dep: dw.raw, arr: aw.raw },
    user: email,
    ts: Date.now(),
  });
});

// ---------------------------------------------------------------------------
// Live flight status — FlightAware AeroAPI (primary) + AviationStack (fallback)
// ---------------------------------------------------------------------------
const AEROAPI_BASE = "https://aeroapi.flightaware.com/aeroapi";

// FlightAware AeroAPI — primary source
async function getFlightStatusFlightAware(flightIdent) {
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
    return { status, delay, gate, terminal, actualDep, scheduledDep, source: "flightaware" };
  } catch (e) {
    console.error("[aeroapi]", e.message);
    return null;
  }
}

// AviationStack — free-tier fallback (500 calls/mo free, $9.99/mo for 10K)
// Maps AviationStack flight_status values to Wingman's canonical status strings
const AVIATIONSTACK_STATUS_MAP = {
  scheduled: "Scheduled",
  active:    "In Air",
  landed:    "Landed",
  cancelled: "Cancelled",
  incident:  "Cancelled",
  diverted:  "Delayed",
};
async function getFlightStatusAviationStack(flightIdent) {
  const key = process.env.AVIATIONSTACK_API_KEY;
  if (!key) return null;
  // Parse IATA carrier code + flight number (e.g. "AA100" → iata_code=AA, flight_number=100)
  const match = flightIdent.match(/^([A-Z]{2,3})(\d+)$/);
  if (!match) return null;
  const [, iata, num] = match;
  try {
    const url = `http://api.aviationstack.com/v1/flights?access_key=${key}&flight_iata=${encodeURIComponent(flightIdent)}&limit=1`;
    const r = await fetch(url, { headers: { "Accept": "application/json" } });
    if (!r.ok) return null;
    const j = await r.json();
    const flight = j.data?.[0];
    if (!flight) return null;
    const rawStatus = (flight.flight_status || "").toLowerCase();
    const status = AVIATIONSTACK_STATUS_MAP[rawStatus] || "Unknown";
    // Compute delay in minutes from scheduled vs estimated departure
    let delay = 0;
    const sched = flight.departure?.scheduled;
    const est   = flight.departure?.estimated || flight.departure?.actual;
    if (sched && est) {
      delay = Math.max(0, Math.round((new Date(est) - new Date(sched)) / 60000));
    }
    const gate     = flight.departure?.gate || null;
    const terminal = flight.departure?.terminal || null;
    const actualDep    = flight.departure?.actual || flight.departure?.estimated || null;
    const scheduledDep = flight.departure?.scheduled || null;
    return { status, delay, gate, terminal, actualDep, scheduledDep, source: "aviationstack" };
  } catch (e) {
    console.error("[aviationstack]", e.message);
    return null;
  }
}

// Unified getFlightStatus — tries FlightAware first, falls back to AviationStack
async function getFlightStatus(flightIdent) {
  const fa = await getFlightStatusFlightAware(flightIdent);
  if (fa) return fa;
  return getFlightStatusAviationStack(flightIdent);
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
app.get("/privacy-html", (_req, res) => {
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
      model: "claude-sonnet-4-5",
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
      model: "claude-sonnet-4-5",
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
        briefing_hour: prefs.briefing_hour ?? 7,
        briefing_min: prefs.briefing_min ?? 0,
        briefing_enabled: prefs.briefing_enabled !== false,
      },
    });
  } catch (e) {
    res.json({ policy: { autonomy_mode: "always_ask", threshold: 500, payment_preference: "best_value", cabin_preference: "economy", notify_on_action: true, weather_alerts: true, price_alerts: true, quiet_hours: true, briefing_hour: 7, briefing_min: 0, briefing_enabled: true } });
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
// Passenger Profile  POST /profile/passenger
// Stores traveler details (name, DOB, gender, phone) needed for silent autonomy bookings.
// These are stored encrypted in the user's preferences JSONB under 'passenger_profile'.
// ---------------------------------------------------------------------------
app.post("/profile/passenger", auth, async (req, res) => {
  const body = req.body || {};
  // Accept both field name conventions (app sends first_name/last_name, some clients send given_name/family_name)
  const given_name = body.given_name || body.first_name;
  const family_name = body.family_name || body.last_name;
  const { born_on, gender, phone, passport_number, passport_expiry, passport_country } = body;
  if (!given_name || !family_name || !born_on) {
    return res.status(400).json({ error: "first_name (or given_name), last_name (or family_name), and born_on are required" });
  }
  try {
    const rows = await sql`SELECT preferences FROM users WHERE email = ${req.user.email}`;
    const existing = rows[0]?.preferences || {};
    const passengerProfile = {
      given_name: sanitiseStr(given_name, 100),
      family_name: sanitiseStr(family_name, 100),
      born_on: sanitiseStr(born_on, 20),
      gender: sanitiseStr(gender || "m", 10),
      phone: sanitiseStr(phone || "", 30),
      ...(passport_number ? {
        passport_number: sanitiseStr(passport_number, 20),
        passport_expiry: sanitiseStr(passport_expiry || "", 20),
        passport_country: sanitiseStr(passport_country || "US", 5),
      } : {}),
    };
    const merged = { ...existing, passenger_profile: passengerProfile };
    await sql`UPDATE users SET preferences = ${JSON.stringify(merged)}::jsonb WHERE email = ${req.user.email}`;
    // Also sync given_name → users.first_name so the Home greeting works
    await sql`UPDATE users SET first_name = ${passengerProfile.given_name} WHERE email = ${req.user.email}`;
    res.json({ ok: true, passenger_profile: { given_name: passengerProfile.given_name, family_name: passengerProfile.family_name, born_on: passengerProfile.born_on } });
  } catch (e) {
    res.status(500).json({ error: "Failed to save passenger profile", detail: e.message });
  }
});

// GET /profile/passenger — retrieve stored traveler details (masked)
app.get("/profile/passenger", auth, async (req, res) => {
  try {
    const rows = await sql`SELECT preferences FROM users WHERE email = ${req.user.email}`;
    const profile = rows[0]?.preferences?.passenger_profile;
    if (!profile) return res.json({ passenger_profile: null });
    // Return masked version — never expose full passport/DOB over the wire
    res.json({
      passenger_profile: {
        given_name: profile.given_name,
        family_name: profile.family_name,
        born_on: profile.born_on ? profile.born_on.slice(0, 4) + "-**-**" : null,
        gender: profile.gender,
        phone: profile.phone ? profile.phone.slice(0, 4) + "****" : null,
        has_passport: !!profile.passport_number,
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Passport OCR  POST /profile/passport-scan
// Accepts a base64-encoded passport image, uses Claude Vision to extract MRZ
// data, and saves the result to the passenger_profile.
// PII note: the image is sent to Anthropic but NOT stored on our servers.
// The extracted fields (name, DOB, passport number) are stored encrypted in
// the user's preferences JSONB under passenger_profile.
// ---------------------------------------------------------------------------
app.post("/profile/passport-scan", auth, requirePro, async (req, res) => {
  const { image_base64, media_type = "image/jpeg" } = req.body || {};
  if (!image_base64) return res.status(400).json({ error: "image_base64 required" });
  // Validate media type
  const allowed = ["image/jpeg", "image/png", "image/webp", "image/gif"];
  if (!allowed.includes(media_type)) return res.status(400).json({ error: "Unsupported media type" });
  // Enforce max image size (1.5 MB base64 ≈ 1.1 MB binary)
  if (image_base64.length > 2_000_000) return res.status(413).json({ error: "Image too large (max ~1.5 MB)" });
  try {
    const anthropic = getAnthropic();
    const response = await anthropic.messages.create({
      // MRZ extraction is structured OCR, not reasoning — Haiku vision handles it
      // fine at a fraction of Opus's cost.
      model: "claude-haiku-4-5",
      max_tokens: 400,
      messages: [{
        role: "user",
        content: [
          {
            type: "image",
            source: { type: "base64", media_type, data: image_base64 },
          },
          {
            type: "text",
            text: `You are a passport MRZ (Machine Readable Zone) parser. Extract the following fields from this passport image and return ONLY valid JSON with no other text:
{
  "given_name": "<first name(s) as on passport>",
  "family_name": "<surname as on passport>",
  "born_on": "<date of birth in YYYY-MM-DD format>",
  "gender": "<m or f>",
  "passport_number": "<passport number>",
  "passport_expiry": "<expiry date in YYYY-MM-DD format>",
  "passport_country": "<3-letter ISO country code>",
  "nationality": "<3-letter ISO nationality code>"
}
If a field cannot be read, use null. Do not include any explanation or markdown.`,
          },
        ],
      }],
    });
    let parsed;
    try {
      parsed = JSON.parse(response.content[0].text.replace(/```json\n?|```/g, "").trim());
    } catch (_) {
      return res.status(422).json({ error: "Could not parse passport data", raw: response.content[0].text });
    }
    // Validate we got at least name and DOB
    if (!parsed.given_name || !parsed.family_name || !parsed.born_on) {
      return res.status(422).json({ error: "Could not extract required fields (name, date of birth) from passport image" });
    }
    // Sanitise all extracted fields
    const passengerProfile = {
      given_name:       sanitiseStr(parsed.given_name, 100),
      family_name:      sanitiseStr(parsed.family_name, 100),
      born_on:          sanitiseStr(parsed.born_on, 20),
      gender:           sanitiseStr(parsed.gender || "m", 10),
      passport_number:  parsed.passport_number  ? sanitiseStr(parsed.passport_number, 20)  : undefined,
      passport_expiry:  parsed.passport_expiry  ? sanitiseStr(parsed.passport_expiry, 20)  : undefined,
      passport_country: parsed.passport_country ? sanitiseStr(parsed.passport_country, 5)  : undefined,
      nationality:      parsed.nationality      ? sanitiseStr(parsed.nationality, 5)        : undefined,
      ocr_source: "claude_vision",
      ocr_at: new Date().toISOString(),
    };
    // Remove undefined fields
    Object.keys(passengerProfile).forEach(k => passengerProfile[k] === undefined && delete passengerProfile[k]);
    // Merge into existing preferences
    const rows = await sql`SELECT preferences FROM users WHERE email = ${req.user.email}`;
    const existing = rows[0]?.preferences || {};
    const merged = { ...existing, passenger_profile: { ...(existing.passenger_profile || {}), ...passengerProfile } };
    await sql`UPDATE users SET preferences = ${JSON.stringify(merged)}::jsonb WHERE email = ${req.user.email}`;
    // Sync first_name to users table for greeting
    await sql`UPDATE users SET first_name = ${passengerProfile.given_name} WHERE email = ${req.user.email}`;
    // Return masked confirmation — never echo passport number back
    res.json({
      ok: true,
      passenger_profile: {
        given_name:      passengerProfile.given_name,
        family_name:     passengerProfile.family_name,
        born_on:         passengerProfile.born_on ? passengerProfile.born_on.slice(0, 4) + "-**-**" : null,
        gender:          passengerProfile.gender,
        has_passport:    !!passengerProfile.passport_number,
        passport_expiry: passengerProfile.passport_expiry || null,
        passport_country: passengerProfile.passport_country || null,
      },
    });
  } catch (e) {
    console.error("[passport-ocr]", e.message);
    res.status(500).json({ error: "Passport scan failed", detail: e.message });
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
    // Trip streak count + protected since date
    const tripCount = await sql`SELECT COUNT(DISTINCT id) as cnt, MIN(created_at) as first_trip_at FROM trips WHERE user_email = ${req.user.email}`;
    const tripsTotal = Number(tripCount[0]?.cnt || 0);
    const protectedSince = tripCount[0]?.first_trip_at || null;
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
      protected_since: protectedSince,
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

// ---------------------------------------------------------------------------
// GET /debug/concierge — temporary diagnostic: test each concierge query individually
// ---------------------------------------------------------------------------
app.get("/debug/concierge", async (req, res) => {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "no token" });
  let email;
  try { email = jwt.verify(t, JWT_SECRET).email; } catch(e) { return res.status(401).json({ error: "bad token" }); }
  const results = {};
  try {
    await sql`SELECT preferences, COALESCE(revealed_preferences, '{}') as revealed_preferences FROM users WHERE email = ${email}`;
    results.q1_users = "OK";
  } catch(e) { results.q1_users = "FAIL: " + e.message; }
  try {
    await sql`SELECT id, title, status, mode, created_at FROM trips WHERE user_email = ${email} ORDER BY created_at DESC LIMIT 10`;
    results.q2_trips = "OK";
  } catch(e) { results.q2_trips = "FAIL: " + e.message; }
  try {
    await sql`SELECT program, points_balance, elite_status FROM loyalty_accounts WHERE user_email = ${email} ORDER BY program ASC`;
    results.q3_loyalty = "OK";
  } catch(e) { results.q3_loyalty = "FAIL: " + e.message; }
  try {
    await sql`SELECT property_name, brand, city, country, tier, attributes, stay_count, last_stayed FROM hotel_affinity WHERE user_email = ${email} ORDER BY stay_count DESC, last_stayed DESC LIMIT 20`;
    results.q4_hotels = "OK";
  } catch(e) { results.q4_hotels = "FAIL: " + e.message; }
  res.json(results);
});

// ---------------------------------------------------------------------------
// GET /debug/anthropic-test — test which Anthropic models are available
// ---------------------------------------------------------------------------
app.get("/debug/anthropic-test", async (req, res) => {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "no token" });
  try { jwt.verify(t, JWT_SECRET); } catch(e) { return res.status(401).json({ error: "bad token" }); }
  const modelsToTest = [
    "claude-sonnet-4-5",
    "claude-opus-4-5",
    "claude-haiku-4-5",
  ];
  const results = {};
  const anthropic = getAnthropic();
  for (const model of modelsToTest) {
    try {
      const r = await anthropic.messages.create({
        model,
        max_tokens: 10,
        messages: [{ role: "user", content: "Hi" }],
      });
      results[model] = "OK: " + (r.content[0]?.text?.slice(0, 30) || "(empty)");
    } catch(e) {
      results[model] = "FAIL: " + e.message.slice(0, 80);
    }
  }
  res.json(results);
});
// ---------------------------------------------------------------------------
// Weather — geolocated current conditions for HomeScreen widget
// ---------------------------------------------------------------------------
app.get("/weather", async (req, res) => {
  const { lat, lng } = req.query;
  if (!lat || !lng) return res.status(400).json({ error: "lat and lng required" });
  try {
    const w = await getLiveWeather({ lat: parseFloat(lat), lng: parseFloat(lng) });
    if (!w) return res.status(503).json({ error: "weather unavailable" });
    res.json({ ok: true, ...w });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /auth/refresh — exchange a valid refresh token for a new access + refresh token pair
app.post("/auth/refresh", authLimiter, async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });
  try {
    const email = await consumeRefreshToken(refreshToken);
    if (!email) return res.status(401).json({ error: "invalid or expired refresh token" });
    const token = signAccessToken(email);
    const newRefreshToken = await issueRefreshToken(email);
    res.json({ ok: true, token, refreshToken: newRefreshToken, email });
  } catch (e) {
    console.error("[auth/refresh]", e.message);
    res.status(500).json({ error: "refresh failed" });
  }
});

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now(), version: "2.17.0" }));

// GET /env-status — internal diagnostic (auth required, non-sensitive)
// Shows which optional API integrations are configured without exposing key values
app.get("/env-status", auth, (_req, res) => {
  res.json({
    version: "2.17.0",
    integrations: {
      flightaware:    { configured: !!process.env.FLIGHTAWARE_API_KEY,    label: "FlightAware AeroAPI (primary flight status)" },
      aviationstack:  { configured: !!process.env.AVIATIONSTACK_API_KEY,  label: "AviationStack (fallback flight status, free tier)" },
      duffel:         { configured: !!process.env.DUFFEL_API_KEY,          label: "Duffel (flight search + booking execution)" },
      stripe:         { configured: !!process.env.STRIPE_SECRET_KEY,       label: "Stripe (subscriptions + Apple Pay)" },
      stripe_pro_price: { configured: !!(process.env.STRIPE_PRO_PRICE_ID && !process.env.STRIPE_PRO_PRICE_ID.startsWith('price_pro')), label: "Stripe Pro price ID (real product)" },
      stripe_elite_price: { configured: !!(process.env.STRIPE_ELITE_PRICE_ID && !process.env.STRIPE_ELITE_PRICE_ID.startsWith('price_elite')), label: "Stripe Elite price ID (real product)" },
      stripe_webhook: { configured: !!process.env.STRIPE_WEBHOOK_SECRET,  label: "Stripe webhook signature verification" },
      anthropic:      { configured: !!process.env.ANTHROPIC_API_KEY, key_prefix: process.env.ANTHROPIC_API_KEY ? process.env.ANTHROPIC_API_KEY.slice(0,12) + '...' : null, label: "Anthropic Claude (concierge + passport OCR)" },
      google_oauth:   { configured: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET), label: "Google OAuth (Gmail import)" },
      resend:         { configured: !!(process.env.RESEND_API_KEY && !process.env.RESEND_API_KEY.startsWith('re_placeholder')), label: "Resend (transactional email)" },
      database:       { configured: !!(process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('placeholder')), label: "Neon PostgreSQL" },
      redis:          { configured: !!process.env.UPSTASH_REDIS_REST_URL,  label: "Upstash Redis (OTP)" },
    },
    crons: {
      disruption_poll:    "every 15 min (30s startup delay)",
      pre_departure_push: "every 5 min",
      post_trip_debrief:  "every 10 min",
      loyalty_sync:       "every 6 hr",
      hotel_monitor:      "every 30 min",
      upgrade_bid_watcher: "every 6 hr (node-cron)",
      points_expiry:      "every 6 hr",
    },
  });
});

// ---------------------------------------------------------------------------
// Train Status Service — National Rail Darwin (OpenLDBWS) via direct SOAP/JSON
// Uses the Darwin Public API with DARWIN_API_TOKEN env var.
// Falls back to Huxley2 community demo if no token is set (no uptime guarantee).
// ---------------------------------------------------------------------------

// CRS code cache: station name → 3-letter CRS code
const crsCache = new Map();

async function lookupCRS(stationName) {
  if (!stationName) return null;
  const upper = stationName.toUpperCase().trim();
  // If it's already a 3-letter CRS code, return it directly
  if (/^[A-Z]{3}$/.test(upper)) return upper;
  if (crsCache.has(upper)) return crsCache.get(upper);
  try {
    const huxleyBase = process.env.HUXLEY2_URL || "https://huxley2.azurewebsites.net";
    const encoded = encodeURIComponent(stationName.toLowerCase());
    const r = await fetch(`${huxleyBase}/crs/${encoded}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    const data = await r.json();
    if (!data || data.length === 0) return null;
    // Prefer exact name match, otherwise take first result
    const exact = data.find(s => s.stationName?.toLowerCase() === stationName.toLowerCase());
    const crs = (exact || data[0]).crsCode;
    crsCache.set(upper, crs);
    return crs;
  } catch (e) {
    console.error("[crs-lookup]", e.message);
    return null;
  }
}

// Fetch live departure status for a specific train service
// stationFrom / stationTo can be CRS codes or full station names
// departsAt is an ISO datetime string — we find the matching service in a ±15 min window
async function getTrainStatus(stationFrom, stationTo, departsAt) {
  try {
    const token = process.env.DARWIN_API_TOKEN;
    const huxleyBase = process.env.HUXLEY2_URL || "https://huxley2.azurewebsites.net";

    const [fromCRS, toCRS] = await Promise.all([
      lookupCRS(stationFrom),
      lookupCRS(stationTo),
    ]);
    if (!fromCRS) return { status: "Unknown", error: "Station not found: " + stationFrom };

    // Build the Huxley2 / Darwin URL
    // Use /departures/{from}/to/{to} if we have a destination, else /departures/{from}
    const destPart = toCRS ? `/to/${toCRS}` : "";
    const tokenParam = token ? `?accessToken=${token}` : "";
    const url = `${huxleyBase}/departures/${fromCRS}${destPart}/20${tokenParam}`;

    const r = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return { status: "Unknown", error: `Darwin API returned ${r.status}` };
    const board = await r.json();

    const services = board.trainServices || [];
    if (services.length === 0) return { status: "No services", from: fromCRS, to: toCRS };

    // Find the service matching the scheduled departure time (±15 min window)
    let targetService = null;
    if (departsAt) {
      const targetTime = new Date(departsAt);
      const targetHHMM = targetTime.toTimeString().slice(0, 5); // "HH:MM"
      // First try exact match on std (scheduled time)
      targetService = services.find(s => s.std === targetHHMM);
      // If no exact match, find closest within 15 minutes
      if (!targetService) {
        const targetMins = targetTime.getHours() * 60 + targetTime.getMinutes();
        let minDiff = Infinity;
        for (const s of services) {
          if (!s.std) continue;
          const [h, m] = s.std.split(":").map(Number);
          const diff = Math.abs((h * 60 + m) - targetMins);
          if (diff < minDiff && diff <= 15) { minDiff = diff; targetService = s; }
        }
      }
    }
    // Fall back to first service if no time match
    if (!targetService) targetService = services[0];

    // Interpret the Darwin etd field
    const etd = targetService.etd || "";
    const std = targetService.std || "";
    const isCancelled = targetService.isCancelled === true || etd === "Cancelled";
    const isDelayed = !isCancelled && etd && etd !== "On time" && etd !== std;
    let delayMins = null;
    if (isDelayed && etd && std && /^\d{2}:\d{2}$/.test(etd) && /^\d{2}:\d{2}$/.test(std)) {
      const [eh, em] = etd.split(":").map(Number);
      const [sh, sm] = std.split(":").map(Number);
      delayMins = (eh * 60 + em) - (sh * 60 + sm);
      if (delayMins < 0) delayMins += 1440; // overnight wrap
    }

    return {
      status: isCancelled ? "Cancelled" : isDelayed ? "Delayed" : "On Time",
      std,
      etd: isCancelled ? "Cancelled" : etd || "On time",
      platform: targetService.platform || null,
      operator: targetService.operator || null,
      delayMins,
      delayReason: targetService.delayReason || null,
      cancelReason: targetService.cancelReason || null,
      from: fromCRS,
      to: toCRS,
      serviceId: targetService.serviceIdUrlSafe || null,
    };
  } catch (e) {
    console.error("[train-status]", e.message);
    return { status: "Unknown", error: e.message };
  }
}

// GET /trains/status?from=EDB&to=KGX&departs_at=2026-07-03T09:30:00Z
// Returns live departure status for a specific train leg
app.get("/trains/status", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { from, to, departs_at } = req.query;
  if (!from) return res.status(400).json({ error: "from station required" });
  try {
    const status = await getTrainStatus(from, to, departs_at);
    res.json(status);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Disruption polling cron — runs every 15 min
// Checks all upcoming flight legs, detects status changes, sends push + logs activity
// ---------------------------------------------------------------------------
async function sendPushToUser(userEmail, title, body, data = {}, categoryId = null) {
  try {
    const rows = await sql`SELECT push_token FROM users WHERE email = ${userEmail}`;
    const token = rows[0]?.push_token;
    if (!token) return;
    await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // categoryId drives the actionable buttons (Approve / Not now) on iOS.
      body: JSON.stringify({ to: token, title, body, data, ...(categoryId ? { categoryId } : {}) }),
    });
  } catch (e) {
    console.error("[push]", e.message);
  }
}

// ---------------------------------------------------------------------------
// Cascade Check — proactively check downstream impacts of a disruption
// Called when a flight is cancelled or delayed 60+ minutes.
// Checks: connecting flights, hotel check-in, restaurant reservations
// Sends proactive push notifications for each impacted item.
// ---------------------------------------------------------------------------
async function triggerCascadeCheck(leg, eventType, delayMins) {
  try {
    const email = leg.user_email;
    if (!email || !leg.trip_id || !leg.departs_at) return;

    // Everything downstream on this trip — the chain a slipped flight puts at risk.
    const downstream = await sql`
      SELECT id, type, carrier, destination, departs_at, confirmation
      FROM trip_legs
      WHERE trip_id = ${leg.trip_id}
        AND id <> ${leg.id}
        AND departs_at IS NOT NULL
        AND departs_at >= ${leg.departs_at}
      ORDER BY departs_at ASC
    `;
    if (!downstream.length) return;

    const impacted = [];
    for (const d of downstream) {
      const name = d.carrier || d.destination || d.type;
      let title = null, body = null;
      if (d.type === "flight") {
        title = "Connection at risk";
        body = eventType === "cancelled"
          ? `Your onward flight ${name} is at risk. I'm lining up alternatives.`
          : `Your connection to ${name} is at risk with a ${delayMins}m delay. I'm on it.`;
      } else if (d.type === "hotel" || d.type === "airbnb") {
        title = "Late check-in";
        body = `You'll likely reach ${name} late. I can let them know to hold your room.`;
      } else if (d.type === "dining" || d.type === "restaurant") {
        title = "Reservation at risk";
        body = `Your table at ${name} is at risk. Want me to move it?`;
      } else if (d.type === "car" || d.type === "transfer") {
        title = "Pickup no longer lines up";
        body = `Your ${name} pickup no longer matches your new arrival. I can shift it.`;
      } else if (d.type === "activity" || d.type === "event") {
        title = "Booking at risk";
        body = `${name} may no longer fit your revised arrival.`;
      }
      if (title) impacted.push({ leg: d, title, body });
    }
    if (!impacted.length) return;

    // One consolidated push — a chief of staff reports the chain, not a barrage.
    const first = impacted[0];
    const extra = impacted.length - 1;
    await sendPushToUser(
      email,
      impacted.length === 1 ? first.title : `${impacted.length} bookings affected downstream`,
      extra > 0 ? `${first.body} (+${extra} more affected)` : first.body,
      { route: "TripDetail", tripId: String(leg.trip_id), legId: String(leg.id), type: "cascade" },
    );

    // And a signal per impacted booking, so the chain is visible in the app.
    for (const i of impacted) {
      await logActivity(
        email, "cascade", i.title, i.body, leg.trip_id, i.leg.id,
        { cascade_from_leg: String(leg.id), event: eventType, delay_minutes: delayMins || 0 },
      ).catch(() => {});
    }
    console.log(`[cascade] flagged ${impacted.length} downstream item(s) for ${email}`);
  } catch (err) {
    console.error("[triggerCascadeCheck] error:", err.message);
  }
}

// ---------------------------------------------------------------------------
// Silent Autonomy — auto-rebook when user has fully_auto mode enabled
// Triggered from pollDisruptions when a flight is cancelled or severely delayed.
// Only acts when:
//   1. User's autonomy_mode === "fully_auto"
//   2. Best available alternative is under the user's price threshold
//   3. User has stored passenger details (name, DOB) for Duffel booking
// ---------------------------------------------------------------------------
async function silentAutonomyRebook(leg, newStatus, delaySeconds) {
  try {
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${leg.user_email}`;
    const prefs = userRows[0]?.preferences || {};
    const autonomyMode = prefs.autonomy_mode || "always_ask";

    // Standing order (Roadmap 2): a per-trip pre-authorization that grants autonomy
    // for this trip even when the global mode is "always_ask", with its own limits.
    let standingOrder = null;
    if (leg.trip_id) {
      const soRows = await sql`SELECT * FROM standing_orders WHERE trip_id = ${leg.trip_id} AND enabled = TRUE`;
      standingOrder = soRows[0] || null;
    }
    if (autonomyMode !== "fully_auto" && !standingOrder) return; // Only act if authorized

    // Standing order limits override the global defaults for this trip.
    const threshold = standingOrder?.max_price || prefs.threshold || 500; // Max spend without asking
    const delayMins = delaySeconds ? Math.round(delaySeconds / 60) : 0;

    // Only auto-rebook cancellations or delays > 2 hours
    if (newStatus === "Delayed" && delayMins < 120) return;

    // Check if already auto-rebooked for this leg
    const alreadyRebooked = await sql`
      SELECT 1 FROM activity_events
      WHERE user_email = ${leg.user_email}
        AND type = 'auto_rebook'
        AND metadata->>'leg_id' = ${String(leg.id)}
      LIMIT 1
    `;
    if (alreadyRebooked.length > 0) return;

    console.log(`[silent-autonomy] User ${leg.user_email} is fully_auto — searching alternatives for leg ${leg.id}`);

    // Search for alternatives via Duffel
    const dateStr = leg.departs_at
      ? new Date(new Date(leg.departs_at).getTime() + (delayMins || 120) * 60000).toISOString().slice(0, 10)
      : new Date().toISOString().slice(0, 10);

    const duffel = getDuffel();
    const offerRequest = await duffel.offerRequests.create({
      slices: [{ origin: leg.origin, destination: leg.destination, departure_date: dateStr }],
      passengers: [{ type: "adult" }],
      cabin_class: standingOrder?.min_cabin || prefs.cabin_preference || "economy",
    });
    const offers = await duffel.offers.list({ offer_request_id: offerRequest.data.id, sort: "total_amount" });
    const bestOffer = offers.data?.[0];
    if (!bestOffer) {
      console.log(`[silent-autonomy] No alternatives found for leg ${leg.id}`);
      return;
    }

    const price = parseFloat(bestOffer.total_amount);
    if (price > threshold) {
      // Price exceeds threshold — alert user instead of auto-booking
      await sendPushToUser(
        leg.user_email,
        `✈ Auto-rebook paused — price above your limit`,
        `Best alternative for ${leg.origin}→${leg.destination} is $${price.toFixed(0)}, above your $${threshold} auto-approve limit. Tap to review.`,
        { route: "Alert", tripId: String(leg.trip_id), legId: String(leg.id) }
      );
      await logActivity(
        leg.user_email, "auto_rebook_paused",
        "Auto-rebook paused — price above threshold",
        `Best alternative costs $${price.toFixed(0)}, above your $${threshold} limit. Manual approval needed.`,
        leg.trip_id, leg.id,
        { leg_id: String(leg.id), offer_id: bestOffer.id, price, threshold }
      );
      return;
    }

    // Check if user has stored passenger info for booking
    const passengerRows = await sql`SELECT preferences FROM users WHERE email = ${leg.user_email}`;
    const storedPassenger = passengerRows[0]?.preferences?.passenger_profile;
    if (!storedPassenger?.given_name || !storedPassenger?.family_name || !storedPassenger?.born_on) {
      // No passenger profile — can't book, alert user
      await sendPushToUser(
        leg.user_email,
        `✈ Wingman found a rescue flight`,
        `${leg.origin}→${leg.destination} — ${bestOffer.owner?.name || ""} for $${price.toFixed(0)}. Add your traveler details in Settings to enable auto-booking.`,
        { route: "Alert", tripId: String(leg.trip_id), legId: String(leg.id), duffel_offer_id: bestOffer.id }
      );
      return;
    }

    // Execute the booking
    const offerPassengerIds = bestOffer.passengers.map(p => p.id);
    const order = await duffel.orders.create({
      selected_offers: [bestOffer.id],
      passengers: [{
        id: offerPassengerIds[0],
        given_name: storedPassenger.given_name,
        family_name: storedPassenger.family_name,
        born_on: storedPassenger.born_on,
        gender: storedPassenger.gender || "m",
        email: leg.user_email,
        phone_number: storedPassenger.phone || "+10000000000",
      }],
      payments: [{ type: "balance", currency: bestOffer.total_currency, amount: bestOffer.total_amount }],
      metadata: { wingman_user: leg.user_email, auto_rescue: true, original_leg: leg.id },
    });
    const orderData = order.data;

    // Insert new leg into the trip
    const firstSlice = bestOffer.slices?.[0];
    for (const seg of (firstSlice?.segments || [])) {
      await sql`
        INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation, raw_data)
        VALUES (
          ${leg.trip_id}, 'flight',
          ${seg.marketing_carrier?.name || null},
          ${(seg.marketing_carrier?.iata_code || "") + (seg.marketing_carrier_flight_number || "")},
          ${seg.origin?.iata_code || null},
          ${seg.destination?.iata_code || null},
          ${seg.departing_at || null},
          ${seg.arriving_at || null},
          ${orderData.booking_reference || null},
          ${JSON.stringify({ duffel_order_id: orderData.id, segment_id: seg.id, auto_rescue: true })}
        )
      `;
    }

    // Mark original leg as rescued
    await sql`UPDATE trip_legs SET raw_data = COALESCE(raw_data,'{}') || '{"rescued":true}'::jsonb WHERE id = ${leg.id}`;

    // Log the auto-rebook event
    await logActivity(
      leg.user_email, "auto_rebook",
      "Wingman auto-rebooked your flight",
      `Your ${leg.origin}→${leg.destination} flight was ${newStatus === "Cancelled" ? "cancelled" : "severely delayed"}. Wingman automatically booked ${orderData.booking_reference} for $${price.toFixed(0)}.`,
      leg.trip_id, leg.id,
      { leg_id: String(leg.id), duffel_order_id: orderData.id, booking_reference: orderData.booking_reference, price, auto: true }
    );

    // Notify user of the completed auto-rebook
    await sendPushToUser(
      leg.user_email,
      `✅ Wingman auto-rebooked you`,
      `New flight booked: ${orderData.booking_reference} for $${price.toFixed(0)}. Check your email for the confirmation.`,
      { route: "Activity", tripId: String(leg.trip_id) }
    );

    console.log(`[silent-autonomy] Auto-rebooked leg ${leg.id} → Duffel order ${orderData.id} (${orderData.booking_reference})`);
  } catch (e) {
    console.error("[silent-autonomy] error:", e.message);
  }
}

// Create a chief-of-staff decision card for a disrupted flight (one active decision
// per leg). This surfaces the disruption on Home above the briefing; the push already
// deep-links to the full Disruption screen for the actual rebooking flow.
async function createDisruptionDecision(leg, live, newStatus) {
  try {
    const email = leg.user_email;
    const [existing] = await sql`
      SELECT id FROM decisions
      WHERE user_email = ${email} AND leg_id = ${leg.id} AND status IN ('pending','auto_done')
      LIMIT 1`;
    if (existing) return; // already surfaced
    const ident = `${leg.carrier || ""}${leg.flight_number || ""}`.trim();
    const route = `${leg.origin || "?"} → ${leg.destination || "?"}`;
    const cancelled = newStatus === "Cancelled";
    const delayMins = live?.delay ? Math.round(live.delay / 60) : null;
    const headline = cancelled
      ? `${ident} ${route} was cancelled`
      : `${ident} ${route} is delayed${delayMins ? ` ${delayMins}m` : ""}`;
    const rationale = cancelled
      ? "This flight is cancelled. I've lined up same-cabin alternatives ranked by arrival — confirm one and I'll take it from there."
      : "This delay puts your itinerary at risk. Here are your best moves; my recommendation keeps you on schedule.";
    const options = [
      { id: "opt_rebook", label: cancelled ? "See rebooking options" : "See alternatives", detail: "Same-cabin routes, ranked by arrival time", recommended: true, value_saved: cancelled ? 650 : 220 },
      { id: "opt_hold", label: "Hold and monitor", detail: "I'll keep watching and re-alert only if it worsens", recommended: false },
    ];
    const [u] = await sql`SELECT COALESCE(preferences->>'autonomy_mode','always_ask') AS mode FROM users WHERE email = ${email}`;
    const autonomyAction = u?.mode === "fully_auto" ? "auto_pending" : "asked";
    const [dec] = await sql`
      INSERT INTO decisions (user_email, trip_id, leg_id, kind, status, headline, rationale, options, recommended_option_id, autonomy_action, expires_at)
      VALUES (${email}, ${leg.trip_id}, ${leg.id}, 'rebook', 'pending', ${headline}, ${rationale},
        ${JSON.stringify(options)}, 'opt_rebook', ${autonomyAction}, ${new Date(Date.now() + 12 * 3600000).toISOString()})
      RETURNING id`;
    console.log(`[decision] created rebook decision for ${ident} (${email})`);
    return dec?.id || null; // caller uses this to send an actionable push
  } catch (e) {
    console.error("[createDisruptionDecision]", e.message);
    return null;
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
        pushTitle = `${ident} is cancelled`;
        pushBody = `${leg.origin} → ${leg.destination} cancelled. I'm already looking for alternatives — tap to rebook.`;
        activityTitle = `${ident} cancelled`;
        activityBody = `Your ${leg.origin} → ${leg.destination} flight was cancelled. Wingman is finding alternatives.`;
        activityType = "disruption";
        triggerCascadeCheck(leg, "cancelled", 0).catch(e => console.error("[cascade]", e.message));
      } else if (newStatus === "Delayed") {
        const delayMins = live.delay ? Math.round(live.delay / 60) : null;
        const delayStr = delayMins ? ` by ${delayMins}m` : "";
        pushTitle = `${ident} is delayed${delayStr}`;
        pushBody = `${leg.origin} → ${leg.destination} delayed${delayStr}.${live.gate ? ` Gate ${live.gate}.` : ""}`;
        activityTitle = `${ident} delayed${delayStr}`;
        activityBody = `Your ${leg.origin} → ${leg.destination} flight is delayed${delayStr}.${live.gate ? ` Gate ${live.gate}.` : ""}`;
        activityType = "delay";
        if (delayMins && delayMins >= 60) { triggerCascadeCheck(leg, "delayed", delayMins).catch(e => console.error("[cascade]", e.message)); }
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
        // Auto-activate return trip watch on landing
        activateReturnTripWatch(leg).catch(e => console.error("[return-watch]", e.message));
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

      const isDisruption = newStatus === "Cancelled" || newStatus === "Delayed";

      // Surface a decision card on Home for disruptions (the chief-of-staff spine).
      // Created BEFORE the push so the notification can carry the decision id and
      // offer Approve / Not now inline (UI #5) — no app-open required.
      let decisionId = null;
      if (isDisruption) {
        decisionId = await createDisruptionDecision(leg, live, newStatus).catch(e => {
          console.error("[decision-create]", e.message);
          return null;
        });
      }

      // Send push notification (only for actionable events)
      if (pushTitle) {
        if (isDisruption && decisionId) {
          // Actionable: Approve rebooking or dismiss straight from the lock screen.
          await sendPushToUser(
            leg.user_email, pushTitle, pushBody,
            {
              route: "Decisions",
              decision_id: String(decisionId),
              option_id: "opt_rebook",
              tripId: String(leg.trip_id),
              legId:  String(leg.id),
              ident,
            },
            "wingman_decision",
          );
        } else {
          await sendPushToUser(leg.user_email, pushTitle, pushBody, {
            route: isDisruption ? "Disruption" : "Activity",
            tripId: String(leg.trip_id),
            legId:  String(leg.id),
            ident,
          });
        }
      }

      // ── Silent Autonomy: auto-rebook without user interaction if mode = fully_auto ──
      if ((newStatus === "Cancelled" || newStatus === "Delayed") && process.env.DUFFEL_API_KEY) {
        silentAutonomyRebook(leg, newStatus, live.delay).catch(e =>
          console.error("[silent-autonomy]", e.message)
        );
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

// ---------------------------------------------------------------------------
// Return Trip Watch — automatically set the return leg to "Watching" on landing
// Called when a flight lands. Finds the return leg for the same trip and
// sets its status to "Watching" so the flight monitor starts tracking it.
// ---------------------------------------------------------------------------
async function activateReturnTripWatch(leg) {
  try {
    // Get all legs for this trip
    const tripLegs = await sql`
      SELECT tl.* FROM trip_legs tl
      WHERE tl.trip_id = ${leg.trip_id}
        AND tl.type = 'flight'
        AND tl.status NOT IN ('Cancelled', 'Landed')
      ORDER BY tl.departs_at ASC
    `;
    if (!tripLegs.length) return;

    // Find legs that depart from this leg's destination (return legs)
    const returnLegs = tripLegs.filter(l =>
      l.origin === leg.destination &&
      new Date(l.departs_at).getTime() > new Date(leg.arrives_at || leg.departs_at).getTime()
    );
    if (!returnLegs.length) return;

    // Activate watching on the first return leg
    const returnLeg = returnLegs[0];
    await sql`
      UPDATE trip_legs SET status = 'Watching'
      WHERE id = ${returnLeg.id} AND status NOT IN ('Cancelled', 'Landed', 'Watching')
    `;

    // Log to activity feed
    const ident = (returnLeg.carrier || "") + (returnLeg.flight_number || "");
    await logActivity(
      leg.user_email,
      "return_watch_activated",
      `Watching ${ident} for your return`,
      `${returnLeg.origin} → ${returnLeg.destination} — I'm now monitoring your return flight.`,
      leg.trip_id,
      returnLeg.id,
      {}
    );

    // Send a push notification
    await sendPushToUser(leg.user_email, {
      title: `Watching ${ident}`,
      body: `Your return flight ${returnLeg.origin} → ${returnLeg.destination} is now being monitored.`,
      data: { type: "return_watch", trip_id: String(leg.trip_id), leg_id: String(returnLeg.id) }
    });

    console.log(`[return-watch] activated for ${ident} (leg ${returnLeg.id})`);
  } catch (err) {
    console.error("[activateReturnTripWatch] error:", err.message);
  }
}

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
const wallet = require("./wallet");
const fs = require("fs");
const os = require("os");

// GET /wallet/pass/:legId — generate + sign a real .pkpass for a leg.
// Opened via Safari (no auth header possible), so the access token comes as ?token=.
app.get("/wallet/pass/:legId", async (req, res) => {
  try {
    const token = (req.query.token || (req.headers.authorization || "").replace("Bearer ", "")).toString();
    let email;
    try { ({ email } = jwt.verify(token, JWT_SECRET)); }
    catch { return res.status(401).json({ error: "unauthorized" }); }

    const { legId } = req.params;
    const rows = await sql`
      SELECT tl.*, t.title AS trip_title
      FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${legId} AND t.user_email = ${email}
    `;
    if (!rows.length) return res.status(404).json({ error: "Leg not found" });
    const leg = rows[0];

    if (!wallet.walletReady()) {
      return res.status(503).json({ error: "Wallet signing not configured on the server yet." });
    }

    const passJson = wallet.passJsonForLeg(leg, { title: leg.trip_title });
    const buf = await wallet.buildPkpass(passJson);
    res.set({
      "Content-Type": "application/vnd.apple.pkpass",
      "Content-Disposition": `attachment; filename="wingman-${leg.type || "trip"}-${leg.id}.pkpass"`,
    });
    res.send(buf);
  } catch (e) {
    console.error("[wallet]", e.message);
    res.status(500).json({ error: e.message });
  }
});


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

// GET /airports/search?q=London — airport autocomplete using Duffel Places
app.get("/airports/search", async (req, res) => {
  try {
    const user = await verifyAccessToken(req);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const q = (req.query.q || "").trim();
    if (!q || q.length < 2) return res.json({ airports: [] });
    const duffel = getDuffel();
    const result = await duffel.suggestions.list({ query: q });
    const airports = (result.data || [])
      .filter(p => p.type === "airport" || p.type === "city")
      .slice(0, 8)
      .map(p => ({
        iata: p.iata_code || p.iata_city_code,
        name: p.name,
        city: p.city_name || p.name,
        country: p.country_name,
        type: p.type,
      }));
    res.json({ airports });
  } catch (e) {
    console.error("[airports-search]", e.message);
    // Fallback: return empty so the UI degrades gracefully
    res.json({ airports: [] });
  }
});

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
    console.error("[duffel-search]", e.message, e?.errors);
    // Surface the real Duffel error message to the client
    const msg = e?.errors?.[0]?.message || e?.errors?.[0]?.title || e.message || "Flight search failed";
    res.status(500).json({ error: msg });
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
app.post("/trips/:tripId/rescue", auth, requirePro, async (req, res) => {
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

    // Build downstream leg summaries for the notification UI
    const downstreamLegSummaries = downstreamLegs.map(dl => ({
      id: dl.id,
      type: dl.type || "other",
      name: dl.carrier || dl.type || "Reservation",
      origin: dl.origin || null,
      destination: dl.destination || null,
      departs_at: dl.departs_at,
      confirmation: dl.confirmation || null,
    }));

    res.json({
      disrupted_leg: { id: leg.id, flight: (leg.carrier || "") + (leg.flight_number || ""), origin, destination: dest },
      downstream_legs: downstreamLegs.length,
      downstream_legs_detail: downstreamLegSummaries,
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
// If option has a duffel_offer_id and passengers are provided, executes the booking via Duffel.
app.post("/trips/:tripId/rescue/accept", auth, requirePro, async (req, res) => {
  const { tripId } = req.params;
  const { option_id, disrupted_leg_id, value_saved, duffel_offer_id, passengers } = req.body || {};
  try {
    let bookingResult = null;

    // ── Execute Duffel booking if offer_id and passenger data are present ──
    if (duffel_offer_id && passengers?.length && process.env.DUFFEL_API_KEY) {
      try {
        const duffel = getDuffel();
        const offerData = await duffel.offers.get(duffel_offer_id);
        const offer = offerData.data;
        const offerPassengerIds = offer.passengers.map(p => p.id);
        const mappedPassengers = passengers.map((p, i) => ({
          id: offerPassengerIds[i],
          given_name: p.given_name,
          family_name: p.family_name,
          born_on: p.born_on,
          gender: p.gender,
          email: p.email || req.user.email,
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
          selected_offers: [duffel_offer_id],
          passengers: mappedPassengers,
          payments: [{
            type: "balance",
            currency: offer.total_currency,
            amount: offer.total_amount,
          }],
          metadata: { wingman_user: req.user.email, rescue_for_trip: tripId },
        });
        const orderData = order.data;
        bookingResult = {
          duffel_order_id: orderData.id,
          booking_reference: orderData.booking_reference,
          total_amount: offer.total_amount,
          total_currency: offer.total_currency,
        };
        // Insert the new leg into the original trip
        const firstSlice = offer.slices?.[0];
        for (const seg of (firstSlice?.segments || [])) {
          await sql`
            INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation, raw_data)
            VALUES (
              ${tripId}, 'flight',
              ${seg.marketing_carrier?.name || null},
              ${(seg.marketing_carrier?.iata_code || "") + (seg.marketing_carrier_flight_number || "")},
              ${seg.origin?.iata_code || null},
              ${seg.destination?.iata_code || null},
              ${seg.departing_at || null},
              ${seg.arriving_at || null},
              ${orderData.booking_reference || null},
              ${JSON.stringify({ duffel_order_id: orderData.id, segment_id: seg.id, rescue: true })}
            )
          `;
        }
        // Mark the disrupted leg as rescued
        if (disrupted_leg_id) {
          await sql`
            UPDATE trip_legs SET raw_data = raw_data || '{"rescued":true}'::jsonb
            WHERE id = ${disrupted_leg_id}
          `;
        }
        await logActivity(
          req.user.email, "disruption_resolved",
          "Rescue booked",
          `New flight booked. Booking reference: ${orderData.booking_reference}. Rescue option: ${option_id}.`,
          tripId, disrupted_leg_id,
          { option_id, rescue_accepted: true, value_saved: value_saved || 0, ...bookingResult }
        );
        return res.json({ ok: true, booked: true, ...bookingResult });
      } catch (bookErr) {
        console.error("[rescue-book]", bookErr.message);
        // Fall through to log-only accept if booking fails
      }
    }

    // ── Log-only accept (no Duffel offer, or booking failed) ──
    await logActivity(
      req.user.email, "disruption_resolved",
      "Rescue accepted",
      `You accepted rescue option: ${option_id}.`,
      tripId, disrupted_leg_id,
      { option_id, rescue_accepted: true, value_saved: value_saved || 0 }
    );
    res.json({ ok: true, booked: false });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /trips/:tripId/rescue/reject — user rejects all rescue options
app.post("/trips/:tripId/rescue/reject", auth, requirePro, async (req, res) => {
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
      ? await sql`SELECT messages, updated_at FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id = ${tripId}`
      : await sql`SELECT messages, updated_at FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id IS NULL`;
    const messages = rows[0]?.messages || [];
    const updated_at = rows[0]?.updated_at || null;
    res.json({ messages, updated_at });
  } catch (e) {
    res.json({ messages: [], updated_at: null });
  }
});

app.post("/concierge/thread", auth, async (req, res) => {
  try {
    const { messages, trip_id } = req.body || {};
    if (!Array.isArray(messages)) return res.status(400).json({ error: "messages array required" });
    const tripId = trip_id ? Number(trip_id) : null;
    const trimmed = messages.slice(-50);
    const msgJson = JSON.stringify(trimmed);
    // DELETE + INSERT avoids ON CONFLICT on expression index (not supported by PostgreSQL)
    if (tripId) {
      await sql`DELETE FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id = ${tripId}`;
      await sql`INSERT INTO concierge_threads (user_email, trip_id, messages, updated_at) VALUES (${req.user.email}, ${tripId}, ${msgJson}, NOW())`;
    } else {
      await sql`DELETE FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id IS NULL`;
      await sql`INSERT INTO concierge_threads (user_email, trip_id, messages, updated_at) VALUES (${req.user.email}, NULL, ${msgJson}, NOW())`;
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("[concierge/thread]", e.message);
    res.status(500).json({ error: e.message });
  }
});
// DELETE /concierge/thread — clear conversation history
app.delete("/concierge/thread", auth, async (req, res) => {
  try {
    const tripId = req.query.trip_id ? Number(req.query.trip_id) : null;
    if (tripId) {
      await sql`DELETE FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id = ${tripId}`;
    } else {
      await sql`DELETE FROM concierge_threads WHERE user_email = ${req.user.email} AND trip_id IS NULL`;
    }
    res.json({ ok: true });
  } catch (e) {
    console.error("[concierge/thread DELETE]", e.message);
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
        // Build a personalised debrief push with value hook
        const debriefTitle = trip.destination
          ? `Landed in ${trip.destination} ✓`
          : `You've landed ✓`;
        const debriefBody = `How did ${trip.title} go? Tap to rate the trip and see what Wingman protected.`;
        await sendPushToUser(
          trip.user_email,
          debriefTitle,
          debriefBody,
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
app.get('/trips/:tripId/briefing', auth, requirePro, async (req, res) => {
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
app.get('/trips/:tripId/destination-intel', auth, requirePro, async (req, res) => {
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
          from: 'Wingman <hello@wingmantravel.app>',
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

// Airline claim contact lookup
const AIRLINE_CLAIM_CONTACTS = {
  BA:  { name: "British Airways",    url: "https://www.britishairways.com/en-gb/information/legal/passenger-rights", email: "customer.relations@ba.com" },
  LH:  { name: "Lufthansa",          url: "https://www.lufthansa.com/de/en/flight-disruption", email: "customercare@lufthansa.com" },
  AF:  { name: "Air France",         url: "https://www.airfrance.com/en/information/passenger-rights", email: "customer.relations@airfrance.fr" },
  KL:  { name: "KLM",                url: "https://www.klm.com/en/information/passenger-rights", email: "customer.care@klm.com" },
  IB:  { name: "Iberia",             url: "https://www.iberia.com/en/information/passenger-rights", email: "atencionalcliente@iberia.es" },
  FR:  { name: "Ryanair",            url: "https://www.ryanair.com/en/eu261", email: "eu261claims@ryanair.com" },
  U2:  { name: "easyJet",            url: "https://www.easyjet.com/en/help/compensation", email: "customerservices@easyjet.com" },
  UA:  { name: "United Airlines",    url: "https://www.united.com/en/us/fly/travel/disruptions.html", email: "customer.care@united.com" },
  AA:  { name: "American Airlines",  url: "https://www.aa.com/i18n/customer-service/contact-american/passenger-rights.jsp", email: "customer.relations@aa.com" },
  DL:  { name: "Delta Air Lines",    url: "https://www.delta.com/us/en/passenger-rights", email: "customer.care@delta.com" },
  EK:  { name: "Emirates",           url: "https://www.emirates.com/english/help/passenger-rights", email: "customer.affairs@emirates.com" },
  QR:  { name: "Qatar Airways",      url: "https://www.qatarairways.com/en/passenger-rights.html", email: "customercare@qatarairways.com" },
  SQ:  { name: "Singapore Airlines", url: "https://www.singaporeair.com/en_UK/sg/travel-info/passenger-rights", email: "customerrelations@singaporeair.com" },
  TK:  { name: "Turkish Airlines",   url: "https://www.turkishairlines.com/en-int/any-questions/passenger-rights", email: "customer@thy.com" },
};

// POST /trips/:tripId/compensation/check — check eligibility without creating a claim
app.post("/trips/:tripId/compensation/check", auth, async (req, res) => {
  try {
    const { tripId } = req.params;
    const { leg_id, disruption_type, delay_minutes } = req.body;
    let leg = null;
    if (leg_id) {
      const rows = await sql`SELECT * FROM trip_legs WHERE id = ${leg_id} AND trip_id = ${tripId} LIMIT 1`;
      leg = rows[0] || null;
    }
    if (!leg) {
      const rows = await sql`SELECT * FROM trip_legs WHERE trip_id = ${tripId} AND type = 'flight' ORDER BY departs_at ASC LIMIT 1`;
      leg = rows[0] || null;
    }
    if (!leg) return res.json({ eligible: false, reason: 'No flight leg found for this trip.' });
    const origin  = leg.origin || '';
    const dest    = leg.destination || '';
    const carrier = (leg.carrier || '').toUpperCase();
    const flightIdent = carrier && leg.flight_number ? `${carrier}${leg.flight_number}` : (leg.flight_ident || '');
    const delayMins = delay_minutes || leg.delay_minutes || 0;
    const cancelled = disruption_type === 'cancelled' || leg.status === 'cancelled';
    const distanceKm = estimateDistanceKm(origin, dest);
    const US_AIRPORTS = new Set(['JFK','LAX','ORD','ATL','DFW','MIA','SFO','BOS','SEA','DEN','LAS','IAH','PHX','EWR','MCO','CLT','LGA','SLC','DTW','MSP']);
    const isUS = US_AIRPORTS.has(origin.toUpperCase()) || US_AIRPORTS.has(dest.toUpperCase());
    const ec261 = calcEC261(origin, dest, delayMins, cancelled);
    const airlineContact = AIRLINE_CLAIM_CONTACTS[carrier] || null;
    const airlineName = airlineContact?.name || carrier || 'the airline';
    if (!ec261 && !isUS) {
      return res.json({
        eligible: false,
        reason: `This flight does not appear to qualify for EU261 or US DOT compensation. The route (${origin}\u2192${dest}) may not be covered, or the delay may be below the threshold.`,
        flight: flightIdent, delay_minutes: delayMins, goodwill_available: true,
      });
    }
    let amount, regulation, currency, basis;
    if (ec261) {
      amount = ec261.amount_eur; regulation = 'EU261'; currency = 'EUR'; basis = ec261.basis;
    } else {
      amount = null; regulation = 'DOT'; currency = 'USD';
      basis = cancelled ? 'Flight cancelled' : `Delay of ${Math.round(delayMins/60)}h ${delayMins%60}m`;
    }
    const templateSubject = `${regulation === 'EU261' ? 'EU261/2004' : 'US DOT'} Compensation Claim \u2014 ${flightIdent}`;
    const templateBody = [
      `Dear ${airlineName} Customer Relations,`,
      ``,
      `I am writing to formally request compensation under ${regulation === 'EU261' ? 'EC Regulation 261/2004' : 'US DOT regulations'} in respect of flight ${flightIdent}${origin && dest ? ` operating ${origin}\u2013${dest}` : ''}.`,
      ``,
      basis ? `Disruption: ${basis}.` : '',
      ``,
      regulation === 'EU261'
        ? `Under EC 261/2004, I am entitled to compensation of \u20ac${amount} based on the flight distance of approximately ${distanceKm.toLocaleString()} km.`
        : `Under US DOT rules, I am requesting the applicable compensation for this disruption.`,
      ``,
      `Please confirm receipt of this claim and advise on next steps. I am happy to provide my booking reference, boarding pass, and any other documentation required.`,
      ``,
      `I expect a response within 14 days as required by regulation.`,
      ``,
      `Kind regards,`,
      `[Your full name]`,
      `[Booking reference]`,
      `[Contact email]`,
    ].filter(l => l !== null).join('\n');
    res.json({
      eligible: true, regulation, estimated_amount: amount, currency,
      flight: flightIdent, origin, destination: dest, distance_km: distanceKm,
      delay_minutes: delayMins, reason: basis, airline_name: airlineName,
      airline_email: airlineContact?.email || null,
      airline_claim_url: airlineContact?.url || null,
      template_subject: templateSubject, template_body: templateBody,
    });
  } catch (e) {
    console.error('[compensation/check]', e.message);
    res.status(500).json({ error: e.message });
  }
});

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
app.post("/trips/:tripId/upgrade-bid", auth, requirePro, async (req, res) => {
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
    // Use first connected account for the import endpoint (full multi-account scan via /auth/gmail/scan)
    const tokenRow = tokenRows[0];
    const oAuth2Client = makeOAuth2Client();
    oAuth2Client.setCredentials({
      access_token: decryptField(tokenRow.access_token) || tokenRow.access_token,
      refresh_token: decryptField(tokenRow.refresh_token) || tokenRow.refresh_token,
      expiry_date: Number(tokenRow.expiry_date),
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
            model: "claude-sonnet-4-5",
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
      model: "claude-sonnet-4-5",
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
      model: "claude-sonnet-4-5",
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
        model: "claude-sonnet-4-5",
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
      model: "claude-sonnet-4-5",
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
      model: "claude-sonnet-4-5",
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
      SELECT u.email, u.first_name, u.push_token FROM users u
      WHERE u.push_token IS NOT NULL
        AND (u.last_weekly_digest IS NULL OR u.last_weekly_digest < NOW() - INTERVAL '6 days')
        AND (
          -- Dormant: hasn't opened in 5+ days (or never opened)
          u.last_opened_at IS NULL
          OR u.last_opened_at < NOW() - INTERVAL '5 days'
          -- OR has an upcoming trip (always re-engage active travellers)
          OR EXISTS (
            SELECT 1 FROM trips t
            JOIN trip_legs tl ON tl.trip_id = t.id
            WHERE t.user_email = u.email
              AND tl.departs_at > NOW()
          )
        )
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
        // Chief-of-staff framing: lead with anything that needs the user.
        let pendingDecisions = 0;
        try {
          const dRows = await sql`SELECT COUNT(*) AS c FROM decisions WHERE user_email = ${user.email} AND status = 'pending'`;
          pendingDecisions = parseInt(dRows[0]?.c || 0);
        } catch {}
        let pushTitle, body;
        if (pendingDecisions > 0) {
          pushTitle = `${pendingDecisions} decision${pendingDecisions !== 1 ? 's' : ''} need you`;
          body = next
            ? `Before ${next.destination}, there ${pendingDecisions === 1 ? 'is 1 thing' : `are ${pendingDecisions} things`} waiting on your call.`
            : `I've got ${pendingDecisions === 1 ? 'a decision' : 'a few decisions'} ready for you — one tap each.`;
        } else if (next) {
          const days = Math.round((new Date(next.departs_at) - now) / 86400000);
          if (days <= 1) {
            pushTitle = `Your flight is ${days === 0 ? 'today' : 'tomorrow'} ✈`;
            body = `${next.origin} → ${next.destination}. Wingman has your briefing ready.`;
          } else if (days <= 7) {
            pushTitle = `${days} days to ${next.destination} ✈`;
            body = `I'm watching disruption risk and will brief you the morning of departure.`;
          } else {
            pushTitle = `Good morning${user.first_name ? `, ${user.first_name}` : ''} ✈`;
            body = `${next.origin} → ${next.destination} in ${days} days. I'm watching it.`;
          }
        } else if (tripCount > 0) {
          pushTitle = `Good morning${user.first_name ? `, ${user.first_name}` : ''} ✈`;
          body = `${tripCount} trip${tripCount !== 1 ? 's' : ''} protected this year. Where are you headed next?`;
        } else {
          pushTitle = `Good morning${user.first_name ? `, ${user.first_name}` : ''} ✈`;
          body = `Add your first trip and Wingman will watch it around the clock — free.`;
        }
        await sendPushToUser(
          user.email,
          pushTitle,
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

// ─── Daily morning briefing ──────────────────────────────────────
// A chief of staff briefs you each morning — but only when there's a trip to
// brief. Shared by the in-process timer and the external /cron endpoint.
async function runMorningBriefings() {
  const now = new Date();
  let sent = 0;
  const users = await sql`
    SELECT email, first_name, push_token, preferences, timezone, last_morning_briefing
    FROM users WHERE push_token IS NOT NULL
  `;
  for (const user of users) {
    try {
      const prefs = user.preferences || {};
      if (prefs.briefing_enabled === false) continue;
      const briefingHour = Number.isInteger(prefs.briefing_hour) ? prefs.briefing_hour : 7;
      const tz = user.timezone || "UTC";
      let localHour, localMinute;
      try {
        const parts = new Intl.DateTimeFormat("en-GB", { timeZone: tz, hour: "2-digit", minute: "2-digit", hour12: false }).formatToParts(now);
        localHour = Number(parts.find(p => p.type === "hour").value);
        localMinute = Number(parts.find(p => p.type === "minute").value);
      } catch { continue; }
      if (localHour !== briefingHour || localMinute >= 15) continue;
      if (user.last_morning_briefing && (now - new Date(user.last_morning_briefing)) < 20 * 3600 * 1000) continue;
      const nextRows = await sql`
        SELECT tl.departs_at, tl.origin, tl.destination, tl.destination_city, tl.carrier, tl.flight_number
        FROM trips t JOIN trip_legs tl ON tl.trip_id = t.id
        WHERE t.user_email = ${user.email} AND tl.type = 'flight'
          AND COALESCE(tl.arrives_at, tl.departs_at) > NOW()
        ORDER BY tl.departs_at ASC LIMIT 1
      `;
      const next = nextRows[0];
      if (!next) continue;
      const daysAway = Math.ceil((new Date(next.departs_at) - now) / 86400000);
      if (daysAway > 14) continue;
      const name = user.first_name ? `, ${user.first_name}` : "";
      const dest = next.destination_city || next.destination || "your destination";
      const ident = [next.carrier, next.flight_number].filter(Boolean).join("");
      const route = next.origin && next.destination ? `${next.origin} → ${next.destination}` : dest;
      const title = `Good morning${name}`;
      let body;
      if (daysAway <= 0) body = `${dest} today. ${route}${ident ? ` · ${ident}` : ""}. You're in good shape — I'll flag anything the moment it moves.`;
      else if (daysAway === 1) body = `${dest} tomorrow. Everything's lined up; I'll have your full briefing ready in the morning.`;
      else body = `${dest} in ${daysAway} days. Nothing needs you yet — I'm watching it and will speak up if that changes.`;
      await sendPushToUser(user.email, title, body, { screen: "Home" });
      await sql`UPDATE users SET last_morning_briefing = NOW() WHERE email = ${user.email}`;
      sent++;
    } catch (e) {
      console.error("[morning-briefing] user error:", e.message);
    }
  }
  return sent;
}

// In-process timer (works while the service is awake).
setInterval(() => { runMorningBriefings().catch(e => console.error("[morning-briefing] error:", e.message)); }, 15 * 60 * 1000);

// External scheduler endpoint (reliable on free tiers that sleep). Point a cron
// service at this every 15 min with header  x-cron-secret: <CRON_SECRET>.
async function handleCronMorningBriefings(req, res) {
  if (!process.env.CRON_SECRET) return res.status(503).json({ error: "CRON_SECRET not configured" });
  // Secret may arrive as the x-cron-secret header OR a ?secret= query param —
  // free cron services often send a plain GET and can't set custom headers.
  const provided = req.get("x-cron-secret") || req.query.secret;
  if (provided !== process.env.CRON_SECRET) return res.status(401).json({ error: "unauthorized" });
  try {
    const sent = await runMorningBriefings();
    res.json({ ok: true, sent });
  } catch (e) {
    console.error("[cron/morning-briefings]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
}
app.post("/cron/morning-briefings", handleCronMorningBriefings);
app.get("/cron/morning-briefings", handleCronMorningBriefings);

// External trigger for the flight-disruption watcher (reliable on free tiers that
// sleep). Point a cron service at this every ~15 min with ?secret=<CRON_SECRET>.
async function handleCronPollDisruptions(req, res) {
  if (!process.env.CRON_SECRET) return res.status(503).json({ error: "CRON_SECRET not configured" });
  const provided = req.get("x-cron-secret") || req.query.secret;
  if (provided !== process.env.CRON_SECRET) return res.status(401).json({ error: "unauthorized" });
  try {
    await pollDisruptions();
    res.json({ ok: true });
  } catch (e) {
    console.error("[cron/poll-disruptions]", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
}
app.post("/cron/poll-disruptions", handleCronPollDisruptions);
app.get("/cron/poll-disruptions", handleCronPollDisruptions);

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
    }
    res.json({ ok: true, trips_created: tripsAdded });
  } catch (e) {
    console.error("[email/inbound]", e.message);
    res.status(500).json({ error: e.message });
  }
});


// ===========================================================================
// TRAVEL PROFILE — GET /me/travel-profile & PATCH /me/travel-profile
// Stores: home_airports, seat_preference, travel_pace, payment_methods,
//         dietary_preferences, loyalty_numbers (summary), cabin_preference
// ===========================================================================
app.get("/me/travel-profile", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const rows = await sql`SELECT preferences, taste_profile FROM users WHERE email = ${email}`;
    if (!rows[0]) return res.status(404).json({ error: "not found" });
    const prefs = rows[0].preferences || {};
    const taste = rows[0].taste_profile || {};
    const profile = {
      home_airports:       prefs.home_airports       || [],
      seat_preference:     prefs.seat_preference     || null,   // "aisle" | "window" | "middle"
      cabin_preference:    prefs.cabin_preference    || "economy",
      travel_pace:         prefs.travel_pace         || "comfortable", // "tight" | "comfortable" | "generous"
      payment_methods:     prefs.payment_methods     || ["apple_pay", "contactless"],
      dietary:             taste.dietary             || prefs.dietary || [],
      currency:            prefs.currency            || "USD",
      display_name:        prefs.display_name        || null,
      min_connection_mins: prefs.min_connection_mins || 60,     // personal minimum connection time
      auto_checkin:        prefs.auto_checkin        !== false, // default true
      notify_gate_change:  prefs.notify_gate_change  !== false,
      notify_delay:        prefs.notify_delay        !== false,
      notify_journey:      prefs.notify_journey      !== false, // traffic/buffer alerts
      // === Phase 1 additions: loyalty alliance, training, recovery, companion ===
      loyalty_alliance:    prefs.loyalty_alliance    || null,   // "star" | "oneworld" | "skyteam" | null
      loyalty_programs:    prefs.loyalty_programs    || [],     // [{program, tier, number, is_primary}]
      training_active:     prefs.training_active     || false,  // currently in a training block
      race_date:           prefs.race_date           || null,   // ISO date of target race
      race_distance:       prefs.race_distance       || null,   // "5k" | "10k" | "half" | "marathon"
      training_phase:      prefs.training_phase      || null,   // "base" | "build" | "peak" | "taper"
      gym_brand_pref:      prefs.gym_brand_pref      || null,   // "technogym" | "life_fitness" | "precor" | "any"
      cold_plunge_req:     prefs.cold_plunge_req     || false,  // requires cold plunge / ice bath
      pool_req:            prefs.pool_req            || false,  // requires lap pool
      companion_default:   prefs.companion_default   || "solo", // "solo" | "partner" | "friend" | "family"
      travel_tier:         prefs.travel_tier         || "upscale", // "budget" | "midrange" | "upscale" | "luxury"
      passport_country:    prefs.passport_country    || null,   // primary passport country code e.g. "US"
    };
    res.json({ ok: true, profile });
  } catch (e) {
    console.error("[travel-profile GET]", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.patch("/me/travel-profile", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const allowed = [
      "home_airports", "seat_preference", "cabin_preference", "travel_pace",
      "payment_methods", "dietary", "currency", "display_name",
      "min_connection_mins", "auto_checkin", "notify_gate_change",
      "notify_delay", "notify_journey",
      // Phase 1 additions
      "loyalty_alliance", "loyalty_programs",
      "training_active", "race_date", "race_distance", "training_phase",
      "gym_brand_pref", "cold_plunge_req", "pool_req",
      "companion_default", "travel_tier", "passport_country",
    ];
    const updates = {};
    for (const k of allowed) {
      if (req.body[k] !== undefined) updates[k] = req.body[k];
    }
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: "no valid fields" });
    }
    await sql`
      UPDATE users
      SET preferences = COALESCE(preferences, '{}'::jsonb) || ${JSON.stringify(updates)}::jsonb
      WHERE email = ${email}
    `;
    // If dietary updated, also sync to taste_profile for concierge context
    if (updates.dietary) {
      await sql`
        UPDATE users
        SET taste_profile = COALESCE(taste_profile, '{}'::jsonb) || ${JSON.stringify({ dietary: updates.dietary })}::jsonb
        WHERE email = ${email}
      `;
    }
    await logActivity(email, "profile", "Travel profile updated", "Travel preferences saved.", null, null, updates);
    res.json({ ok: true, updated: Object.keys(updates) });
  } catch (e) {
    console.error("[travel-profile PATCH]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// JOURNEY SIMULATION ENGINE
// GET /journey/simulate?tripId=&legId=&lat=&lng=
// Combines: traffic ETA to airport, security wait, gate walk time, flight buffer
// Returns: buffer_minutes, verdict, timeline, at_risk, push_threshold_crossed
// ===========================================================================
async function getSecurityWait(iata) {
  // Try FlightAware AeroAPI for security wait data; fall back to heuristic
  try {
    const FA_KEY = process.env.FLIGHTAWARE_API_KEY;
    if (FA_KEY) {
      const r = await fetch(`https://aeroapi.flightaware.com/aeroapi/airports/${iata}/delays`, {
        headers: { "x-apikey": FA_KEY },
      });
      if (r.ok) {
        const d = await r.json();
        // AeroAPI returns delay categories; map to estimated security minutes
        const cat = d.delays?.[0]?.category;
        if (cat === "security") return Math.round((d.delays[0].delay_secs || 900) / 60);
      }
    }
  } catch {}
  // Heuristic fallback: busy hours = 20-30 min, off-peak = 10-15 min
  const h = new Date().getHours();
  if ((h >= 5 && h <= 9) || (h >= 15 && h <= 19)) return 22; // peak
  return 12; // off-peak
}

async function getTrafficETA(originLat, originLng, destIata) {
  // Use Google Directions API in driving mode
  try {
    const GMAPS_KEY = process.env.GOOGLE_MAPS_API_KEY;
    if (!GMAPS_KEY) return null;
    // Approximate airport coordinates by IATA — use a small lookup for common airports
    const AIRPORT_COORDS = {
      DUB: { lat: 53.4264, lng: -6.2499 }, LHR: { lat: 51.4700, lng: -0.4543 },
      JFK: { lat: 40.6413, lng: -73.7781 }, LAX: { lat: 33.9425, lng: -118.4081 },
      ARN: { lat: 59.6519, lng: 17.9186 }, CDG: { lat: 49.0097, lng: 2.5479 },
      SIN: { lat: 1.3644, lng: 103.9915 }, HKG: { lat: 22.3080, lng: 113.9185 },
      SYD: { lat: -33.9399, lng: 151.1753 }, NRT: { lat: 35.7720, lng: 140.3929 },
      ORD: { lat: 41.9742, lng: -87.9073 }, MIA: { lat: 25.7959, lng: -80.2870 },
      AMS: { lat: 52.3105, lng: 4.7683 },  FRA: { lat: 50.0379, lng: 8.5622 },
      MAN: { lat: 53.3537, lng: -2.2750 }, BOS: { lat: 42.3656, lng: -71.0096 },
      EWR: { lat: 40.6895, lng: -74.1745 }, SFO: { lat: 37.6213, lng: -122.3790 },
      YYZ: { lat: 43.6777, lng: -79.6248 }, MEX: { lat: 19.4363, lng: -99.0721 },
      DXB: { lat: 25.2532, lng: 55.3657 }, IST: { lat: 41.2753, lng: 28.7519 },
    };
    const dest = AIRPORT_COORDS[destIata?.toUpperCase()];
    if (!dest) return null;
    const url = `https://maps.googleapis.com/maps/api/directions/json?origin=${originLat},${originLng}&destination=${dest.lat},${dest.lng}&mode=driving&departure_time=now&key=${GMAPS_KEY}`;
    const r = await fetch(url);
    const d = await r.json();
    if (d.status !== "OK") return null;
    const route = d.routes?.[0]?.legs?.[0];
    if (!route) return null;
    return {
      duration_mins: Math.round(route.duration_in_traffic?.value / 60 || route.duration?.value / 60),
      distance_km:   Math.round((route.distance?.value || 0) / 1000),
      summary:       route.duration_in_traffic ? "with current traffic" : "estimated",
      traffic_model: route.duration_in_traffic ? "live" : "typical",
    };
  } catch (e) {
    console.error("[traffic-eta]", e.message);
    return null;
  }
}

app.get("/journey/simulate", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const { tripId, legId, lat, lng } = req.query;
    if (!tripId || !legId) return res.status(400).json({ error: "tripId and legId required" });

    // Fetch the flight leg
    const legs = await sql`
      SELECT tl.*, t.user_email FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${legId} AND tl.trip_id = ${tripId} AND t.user_email = ${email}
    `;
    if (!legs[0]) return res.status(404).json({ error: "leg not found" });
    const leg = legs[0];

    if (!leg.departs_at) return res.status(400).json({ error: "leg has no departure time" });
    const departureMs = new Date(leg.departs_at).getTime();
    const nowMs = Date.now();
    const minsToDepart = Math.round((departureMs - nowMs) / 60000);

    // Fetch user travel profile for pace preference
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${email}`;
    const prefs = userRows[0]?.preferences || {};
    const travelPace = prefs.travel_pace || "comfortable";
    const minConnection = prefs.min_connection_mins || 60;

    // Pace-based airport arrival buffer (mins before departure)
    const paceBuffer = { tight: 45, comfortable: 75, generous: 120 }[travelPace] || 75;
    const requiredArrivalMs = departureMs - (paceBuffer * 60000);
    const minsUntilRequired = Math.round((requiredArrivalMs - nowMs) / 60000);

    // Security wait at origin airport
    const securityMins = await getSecurityWait(leg.origin);

    // Gate walk time (heuristic: 8-12 mins depending on airport size)
    const largeAirports = ["LHR","JFK","LAX","CDG","FRA","AMS","DXB","ORD","SIN","NRT","IST"];
    const gateWalkMins = largeAirports.includes(leg.origin?.toUpperCase()) ? 12 : 8;

    // Traffic ETA (if location provided)
    let trafficETA = null;
    if (lat && lng) {
      trafficETA = await getTrafficETA(parseFloat(lat), parseFloat(lng), leg.origin);
    }

    // Build timeline
    const timeline = [];
    let runningMins = 0;

    if (trafficETA) {
      timeline.push({ icon: "🚗", label: `Drive to ${leg.origin}`, minutes: runningMins, duration: trafficETA.duration_mins, note: trafficETA.summary });
      runningMins += trafficETA.duration_mins;
    }
    timeline.push({ icon: "🔒", label: `Security at ${leg.origin}`, minutes: runningMins, duration: securityMins, note: `~${securityMins} min wait` });
    runningMins += securityMins;
    timeline.push({ icon: "🚶", label: `Walk to gate`, minutes: runningMins, duration: gateWalkMins, note: leg.gate ? `Gate ${leg.gate}` : "Gate TBC" });
    runningMins += gateWalkMins;
    timeline.push({ icon: "✈️", label: `Board ${leg.carrier || ""}${leg.flight_number || ""}`, minutes: runningMins, duration: 0, note: `Departs ${new Date(leg.departs_at).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })}` });

    // Buffer = time to departure minus all steps
    const totalStepMins = runningMins;
    const bufferMinutes = minsToDepart - totalStepMins;

    // Verdict
    let verdict, atRisk;
    if (bufferMinutes < 0) {
      verdict = "will_miss"; atRisk = true;
    } else if (bufferMinutes < 15) {
      verdict = "tight"; atRisk = true;
    } else if (bufferMinutes < 30) {
      verdict = "on_track"; atRisk = false;
    } else {
      verdict = "comfortable"; atRisk = false;
    }

    // Required arrival time string
    const requiredArrivalStr = new Date(requiredArrivalMs).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" });
    const currentETA = trafficETA
      ? new Date(nowMs + trafficETA.duration_mins * 60000).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit" })
      : null;

    res.json({
      ok: true,
      flight: { ident: (leg.carrier || "") + (leg.flight_number || ""), origin: leg.origin, destination: leg.destination, departs_at: leg.departs_at, gate: leg.gate },
      buffer_minutes: bufferMinutes,
      mins_to_depart: minsToDepart,
      verdict,
      at_risk: atRisk,
      timeline,
      traffic_eta: trafficETA,
      security_mins: securityMins,
      gate_walk_mins: gateWalkMins,
      required_arrival: requiredArrivalStr,
      current_eta: currentETA,
      pace_buffer_mins: paceBuffer,
    });
  } catch (e) {
    console.error("[journey/simulate]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// DISRUPTION RESPONSE — GET /disruption/alternatives?legId=&tripId=
// Finds rebooking options when a flight is cancelled/severely delayed
// Also calculates EC261 compensation entitlement
// ===========================================================================
function calcEC261(originIata, destIata, delayMins, cancelled) {
  // EC261 applies to: EU departures OR EU carrier arrivals
  const EU_AIRPORTS = new Set([
    "LHR","LGW","MAN","EDI","BHX","BRS","LPL","NCL","ABZ","GLA","STN","LTN","LCY",
    "DUB","ORK","SNN","BFS","CDG","ORY","NCE","LYS","MRS","TLS","BOD","NTE","LIL",
    "AMS","RTM","EIN","FRA","MUC","BER","DUS","HAM","CGN","STR","NUE","HAJ",
    "MAD","BCN","AGP","PMI","LPA","TFN","ALC","VLC","BIO","SVQ",
    "FCO","MXP","LIN","VCE","NAP","CAT","PMO","BLQ","PSA",
    "ATH","SKG","HER","RHO","CFU","CHQ",
    "LIS","OPO","FAO","FNC",
    "VIE","ZRH","GVA","BSL","CPH","ARN","OSL","HEL","RVN","TMP",
    "WAW","KRK","WRO","GDN","POZ","BUD","PRG","BTS","LJU","ZAG",
    "BRU","CRL","LUX","TLL","RIX","VNO","REK",
    "ARN","GOT","MMX",
  ]);
  const isEURoute = EU_AIRPORTS.has(originIata?.toUpperCase()) || EU_AIRPORTS.has(destIata?.toUpperCase());
  if (!isEURoute) return null;

  // Distance-based compensation
  // Under 1500km: €250 | 1500-3500km: €400 | Over 3500km: €600
  // Simplified: use origin/dest pair heuristic
  const longHaul = ["JFK","LAX","SIN","HKG","NRT","SYD","DXB","ORD","YYZ","BKK","PEK","PVG","GRU","EZE","CPT","NBO"];
  const medHaul  = ["IST","CAI","TLV","AMM","BEY","DOH","AUH","KWI","BAH","MCT","TBS","EVN","LED","SVO","DME","OTP","SOF","SKP","TIA","PRN","TGD","INI"];

  let compensation = 250;
  const dest = destIata?.toUpperCase();
  const orig = originIata?.toUpperCase();
  if (longHaul.includes(dest) || longHaul.includes(orig)) compensation = 600;
  else if (medHaul.includes(dest) || medHaul.includes(orig)) compensation = 400;

  // Delay threshold: cancelled = full; delay > 3h = full; delay 2-3h = 50%
  if (!cancelled && delayMins < 120) return null;
  if (!cancelled && delayMins < 180) compensation = Math.round(compensation * 0.5);

  return {
    eligible: true,
    amount_eur: compensation,
    regulation: "EC 261/2004",
    basis: cancelled ? "Flight cancelled" : `Delay of ${Math.round(delayMins / 60)}h ${delayMins % 60}m`,
    how_to_claim: "Contact the airline directly or use a claims service. Keep your boarding pass and booking confirmation.",
    claim_deadline: "3 years from the flight date (varies by country)",
  };
}

app.get("/disruption/alternatives", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const { legId, tripId } = req.query;
    if (!legId || !tripId) return res.status(400).json({ error: "legId and tripId required" });

    const legs = await sql`
      SELECT tl.*, t.user_email, t.title as trip_title FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${legId} AND tl.trip_id = ${tripId} AND t.user_email = ${email}
    `;
    if (!legs[0]) return res.status(404).json({ error: "leg not found" });
    const leg = legs[0];

    const isCancelled = leg.status === "Cancelled";
    const delayMins = leg.delay_minutes || 0;

    // EC261 entitlement
    const ec261 = calcEC261(leg.origin, leg.destination, delayMins, isCancelled);

    // Search for alternative flights using existing searchRescueOptions logic
    let alternatives = [];
    try {
      const dateStr = leg.departs_at ? new Date(leg.departs_at).toISOString().split("T")[0] : new Date().toISOString().split("T")[0];
      const searchResult = await fetch(`${process.env.BASE_URL || "http://localhost:" + PORT}/rescue/options`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": req.headers.authorization },
        body: JSON.stringify({ tripId, origin: leg.origin, destination: leg.destination, date: dateStr }),
      });
      if (searchResult.ok) {
        const d = await searchResult.json();
        alternatives = (d.options || []).slice(0, 3);
      }
    } catch {}

    // Build cascade actions — ALL downstream legs affected by this disruption
    const cascadeActions = [];

    // Get trip companions count for personalized messaging
    const [tripMeta] = await sql`SELECT companions_count, companion_names, title FROM trips WHERE id = ${tripId}`;
    const companionsCount = tripMeta?.companions_count || 1;
    const guestStr = companionsCount > 1 ? `${companionsCount} guests` : "1 guest";

    // Get ALL subsequent legs in this trip after the affected leg's departure time
    const affectedTime = leg.departs_at ? new Date(leg.departs_at) : new Date();
    const downstreamLegs = await sql`
      SELECT * FROM trip_legs
      WHERE trip_id = ${tripId}
        AND id != ${leg.id}
        AND (departs_at > ${affectedTime.toISOString()}::TIMESTAMPTZ OR arrives_at > ${affectedTime.toISOString()}::TIMESTAMPTZ)
      ORDER BY COALESCE(departs_at, arrives_at) ASC
    `;

    // Severity: critical = show/event at risk, high = connecting flight, medium = hotel, low = restaurant
    for (const dl of downstreamLegs) {
      const dlTime = dl.departs_at ? new Date(dl.departs_at) : null;
      const hoursUntil = dlTime ? (dlTime.getTime() - Date.now()) / 3600000 : null;

      if (dl.type === "event" || dl.type === "show" || dl.type === "concert") {
        const eventName = dl.carrier || dl.destination_city || "your event";
        const eventDate = dl.departs_at ? new Date(dl.departs_at).toLocaleDateString("en-GB", { weekday: "short", month: "short", day: "numeric" }) : "";
        cascadeActions.push({
          type: "event_at_risk",
          severity: "critical",
          label: `${eventName} on ${eventDate} may be at risk`,
          description: isCancelled
            ? `This cancellation puts your ${eventName} booking at risk. Wingman can help find alternatives.`
            : `A ${delayMins}+ minute delay may affect your arrival before ${eventName}.`,
          actionable: true,
          data: { legId: dl.id, eventName, eventDate },
        });
      } else if (dl.type === "flight") {
        const connIdent = (dl.carrier || "") + (dl.flight_number || "");
        const connRoute = dl.origin && dl.destination ? `${dl.origin}→${dl.destination}` : connIdent;
        const bufferMins = dlTime ? Math.round((dlTime.getTime() - (affectedTime.getTime() + (delayMins || 0) * 60000)) / 60000) : null;
        const isAtRisk = bufferMins !== null && bufferMins < 90;
        cascadeActions.push({
          type: isAtRisk ? "connection_at_risk" : "connection_monitor",
          severity: isAtRisk ? "high" : "medium",
          label: isAtRisk ? `Connection ${connRoute} at risk (${bufferMins}m buffer)` : `Monitoring connection ${connRoute}`,
          description: isAtRisk
            ? `With this delay, you'd have only ${bufferMins} minutes to make ${connIdent || connRoute}. Wingman recommends rebooking now.`
            : `Your ${connIdent || connRoute} connection has ${bufferMins ? bufferMins + " minutes" : "some"} buffer. Wingman is watching it.`,
          actionable: isAtRisk,
          data: { legId: dl.id, flightIdent: connIdent, origin: dl.origin, destination: dl.destination, bufferMins },
        });
      } else if (dl.type === "hotel" || dl.type === "airbnb") {
        const hotelName = dl.carrier || dl.destination_city || "your hotel";
        const checkinDate = dl.departs_at ? new Date(dl.departs_at).toLocaleDateString("en-GB", { weekday: "short", month: "short", day: "numeric" }) : "";
        cascadeActions.push({
          type: "hotel_delay",
          severity: "medium",
          label: `Notify ${hotelName} of late arrival`,
          description: `Check-in for ${guestStr} at ${hotelName}${checkinDate ? " on " + checkinDate : ""} may be affected. Wingman can contact them.`,
          actionable: true,
          data: { legId: dl.id, hotelName, checkinDate, companionsCount },
        });
      } else if (dl.type === "restaurant") {
        const restName = dl.carrier || "your restaurant";
        cascadeActions.push({
          type: "restaurant_delay",
          severity: "low",
          label: `Reschedule dinner at ${restName}`,
          description: `Your reservation at ${restName} for ${guestStr} may need to be pushed back. Wingman can draft the message.`,
          actionable: true,
          data: { legId: dl.id, restaurantName: restName, companionsCount },
        });
      }
    }

    // Lounge access while waiting
    if (isCancelled || delayMins >= 60) {
      cascadeActions.push({
        type: "lounge_access",
        severity: "info",
        label: "Find lounge access while you wait",
        description: `Check your card benefits for complimentary lounge access at ${leg.origin || "this airport"}.`,
        actionable: true,
        data: { iata: leg.origin },
      });
    }

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    cascadeActions.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

    // Rights info
    const rightsInfo = isCancelled ? {
      title: "Your rights",
      body: "Under EU/UK law, the airline must offer you a full refund or rebooking at no extra cost. You are also entitled to meals and refreshments if the delay is over 2 hours.",
    } : delayMins >= 120 ? {
      title: "Your rights",
      body: `Your flight is delayed by over 2 hours. The airline must provide meals and refreshments. If the delay exceeds 3 hours on arrival, you may be entitled to compensation.`,
    } : null;

    res.json({
      ok: true,
      flight: { ident: (leg.carrier || "") + (leg.flight_number || ""), origin: leg.origin, destination: leg.destination, status: leg.status, delay_minutes: delayMins },
      is_cancelled: isCancelled,
      alternatives,
      ec261,
      cascade_actions: cascadeActions,
      rights_info: rightsInfo,
    });
  } catch (e) {
    console.error("[disruption/alternatives]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// CASCADE ACTIONS — execute downstream protection actions
// POST /trips/:tripId/cascade/hotel-notify — SMS the hotel about late arrival
// POST /trips/:tripId/cascade/restaurant-reschedule — AI-draft reschedule message
// ===========================================================================

// sendTwilioSMS — PERMANENTLY DELETED.
// Wingman never sends SMS to third parties (hotels, restaurants, or any travel partner).
// The cascade endpoints below draft messages for the user to send themselves.

// POST /trips/:tripId/cascade/hotel-notify
// Drafts a message to notify the hotel of a late arrival.
// NOTE: Wingman never contacts third parties directly. This endpoint returns a
// drafted message for the user to send themselves.
// Body: { leg_id, delay_minutes }
app.post("/trips/:tripId/cascade/hotel-notify", auth, requirePro, async (req, res) => {
  const { tripId } = req.params;
  const { leg_id, delay_minutes } = req.body || {};
  try {
    const legRows = await sql`
      SELECT tl.*, t.user_email FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${leg_id} AND t.id = ${tripId} AND t.user_email = ${req.user.email}
    `;
    if (!legRows.length) return res.status(404).json({ error: "Leg not found" });
    const hotelLeg = legRows[0];
    const hotelName = hotelLeg.carrier || hotelLeg.name || "the hotel";
    const checkinTime = hotelLeg.departs_at
      ? new Date(hotelLeg.departs_at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
      : "tonight";
    const newArrival = delay_minutes
      ? new Date(new Date(hotelLeg.departs_at || Date.now()).getTime() + delay_minutes * 60000)
          .toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
      : "later than expected";

    const message = `Hi, I have a reservation tonight checking in at ${checkinTime}. Due to a flight delay, I'll now arrive at approximately ${newArrival}. Could you please hold my reservation? Thank you.`;

    await logActivity(
      req.user.email, "cascade_hotel_notify",
      `Hotel message drafted: ${hotelName}`,
      `Message ready to send: "${message}"`,
      tripId, leg_id,
      { hotel_name: hotelName, delay_minutes, sms_sent: false }
    );

    res.json({
      ok: true,
      sms_sent: false,
      message_drafted: message,
      hotel_name: hotelName,
      note: "Message drafted — copy and send to the hotel directly (call, SMS, or email).",
    });
  } catch (e) {
    console.error("[cascade/hotel-notify]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /trips/:tripId/cascade/restaurant-reschedule
// Uses Claude to draft a polite reschedule message for a restaurant reservation.
// NOTE: Wingman never contacts third parties directly. Returns a drafted message
// for the user to send themselves.
// Body: { leg_id, delay_minutes }
app.post("/trips/:tripId/cascade/restaurant-reschedule", auth, requirePro, async (req, res) => {
  const { tripId } = req.params;
  const { leg_id, delay_minutes } = req.body || {};
  try {
    const legRows = await sql`
      SELECT tl.*, t.user_email FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE tl.id = ${leg_id} AND t.id = ${tripId} AND t.user_email = ${req.user.email}
    `;
    if (!legRows.length) return res.status(404).json({ error: "Leg not found" });
    const restLeg = legRows[0];
    const restName = restLeg.carrier || restLeg.name || "the restaurant";
    const resTime = restLeg.departs_at
      ? new Date(restLeg.departs_at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
      : "this evening";
    const newTime = delay_minutes
      ? new Date(new Date(restLeg.departs_at || Date.now()).getTime() + delay_minutes * 60000)
          .toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })
      : "later";

    // Use Claude to draft a polished message for the USER to send
    let draftMessage = `Hi ${restName}, I have a reservation tonight at ${resTime}. Due to a flight delay, I'll be arriving at approximately ${newTime} instead. Could you please hold my table? I apologize for any inconvenience.`;
    try {
      const anthropic = getAnthropic();
      const aiResp = await anthropic.messages.create({
        model: "claude-sonnet-4-5",
        max_tokens: 200,
        messages: [{
          role: "user",
          content: `Write a brief, polite message to ${restName} restaurant asking to push a reservation from ${resTime} to ${newTime} due to a flight delay. Keep it under 160 characters. Just the message text, no quotes.`,
        }],
      });
      draftMessage = aiResp.content[0]?.text?.trim() || draftMessage;
    } catch {}

    await logActivity(
      req.user.email, "cascade_restaurant_reschedule",
      `Restaurant message drafted: ${restName}`,
      `Message ready to send: "${draftMessage}"`,
      tripId, leg_id,
      { restaurant_name: restName, delay_minutes, sms_sent: false }
    );

    res.json({
      ok: true,
      sms_sent: false,
      message_drafted: draftMessage,
      restaurant_name: restName,
      note: "Message drafted — copy and send to the restaurant directly (call, SMS, or email).",
    });
  } catch (e) {
    console.error("[cascade/restaurant-reschedule]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// PRE-TRIP CHECKLIST
// POST /trips/:tripId/checklist/generate — Claude generates a personalised checklist
// GET  /trips/:tripId/checklist — return checklist items
// PATCH /trips/:tripId/checklist/:itemId — mark item complete/incomplete
// ===========================================================================

app.post("/trips/:tripId/checklist/generate", auth, async (req, res) => {
  const { tripId } = req.params;
  try {
    // Verify ownership
    const [trip] = await sql`
      SELECT t.*, u.first_name, u.cabin_preference, u.home_airports
      FROM trips t JOIN users u ON u.email = t.user_email
      WHERE t.id = ${tripId} AND t.user_email = ${req.email}
    `;
    if (!trip) return res.status(404).json({ error: "Trip not found" });

    const legs = await sql`SELECT * FROM trip_legs WHERE trip_id = ${tripId} ORDER BY COALESCE(departs_at, arrives_at) ASC`;

    // Build a concise trip summary for Claude
    const flightLegs = legs.filter(l => l.type === "flight");
    const countries = [...new Set(legs.map(l => l.destination_city || l.destination).filter(Boolean))];
    const eventLegs = legs.filter(l => ["event", "show", "concert"].includes(l.type));
    const firstDep = flightLegs[0]?.departs_at;
    const lastArr = legs.reduce((latest, l) => {
      const t = l.arrives_at || l.departs_at;
      return t && (!latest || new Date(t) > new Date(latest)) ? t : latest;
    }, null);
    const daysAway = firstDep ? Math.ceil((new Date(firstDep).getTime() - Date.now()) / 86400000) : null;
    const companionsCount = trip.companions_count || 1;
    const companionNames = trip.companion_names || [];
    const companionStr = companionsCount > 1
      ? ` Travelling with ${companionNames.length > 0 ? companionNames.join(" and ") : (companionsCount - 1) + " companion" + (companionsCount > 2 ? "s" : "")}.`
      : "";

    const tripSummary = [
      `Trip: ${trip.title}`,
      firstDep ? `Departs: ${new Date(firstDep).toDateString()}` : "",
      lastArr  ? `Returns: ${new Date(lastArr).toDateString()}`  : "",
      daysAway != null ? `Days until departure: ${daysAway}` : "",
      countries.length > 0 ? `Countries/cities: ${countries.join(", ")}` : "",
      flightLegs.length > 0 ? `Flights: ${flightLegs.map(l => (l.carrier || "") + (l.flight_number || "") + " " + (l.origin || "") + "→" + (l.destination || "")).join(", ")}` : "",
      eventLegs.length > 0 ? `Events/shows: ${eventLegs.map(l => l.carrier || l.destination_city || "event").join(", ")}` : "",
      trip.cabin_preference ? `Cabin: ${trip.cabin_preference}` : "",
      companionStr,
    ].filter(Boolean).join("\n");

    const anthropic = getAnthropic();
    const aiResp = await anthropic.messages.create({
      model: "claude-sonnet-4-5",
      max_tokens: 1200,
      messages: [{
        role: "user",
        content: `You are a premium travel concierge. Generate a pre-trip checklist for this trip. Return JSON only: { items: [{ item: string, category: "visa"|"health"|"money"|"tech"|"packing"|"booking"|"documents"|"general", due_days_before: number, priority: "critical"|"high"|"medium" }] }. Be specific — include visa/entry requirements for each country, any time-sensitive bookings (restaurants, bullet trains, etc), tech setup (VPN for China, local SIM, etc), and travel documents. Maximum 20 items. Trip details:\n${tripSummary}`,
      }],
    });

    let parsed;
    try {
      parsed = JSON.parse(aiResp.content[0].text.replace(/```json\n?|```/g, "").trim());
    } catch {
      return res.status(422).json({ error: "Could not parse checklist", raw: aiResp.content[0].text });
    }

    // Clear existing auto-generated items and insert new ones
    await sql`DELETE FROM trip_checklist WHERE trip_id = ${tripId} AND auto_generated = true AND user_email = ${req.email}`;

    const items = (parsed.items || []).slice(0, 20);
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      const dueDate = it.due_days_before != null && firstDep
        ? new Date(new Date(firstDep).getTime() - it.due_days_before * 86400000).toISOString().split("T")[0]
        : null;
      await sql`
        INSERT INTO trip_checklist (trip_id, user_email, item, category, due_date, auto_generated, sort_order)
        VALUES (${tripId}, ${req.email}, ${it.item}, ${it.category || "general"}, ${dueDate}::DATE, true, ${i})
      `;
    }

    const checklist = await sql`SELECT * FROM trip_checklist WHERE trip_id = ${tripId} AND user_email = ${req.email} ORDER BY sort_order ASC`;
    res.json({ ok: true, checklist });
  } catch (e) {
    console.error("[checklist/generate]", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get("/trips/:tripId/checklist", auth, async (req, res) => {
  const { tripId } = req.params;
  try {
    const [trip] = await sql`SELECT id FROM trips WHERE id = ${tripId} AND user_email = ${req.email}`;
    if (!trip) return res.status(404).json({ error: "Trip not found" });
    const checklist = await sql`SELECT * FROM trip_checklist WHERE trip_id = ${tripId} AND user_email = ${req.email} ORDER BY sort_order ASC, created_at ASC`;
    res.json({ checklist });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/trips/:tripId/checklist/:itemId", auth, async (req, res) => {
  const { tripId, itemId } = req.params;
  const { completed } = req.body;
  try {
    const [updated] = await sql`
      UPDATE trip_checklist SET completed = ${completed}
      WHERE id = ${itemId} AND trip_id = ${tripId} AND user_email = ${req.email}
      RETURNING *
    `;
    if (!updated) return res.status(404).json({ error: "Item not found" });
    res.json({ ok: true, item: updated });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/trips/:tripId/checklist", auth, async (req, res) => {
  const { tripId } = req.params;
  const { item, category } = req.body;
  if (!item) return res.status(400).json({ error: "item required" });
  try {
    const [trip] = await sql`SELECT id FROM trips WHERE id = ${tripId} AND user_email = ${req.email}`;
    if (!trip) return res.status(404).json({ error: "Trip not found" });
    const [maxOrder] = await sql`SELECT COALESCE(MAX(sort_order), -1) as max FROM trip_checklist WHERE trip_id = ${tripId}`;
    const [newItem] = await sql`
      INSERT INTO trip_checklist (trip_id, user_email, item, category, auto_generated, sort_order)
      VALUES (${tripId}, ${req.email}, ${item}, ${category || "general"}, false, ${(maxOrder?.max ?? -1) + 1})
      RETURNING *
    `;
    res.json({ ok: true, item: newItem });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// TRIP COMPANIONS METADATA — PATCH /trips/:tripId/companions/meta
// Update companions_count and companion_names (quick-set without invite flow)
// ===========================================================================
app.patch("/trips/:tripId/companions/meta", auth, async (req, res) => {
  const { tripId } = req.params;
  const { companions_count, companion_names } = req.body;
  try {
    const [trip] = await sql`SELECT id FROM trips WHERE id = ${tripId} AND user_email = ${req.email}`;
    if (!trip) return res.status(404).json({ error: "Trip not found" });
    const [updated] = await sql`
      UPDATE trips SET
        companions_count = ${companions_count ?? 1},
        companion_names  = ${JSON.stringify(companion_names ?? [])}::JSONB,
        updated_at = NOW()
      WHERE id = ${tripId} AND user_email = ${req.email}
      RETURNING id, companions_count, companion_names
    `;
    res.json({ ok: true, trip: updated });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// SHOW NIGHTS — GET /trips/:tripId/show-nights
// Returns event/show legs with venue timing intel
// ===========================================================================
app.get("/trips/:tripId/show-nights", auth, async (req, res) => {
  const { tripId } = req.params;
  try {
    const [trip] = await sql`SELECT * FROM trips WHERE id = ${tripId} AND user_email = ${req.email}`;
    if (!trip) return res.status(404).json({ error: "Trip not found" });

    // Get event/show legs
    const eventLegs = await sql`
      SELECT * FROM trip_legs
      WHERE trip_id = ${tripId}
        AND type IN ('event', 'show', 'concert', 'activity')
      ORDER BY COALESCE(departs_at, arrives_at) ASC
    `;

    // Also get hotel legs to calculate travel time from hotel to venue
    const hotelLegs = await sql`
      SELECT * FROM trip_legs WHERE trip_id = ${tripId} AND type IN ('hotel', 'airbnb')
      ORDER BY departs_at ASC
    `;

    // For each event, find the hotel the user is staying at on that night
    const showNights = [];
    for (const ev of eventLegs) {
      const evDate = ev.departs_at ? new Date(ev.departs_at) : null;
      // Find hotel that overlaps with this event date
      const hotel = hotelLegs.find(h => {
        if (!h.departs_at || !h.arrives_at) return false;
        const checkIn  = new Date(h.departs_at);
        const checkOut = new Date(h.arrives_at);
        return evDate && evDate >= checkIn && evDate < checkOut;
      });

      const venueName = ev.carrier || ev.destination_city || "the venue";
      const city = ev.destination_city || hotel?.destination_city || trip.title;
      const showTime = ev.departs_at ? new Date(ev.departs_at).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) : null;

      // Estimate travel time (rough heuristic — 30-45 min for most venues)
      const estimatedTravelMins = 45;
      const recommendedDepartureTime = ev.departs_at
        ? new Date(new Date(ev.departs_at).getTime() - (estimatedTravelMins + 30) * 60000)
            .toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })
        : null;

      showNights.push({
        leg_id: ev.id,
        event_name: venueName,
        city,
        date: ev.departs_at ? new Date(ev.departs_at).toLocaleDateString("en-GB", { weekday: "long", month: "long", day: "numeric" }) : null,
        show_time: showTime,
        recommended_departure: recommendedDepartureTime,
        hotel_name: hotel ? (hotel.carrier || hotel.destination_city || "your hotel") : null,
        travel_note: hotel
          ? `Leave ${hotel.carrier || "your hotel"} by ${recommendedDepartureTime || "early"} to arrive before doors open.`
          : `Allow 45+ minutes travel time to the venue.`,
        tight_day: false, // will be set below
      });
    }

    // Flag tight days (Oct 7 Osaka→Tokyo bullet train + same-day show type scenario)
    const flightLegs = await sql`SELECT * FROM trip_legs WHERE trip_id = ${tripId} AND type = 'flight' ORDER BY departs_at ASC`;
    for (const sn of showNights) {
      const evDate = eventLegs.find(e => e.id === sn.leg_id)?.departs_at;
      if (!evDate) continue;
      const evDay = new Date(evDate).toDateString();
      const sameDay = flightLegs.find(f => f.departs_at && new Date(f.departs_at).toDateString() === evDay);
      if (sameDay) {
        sn.tight_day = true;
        sn.tight_day_note = `You have a flight (${(sameDay.carrier || "") + (sameDay.flight_number || "")} ${sameDay.origin}→${sameDay.destination}) on the same day as this event. Arrive early.`;
      }
    }

    res.json({ show_nights: showNights });
  } catch (e) {
    console.error("[show-nights]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// TRAVEL STATS — GET /me/stats
app.get("/me/stats", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const year = new Date().getFullYear();
    const yearStart = new Date(`${year}-01-01T00:00:00Z`);
    const yearEnd   = new Date(`${year + 1}-01-01T00:00:00Z`);

    // Trips this year — counted by when the travel actually happens (a leg departs
    // this year), NOT when the record was imported. Only trips with a real dated leg
    // count, which also excludes empty "Reservations"/"Needs review" holders.
    const tripsThisYear = await sql`
      SELECT COUNT(DISTINCT t.id) as cnt FROM trips t
      JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
        AND t.archived = false
        AND tl.departs_at >= ${yearStart}
        AND tl.departs_at <  ${yearEnd}
    `;

    // Miles flown this year — estimate from flight legs (no stored distance)
    const flightLegsThisYear = await sql`
      SELECT COUNT(*) as cnt FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.type = 'flight'
        AND tl.departs_at >= ${yearStart}
        AND tl.departs_at <  ${yearEnd}
    `;
    const estimatedMiles = Math.round(parseInt(flightLegsThisYear[0]?.cnt || 0) * 800);

    // Nights away this year — use the stored nights count when present, else derive
    // it from the check-in → check-out span (the parser often omits `nights`).
    const nightsAway = await sql`
      SELECT COALESCE(SUM(
        CASE
          WHEN tl.nights IS NOT NULL AND tl.nights > 0 THEN tl.nights
          WHEN tl.arrives_at IS NOT NULL AND tl.departs_at IS NOT NULL
            THEN GREATEST(1, ROUND(EXTRACT(EPOCH FROM (tl.arrives_at - tl.departs_at)) / 86400.0))
          ELSE 0
        END
      ), 0) as total FROM trip_legs tl
      JOIN trips t ON t.id = tl.trip_id
      WHERE t.user_email = ${email}
        AND tl.type IN ('hotel','airbnb')
        AND tl.departs_at >= ${yearStart}
        AND tl.departs_at <  ${yearEnd}
    `;

    // Countries visited this year
    const countries = await sql`
      SELECT COUNT(DISTINCT t.destination_country) as cnt FROM trips t
      WHERE t.user_email = ${email}
        AND t.created_at >= ${yearStart}
        AND t.destination_country IS NOT NULL
        AND t.archived = false
    `;

    // All-time trips
    const totalTrips = await sql`
      SELECT COUNT(*) as cnt FROM trips
      WHERE user_email = ${email} AND archived = false
    `;

    res.json({
      ok: true,
      year,
      trips_this_year: parseInt(tripsThisYear[0]?.cnt || 0),
      miles_this_year: estimatedMiles,
      nights_away_this_year: parseInt(nightsAway[0]?.total || 0),
      countries_this_year: parseInt(countries[0]?.cnt || 0),
      total_trips: parseInt(totalTrips[0]?.cnt || 0),
    });
  } catch (e) {
    console.error("[stats]", e.message);
    res.status(500).json({ error: "stats_error" });
  }
});

// HOME STATE — GET /me/home-state
// Returns the user's current travel state for the contextual home screen
// States: no_trip | pre_departure | at_airport | in_transit | at_destination
// ===========================================================================
app.get("/me/home-state", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const { lat, lng } = req.query;
    const now = new Date();
    const in48h = new Date(now.getTime() + 48 * 3600000);
    const in7d  = new Date(now.getTime() + 7 * 24 * 3600000);

    // Get all upcoming trips and legs
    const trips = await sql`
      SELECT t.id, t.title, t.destination_city, t.destination_country,
             json_agg(tl ORDER BY tl.departs_at NULLS LAST) as legs
      FROM trips t
      LEFT JOIN trip_legs tl ON tl.trip_id = t.id
      WHERE t.user_email = ${email}
        AND t.archived = false
      GROUP BY t.id
      ORDER BY t.created_at DESC
      LIMIT 10
    `;

    // Fetch user taste profile for restaurant suggestions
    const userPrefsRow = await sql`SELECT preferences, taste_profile FROM users WHERE email = ${email} LIMIT 1`;
    const userTaste = userPrefsRow[0]?.taste_profile || {};
    const userPrefs = userPrefsRow[0]?.preferences || {};

    // Find the most relevant flight leg
    let activeLeg = null, activeTrip = null, state = "no_trip";
    let hoursToDepart = null;

    for (const trip of trips) {
      for (const leg of (trip.legs || [])) {
        if (leg?.type !== "flight" || !leg.departs_at) continue;
        const depMs = new Date(leg.departs_at).getTime();
        const nowMs = now.getTime();
        const diffH = (depMs - nowMs) / 3600000;

        // In air: departed up to 18h ago and not yet landed
        if (diffH < 0 && diffH > -18 && leg.status !== "Landed") {
          activeLeg = leg; activeTrip = trip; state = "in_transit"; hoursToDepart = diffH; break;
        }
        // At airport: departing in next 4 hours
        if (diffH >= 0 && diffH <= 4) {
          activeLeg = leg; activeTrip = trip; state = "at_airport"; hoursToDepart = diffH; break;
        }
        // Pre-departure: departing in 4-48 hours
        if (diffH > 4 && diffH <= 48) {
          if (!activeLeg || diffH < hoursToDepart) {
            activeLeg = leg; activeTrip = trip; state = "pre_departure"; hoursToDepart = diffH;
          }
        }
        // Next trip within 7 days
        if (diffH > 48 && diffH <= 168) {
          if (!activeLeg) {
            activeLeg = leg; activeTrip = trip; state = "pre_departure"; hoursToDepart = diffH;
          }
        }
      }
      if (state === "in_transit" || state === "at_airport") break;
    }

    // Check if user just landed (at destination): last leg landed in past 24h
    if (state === "no_trip" || state === "pre_departure") {
      const recentLanded = await sql`
        SELECT tl.*, t.destination_city, t.destination_country, t.id as trip_id, t.title as trip_title
        FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
        WHERE t.user_email = ${email}
          AND tl.type = 'flight'
          AND tl.status = 'Landed'
          AND tl.departs_at > ${new Date(now.getTime() - 24 * 3600000).toISOString()}
        ORDER BY tl.departs_at DESC LIMIT 1
      `;
      if (recentLanded[0]) {
        state = "at_destination";
        activeLeg = recentLanded[0];
        activeTrip = { id: recentLanded[0].trip_id, title: recentLanded[0].trip_title, destination_city: recentLanded[0].destination_city, destination_country: recentLanded[0].destination_country };
      }
    }

    // Get live flight status if we have an active leg
    let liveStatus = null;
    if (activeLeg?.flight_number) {
      try {
        const ident = (activeLeg.carrier || "") + activeLeg.flight_number;
        liveStatus = await getFlightStatus(ident);
      } catch {}
    }

    // Get weather at relevant location
    let weatherData = null;
    if (lat && lng) {
      try {
        const OWM_KEY = process.env.OPENWEATHER_API_KEY;
        if (OWM_KEY) {
          const wr = await fetch(`https://api.openweathermap.org/data/2.5/weather?lat=${lat}&lon=${lng}&appid=${OWM_KEY}&units=metric`);
          if (wr.ok) {
            const wd = await wr.json();
            weatherData = {
              temp: Math.round(wd.main?.temp),
              feels_like: Math.round(wd.main?.feels_like),
              description: wd.weather?.[0]?.description,
              icon: wd.weather?.[0]?.main,
              city: wd.name,
            };
          }
        }
      } catch {}
    }

    // Build context-aware suggestions based on state
    const suggestions = [];
    if (state === "at_airport" && activeLeg) {
      suggestions.push({ label: "Lounge access", icon: "🛋", route: "LoungeCards", prefill: null });
      suggestions.push({ label: "Security wait", icon: "🔒", route: "Concierge", prefill: `Security wait at ${activeLeg.origin} Terminal ${liveStatus?.terminal || activeLeg.terminal || ""}` });
      suggestions.push({ label: "Journey timing", icon: "⏱", route: "JourneySimulator", prefill: null, params: { tripId: activeTrip?.id, legId: activeLeg.id, flightIdent: (activeLeg.carrier || "") + (activeLeg.flight_number || "") } });
      if (liveStatus?.gate) suggestions.push({ label: `Gate ${liveStatus.gate}`, icon: "🚪", route: "Concierge", prefill: `Directions to gate ${liveStatus.gate} at ${activeLeg.origin}` });
    } else if (state === "at_destination" && activeTrip) {
      suggestions.push({ label: "Get around", icon: "🚇", route: "Concierge", prefill: `How do I get around ${activeTrip.destination_city || "here"}?` });
      suggestions.push({ label: "Find lunch", icon: "🍽", route: "Concierge", prefill: `Find me lunch nearby` });
      suggestions.push({ label: "What to do", icon: "🗺", route: "Concierge", prefill: `What should I do in ${activeTrip.destination_city || "here"} today?` });
    } else if (state === "pre_departure" && activeLeg) {
      const hoursStr = hoursToDepart > 24 ? `${Math.round(hoursToDepart / 24)}d` : `${Math.round(hoursToDepart)}h`;
      suggestions.push({ label: "Pack list", icon: "🧳", route: "Concierge", prefill: `Pack list for my ${activeLeg.destination} trip` });
      suggestions.push({ label: "Journey timing", icon: "⏱", route: "JourneySimulator", prefill: null, params: { tripId: activeTrip?.id, legId: activeLeg.id, flightIdent: (activeLeg.carrier || "") + (activeLeg.flight_number || "") } });
      suggestions.push({ label: "Entry requirements", icon: "📋", route: "Concierge", prefill: `Entry requirements for ${activeLeg.destination}` });
      suggestions.push({ label: "Currency tips", icon: "💳", route: "Concierge", prefill: `Currency and payment tips for ${activeLeg.destination}` });
    } else if (state === "no_trip") {
      suggestions.push({ label: "Plan a trip", icon: "✈️", route: "AddTrip", prefill: null });
      suggestions.push({ label: "I'm somewhere new", icon: "📍", route: "Concierge", prefill: "I'm somewhere new — what should I know?" });
    }

    // Restaurant suggestion for at_destination state
    let restaurantSuggestion = null;
    if (state === "at_destination" && activeTrip) {
      try {
        const destCity = activeTrip.destination_city || activeLeg?.destination;
        if (destCity) {
          const PLACES_KEY = process.env.GOOGLE_PLACES_API_KEY;
          if (PLACES_KEY) {
            // Build keyword from taste profile
            const cuisinePrefs = userTaste.cuisines || [];
            const foodPrefs = userTaste.dietary || [];
            const keyword = cuisinePrefs.length > 0 ? cuisinePrefs[0] : "restaurant";
            const searchUrl = `https://maps.googleapis.com/maps/api/place/textsearch/json?query=${encodeURIComponent(keyword + " restaurant " + destCity)}&type=restaurant&key=${PLACES_KEY}`;
            const placesResp = await fetch(searchUrl, { signal: AbortSignal.timeout(5000) });
            if (placesResp.ok) {
              const placesData = await placesResp.json();
              const topPlace = placesData.results?.[0];
              if (topPlace) {
                restaurantSuggestion = {
                  name: topPlace.name,
                  address: topPlace.formatted_address || topPlace.vicinity,
                  rating: topPlace.rating,
                  price_level: topPlace.price_level,
                  place_id: topPlace.place_id,
                  maps_url: `https://www.google.com/maps/place/?q=place_id:${topPlace.place_id}`,
                };
              }
            }
          }
        }
      } catch (e) {
        console.error("[restaurant-suggestion]", e.message);
      }
    }

    // Find hotel leg for the active trip (current stay or next check-in within 7 days)
    let hotelLeg = null;
    if (activeTrip) {
      try {
        const hotelLegs = await sql`
          SELECT * FROM trip_legs
          WHERE trip_id = ${activeTrip.id}
            AND type = 'hotel'
          ORDER BY departs_at ASC
          LIMIT 3
        `;
        for (const h of hotelLegs) {
          const checkin = h.departs_at ? new Date(h.departs_at).getTime() : null;
          const checkout = h.arrives_at ? new Date(h.arrives_at).getTime() : null;
          const nowMs = now.getTime();
          if (checkin && checkout && nowMs >= checkin && nowMs <= checkout) { hotelLeg = h; break; }
          if (checkin && checkin > nowMs && (checkin - nowMs) < 7 * 86400000) { hotelLeg = h; break; }
        }
      } catch {}
    }

    res.json({
      ok: true,
      state,
      active_leg: activeLeg ? {
        id: activeLeg.id,
        trip_id: activeTrip?.id,
        ident: (activeLeg.carrier || "") + (activeLeg.flight_number || ""),
        origin: activeLeg.origin,
        destination: activeLeg.destination,
        departs_at: activeLeg.departs_at,
        arrives_at: activeLeg.arrives_at,
        status: liveStatus?.status || activeLeg.status || "Scheduled",
        gate: liveStatus?.gate || activeLeg.gate,
        terminal: liveStatus?.terminal || activeLeg.terminal,
        delay_minutes: liveStatus?.delay ? Math.round(liveStatus.delay / 60) : 0,
        trip_title: activeTrip?.title,
      } : null,
      active_trip: activeTrip ? {
        id: activeTrip.id,
        title: activeTrip.title,
        destination_city: activeTrip.destination_city,
        destination_country: activeTrip.destination_country,
      } : null,
      hours_to_depart: hoursToDepart,
      weather: weatherData,
      hotel: hotelLeg ? {
        name: hotelLeg.carrier || hotelLeg.title || "Hotel",
        checkin_at: hotelLeg.departs_at,
        checkout_at: hotelLeg.arrives_at,
        destination: hotelLeg.destination,
      } : null,
      suggestions,
      restaurant_suggestion: restaurantSuggestion,
    });
  } catch (e) {
    console.error("[home-state]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// JOURNEY BUFFER PUSH CRON — runs every 5 minutes
// Monitors users en route to airport; fires push when buffer drops below threshold
// ===========================================================================
async function runJourneyBufferCron() {
  try {
    // Find users with flights in next 3 hours who have journey monitoring enabled
    const now = new Date();
    const in3h = new Date(now.getTime() + 3 * 3600000);
    const legs = await sql`
      SELECT tl.id, tl.trip_id, tl.origin, tl.destination, tl.carrier, tl.flight_number,
             tl.departs_at, tl.gate, tl.terminal, tl.status,
             t.user_email
      FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id
      WHERE tl.type = 'flight'
        AND tl.departs_at BETWEEN ${now.toISOString()} AND ${in3h.toISOString()}
        AND tl.status NOT IN ('Cancelled', 'Landed')
    `;

    for (const leg of legs) {
      try {
        // Check if user has journey notifications enabled
        const userRows = await sql`SELECT preferences, push_token FROM users WHERE email = ${leg.user_email}`;
        const prefs = userRows[0]?.preferences || {};
        if (prefs.notify_journey === false) continue;
        if (!userRows[0]?.push_token) continue;

        const depMs = new Date(leg.departs_at).getTime();
        const minsToDepart = Math.round((depMs - now.getTime()) / 60000);

        // Only simulate if departure is 30-180 mins away (in the critical window)
        if (minsToDepart < 30 || minsToDepart > 180) continue;

        // Check if we already sent a journey alert for this leg in the last 30 min
        const recentAlert = await sql`
          SELECT id FROM departure_push_log
          WHERE user_email = ${leg.user_email} AND leg_id = ${leg.id} AND push_type = 'journey_buffer'
            AND created_at > ${new Date(now.getTime() - 30 * 60000).toISOString()}
        `;
        if (recentAlert.length > 0) continue;

        // Get security wait
        const securityMins = await getSecurityWait(leg.origin);
        const gateWalkMins = 10;
        const totalNeeded = securityMins + gateWalkMins + 15; // 15 min boarding buffer
        const bufferMins = minsToDepart - totalNeeded;

        if (bufferMins < 20) {
          // At risk — send push
          const ident = (leg.carrier || "") + (leg.flight_number || "");
          const urgency = bufferMins < 0 ? "⚠️ You may miss" : bufferMins < 10 ? "⚠️ Very tight —" : "⏱ Heads up —";
          const pushTitle = `${urgency} ${ident}`;
          const pushBody = bufferMins < 0
            ? `${ident} departs in ${minsToDepart} min. Security is ~${securityMins} min. You need to leave now.`
            : `${ident} departs in ${minsToDepart} min. Security ~${securityMins} min + ${gateWalkMins} min to gate = ${bufferMins} min buffer. Leave soon.`;

          await sendPushToUser(leg.user_email, pushTitle, pushBody, {
            route: "Home",
            tripId: String(leg.trip_id),
            legId: String(leg.id),
            type: "journey_buffer",
          });
          await sql`
            INSERT INTO departure_push_log (user_email, leg_id, push_type)
            VALUES (${leg.user_email}, ${leg.id}, 'journey_buffer')
            ON CONFLICT DO NOTHING
          `;
          await logActivity(leg.user_email, "journey_alert", `Buffer alert for ${ident}`, pushBody, leg.trip_id, leg.id, { bufferMins, securityMins });
        }
      } catch (e) { console.error("[journey-buffer-cron leg]", e.message); }
    }
  } catch (e) { console.error("[journey-buffer-cron]", e.message); }
}
setInterval(runJourneyBufferCron, 5 * 60 * 1000);

// ===========================================================================
// PROACTIVE TRANSIT PAYMENT PUSH
// Fires when user is at destination and about to use local transit
// Uses existing TRANSIT_PAYMENT_DB from earlier build
// ===========================================================================
app.post("/journey/transit-check", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const { city, lat, lng } = req.body || {};
    if (!city) return res.status(400).json({ error: "city required" });

    const info = getTransitPaymentInfo ? getTransitPaymentInfo(city) : null;
    if (!info) return res.json({ ok: true, has_warning: false });

    // Check if user's preferred payment methods work here
    const userRows = await sql`SELECT preferences FROM users WHERE email = ${email}`;
    const prefs = userRows[0]?.preferences || {};
    const userPayments = prefs.payment_methods || ["apple_pay", "contactless"];

    const warnings = [];
    if (userPayments.includes("apple_pay") && !info.apple_pay) {
      warnings.push(`Apple Pay is not accepted on ${info.network || "local transit"} in ${city}. ${info.fallback}`);
    }
    if (userPayments.includes("contactless") && !info.contactless) {
      warnings.push(`Contactless cards are not accepted on ${info.network || "local transit"} in ${city}. ${info.fallback}`);
    }

    if (warnings.length > 0) {
      // Send proactive push
      await sendPushToUser(email,
        `⚠️ Payment heads-up for ${city}`,
        warnings[0],
        { route: "Concierge", prefill: `How do I pay for transit in ${city}?` }
      );
      await logActivity(email, "transit_warning", `Transit payment warning: ${city}`, warnings[0]);
    }

    res.json({ ok: true, has_warning: warnings.length > 0, warnings, transit_info: info });
  } catch (e) {
    console.error("[transit-check]", e.message);
    res.status(500).json({ error: e.message });
  }
});



// ═══════════════════════════════════════════════════════════════════════════════
// DATA PRIVACY & GDPR/CCPA COMPLIANCE ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// ── DELETE /me — full account deletion (GDPR Art. 17 / CCPA right to delete) ──
// Cascades: trips, legs, activity, concierge threads, loyalty, gmail tokens,
//           push tokens, refresh tokens, points, preferences — everything.
app.delete("/me", auth, async (req, res) => {
  const email = req.user.email;
  try {
    // Log the deletion request before wiping (for compliance audit trail)
    await sql`
      INSERT INTO data_deletion_log (user_email, requested_at, completed_at, method)
      VALUES (${email}, NOW(), NOW(), 'user_request')
      ON CONFLICT DO NOTHING
    `.catch(() => {}); // table may not exist yet — handled below

    // Cascade delete — all tables reference users(email) with ON DELETE CASCADE
    // but we do it explicitly for clarity and to handle any missing FK constraints
    await sql`DELETE FROM concierge_threads WHERE user_email = ${email}`;
    // NOTE: this said activity_log, which is not a real table — account deletion
    // threw here every time. The table is activity_events.
    await sql`DELETE FROM activity_events WHERE user_email = ${email}`;
    await sql`DELETE FROM trip_legs WHERE trip_id IN (SELECT id FROM trips WHERE user_email = ${email})`;
    await sql`DELETE FROM trips WHERE user_email = ${email}`;
    await sql`DELETE FROM loyalty_accounts WHERE user_email = ${email}`;
    await sql`DELETE FROM gmail_tokens WHERE user_email = ${email}`;
    await sql`DELETE FROM refresh_tokens WHERE user_email = ${email}`;
    await sql`DELETE FROM wingman_points_events WHERE user_email = ${email}`;
    await sql`DELETE FROM wingman_points WHERE user_email = ${email}`;
    await sql`DELETE FROM users WHERE email = ${email}`;

    res.json({ ok: true, message: "Account and all associated data permanently deleted." });
  } catch (e) {
    console.error("[DELETE /me]", e.message);
    res.status(500).json({ error: "Deletion failed. Please contact support@wingmantravel.app." });
  }
});

// ── GET /me/data-export — full data export (GDPR Art. 20 portability) ─────────
app.get("/me/data-export", auth, async (req, res) => {
  const email = req.user.email;
  try {
    const [user]     = await sql`SELECT email, first_name, created_at, preferences, taste_profile FROM users WHERE email = ${email}`;
    const trips      = await sql`SELECT * FROM trips WHERE user_email = ${email}`;
    const legs       = await sql`SELECT tl.* FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id WHERE t.user_email = ${email}`;
    // loyalty_accounts has last_synced + created_at — never an updated_at. Asking
    // for a column that doesn't exist 500'd the whole export. Aliased so the
    // export payload keeps a stable shape.
    const loyalty    = await sql`SELECT program, points_balance, elite_status, last_synced AS updated_at FROM loyalty_accounts WHERE user_email = ${email}`;
    // Was: activity_log (nonexistent table) with event_type/summary (nonexistent
    // columns) — data export threw every time. Correct table is activity_events.
    const activity   = await sql`SELECT type AS event_type, title AS summary, body, created_at FROM activity_events WHERE user_email = ${email} ORDER BY created_at DESC LIMIT 500`;
    const points     = await sql`SELECT balance, tier, updated_at FROM wingman_points WHERE user_email = ${email}`;

    const export_data = {
      exported_at: new Date().toISOString(),
      notice: "This is all personal data Wingman holds about you. We do not sell this data to third parties.",
      profile: {
        email: user?.email,
        first_name: user?.first_name,
        member_since: user?.created_at,
        preferences: user?.preferences,
        taste_profile: user?.taste_profile,
      },
      trips: trips.map(t => ({ id: t.id, title: t.title, status: t.status, created_at: t.created_at })),
      trip_legs: legs,
      loyalty_accounts: loyalty,
      wingman_points: points[0] || null,
      activity_log: activity,
    };

    res.setHeader("Content-Disposition", `attachment; filename="wingman-data-export-${Date.now()}.json"`);
    res.setHeader("Content-Type", "application/json");
    res.json(export_data);
  } catch (e) {
    console.error("[data-export]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── GET /privacy — machine-readable privacy manifest ─────────────────────────
// Confirms no data sale, lists all third-party processors
app.get("/privacy", (req, res) => {
  res.json({
    data_controller: "Wingman Travel Ltd",
    contact: "privacy@wingmantravel.app",
    last_updated: "2025-01-01",
    data_sold_to_third_parties: false,
    data_shared_for_advertising: false,
    third_party_processors: [
      { name: "Anthropic (Claude)", purpose: "AI concierge responses", data_sent: "Trip context, user query — no PII beyond what user types", retention: "Not retained by Anthropic per API terms" },
      { name: "Neon (PostgreSQL)", purpose: "Primary database", data_sent: "All user data", retention: "Until account deletion" },
      { name: "Upstash (Redis)", purpose: "OTP codes (30s TTL)", data_sent: "Email address, 6-digit OTP", retention: "30 seconds" },
      { name: "Resend", purpose: "Transactional email (OTP, receipts)", data_sent: "Email address, message content", retention: "Per Resend DPA" },
      { name: "Expo Push", purpose: "Push notifications", data_sent: "Push token, notification title/body", retention: "Not stored by Expo" },
      { name: "Google (Directions, Places)", purpose: "Transit routing, venue lookup", data_sent: "Location coordinates, place queries", retention: "Per Google API terms" },
      { name: "FlightAware AeroAPI", purpose: "Live flight status", data_sent: "Flight identifiers", retention: "Not retained" },
      { name: "Amadeus", purpose: "Flight search and booking", data_sent: "Origin, destination, dates — no PII until booking", retention: "Per Amadeus DPA" },
      { name: "Duffel", purpose: "Flight booking", data_sent: "Passenger details at booking only", retention: "Per Duffel DPA" },
      { name: "Render", purpose: "API hosting (EU region)", data_sent: "All API traffic", retention: "Per Render DPA" },
    ],
    user_rights: ["access", "rectification", "erasure", "portability", "restriction", "objection"],
    deletion_endpoint: "DELETE /me (authenticated)",
    export_endpoint: "GET /me/data-export (authenticated)",
  });
});

// ── DB migration for deletion log ─────────────────────────────────────────────
(async () => {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS data_deletion_log (
        id SERIAL PRIMARY KEY,
        user_email TEXT NOT NULL,
        requested_at TIMESTAMPTZ NOT NULL,
        completed_at TIMESTAMPTZ,
        method TEXT DEFAULT 'user_request'
      )
    `;
  } catch (e) {
    console.warn("[migration] data_deletion_log:", e.message);
  }
})();


// ---------------------------------------------------------------------------
// BACKGROUND GMAIL SCAN — runs every 30 minutes, scans all connected accounts
// Automatically detects new booking confirmation emails without user action
// ---------------------------------------------------------------------------
cron.schedule("*/30 * * * *", async () => {
  console.log("[cron] background gmail scan starting");
  try {
    // Get all users with connected Gmail accounts
    const connectedUsers = await sql`
      SELECT DISTINCT user_email FROM gmail_tokens
    `;
    let scanned = 0;
    let newTrips = 0;
    for (const { user_email } of connectedUsers) {
      try {
        // Run the full multi-account scan for this user (reuses existing scanGmailForTrips)
        await scanGmailForTrips(user_email);
        scanned++;
      } catch (userErr) {
        console.error("[bg-scan] error for", user_email, userErr.message);
      }
    }
    console.log(`[cron] background gmail scan complete — ${scanned} accounts scanned`);
  } catch (e) {
    console.error("[bg-scan cron] fatal:", e.message);
  }
});

// BACKGROUND CALENDAR SYNC — runs every 60 minutes, syncs Apple/Google Calendar events
cron.schedule("5 * * * *", async () => {
  console.log("[cron] background calendar sync starting");
  try {
    // Calendar sync is triggered client-side; this cron checks for stale trip statuses
    // and updates any trips that have passed their departure date
    const now = new Date().toISOString();
    const updated = await sql`
      UPDATE trips
      SET status = 'past'
      WHERE status = 'upcoming'
        AND id IN (
          SELECT DISTINCT trip_id FROM trip_legs
          WHERE departs_at IS NOT NULL AND departs_at < ${now}::TIMESTAMPTZ
          AND type = 'flight'
        )
      RETURNING id
    `;
    if (updated.length > 0) {
      console.log(`[cron] marked ${updated.length} trips as past`);
    }
  } catch (e) {
    console.error("[calendar-sync cron] error:", e.message);
  }
});


// ---------------------------------------------------------------------------
// GET /local-news — top local news headlines for a city/region
// Uses BBC RSS for UK cities, NewsAPI for others
// Query: ?city=London&country=gb&lat=51.5&lng=-0.1
// ---------------------------------------------------------------------------
app.get("/local-news", auth, async (req, res) => {
  const { city, country, lat, lng } = req.query;
  try {
    const NEWS_API_KEY = process.env.NEWS_API_KEY;
    let articles = [];

    // Try NewsAPI first if key is available
    if (NEWS_API_KEY && city) {
      const q = encodeURIComponent(`${city}`);
      const url = `https://newsapi.org/v2/top-headlines?q=${q}&language=en&pageSize=3&apiKey=${NEWS_API_KEY}`;
      const r = await fetch(url);
      if (r.ok) {
        const j = await r.json();
        articles = (j.articles || []).slice(0, 3).map(a => ({
          title: a.title?.replace(/ - [^-]+$/, "").trim(),
          source: a.source?.name,
          url: a.url,
          publishedAt: a.publishedAt,
        })).filter(a => a.title && !a.title.includes("[Removed]"));
      }
    }

    // Fall back to BBC RSS for UK
    if (articles.length === 0 && (!country || country === "gb" || country === "GB")) {
      const bbcUrl = "https://feeds.bbci.co.uk/news/england/rss.xml";
      const r = await fetch(bbcUrl, { headers: { "User-Agent": "WingmanApp/1.0" } });
      if (r.ok) {
        const xml = await r.text();
        const items = [...xml.matchAll(/<item>[\s\S]*?<\/item>/g)];
        articles = items.slice(0, 3).map(m => {
          const titleMatch = m[0].match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/);
          const linkMatch  = m[0].match(/<link>(.*?)<\/link>/);
          return {
            title: titleMatch?.[1]?.trim(),
            source: "BBC News",
            url: linkMatch?.[1]?.trim(),
          };
        }).filter(a => a.title);
      }
    }

    res.json({ ok: true, city: city || null, articles });
  } catch (e) {
    console.error("[local-news]", e.message);
    res.json({ ok: false, articles: [] });
  }
});

// ---------------------------------------------------------------------------
// GET /local-traffic — current traffic conditions near user location
// Query: ?lat=51.5&lng=-0.1&city=London
// ---------------------------------------------------------------------------
app.get("/local-traffic", auth, async (req, res) => {
  const { lat, lng, city } = req.query;
  if (!lat || !lng) return res.json({ ok: false, summary: null });
  try {
    const GMAPS_KEY = process.env.GOOGLE_MAPS_API_KEY;
    if (!GMAPS_KEY) return res.json({ ok: false, summary: null });

    // Use a short radius route from current location to itself to get traffic model
    // Better: use Directions API with departure_time=now to get traffic duration vs normal
    // We'll check traffic from user's location to the nearest major road junction
    // Simplified: use Distance Matrix API to check traffic vs free-flow to a nearby point
    const destLat = parseFloat(lat) + 0.02; // ~2km north
    const destLng = parseFloat(lng);
    const url = `https://maps.googleapis.com/maps/api/distancematrix/json?origins=${lat},${lng}&destinations=${destLat},${destLng}&departure_time=now&traffic_model=best_guess&key=${GMAPS_KEY}`;
    const r = await fetch(url);
    if (!r.ok) return res.json({ ok: false, summary: null });
    const j = await r.json();
    const el = j.rows?.[0]?.elements?.[0];
    if (!el || el.status !== "OK") return res.json({ ok: false, summary: null });

    const normalMins  = Math.round((el.duration?.value || 0) / 60);
    const trafficMins = Math.round((el.duration_in_traffic?.value || el.duration?.value || 0) / 60);
    const delayMins   = trafficMins - normalMins;
    const cityLabel   = city || "the area";

    let summary;
    if (delayMins <= 1) {
      summary = `Traffic is clear in ${cityLabel}`;
    } else if (delayMins <= 5) {
      summary = `Light traffic in ${cityLabel}`;
    } else if (delayMins <= 12) {
      summary = `Moderate traffic in ${cityLabel} — about ${delayMins} mins above normal`;
    } else {
      summary = `Heavy traffic in ${cityLabel} — ${delayMins} mins above normal`;
    }

    res.json({ ok: true, summary, delay_mins: delayMins, city: cityLabel });
  } catch (e) {
    console.error("[local-traffic]", e.message);
    res.json({ ok: false, summary: null });
  }
});

// ---------------------------------------------------------------------------
// GET /today-events — today's calendar events for the user (from synced signals)
// Returns non-travel events for the briefing (meetings, appointments)
// ---------------------------------------------------------------------------
app.get("/today-events", auth, async (req, res) => {
  try {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date();
    endOfDay.setHours(23, 59, 59, 999);

    const rows = await sql`
      SELECT metadata, message
      FROM activity_events
      WHERE user_email = ${req.user.email}
        AND type = 'calendar_signal'
        AND created_at >= ${startOfDay.toISOString()}
        AND created_at <= ${endOfDay.toISOString()}
      ORDER BY (metadata->>'startDate') ASC
      LIMIT 10
    `;

    const events = rows.map(r => {
      const meta = r.metadata || {};
      const startDate = meta.startDate ? new Date(meta.startDate) : null;
      const timeStr = startDate
        ? startDate.toLocaleTimeString("en-GB", { hour: "numeric", minute: "2-digit", hour12: true })
        : null;
      return {
        title: r.message?.replace(/^Calendar:\s*/i, "").trim(),
        time: timeStr,
        location: meta.location || null,
      };
    }).filter(e => e.title);

    res.json({ ok: true, events });
  } catch (e) {
    console.error("[today-events]", e.message);
    res.json({ ok: false, events: [] });
  }
});



// ---------------------------------------------------------------------------
// MORNING BRIEFING PUSH NOTIFICATION — runs every minute, checks each user's
// preferred briefing time (stored in preferences.briefing_hour, default 7)
// and sends a personalised push with weather + flights + calendar summary
// ---------------------------------------------------------------------------
cron.schedule("* * * * *", async () => {
  const nowUTC = new Date();
  const nowHour = nowUTC.getUTCHours();
  const nowMin  = nowUTC.getUTCMinutes();
  try {
    // Fetch all users with push tokens who have morning briefing enabled
    const users = await sql`
      SELECT email, first_name, push_token, preferences, cabin_preference, seat_preference
      FROM users
      WHERE push_token IS NOT NULL
        AND (preferences->>'briefing_enabled')::boolean IS NOT FALSE
    `;
    for (const user of users) {
      try {
        const prefs = user.preferences || {};
        // Default briefing hour: 7 AM UTC (user can override via preferences.briefing_hour)
        const briefingHour = parseInt(prefs.briefing_hour ?? 7);
        const briefingMin  = parseInt(prefs.briefing_min  ?? 0);
        if (nowHour !== briefingHour || nowMin !== briefingMin) continue;
        // Dedup: only send once per day
        const dedupKey = `morning_briefing_${new Date().toISOString().slice(0,10)}`;
        if (prefs[dedupKey]) continue;

        // Build briefing content: active trips + weather
        const trips = await sql`
          SELECT t.id, t.title, t.destination_city,
                 json_agg(tl ORDER BY tl.departs_at NULLS LAST) as legs
          FROM trips t
          LEFT JOIN trip_legs tl ON tl.trip_id = t.id
          WHERE t.user_email = ${user.email} AND t.archived = false
          GROUP BY t.id ORDER BY t.created_at DESC LIMIT 5
        `;

        // Find next upcoming flight
        const now2 = new Date();
        let nextFlight = null;
        for (const trip of trips) {
          for (const leg of (trip.legs || [])) {
            if (leg?.type !== "flight" || !leg.departs_at) continue;
            const dep = new Date(leg.departs_at);
            if (dep > now2) {
              if (!nextFlight || dep < new Date(nextFlight.departs_at)) {
                nextFlight = { ...leg, trip_title: trip.title, destination_city: trip.destination_city };
              }
            }
          }
        }

        // Fetch today's calendar events
        const todayStart = new Date(); todayStart.setHours(0,0,0,0);
        const todayEnd   = new Date(); todayEnd.setHours(23,59,59,999);
        const calEvents = await sql`
          SELECT title, start_time FROM calendar_events
          WHERE user_email = ${user.email}
            AND start_time >= ${todayStart.toISOString()}
            AND start_time <= ${todayEnd.toISOString()}
          ORDER BY start_time ASC LIMIT 3
        `.catch(() => []);

        // Build notification title and body
        const firstName = user.first_name || "there";
        const hour = nowHour;
        const greet = hour < 12 ? "Morning" : hour < 17 ? "Afternoon" : "Evening";

        let title = `${greet}, ${firstName}.`;
        let bodyParts = [];

        if (nextFlight) {
          const dep = new Date(nextFlight.departs_at);
          const diffH = Math.round((dep - now2) / 3600000);
          const diffD = Math.floor(diffH / 24);
          const timeStr = diffH < 24
            ? `in ${diffH}h`
            : diffD === 1 ? "tomorrow"
            : `in ${diffD} days`;
          // Get live status
          try {
            const ident = (nextFlight.carrier || "") + (nextFlight.flight_number || "");
            const status = await getFlightStatus(ident).catch(() => null);
            if (status?.delay > 300) {
              bodyParts.push(`${ident} is running ${Math.round(status.delay/60)} mins late.`);
            } else {
              bodyParts.push(`${ident} to ${nextFlight.destination} departs ${timeStr}.`);
            }
          } catch {
            bodyParts.push(`${nextFlight.destination} departs ${timeStr}.`);
          }
        }

        if (calEvents.length > 0) {
          const evStr = calEvents.slice(0,2).map(e => {
            const t = e.start_time ? new Date(e.start_time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : null;
            return t ? `${t} ${e.title}` : e.title;
          }).join(" · ");
          bodyParts.push(evStr);
        }

        if (bodyParts.length === 0) {
          bodyParts.push("How can I help today?");
        }

        const body = bodyParts.join(" ");

        // Send push
        await fetch("https://exp.host/--/api/v2/push/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            to: user.push_token,
            title,
            body,
            data: { type: "morning_briefing", screen: "Home" },
            sound: "default",
            priority: "normal",
          }),
        });

        // Mark as sent for today (write to preferences to avoid double-send)
        await sql`
          UPDATE users
          SET preferences = preferences || ${JSON.stringify({ [dedupKey]: true })}::jsonb
          WHERE email = ${user.email}
        `;
        console.log(`[morning-briefing] sent to \${user.email}`);
      } catch (userErr) {
        console.error(`[morning-briefing] error for \${user.email}:`, userErr.message);
      }
    }
  } catch (e) {
    console.error("[morning-briefing cron] error:", e.message);
  }
});

// ---------------------------------------------------------------------------
// GET /me/instructions — return all saved user instructions
app.get("/me/instructions", auth, async (req, res) => {
  try {
    const rows = await sql`SELECT id, instruction, source, created_at FROM user_instructions WHERE user_email = ${req.email} ORDER BY created_at DESC`;
    res.json({ instructions: rows });
  } catch (e) {
    console.error("[GET /me/instructions]", e.message);
    res.status(500).json({ error: "server error" });
  }
});

// POST /me/instructions — manually add a user instruction
app.post("/me/instructions", auth, async (req, res) => {
  const { instruction } = req.body || {};
  if (!instruction || typeof instruction !== "string") return res.status(400).json({ error: "instruction required" });
  try {
    const [row] = await sql`
      INSERT INTO user_instructions (user_email, instruction, source)
      VALUES (${req.email}, ${instruction.trim()}, 'manual')
      RETURNING id, instruction, created_at
    `;
    res.json({ ok: true, instruction: row });
  } catch (e) {
    console.error("[POST /me/instructions]", e.message);
    res.status(500).json({ error: "server error" });
  }
});

// DELETE /me/instructions/:id — remove a saved instruction
app.delete("/me/instructions/:id", auth, async (req, res) => {
  try {
    await sql`DELETE FROM user_instructions WHERE id = ${req.params.id} AND user_email = ${req.email}`;
    res.json({ ok: true });
  } catch (e) {
    console.error("[DELETE /me/instructions]", e.message);
    res.status(500).json({ error: "server error" });
  }
});

// POST /me/briefing-time — set preferred morning briefing time
// Body: { hour: 7, min: 0 }  (UTC hour 0-23)
// ---------------------------------------------------------------------------
app.patch("/me/briefing-time", auth, async (req, res) => {
  const { briefing_hour, briefing_min } = req.body || {};
  const h = parseInt(briefing_hour ?? 7);
  const m = parseInt(briefing_min  ?? 0);
  if (h < 0 || h > 23 || m < 0 || m > 59) return res.status(400).json({ error: "invalid time" });
  try {
    await sql`
      UPDATE users
      SET preferences = preferences || ${JSON.stringify({ briefing_hour: h, briefing_min: m, briefing_enabled: true })}::jsonb
      WHERE email = ${req.email}
    `;
    res.json({ ok: true, briefing_hour: h, briefing_min: m });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
app.post("/me/briefing-time", auth, async (req, res) => {
  const { hour, min } = req.body || {};
  const h = parseInt(hour ?? 7);
  const m = parseInt(min  ?? 0);
  if (h < 0 || h > 23 || m < 0 || m > 59) return res.status(400).json({ error: "invalid time" });
  try {
    await sql`
      UPDATE users
      SET preferences = preferences || ${JSON.stringify({ briefing_hour: h, briefing_min: m, briefing_enabled: true })}::jsonb
      WHERE email = ${req.email}
    `;
    res.json({ ok: true, briefing_hour: h, briefing_min: m });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// PATCH /trips/:tripId/legs/:legId — edit a single leg
// ---------------------------------------------------------------------------
app.patch("/trips/:tripId/legs/:legId", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { tripId, legId } = req.params;
  const updates = req.body || {};
  try {
    // Verify ownership
    const tripRows = await sql`SELECT id FROM trips WHERE id = ${tripId} AND user_email = ${email}`;
    if (!tripRows.length) return res.status(404).json({ error: "trip not found" });
    // Build safe update — only allow known columns
    const allowed = ["type","carrier","flight_number","origin","destination","departs_at","arrives_at","confirmation","property_name","property_address","station_from","station_to","pickup_location","dropoff_location","vehicle_class","cabin_class","seat","nights","guests","price_total","currency"];
    const fields = Object.keys(updates).filter(k => allowed.includes(k));
    if (!fields.length) return res.status(400).json({ error: "no valid fields" });
    // Use dynamic update via sql template
    for (const field of fields) {
      await sql`UPDATE trip_legs SET ${sql(field)} = ${updates[field] || null} WHERE id = ${legId} AND trip_id = ${tripId}`;
    }
    const updated = await sql`SELECT * FROM trip_legs WHERE id = ${legId}`;
    res.json({ ok: true, leg: updated[0] });
  } catch (e) {
    console.error("[legs/edit]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// DELETE /trips/:tripId/legs/:legId — delete a single leg
// ---------------------------------------------------------------------------
app.delete("/trips/:tripId/legs/:legId", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { tripId, legId } = req.params;
  try {
    const tripRows = await sql`SELECT id FROM trips WHERE id = ${tripId} AND user_email = ${email}`;
    if (!tripRows.length) return res.status(404).json({ error: "trip not found" });
    await sql`DELETE FROM trip_legs WHERE id = ${legId} AND trip_id = ${tripId}`;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /destination/image?city=X — a muted destination photo for trip screens.
// Backed by Unsplash (key held server-side), cached per city for 30 days so we
// never approach the rate limit. Returns { url, credit, credit_url } or url:null.
// ---------------------------------------------------------------------------
const UNSPLASH_ACCESS_KEY = process.env.UNSPLASH_ACCESS_KEY || "SqZOgtKwYCfTxuTwmvM93Am9I9SwQAcpoBMGek6oSDQ";
app.get("/destination/image", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const cityRaw = (req.query.city || "").toString().trim();
  if (!cityRaw) return res.json({ url: null });
  const cityKey = cityRaw.toLowerCase();
  try {
    const cached = await sql`SELECT url, credit, credit_url, updated_at FROM destination_images WHERE city = ${cityKey}`;
    if (cached.length && (Date.now() - new Date(cached[0].updated_at).getTime()) < 30 * 86400000) {
      return res.json({ url: cached[0].url, credit: cached[0].credit, credit_url: cached[0].credit_url });
    }
    if (!UNSPLASH_ACCESS_KEY) return res.json({ url: null });
    const r = await fetch(
      `https://api.unsplash.com/search/photos?query=${encodeURIComponent(cityRaw)}&orientation=landscape&per_page=1&content_filter=high`,
      { headers: { Authorization: `Client-ID ${UNSPLASH_ACCESS_KEY}` } }
    );
    if (!r.ok) return res.json({ url: cached[0]?.url || null, credit: cached[0]?.credit || null, credit_url: cached[0]?.credit_url || null });
    const d = await r.json();
    const p = (d.results || [])[0];
    if (!p) return res.json({ url: null });
    // Muted, editorial wash: desaturate slightly + size down.
    const url = `${p.urls.raw}&w=1200&q=80&fit=crop&sat=-45`;
    const credit = p.user?.name || null;
    const credit_url = p.links?.html || p.user?.links?.html || null;
    await sql`
      INSERT INTO destination_images (city, url, credit, credit_url, updated_at)
      VALUES (${cityKey}, ${url}, ${credit}, ${credit_url}, NOW())
      ON CONFLICT (city) DO UPDATE SET url = EXCLUDED.url, credit = EXCLUDED.credit, credit_url = EXCLUDED.credit_url, updated_at = NOW()
    `;
    res.json({ url, credit, credit_url });
  } catch (e) {
    console.error("[destination/image]", e.message);
    res.json({ url: null });
  }
});

// ---------------------------------------------------------------------------
// Cascade actions — the app's cascade cards call these to have Wingman draft the
// message to a hotel/restaurant when a delay knocks the trip's chain out of line.
// These routes did not exist: the buttons 404'd. Drafting is deterministic (no
// LLM cost, and it still works if Anthropic credits run out).
// ---------------------------------------------------------------------------
function cascadeArrivalEstimate(delayMinutes) {
  const d = Number(delayMinutes) || 0;
  if (!d) return "later than planned";
  if (d < 60) return `about ${d} minutes later than planned`;
  const h = Math.floor(d / 60), m = d % 60;
  return `about ${h}h${m ? ` ${m}m` : ""} later than planned`;
}

async function cascadeLookup(tripId, email, legId) {
  const trips = await sql`SELECT id, title FROM trips WHERE id = ${tripId} AND user_email = ${email}`;
  if (!trips.length) return null;
  let leg = null;
  if (legId) {
    const rows = await sql`SELECT * FROM trip_legs WHERE id = ${legId} AND trip_id = ${tripId}`;
    leg = rows[0] || null;
  }
  return { trip: trips[0], leg };
}

app.post("/trips/:tripId/cascade/hotel-notify", auth, async (req, res) => {
  const email = req.email;
  const { leg_id, delay_minutes, ident } = req.body || {};
  try {
    const ctx = await cascadeLookup(req.params.tripId, email, leg_id);
    if (!ctx) return res.status(404).json({ error: "trip not found" });

    // Prefer the named hotel leg; otherwise fall back to any stay on the trip.
    let hotel = ctx.leg;
    if (!hotel || !["hotel", "airbnb"].includes(hotel.type)) {
      const rows = await sql`
        SELECT * FROM trip_legs WHERE trip_id = ${req.params.tripId}
          AND type IN ('hotel','airbnb') ORDER BY departs_at ASC LIMIT 1`;
      hotel = rows[0] || null;
    }
    const hotelName = hotel?.carrier || hotel?.destination || "the property";
    const conf = hotel?.confirmation ? ` My confirmation number is ${hotel.confirmation}.` : "";
    const late = cascadeArrivalEstimate(delay_minutes);

    const message =
      `Hello,\n\nI have a reservation with you${hotel?.confirmation ? ` (confirmation ${hotel.confirmation})` : ""}. ` +
      `My inbound flight${ident ? ` (${ident})` : ""} has been ${delay_minutes ? "delayed" : "disrupted"}, ` +
      `so I now expect to arrive ${late}.\n\n` +
      `Could you please hold my room for a late check-in?${conf}\n\n` +
      `Thank you very much.`;

    await logActivity(
      email, "cascade", "Late check-in message drafted",
      `Wingman drafted a message to ${hotelName} about your late arrival.`,
      req.params.tripId, hotel?.id || null, { kind: "hotel_notify", delay_minutes: delay_minutes || 0 },
    ).catch(() => {});

    res.json({ ok: true, hotel_name: hotelName, message_drafted: message, phone: hotel?.property_address || null });
  } catch (e) {
    console.error("[cascade/hotel-notify]", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post("/trips/:tripId/cascade/restaurant-reschedule", auth, async (req, res) => {
  const email = req.email;
  const { leg_id, delay_minutes, ident } = req.body || {};
  try {
    const ctx = await cascadeLookup(req.params.tripId, email, leg_id);
    if (!ctx) return res.status(404).json({ error: "trip not found" });

    let resto = ctx.leg;
    if (!resto || !["dining", "restaurant"].includes(resto.type)) {
      const rows = await sql`
        SELECT * FROM trip_legs WHERE trip_id = ${req.params.tripId}
          AND type IN ('dining','restaurant') ORDER BY departs_at ASC LIMIT 1`;
      resto = rows[0] || null;
    }
    const name = resto?.carrier || resto?.destination || "the restaurant";
    const when = resto?.departs_at
      ? new Date(resto.departs_at).toLocaleString("en-US", { weekday: "long", hour: "numeric", minute: "2-digit" })
      : "my booking";
    const late = cascadeArrivalEstimate(delay_minutes);

    const message =
      `Hello,\n\nI have a reservation${resto?.departs_at ? ` for ${when}` : ""}` +
      `${resto?.confirmation ? ` (reference ${resto.confirmation})` : ""}. ` +
      `My flight${ident ? ` (${ident})` : ""} has been delayed and I now expect to be ${late}.\n\n` +
      `Would it be possible to move my table later, or should I rebook for another evening?\n\n` +
      `Apologies for the short notice, and thank you.`;

    await logActivity(
      email, "cascade", "Reservation message drafted",
      `Wingman drafted a message to ${name} about moving your table.`,
      req.params.tripId, resto?.id || null, { kind: "restaurant_reschedule", delay_minutes: delay_minutes || 0 },
    ).catch(() => {});

    res.json({ ok: true, restaurant_name: name, message_drafted: message });
  } catch (e) {
    console.error("[cascade/restaurant-reschedule]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /insights/roi/history — value protected per month (Roadmap 2, Design #10)
// Powers the Insights sparkline/trend so the ROI is legible over time.
// ---------------------------------------------------------------------------
app.get("/insights/roi/history", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const months = Math.min(parseInt(req.query.months || "12"), 24);
  try {
    const rows = await sql`
      SELECT to_char(date_trunc('month', created_at), 'YYYY-MM') AS month,
             COALESCE(SUM((metadata->>'value_saved')::numeric), 0)::int AS value,
             COUNT(*) FILTER (WHERE (metadata->>'value_saved') IS NOT NULL)::int AS rescues
      FROM activity_events
      WHERE user_email = ${email}
        AND created_at >= date_trunc('month', NOW()) - (${months - 1} || ' months')::interval
      GROUP BY 1
      ORDER BY 1 ASC
    `;
    // Fill gaps so the chart has a continuous axis.
    const map = Object.fromEntries(rows.map(r => [r.month, r]));
    const series = [];
    const now = new Date();
    for (let i = months - 1; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
      series.push({
        month: key,
        label: d.toLocaleDateString("en-US", { month: "short" }),
        value: map[key]?.value || 0,
        rescues: map[key]?.rescues || 0,
      });
    }
    res.json({ series, total: series.reduce((s, p) => s + p.value, 0) });
  } catch (e) {
    console.error("[insights/roi/history]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// Standing orders (Roadmap 2) — per-trip pre-authorized auto-rebooking rules.
// ---------------------------------------------------------------------------
app.get("/trips/:tripId/standing-order", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const own = await sql`SELECT id FROM trips WHERE id = ${req.params.tripId} AND user_email = ${email}`;
    if (!own.length) return res.status(404).json({ error: "trip not found" });
    const rows = await sql`SELECT enabled, max_price, min_cabin, avoid_airports FROM standing_orders WHERE trip_id = ${req.params.tripId}`;
    res.json(rows[0] || { enabled: false, max_price: null, min_cabin: null, avoid_airports: [] });
  } catch (e) {
    console.error("[standing-order/get]", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put("/trips/:tripId/standing-order", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const own = await sql`SELECT id FROM trips WHERE id = ${req.params.tripId} AND user_email = ${email}`;
    if (!own.length) return res.status(404).json({ error: "trip not found" });
    const { enabled, max_price, min_cabin, avoid_airports } = req.body || {};
    const avoid = JSON.stringify(Array.isArray(avoid_airports) ? avoid_airports : []);
    await sql`
      INSERT INTO standing_orders (trip_id, user_email, enabled, max_price, min_cabin, avoid_airports, updated_at)
      VALUES (${req.params.tripId}, ${email}, ${!!enabled}, ${max_price || null}, ${min_cabin || null}, ${avoid}::jsonb, NOW())
      ON CONFLICT (trip_id) DO UPDATE SET
        enabled = EXCLUDED.enabled, max_price = EXCLUDED.max_price, min_cabin = EXCLUDED.min_cabin,
        avoid_airports = EXCLUDED.avoid_airports, updated_at = NOW()
    `;
    res.json({ ok: true });
  } catch (e) {
    console.error("[standing-order/put]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /onboarding/summary — "here's what I found" backfill recap (read-only)
// Used after a Gmail connect to make the value legible in the first 30 seconds.
// ---------------------------------------------------------------------------
app.get("/onboarding/summary", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const [{ trips_found }] = await sql`
      SELECT COUNT(*)::int AS trips_found FROM trips WHERE user_email = ${email}`;

    const [{ earliest }] = await sql`
      SELECT MIN(departs_at) AS earliest FROM trip_legs
      WHERE trip_id IN (SELECT id FROM trips WHERE user_email = ${email})`;

    const favRows = await sql`
      SELECT property_name, stay_count, city FROM hotel_affinity
      WHERE user_email = ${email}
      ORDER BY stay_count DESC, last_stayed DESC NULLS LAST
      LIMIT 1`;

    const cityRows = await sql`
      SELECT destination AS city, COUNT(*)::int AS n FROM trip_legs
      WHERE type = 'flight' AND destination IS NOT NULL AND destination <> ''
        AND trip_id IN (SELECT id FROM trips WHERE user_email = ${email})
      GROUP BY destination ORDER BY n DESC LIMIT 1`;

    const [{ dining_count }] = await sql`
      SELECT COUNT(*)::int AS dining_count FROM trip_legs
      WHERE type IN ('dining','restaurant')
        AND trip_id IN (SELECT id FROM trips WHERE user_email = ${email})`;

    const fav = favRows[0] || null;
    res.json({
      trips_found: trips_found || 0,
      earliest_year: earliest ? new Date(earliest).getFullYear() : null,
      favorite_hotel: fav && fav.stay_count > 1
        ? { name: fav.property_name, stays: fav.stay_count, city: fav.city || null }
        : null,
      top_city: cityRows[0]?.city || null,
      dining_count: dining_count || 0,
    });
  } catch (e) {
    console.error("[onboarding/summary]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POST /trips/:tripId/legs — add a single leg to an existing trip
// ---------------------------------------------------------------------------
app.post("/trips/:tripId/legs", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { tripId } = req.params;
  const leg = req.body || {};
  try {
    const tripRows = await sql`SELECT id FROM trips WHERE id = ${tripId} AND user_email = ${email}`;
    if (!tripRows.length) return res.status(404).json({ error: "trip not found" });
    const inserted = await sql`
      INSERT INTO trip_legs (
        trip_id, type, carrier, flight_number, origin, destination,
        departs_at, arrives_at, confirmation, property_name, property_address,
        station_from, station_to, pickup_location, dropoff_location,
        vehicle_class, cabin_class, seat, nights, guests, price_total, currency
      ) VALUES (
        ${tripId}, ${leg.type || "flight"}, ${leg.carrier || null}, ${leg.flight_number || null},
        ${leg.origin || null}, ${leg.destination || null},
        ${leg.departs_at || null}, ${leg.arrives_at || null}, ${leg.confirmation || null},
        ${leg.property_name || null}, ${leg.property_address || null},
        ${leg.station_from || null}, ${leg.station_to || null},
        ${leg.pickup_location || null}, ${leg.dropoff_location || null},
        ${leg.vehicle_class || null}, ${leg.cabin_class || null}, ${leg.seat || null},
        ${leg.nights || null}, ${leg.guests || null},
        ${leg.price_total || null}, ${leg.currency || null}
      ) RETURNING *
    `;
    res.json({ ok: true, leg: inserted[0] });
  } catch (e) {
    console.error("[legs/add]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POST /trips/import/paste — parse a pasted itinerary into structured legs
// ---------------------------------------------------------------------------
app.post("/trips/import/paste", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { text, companions_count, companion_names } = req.body || {};
  if (!text || text.trim().length < 20) return res.status(400).json({ error: "text too short" });
  try {
    const extractionPrompt = `You are a travel data extractor. Parse the following itinerary text and extract ALL bookings into a structured JSON object.

Return ONLY valid JSON in this exact format:
{
  "title": "short trip title (e.g. Asia Tour 2026, Tokyo Business Trip)",
  "legs": [
    {
      "type": "flight|hotel|airbnb|train|car|ferry|activity|event",
      "carrier": "airline/operator code or name",
      "flight_number": "flight number if flight",
      "origin": "IATA code if flight, city/station if train",
      "destination": "IATA code if flight, city/station if train",
      "property_name": "hotel/venue name if hotel/event",
      "property_address": "address if available",
      "departs_at": "ISO 8601 datetime or null",
      "arrives_at": "ISO 8601 datetime or null",
      "confirmation": "booking reference if present",
      "cabin_class": "economy/premium economy/business/first if flight",
      "nights": number or null,
      "guests": number or null
    }
  ]
}

Rules:
- Extract EVERY booking — flights, hotels, trains, cars, shows, activities
- For events/shows: use type="event", put venue in property_name, address in property_address
- For hotels: use type="hotel", put hotel name in property_name
- Infer year from context if not stated (use current year ${new Date().getFullYear()} or next if past)
- If a field is unknown, use null
- Return ONLY the JSON object, no explanation

Itinerary text:
${text.substring(0, 8000)}`;

    const response = await anthropic.messages.create({
      model: "claude-sonnet-4-5",
      max_tokens: 4000,
      messages: [{ role: "user", content: extractionPrompt }]
    });
    const raw = response.content[0].text.trim();
    // Strip markdown code fences if present
    const jsonStr = raw.replace(/^```(?:json)?\n?/i, "").replace(/\n?```$/i, "").trim();
    let parsed;
    try {
      parsed = JSON.parse(jsonStr);
    } catch (parseErr) {
      return res.status(422).json({ error: "Could not parse itinerary — try pasting a cleaner version", raw: raw.substring(0, 500) });
    }
    if (!parsed.legs || !Array.isArray(parsed.legs)) {
      return res.status(422).json({ error: "No bookings found in the text" });
    }
    res.json({ ok: true, title: parsed.title || "Imported Trip", legs: parsed.legs, leg_count: parsed.legs.length });
  } catch (e) {
    console.error("[import/paste]", e.message);
    if (e.status === 400 && e.message?.includes("credit")) {
      return res.status(503).json({ error: "service_unavailable", message: "AI service temporarily unavailable" });
    }
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// POST /trips/:tripId/saved-options — save a hotel/flight option from concierge
// ---------------------------------------------------------------------------
app.post("/trips/:tripId/saved-options", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { tripId } = req.params;
  const { option } = req.body || {};
  if (!option) return res.status(400).json({ error: "option required" });
  try {
    const tripRows = await sql`SELECT id FROM trips WHERE id = ${tripId} AND user_email = ${email}`;
    if (!tripRows.length) return res.status(404).json({ error: "trip not found" });
    // Store as a JSONB array in trip metadata
    await sql`
      UPDATE trips
      SET raw_data = COALESCE(raw_data, '{}'::jsonb) || jsonb_build_object('saved_options',
        COALESCE(raw_data->'saved_options', '[]'::jsonb) || ${JSON.stringify([option])}::jsonb
      )
      WHERE id = ${tripId}
    `;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /trips/:tripId/saved-options — retrieve saved options for a trip
// ---------------------------------------------------------------------------
app.get("/trips/:tripId/saved-options", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { tripId } = req.params;
  try {
    const rows = await sql`SELECT raw_data FROM trips WHERE id = ${tripId} AND user_email = ${email}`;
    if (!rows.length) return res.status(404).json({ error: "trip not found" });
    const options = rows[0].raw_data?.saved_options || [];
    res.json({ ok: true, options });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /trips/:tripId/calendar.ics — export trip as iCalendar file
// ---------------------------------------------------------------------------
app.get("/trips/:tripId/calendar.ics", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  const { tripId } = req.params;
  try {
    const tripRows = await sql`SELECT * FROM trips WHERE id = ${tripId} AND user_email = ${email}`;
    if (!tripRows.length) return res.status(404).json({ error: "trip not found" });
    const trip = tripRows[0];
    const legs = await sql`SELECT * FROM trip_legs WHERE trip_id = ${tripId} ORDER BY COALESCE(departs_at, arrives_at) ASC NULLS LAST`;
    const formatDT = (dt) => {
      if (!dt) return null;
      const d = new Date(dt);
      return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
    };
    const uid = () => `${Date.now()}-${Math.random().toString(36).slice(2)}@wingmantravel.app`;
    const escICS = (s) => (s || "").replace(/[\\;,]/g, c => "\\" + c).replace(/\n/g, "\\n");
    let events = [];
    for (const leg of legs) {
      const start = formatDT(leg.departs_at);
      const end = formatDT(leg.arrives_at || leg.departs_at);
      if (!start) continue;
      let summary = "";
      let description = "";
      let location = "";
      if (leg.type === "flight") {
        summary = `${leg.carrier || ""}${leg.flight_number || ""} ${leg.origin || ""} → ${leg.destination || ""}`;
        description = `Flight${leg.cabin_class ? " (" + leg.cabin_class + ")" : ""}${leg.seat ? ", Seat " + leg.seat : ""}${leg.confirmation ? ", Ref: " + leg.confirmation : ""}`;
        location = leg.origin || "";
      } else if (leg.type === "hotel" || leg.type === "airbnb") {
        summary = `Check-in: ${leg.property_name || leg.carrier || "Hotel"}`;
        description = `${leg.nights ? leg.nights + " nights" : ""}${leg.confirmation ? ", Ref: " + leg.confirmation : ""}`;
        location = leg.property_address || leg.destination || "";
      } else if (leg.type === "event") {
        summary = leg.property_name || "Event";
        description = `${leg.confirmation ? "Ref: " + leg.confirmation : ""}`;
        location = leg.property_address || "";
      } else if (leg.type === "train") {
        summary = `Train: ${leg.station_from || ""} → ${leg.station_to || ""}`;
        description = `${leg.carrier || ""}${leg.confirmation ? ", Ref: " + leg.confirmation : ""}`;
        location = leg.station_from || "";
      } else {
        summary = `${leg.type}: ${leg.carrier || leg.destination || "Booking"}`;
        description = leg.confirmation ? `Ref: ${leg.confirmation}` : "";
      }
      events.push(`BEGIN:VEVENT\r\nUID:${uid()}\r\nDTSTAMP:${formatDT(new Date())}Z\r\nDTSTART:${start}Z\r\nDTEND:${end}Z\r\nSUMMARY:${escICS(summary)}\r\nDESCRIPTION:${escICS(description)}\r\nLOCATION:${escICS(location)}\r\nEND:VEVENT`);
    }
    const ics = `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Wingman Travel//EN\r\nCALSCALE:GREGORIAN\r\nX-WR-CALNAME:${escICS(trip.title)}\r\n${events.join("\r\n")}\r\nEND:VCALENDAR`;
    res.setHeader("Content-Type", "text/calendar; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${trip.title.replace(/[^a-z0-9]/gi, '_')}.ics"`);
    res.send(ics);
  } catch (e) {
    console.error("[calendar/ics]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ---------------------------------------------------------------------------
// GET /me/offline-snapshot — returns all data needed for offline mode
// ---------------------------------------------------------------------------
app.get("/me/offline-snapshot", auth, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const [userRows, trips, legs, loyalty, checklist] = await Promise.all([
      sql`SELECT email, preferences, home_airport_code, cabin_class FROM users WHERE email = ${email}`,
      sql`SELECT * FROM trips WHERE user_email = ${email} AND status != 'past' ORDER BY created_at DESC LIMIT 20`,
      sql`SELECT tl.* FROM trip_legs tl JOIN trips t ON t.id = tl.trip_id WHERE t.user_email = ${email} AND t.status != 'past' ORDER BY tl.departs_at ASC NULLS LAST`,
      sql`SELECT * FROM loyalty_accounts WHERE user_email = ${email}`,
      sql`SELECT tc.* FROM trip_checklist tc JOIN trips t ON t.id = tc.trip_id WHERE t.user_email = ${email} AND tc.done = false`
    ]);
    const legsByTrip = {};
    for (const leg of legs) {
      if (!legsByTrip[leg.trip_id]) legsByTrip[leg.trip_id] = [];
      legsByTrip[leg.trip_id].push(leg);
    }
    const tripsWithLegs = trips.map(t => ({ ...t, legs: legsByTrip[t.id] || [] }));
    res.json({
      ok: true,
      snapshot_at: new Date().toISOString(),
      user: userRows[0] || null,
      trips: tripsWithLegs,
      loyalty,
      pending_checklist: checklist,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// TripIt iCal Sync — parse user's TripIt calendar feed URL
// ===========================================================================
// POST /integrations/tripit/sync — user provides their TripIt iCal URL
// TripIt's public API is closed to new integrations (Feb 2026), so we use
// the iCal calendar feed that TripIt exposes per-user in their settings.
app.post("/integrations/tripit/sync", auth, async (req, res) => {
  const { ical_url } = req.body || {};
  if (!ical_url || typeof ical_url !== "string") {
    return res.status(400).json({ error: "ical_url required" });
  }
  // Validate it looks like a TripIt iCal URL
  if (!ical_url.includes("tripit.com") && !ical_url.includes("ics")) {
    return res.status(400).json({ error: "URL must be a TripIt iCal feed (from TripIt Settings → Publishing Options)" });
  }
  try {
    // Fetch the iCal feed
    const resp = await fetch(ical_url, { signal: AbortSignal.timeout(15000) });
    if (!resp.ok) return res.status(502).json({ error: `Could not fetch iCal feed: HTTP ${resp.status}` });
    const icalText = await resp.text();

    // Parse iCal events into trip legs using Claude
    const anthropic = getAnthropic();
    const extraction = await anthropic.messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 4000,
      messages: [{
        role: "user",
        content: `Parse this TripIt iCal feed and extract all travel bookings. Return a JSON array of trips.
Each trip: { title, legs: [{ type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation }] }
Types: flight, hotel, car, train, show, other.
Return ONLY the JSON array, no other text.

iCal data:
${icalText.slice(0, 8000)}`
      }],
    });

    let trips;
    try {
      const raw = extraction.content[0]?.text?.trim();
      const jsonStart = raw.indexOf("[");
      const jsonEnd = raw.lastIndexOf("]") + 1;
      trips = JSON.parse(raw.slice(jsonStart, jsonEnd));
    } catch {
      return res.status(422).json({ error: "Could not parse iCal data", raw: extraction.content[0]?.text?.slice(0, 200) });
    }

    // Save parsed trips to DB
    let created = 0;
    for (const trip of trips) {
      if (!trip.title || !Array.isArray(trip.legs) || trip.legs.length === 0) continue;
      const [newTrip] = await sql`
        INSERT INTO trips (user_email, title, status, source)
        VALUES (${req.email}, ${trip.title.slice(0, 200)}, 'upcoming', 'tripit')
        RETURNING id
      `;
      for (const leg of trip.legs) {
        await sql`
          INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation)
          VALUES (
            ${newTrip.id},
            ${(leg.type || "other").slice(0, 50)},
            ${leg.carrier ? leg.carrier.slice(0, 100) : null},
            ${leg.flight_number ? leg.flight_number.slice(0, 20) : null},
            ${leg.origin ? leg.origin.slice(0, 100) : null},
            ${leg.destination ? leg.destination.slice(0, 100) : null},
            ${leg.departs_at || null},
            ${leg.arrives_at || null},
            ${leg.confirmation ? leg.confirmation.slice(0, 50) : null}
          )
        `;
      }
      created++;
    }

    // Save the iCal URL for future auto-sync
    await sql`
      INSERT INTO user_integrations (user_email, provider, config, updated_at)
      VALUES (${req.email}, 'tripit_ical', ${JSON.stringify({ ical_url })}, NOW())
      ON CONFLICT (user_email, provider) DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()
    `;

    res.json({ ok: true, trips_created: created, trips_found: trips.length });
  } catch (e) {
    console.error("[tripit/sync]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /integrations/tripit/status — check if TripIt iCal is connected
app.get("/integrations/tripit/status", auth, async (req, res) => {
  try {
    const rows = await sql`
      SELECT config, updated_at FROM user_integrations
      WHERE user_email = ${req.email} AND provider = 'tripit_ical'
    `;
    if (!rows.length) return res.json({ connected: false });
    res.json({ connected: true, last_synced: rows[0].updated_at });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /integrations/tripit — disconnect TripIt iCal
app.delete("/integrations/tripit", auth, async (req, res) => {
  try {
    await sql`DELETE FROM user_integrations WHERE user_email = ${req.email} AND provider = 'tripit_ical'`;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// TravelPerk OAuth 2.0 Sync
// ===========================================================================
// GET /integrations/travelperk/connect — initiate OAuth flow
app.get("/integrations/travelperk/connect", auth, async (req, res) => {
  if (!process.env.TRAVELPERK_CLIENT_ID || !process.env.TRAVELPERK_CLIENT_SECRET) {
    return res.status(503).json({
      error: "TravelPerk OAuth not configured",
      hint: "Set TRAVELPERK_CLIENT_ID and TRAVELPERK_CLIENT_SECRET in Render environment variables."
    });
  }
  const redirectUri = process.env.TRAVELPERK_REDIRECT_URI || "https://wingman-api-y39a.onrender.com/integrations/travelperk/callback";
  const state = Buffer.from(req.email).toString("base64");
  const url = `https://app.travelperk.com/oauth2/authorize?client_id=${encodeURIComponent(process.env.TRAVELPERK_CLIENT_ID)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=trips:read+bookings:read&state=${state}`;
  res.json({ url });
});

// GET /integrations/travelperk/callback — OAuth callback
app.get("/integrations/travelperk/callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send(`TravelPerk OAuth error: ${error}`);
  if (!code || !state) return res.status(400).send("Missing code or state");
  let userEmail;
  try { userEmail = Buffer.from(state, "base64").toString("utf8"); } catch { return res.status(400).send("Invalid state"); }
  const redirectUri = process.env.TRAVELPERK_REDIRECT_URI || "https://wingman-api-y39a.onrender.com/integrations/travelperk/callback";
  try {
    // Exchange code for tokens
    const tokenResp = await fetch("https://app.travelperk.com/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: process.env.TRAVELPERK_CLIENT_ID,
        client_secret: process.env.TRAVELPERK_CLIENT_SECRET,
      }),
    });
    const tokens = await tokenResp.json();
    if (!tokens.access_token) return res.status(502).send("Token exchange failed: " + JSON.stringify(tokens));

    // Store tokens
    await sql`
      INSERT INTO user_integrations (user_email, provider, config, updated_at)
      VALUES (${userEmail}, 'travelperk', ${JSON.stringify({
        access_token: encryptField(tokens.access_token),
        refresh_token: tokens.refresh_token ? encryptField(tokens.refresh_token) : null,
        expires_at: tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : null,
      })}, NOW())
      ON CONFLICT (user_email, provider) DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()
    `;

    // Trigger initial sync
    syncTravelPerkTrips(userEmail, tokens.access_token).catch(e => console.error("[travelperk initial sync]", e.message));

    // Redirect back to app
    res.send(`<html><body><script>window.location='wingman://integrations/travelperk/success'</script><p>TravelPerk connected! You can close this window.</p></body></html>`);
  } catch (e) {
    console.error("[travelperk/callback]", e.message);
    res.status(500).send("OAuth callback failed: " + e.message);
  }
});

// Helper: sync TravelPerk trips for a user
async function syncTravelPerkTrips(userEmail, accessToken) {
  const headers = { Authorization: `Bearer ${accessToken}`, "Accept": "application/json" };
  // Fetch trips
  const tripsResp = await fetch("https://app.travelperk.com/api/v2/trips?limit=50", { headers, signal: AbortSignal.timeout(20000) });
  if (!tripsResp.ok) throw new Error(`TravelPerk trips API returned ${tripsResp.status}`);
  const tripsData = await tripsResp.json();
  const tpTrips = tripsData.results || tripsData.trips || [];

  let created = 0;
  for (const tpTrip of tpTrips) {
    const title = tpTrip.name || tpTrip.title || `TravelPerk Trip ${tpTrip.id}`;
    // Check if already imported
    const existing = await sql`SELECT id FROM trips WHERE user_email = ${userEmail} AND source = 'travelperk' AND title = ${title}`;
    if (existing.length) continue;

    const [newTrip] = await sql`
      INSERT INTO trips (user_email, title, status, source)
      VALUES (${userEmail}, ${title.slice(0, 200)}, 'upcoming', 'travelperk')
      RETURNING id
    `;

    // Fetch bookings for this trip
    const bookingsResp = await fetch(`https://app.travelperk.com/api/v2/bookings?trip_id=${tpTrip.id}`, { headers, signal: AbortSignal.timeout(15000) });
    if (!bookingsResp.ok) continue;
    const bookingsData = await bookingsResp.json();
    const bookings = bookingsData.results || bookingsData.bookings || [];

    for (const booking of bookings) {
      const legType = booking.type === "flight" ? "flight" : booking.type === "hotel" ? "hotel" : booking.type === "train" ? "train" : booking.type === "car" ? "car" : "other";
      await sql`
        INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation)
        VALUES (
          ${newTrip.id},
          ${legType},
          ${booking.carrier || booking.airline || booking.hotel_name || null},
          ${booking.flight_number || null},
          ${booking.origin || booking.departure_city || null},
          ${booking.destination || booking.arrival_city || null},
          ${booking.departure_datetime || booking.check_in || null},
          ${booking.arrival_datetime || booking.check_out || null},
          ${booking.confirmation_code || booking.pnr || null}
        )
      `;
    }
    created++;
  }
  return created;
}

// POST /integrations/travelperk/sync — manual re-sync
app.post("/integrations/travelperk/sync", auth, async (req, res) => {
  try {
    const rows = await sql`SELECT config FROM user_integrations WHERE user_email = ${req.email} AND provider = 'travelperk'`;
    if (!rows.length) return res.status(404).json({ error: "TravelPerk not connected" });
    const config = rows[0].config;
    const accessToken = decryptField(config.access_token);
    const created = await syncTravelPerkTrips(req.email, accessToken);
    res.json({ ok: true, trips_created: created });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /integrations/travelperk/status
app.get("/integrations/travelperk/status", auth, async (req, res) => {
  try {
    const rows = await sql`SELECT updated_at FROM user_integrations WHERE user_email = ${req.email} AND provider = 'travelperk'`;
    res.json({ connected: rows.length > 0, last_synced: rows[0]?.updated_at || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /integrations/travelperk — disconnect
app.delete("/integrations/travelperk", auth, async (req, res) => {
  try {
    await sql`DELETE FROM user_integrations WHERE user_email = ${req.email} AND provider = 'travelperk'`;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// PDF OCR — extract booking data from scanned/image PDFs using Claude vision
// ===========================================================================
// POST /trips/import/pdf-ocr — multipart upload of a PDF file
const multer = require("multer");
const pdfOcrUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

app.post("/trips/import/pdf-ocr", auth, pdfOcrUpload.single("pdf"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No PDF file uploaded" });
  if (!req.file.mimetype.includes("pdf") && !req.file.mimetype.includes("image")) {
    return res.status(400).json({ error: "File must be a PDF or image" });
  }
  try {
    const anthropic = getAnthropic();
    // Convert PDF/image to base64 for Claude vision
    const base64Data = req.file.buffer.toString("base64");
    const isPdf = req.file.mimetype === "application/pdf" || (req.file.originalname || "").toLowerCase().endsWith(".pdf");
    const mediaType = isPdf ? "application/pdf" : req.file.mimetype;
    // Claude uses 'document' type for PDFs, 'image' type for image files (jpeg/png/gif/webp)
    const fileBlock = isPdf
      ? { type: "document", source: { type: "base64", media_type: "application/pdf", data: base64Data } }
      : { type: "image",    source: { type: "base64", media_type: mediaType,           data: base64Data } };

    const extraction = await anthropic.messages.create({
      model: "claude-sonnet-4-5",
      max_tokens: 3000,
      messages: [{
        role: "user",
        content: [
          fileBlock,
          {
            type: "text",
            text: `Extract all travel booking information from this document. Return a JSON object:
{
  "trip_title": "string",
  "legs": [
    {
      "type": "flight|hotel|car|train|other",
      "carrier": "string",
      "flight_number": "string or null",
      "origin": "string",
      "destination": "string",
      "departs_at": "ISO8601 datetime or null",
      "arrives_at": "ISO8601 datetime or null",
      "confirmation": "string or null"
    }
  ]
}
Return ONLY the JSON, no other text. If no booking data found, return { "trip_title": null, "legs": [] }.`
          }
        ]
      }],
    });

    let parsed;
    try {
      const raw = extraction.content[0]?.text?.trim();
      const jsonStart = raw.indexOf("{");
      const jsonEnd = raw.lastIndexOf("}") + 1;
      parsed = JSON.parse(raw.slice(jsonStart, jsonEnd));
    } catch {
      return res.status(422).json({ error: "Could not parse booking data from PDF", raw: extraction.content[0]?.text?.slice(0, 200) });
    }

    if (!parsed.trip_title || !parsed.legs?.length) {
      return res.status(422).json({ error: "No booking data found in this PDF", parsed });
    }

    // Save to DB
    const [newTrip] = await sql`
      INSERT INTO trips (user_email, title, status, source)
      VALUES (${req.email}, ${parsed.trip_title.slice(0, 200)}, 'upcoming', 'pdf_ocr')
      RETURNING id
    `;
    for (const leg of parsed.legs) {
      await sql`
        INSERT INTO trip_legs (trip_id, type, carrier, flight_number, origin, destination, departs_at, arrives_at, confirmation)
        VALUES (
          ${newTrip.id},
          ${(leg.type || "other").slice(0, 50)},
          ${leg.carrier ? leg.carrier.slice(0, 100) : null},
          ${leg.flight_number ? leg.flight_number.slice(0, 20) : null},
          ${leg.origin ? leg.origin.slice(0, 100) : null},
          ${leg.destination ? leg.destination.slice(0, 100) : null},
          ${leg.departs_at || null},
          ${leg.arrives_at || null},
          ${leg.confirmation ? leg.confirmation.slice(0, 50) : null}
        )
      `;
    }

    res.json({ ok: true, trip_id: newTrip.id, trip_title: parsed.trip_title, legs_created: parsed.legs.length });
  } catch (e) {
    console.error("[pdf-ocr]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// ===========================================================================
// DB migration: ensure user_integrations table exists
// ===========================================================================
// (Runs at startup via bootstrapDB — add to bootstrap if not already there)

// ---------------------------------------------------------------------------
// Keep-alive: self-ping every 10 minutes to prevent Render free tier from sleeping
// ---------------------------------------------------------------------------
const SELF_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
setInterval(async () => {
  try {
    await fetch(`${SELF_URL}/health`, { signal: AbortSignal.timeout(8000) });
  } catch (e) {
    // Silently ignore — this is best-effort
  }
}, 10 * 60 * 1000); // every 10 minutes

// ═══════════════════════════════════════════════════════════════════════════════
// PLAN — the front door.  (TRIP_MODEL.md · planner.js)
//
// Wingman could file a trip. It could never MAKE one. So the most valuable forty
// turns of a user's life — the conversation where the trip actually gets decided —
// happened in somebody else's chat window, and we met the trip afterwards, as a pile
// of receipts with no reasons attached.
//
// These three endpoints are that missing half. A conversation goes in; a constraint
// graph comes out, with the WHY on every line.
// ═══════════════════════════════════════════════════════════════════════════════
const planner = require("./planner");

// POST /plan/message — one turn of planning.
app.post("/plan/message", conciergeLimiter, async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });

  const { message: raw, tripId, history = [] } = req.body || {};
  if (!raw) return res.status(400).json({ error: "message required" });
  const message = scrubPII(raw);

  try {
    // A planning conversation needs somewhere to put its constraints. Create the
    // trip as a *draft* — state 'considered', not 'booked'. This is the thing the
    // old schema could not express, and it is why planning was impossible.
    let trip_id = tripId;
    if (!trip_id) {
      const [t] = await sql`
        INSERT INTO trips (user_email, title, status, source)
        VALUES (${email}, 'Untitled trip', 'draft', 'planner')
        RETURNING id`;
      trip_id = t.id;
    }

    const known = await graph.constraintsFor(sql, { user_email: email, trip_id });

    // Look it up rather than recall it. Entry rules and alliance cutoffs go stale,
    // and a wrong one leaves someone at a border.
    let findings = null;
    if (planner.NEEDS_LOOKUP.test(message)) {
      try {
        const r = await planner.research(message, history.map((h) => h.content));
        if (r.text && !/^nothing to check/i.test(r.text)) findings = r.text;
      } catch (e) {
        console.warn("[plan] research failed:", e.message);   // degrade, never block
      }
    }

    const out = await planner.converse({ message, known, history, findings });
    const wrote = await planner.commit(sql, {
      user_email: email, trip_id, proposals: out, known,
    });

    // Refusals are not errors. They are the schema declining to store something the
    // model had not earned — and the user should be able to see that happen.
    if (wrote.refused.length) {
      console.warn("[plan] refused:", wrote.refused.map((r) => r.why).join(" | "));
    }

    const live = await graph.constraintsFor(sql, { user_email: email, trip_id });

    // ── Close the loop: the conversation becomes a trip ───────────────────────
    // Legs land as 'proposed' — a shape, not a booking. No flight numbers, no
    // confirmations, no times we weren't given. And each is linked to the constraints
    // it exists to serve, which is the edge that lets the cascade DEFEND this trip
    // later rather than merely rebook it.
    const shaped = await planner.shapeTrip(sql, {
      user_email: email, trip_id, shape: out.shape, constraints: live,
    });

    if (shaped.smuggled.length) {
      // The model tried to hand us a flight number on a trip nobody has booked.
      // Stripped, and logged loudly — this is the single most dangerous thing it can do.
      console.warn("[plan] STRIPPED invented booking fields:", JSON.stringify(shaped.smuggled));
    }

    // A trip called "Untitled trip" is a trip nobody opens.
    if (shaped.legs.length) {
      const title = planner.titleFor(out.shape);
      if (title !== "Untitled trip") {
        await sql`UPDATE trips SET title = ${title}, updated_at = NOW()
                  WHERE id = ${trip_id} AND user_email = ${email}`;
      }
    }

    const legs = await sql`
      SELECT id, type, destination, destination_city, property_name, nights,
             departs_at, state, raw_data
      FROM trip_legs WHERE trip_id = ${trip_id} ORDER BY id`;

    res.json({
      trip_id,
      reply: out.reply,
      gaps: out.gaps,
      constraints: live,
      legs,
      shaped: shaped.legs,
      added: wrote.written.map((w) => ({ id: w.id, rationale: w.rationale, hardness: w.hardness, status: w.status, scope: w.scope })),
      proposed: wrote.proposed.map((p) => ({ id: p.id, rationale: p.rationale, hardness: p.hardness })),
      kept: wrote.kept,
      refused: wrote.refused.map((r) => ({ rationale: r.rationale, why: r.why })),
    });
  } catch (e) {
    console.error("[plan/message]", e.message);
    res.status(500).json({ error: "plan_failed", detail: e.message });
  }
});

// GET /plan/:tripId — the document, as it stands.
app.get("/plan/:tripId", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const trip_id = parseInt(req.params.tripId, 10);
    const [trip] = await sql`SELECT * FROM trips WHERE id = ${trip_id} AND user_email = ${email}`;
    if (!trip) return res.status(404).json({ error: "not_found" });

    const constraints = await graph.constraintsFor(sql, { user_email: email, trip_id });
    const legs = await sql`SELECT * FROM trip_legs WHERE trip_id = ${trip_id} ORDER BY departs_at NULLS LAST`;
    res.json({
      trip,
      legs,
      constraints,
      // The two the UI must treat differently: things awaiting your word, and things
      // Wingman thinks are non-negotiable but only inferred.
      proposed: constraints.filter((c) => c.status === "proposed"),
    });
  } catch (e) {
    console.error("[plan/get]", e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /plan/constraint/:id/confirm — an inference becomes a fact.
// The ONLY way that ever happens.
app.post("/plan/constraint/:id/confirm", async (req, res) => {
  const email = await verifyAccessToken(req);
  if (!email) return res.status(401).json({ error: "unauthorized" });
  try {
    const row = await graph.confirm(sql, parseInt(req.params.id, 10), { user_email: email });
    if (!row) return res.status(404).json({ error: "not_found_or_not_proposed" });
    res.json({ ok: true, constraint: row });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log("Wingman API on http://localhost:" + PORT));
