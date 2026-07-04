
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

