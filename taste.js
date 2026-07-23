// taste.js — everything Wingman knows about your palate, in one brief.
//
// ─────────────────────────────────────────────────────────────────────────────
// The Curator is only as good as its sense of you. This assembles that sense from
// two truths and one aspiration:
//   • revealed — the hotels and restaurants you actually chose (affinity, ranked
//     by how often you came back).
//   • stated — dietary lines, cabin, price tier.
//   • aspirational — the editors you read (36 Hours, Service 95, Hotels Above Par).
//
// Pure and dependency-free: it takes already-fetched rows and returns the brief the
// curation engine (and its LLM prompt) consumes. No taste is invented here — an
// empty history yields an honestly empty brief, and the curator says so rather than
// guessing a personality you never showed it.
// ─────────────────────────────────────────────────────────────────────────────

const uniq = (a) => [...new Set((a || []).filter((x) => x != null && String(x).trim() !== ""))];

/**
 * @param src.hotelAffinity      [{ property_name, brand, city, stay_count }]
 * @param src.restaurantAffinity [{ restaurant_name, cuisine, city, visit_count }]
 * @param src.prefs              { dietary:[], cabin_preference, price_tier, home_bases:[] }
 * @param src.sources            ["NYT 36 Hours", "Service 95", ...]
 * @returns a structured taste brief
 */
function assembleBrief({ hotelAffinity = [], restaurantAffinity = [], prefs = {}, sources = [] } = {}) {
  const hotels = [...hotelAffinity].sort((a, b) => (b.stay_count || 0) - (a.stay_count || 0));
  const rests = [...restaurantAffinity].sort((a, b) => (b.visit_count || 0) - (a.visit_count || 0));

  return {
    hotels: {
      brands: uniq(hotels.map((h) => h.brand)).slice(0, 5),
      favorites: hotels.slice(0, 6).map((h) => ({ name: h.property_name, city: h.city || null, stays: h.stay_count || 0 })),
      cities: uniq(hotels.map((h) => h.city)).slice(0, 10),
    },
    dining: {
      cuisines: uniq(rests.map((r) => r.cuisine)).slice(0, 6),
      favorites: rests.slice(0, 6).map((r) => ({ name: r.restaurant_name, city: r.city || null })),
      dietary: uniq(prefs.dietary),
      // Richer than a flag: cuisines you love and free-text notes ("no fusion",
      // "counter seats", "quiet enough to talk"). The curator reads these too.
      loved: uniq(prefs.loved_cuisines),
      notes: (prefs.dining_notes && String(prefs.dining_notes).trim()) || null,
    },
    cabin: prefs.cabin_preference || null,
    price_tier: prefs.price_tier || null,
    home_bases: uniq((prefs.home_bases && prefs.home_bases.length) ? prefs.home_bases : ["New York", "London"]),
    sources: uniq(sources),
    // Honest self-assessment: does the curator actually know this person yet?
    known: hotels.length > 0 || rests.length > 0 || uniq(sources).length > 0,
  };
}

module.exports = { assembleBrief };
