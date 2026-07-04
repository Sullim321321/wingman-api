#!/usr/bin/env node
// One-time script: rename all "United Airlines Booking" / "Unknown Trip" trips
// to human-readable destination-based titles using leg data already in the DB.
// Usage: DATABASE_URL="..." node scripts/rename_trips.js [--dry-run]

const { neon } = require("@neondatabase/serverless");

const DRY_RUN = process.argv.includes("--dry-run");
const sql = neon(process.env.DATABASE_URL);

// IATA city map for common destinations
const IATA_CITY = {
  JFK: "New York", LGA: "New York", EWR: "New York",
  LAX: "Los Angeles", SFO: "San Francisco", ORD: "Chicago",
  MIA: "Miami", BOS: "Boston", SEA: "Seattle", DEN: "Denver",
  ATL: "Atlanta", DFW: "Dallas", PHX: "Phoenix", LAS: "Las Vegas",
  IAD: "Washington DC", DCA: "Washington DC", BWI: "Baltimore",
  LHR: "London", LGW: "London", STN: "London", LCY: "London",
  CDG: "Paris", ORY: "Paris", AMS: "Amsterdam", FRA: "Frankfurt",
  MAD: "Madrid", BCN: "Barcelona", FCO: "Rome", MXP: "Milan",
  ZRH: "Zurich", VIE: "Vienna", BRU: "Brussels", CPH: "Copenhagen",
  ARN: "Stockholm", OSL: "Oslo", HEL: "Helsinki", DUB: "Dublin",
  EDI: "Edinburgh", GLA: "Glasgow", MAN: "Manchester", BHX: "Birmingham",
  BRS: "Bristol", LBA: "Leeds", NCL: "Newcastle", ABZ: "Aberdeen",
  INV: "Inverness", GVA: "Geneva", NRT: "Tokyo", HND: "Tokyo",
  HKG: "Hong Kong", SIN: "Singapore", BKK: "Bangkok", DXB: "Dubai",
  AUH: "Abu Dhabi", DOH: "Doha", SYD: "Sydney", MEL: "Melbourne",
  YYZ: "Toronto", YVR: "Vancouver", YUL: "Montreal",
  GRU: "São Paulo", EZE: "Buenos Aires", BOG: "Bogotá",
  MEX: "Mexico City", CUN: "Cancún",
};

function bestTitle(legs) {
  if (!legs || legs.length === 0) return null;

  // 1. Use destination_city if available on any leg
  const cityLeg = legs.find(l => l.destination_city && l.destination_city.trim());
  if (cityLeg) return titleCase(cityLeg.destination_city.trim());

  // 2. Use IATA destination code
  const flightLeg = legs.find(l => l.destination && /^[A-Z]{3}$/.test(l.destination));
  if (flightLeg) {
    const city = IATA_CITY[flightLeg.destination];
    if (city) return city;
    return flightLeg.destination; // raw IATA if no mapping
  }

  // 4. Use station_to for train legs
  const trainLeg = legs.find(l => l.station_to && l.station_to.trim());
  if (trainLeg) return titleCase(trainLeg.station_to.trim());

  // 5. Use dropoff_location for car legs
  const carLeg = legs.find(l => l.dropoff_location && l.dropoff_location.trim());
  if (carLeg) return titleCase(carLeg.dropoff_location.trim());

  return null;
}

function titleCase(str) {
  return str.replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
}

function isGenericTitle(title) {
  if (!title) return true;
  const t = title.toLowerCase().trim();
  return (
    t.includes("booking") ||
    t.includes("unknown trip") ||
    t.includes("unknown") ||
    t === "flight" ||
    t === "hotel" ||
    t === "train" ||
    t === "car rental"
  );
}

(async () => {
  console.log(DRY_RUN ? "🔍  DRY RUN — no changes will be written\n" : "✏️   Applying renames...\n");

  const trips = await sql`SELECT id, title, user_email FROM trips ORDER BY user_email, id`;
  const legs  = await sql`SELECT trip_id, type, carrier, flight_number, origin, destination, destination_city, station_from, station_to, pickup_location, dropoff_location, departs_at FROM trip_legs ORDER BY trip_id, departs_at ASC NULLS LAST`;

  const legsByTrip = {};
  for (const leg of legs) {
    if (!legsByTrip[leg.trip_id]) legsByTrip[leg.trip_id] = [];
    legsByTrip[leg.trip_id].push(leg);
  }

  let renamed = 0;
  let skipped = 0;

  for (const trip of trips) {
    if (!isGenericTitle(trip.title)) {
      console.log(`  ✓ [${trip.id}] "${trip.title}" — already named, skipping`);
      skipped++;
      continue;
    }

    const tripLegs = legsByTrip[trip.id] || [];
    const newTitle = bestTitle(tripLegs);

    if (!newTitle) {
      console.log(`  ? [${trip.id}] "${trip.title}" — no leg data to derive name from, skipping`);
      skipped++;
      continue;
    }

    console.log(`  → [${trip.id}] "${trip.title}"  ➜  "${newTitle}"`);

    if (!DRY_RUN) {
      await sql`UPDATE trips SET title = ${newTitle} WHERE id = ${trip.id}`;
    }
    renamed++;
  }

  console.log(`\n${DRY_RUN ? "[DRY RUN] Would rename" : "Renamed"} ${renamed} trip(s), skipped ${skipped}.`);
})().catch(e => { console.error(e); process.exit(1); });
