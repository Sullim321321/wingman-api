/**
 * Wingman Flight Disruption Prediction Service
 * =============================================
 * Pure Node.js logistic regression inference — no Python dependency at runtime.
 * Loads pre-trained weights from model_weights.json and serves predictions.
 *
 * Trained on: BTS Reporting Carrier On-Time Performance 2022-2024
 * Dataset:    1,020,693 training flights across 20 US carriers
 * Model:      Logistic Regression (L2, balanced class weights)
 * ROC-AUC:    0.6346  |  Accuracy: 0.6041
 *
 * Endpoint: POST /predict
 * Body: {
 *   carrier: "AA",          // IATA carrier code
 *   origin: "JFK",          // IATA origin airport
 *   dest: "LAX",            // IATA destination airport
 *   month: 7,               // 1-12
 *   day_of_week: 5,         // 1=Mon, 7=Sun
 *   dep_hour: 8,            // 0-23 (scheduled departure hour)
 *   distance: 2475,         // miles
 *   metar_score: 0.3        // optional: 0-1 from METAR weather scoring
 * }
 * Response: {
 *   disruption_probability: 0.31,   // 0-1, ML model output
 *   risk_score: 42,                 // 0-100 composite (ML + METAR)
 *   risk_label: "moderate",         // low / moderate / high / critical
 *   ml_probability: 0.31,           // raw ML output
 *   metar_boost: 0.05,              // METAR weather contribution
 *   model_version: "1.0.0",
 *   trained_rows: 1020693,
 *   data_source: "BTS Reporting Carrier On-Time Performance 2022-2024"
 * }
 */

const fs   = require('fs');
const path = require('path');

// ── Load model weights ────────────────────────────────────────
const MODEL_PATH = path.join(__dirname, 'model_weights.json');
const META_PATH  = path.join(__dirname, 'model_meta.json');

let MODEL = null;
let META  = null;

function loadModel() {
  if (MODEL) return;
  MODEL = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf8'));
  META  = JSON.parse(fs.readFileSync(META_PATH,  'utf8'));
  console.log(`[predict] Model loaded — ${MODEL.feature_names.length} features, ROC-AUC ${META.metrics.roc_auc}`);
}

// ── Sigmoid ───────────────────────────────────────────────────
function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

// ── Distance bucket ───────────────────────────────────────────
function distBucket(miles) {
  if (miles <= 500)  return 'short';
  if (miles <= 1000) return 'medium';
  if (miles <= 2000) return 'long';
  return 'ultra';
}

// ── Build feature vector ──────────────────────────────────────
function buildFeatureVector(input) {
  const { carrier, origin, dest, month, day_of_week, dep_hour, distance } = input;

  const cats = MODEL.cat_categories;

  // Collapse to "OTHER" if not in training vocab
  const carrierGrp = cats.carrier_grp.includes(carrier) ? carrier : 'OTHER';
  const originGrp  = cats.origin_grp.includes(origin)   ? origin  : 'OTHER';
  const destGrp    = cats.dest_grp.includes(dest)        ? dest    : 'OTHER';
  const distBkt    = distBucket(distance || 1000);
  const distGrp    = cats.dist_bucket.includes(distBkt)  ? distBkt : 'medium';

  // Build one-hot vector
  const vec = new Array(MODEL.feature_names.length).fill(0);
  const fn  = MODEL.feature_names;

  // One-hot categorical
  const catMappings = [
    ['carrier_grp', carrierGrp],
    ['origin_grp',  originGrp],
    ['dest_grp',    destGrp],
    ['dist_bucket', distGrp],
  ];
  for (const [prefix, val] of catMappings) {
    const idx = fn.indexOf(`${prefix}_${val}`);
    if (idx >= 0) vec[idx] = 1;
  }

  // Numeric passthrough
  const monthIdx  = fn.indexOf('Month');
  const dowIdx    = fn.indexOf('DayOfWeek');
  const hourIdx   = fn.indexOf('dep_hour');
  if (monthIdx  >= 0) vec[monthIdx]  = month      || 1;
  if (dowIdx    >= 0) vec[dowIdx]    = day_of_week || 1;
  if (hourIdx   >= 0) vec[hourIdx]   = dep_hour    || 8;

  return vec;
}

// ── Core prediction ───────────────────────────────────────────
function predict(input) {
  loadModel();

  const vec = buildFeatureVector(input);
  const coef = MODEL.coef[0];  // shape: [n_features]
  const intercept = MODEL.intercept[0];

  // dot product
  let logit = intercept;
  for (let i = 0; i < coef.length; i++) {
    logit += coef[i] * vec[i];
  }

  const mlProb = sigmoid(logit);

  // Blend with METAR weather score if provided (0-1)
  const metarScore = typeof input.metar_score === 'number'
    ? Math.max(0, Math.min(1, input.metar_score))
    : 0;

  // METAR boost: weather score adds up to 15 percentage points to the ML probability
  const metarBoost = metarScore * 0.15;
  const compositeProb = Math.min(0.99, mlProb + metarBoost);

  // Convert to 0-100 risk score
  const riskScore = Math.round(compositeProb * 100);

  // Risk label
  let riskLabel;
  if (riskScore < 20)      riskLabel = 'low';
  else if (riskScore < 40) riskLabel = 'moderate';
  else if (riskScore < 65) riskLabel = 'high';
  else                     riskLabel = 'critical';

  return {
    disruption_probability: Math.round(compositeProb * 1000) / 1000,
    risk_score: riskScore,
    risk_label: riskLabel,
    ml_probability: Math.round(mlProb * 1000) / 1000,
    metar_boost: Math.round(metarBoost * 1000) / 1000,
    model_version: META.version,
    trained_rows: META.rows_trained,
    data_source: META.trained_on,
    features_used: {
      carrier: input.carrier,
      origin: input.origin,
      dest: input.dest,
      month: input.month,
      day_of_week: input.day_of_week,
      dep_hour: input.dep_hour,
      distance: input.distance,
    },
  };
}

// ── Export for use as a module in server.js ───────────────────
module.exports = { predict, loadModel };

// ── Standalone HTTP server (for testing / separate Render service) ──
if (require.main === module) {
  const http = require('http');
  loadModel();

  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, model_version: META.version, roc_auc: META.metrics.roc_auc }));
      return;
    }
    if (req.method === 'POST' && req.url === '/predict') {
      let body = '';
      req.on('data', d => body += d);
      req.on('end', () => {
        try {
          const input = JSON.parse(body);
          const result = predict(input);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(result));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const PORT = process.env.PREDICT_PORT || 4001;
  server.listen(PORT, () => console.log(`[predict] Listening on :${PORT}`));
}
