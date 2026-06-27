# Wingman API — backend slice

A tiny Node/Express service that powers the app's **live disruption prediction** and a **dev-grade email sign-in**. It uses real, free aviation weather (METARs from aviationweather.gov — no API key) and a transparent v1 heuristic to produce a calibrated-ish risk score with factor contributions.

## Run

```bash
cd wingman-api
npm install
npm start          # http://localhost:4000
```

## Endpoints

- `GET /health` → `{ ok: true }`
- `GET /predict?dep=DEN&arr=ASE` → live risk + factor breakdown.
- `POST /auth/request` `{ email }` → 6-digit code (logged to console; returned as `devCode` when not in production).
- `POST /auth/verify` `{ email, code }` → `{ token }`.

## How the prediction works (v1)

For the departure and arrival airports it pulls the latest METAR and scores **visibility, ceiling, wind/gust, and phenomena** (snow, thunder, freezing, fog), plus an **airport-sensitivity** term (mountain/short-runway fields like Aspen have strict minimums) and a small baseline. Each input is returned as a labelled factor with its point contribution — the same transparency the app's reasoning screen shows.

## Deploy

Push to GitHub → Render → New → Blueprint (reads `render.yaml`). Put the resulting https URL into `wingman-app/src/config.js`.

## Env

| var | default | notes |
|-----|---------|-------|
| `PORT` | 4000 | |
| `JWT_SECRET` | dev-secret | set in prod |
| `NODE_ENV` | — | `production` stops returning `devCode` |
# Deploy trigger Sat Jun 27 17:37:12 UTC 2026
