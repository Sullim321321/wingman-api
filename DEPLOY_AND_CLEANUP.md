# Deploy the fixes + clean up your trips

Follow these in order. Everything is scoped to your account only, the cleanup runs in **dry-run first** (changes nothing until you say so), and there's a backup of the original `server.js` at `server.js.bak_cowork`.

Your API: `https://wingman-api-y39a.onrender.com`
Your email: `maddie@welcometothefight.club`

---

## 1. Push the backend (Render auto-deploys)

From a terminal in your backend repo:

```bash
cd ~/Desktop/wingman-api

# Don't commit the local backup file
rm -f server.js.bak_cowork

git add server.js DEPLOY_AND_CLEANUP.md
git commit -m "Fix trip grouping + parser, add cleanup migration, chief-of-staff prompt"
git push
```

Render is connected to this repo and will build and deploy automatically. Watch it in the Render dashboard until the deploy is **Live** (about 1–3 minutes).

Confirm it's up:

```bash
curl https://wingman-api-y39a.onrender.com/health
```

---

## 2. Get a sign-in token (for the admin cleanup call)

The cleanup endpoint needs your login token. Get one with two curls.

Request a code:

```bash
curl -X POST https://wingman-api-y39a.onrender.com/auth/request \
  -H "Content-Type: application/json" \
  -d '{"email":"maddie@welcometothefight.club"}'
```

The 6-digit code arrives in your email. (If email isn't wired up, it's printed in the Render logs: dashboard → your service → Logs, look for `OTP for maddie@…`.)

Exchange the code for a token — replace `123456`:

```bash
curl -X POST https://wingman-api-y39a.onrender.com/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"email":"maddie@welcometothefight.club","code":"123456"}'
```

Copy the `token` value from the response. For convenience:

```bash
export WINGMAN_TOKEN="paste-the-token-here"
```

---

## 3. Preview the cleanup (dry-run — changes nothing)

```bash
curl -X POST https://wingman-api-y39a.onrender.com/admin/cleanup-trips \
  -H "Authorization: Bearer $WINGMAN_TOKEN"
```

You'll get a JSON report: how many duplicate legs it would remove, trips it would merge, titles it would fix (e.g. "United Airlines Trip" → "Austin"), and empty trips it would delete. The `details` array lists each change. Read it and make sure it looks right.

---

## 4. Apply the cleanup (for real)

When the dry-run looks good, run it with `?apply=true`:

```bash
curl -X POST "https://wingman-api-y39a.onrender.com/admin/cleanup-trips?apply=true" \
  -H "Authorization: Bearer $WINGMAN_TOKEN"
```

Same report, now with the changes actually made.

---

## 5. Check the app

Open Wingman and pull-to-refresh on the Trips screen. The wall of "United Airlines Trip" duplicates should be gone, replaced by real destination-named trips. Home should start showing a real next flight instead of "Standing by," and Signals should be much shorter.

Any bookings Wingman genuinely couldn't parse are parked in a single trip called **"Needs review"** — nothing is lost; you can open it and sort or delete.

---

## 6. Frontend changes (separate repo — new TestFlight build)

The app repo (`wingman-app`) also changed: the Home screen now uses the chief-of-staff briefing (italic greeting + upright read + `· <DEST> BRIEFING` edition line), the Signals feed collapses duplicate import spam, and the Trips list now correctly hides "…Airlines Trip" junk titles.

To ship these, commit and push the app repo, then build for TestFlight as usual:

```bash
cd ~/Desktop/wingman-app
rm -f src/screens/*.bak_cowork          # don't commit the safety backups
git add src/screens/HomeScreen.js src/screens/ActivityScreen.js src/screens/TripsScreen.js
git commit -m "Chief-of-staff Home briefing; dedupe Signals; fix Trips junk-title filter"
git push
eas build --platform ios --profile production   # then submit to TestFlight
```

You can preview the Home changes instantly in Expo Go / the dev client before building — no App Store round-trip needed.

## Notes

- Safety backups were saved next to each edited file as `*.bak_cowork` (in both repos). They're for your peace of mind — delete them or just don't commit them.
- The grouping + parser fixes apply to all **future** imports automatically — new emails won't recreate the mess.
- The cleanup is safe to run again anytime; running it twice does no harm.
- If anything looks wrong, the original backend is one command away: restore `server.js.bak_cowork` (if you kept it) or `git revert` the commit.
- Optional: to re-pull your inbox with the improved parser, trigger a Gmail rescan from the app (Settings → data sources) after the cleanup.
