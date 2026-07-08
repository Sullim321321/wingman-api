# Push guide — Daily Morning Briefing

A step-by-step guide to ship the morning-briefing changes. Two repos change (backend + app), plus two dashboard settings (Render env var + a cron scheduler). Takes about 15 minutes.

Your API: `https://wingman-api-y39a.onrender.com`

---

## Before you start

You'll do everything from the macOS **Terminal** app (Applications → Utilities → Terminal). You should already be signed into git/GitHub on this machine (you pushed earlier, so you are). For the app build you need the EAS CLI — if `eas` isn't installed, run once: `npm install -g eas-cli` then `eas login`.

---

## Step 1 — Push the backend

Copy-paste these lines one block at a time.

```bash
cd ~/Desktop/wingman-api
```

Remove the safety backup so it doesn't get committed:

```bash
rm -f server.js.bak_cowork
```

Stage, commit, and push:

```bash
git add -A
git commit -m "Daily morning briefing: timezone-aware cron + external endpoint"
git push
```

Now go to your **Render dashboard** → the `wingman-api` service → watch **Events/Logs** until it says the deploy is **Live** (1–3 min). The new database columns migrate themselves on startup — nothing to do.

Confirm it's up:

```bash
curl https://wingman-api-y39a.onrender.com/health
```

---

## Step 2 — Add the cron secret in Render

This is a password that lets the scheduler (Step 3) call your app securely.

1. Render dashboard → `wingman-api` → **Environment** (left sidebar).
2. Click **Add Environment Variable**.
3. Key: `CRON_SECRET`
4. Value: any long random string — for example mash the keyboard, or run this in Terminal to generate one and copy the output:
   ```bash
   openssl rand -hex 24
   ```
5. **Save changes.** Render redeploys automatically (~1–2 min). Keep this value handy for Step 3.

---

## Step 3 — Schedule the briefing (free, reliable)

This wakes the server and runs the briefing check every 15 minutes.

1. Go to **https://cron-job.org** and create a free account.
2. Click **Create cronjob**.
3. Fill in:
   - **Title:** Wingman morning briefing
   - **URL:** `https://wingman-api-y39a.onrender.com/cron/morning-briefings`
   - **Schedule:** every 15 minutes (in the schedule editor, choose "Every 15 minutes", or set minutes to `*/15`).
4. Expand **Advanced / Headers** and add a request header:
   - **Name:** `x-cron-secret`
   - **Value:** the exact string you set as `CRON_SECRET` in Step 2.
5. Set the request **method to POST**.
6. **Save.**

That's it — it will now check every 15 minutes and send each person their briefing at their local 7am, once a day.

---

## Step 4 — Push the app + new TestFlight build

The app changed one file (it now tells the server your timezone). This needs a new build to reach your phone.

```bash
cd ~/Desktop/wingman-app
rm -f src/screens/*.bak_cowork
git add -A
git commit -m "Send timezone on push registration"
git push
```

Then build and submit to TestFlight (this part takes ~15–25 min, mostly waiting):

```bash
eas build --platform ios --profile production
```

When it finishes, submit it:

```bash
eas submit --platform ios --latest
```

(Or use whatever build/submit flow you normally use — the only app change is `src/api.js`.)

---

## Step 5 — Test it now (don't wait until 7am)

First get a login token (if you don't still have one from before):

```bash
curl -X POST https://wingman-api-y39a.onrender.com/auth/request \
  -H "Content-Type: application/json" \
  -d '{"email":"maddie@welcometothefight.club"}'
```

Check your email for the 6-digit code, then (replace `123456`):

```bash
curl -X POST https://wingman-api-y39a.onrender.com/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"email":"maddie@welcometothefight.club","code":"123456"}'
```

Copy the `token` from the response and save it:

```bash
export WINGMAN_TOKEN="paste-the-token-here"
```

Now fire yourself a test briefing (works any time of day):

```bash
curl -X POST https://wingman-api-y39a.onrender.com/me/test-morning-briefing \
  -H "Authorization: Bearer $WINGMAN_TOKEN"
```

The response shows the exact `title` and `body`, and if your phone has notifications on (and the new build installed), the push arrives. You can also test the scheduler endpoint directly (replace the secret):

```bash
curl -X POST https://wingman-api-y39a.onrender.com/cron/morning-briefings \
  -H "x-cron-secret: your-cron-secret-here"
```

It returns `{"ok":true,"sent":N}` — `sent` will be 0 unless it's currently someone's briefing hour, which is expected.

---

## If something goes wrong

- **`/health` doesn't respond:** the deploy may still be building, or the free service is waking up — wait 30–60s and retry.
- **Test briefing returns `sent: false`:** no push token is registered yet — open the app once (with the new build) and allow notifications, then retry.
- **Scheduler shows 401:** the `x-cron-secret` header doesn't match the Render `CRON_SECRET` value — re-check both.
- **Need to undo the backend:** `git revert HEAD && git push`, or restore from `server.js.bak_cowork` if you kept it.
