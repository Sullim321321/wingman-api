#!/usr/bin/env node
// dedupe-constraints.js — one-time cleanup for duplicates already in the table.
//
//   node --env-file=.env dedupe-constraints.js you@email.com            # dry run
//   node --env-file=.env dedupe-constraints.js you@email.com --apply
//
// addConstraint() is idempotent now, so this cannot recur. But the rows written
// before that fix are still there — the Plan tab showed "Dietary: vegetarian, vegan"
// and "Prefer marriott properties" twice each, which is what sent me looking.
//
// Why this matters beyond tidiness: scoreOption() SUMS weight across constraints when
// ranking a rescue. A duplicated 'must' is worth 200 instead of 100. The ranking bends
// toward whatever got recorded twice, silently, and the explanation Wingman gives you
// would still sound perfectly reasonable. That is the exact failure shape we have been
// hunting all day — confident output, unchecked input.
//
// Supersession, not deletion: the loser is marked superseded_by the keeper, so the
// history survives and satisfies/depends_on edges keep resolving.

const { neon } = require("@neondatabase/serverless");
const sql = neon(process.env.DATABASE_URL);

const email = process.argv[2];
const APPLY = process.argv.includes("--apply");
if (!email) { console.error("usage: node dedupe-constraints.js you@email.com [--apply]"); process.exit(1); }

const c = { d:"\x1b[2m", g:"\x1b[32m", y:"\x1b[33m", r:"\x1b[31m", b:"\x1b[1m", x:"\x1b[0m" };

(async () => {
  const rows = await sql`
    SELECT id, trip_id, kind, predicate, scope, rationale, hardness, source,
           evidence, expires_at, created_at
    FROM constraints
    WHERE user_email = ${email} AND superseded_by IS NULL
    ORDER BY created_at ASC, id ASC`;

  const key = (r) => JSON.stringify([r.trip_id, r.kind, r.predicate, r.scope || null]);
  const groups = {};
  for (const r of rows) (groups[key(r)] ||= []).push(r);

  const dupes = Object.values(groups).filter((g) => g.length > 1);

  console.log();
  console.log(`${c.b}Duplicate beliefs${c.x}  ${c.d}${email}${c.x}`);
  console.log(`${c.d}${APPLY ? "APPLY" : "DRY RUN"} · ${rows.length} live constraints · ${dupes.length} duplicated${c.x}`);
  console.log(`${c.d}──────────────────────────────────────────────────────────${c.x}`);

  if (!dupes.length) {
    console.log(`  ${c.g}Every belief is held exactly once.${c.x}\n`);
    return;
  }

  let removed = 0;
  for (const g of dupes) {
    // Keep the best-evidenced copy, not merely the oldest: a row carrying a source URL
    // or an expiry knows strictly more than one that doesn't.
    const score = (r) => (r.evidence?.url ? 2 : 0) + (r.expires_at ? 1 : 0);
    const keeper = g.slice().sort((a, b) => score(b) - score(a) || a.id - b.id)[0];
    const losers = g.filter((r) => r.id !== keeper.id);

    console.log(`  ${c.y}×${g.length}${c.x} ${keeper.rationale}`);
    console.log(`      ${c.g}keep${c.x} #${keeper.id} ${c.d}[${keeper.hardness}/${keeper.source}]${keeper.evidence?.url ? " sourced" : ""}${c.x}`);
    for (const l of losers) console.log(`      ${c.d}drop #${l.id} [${l.hardness}/${l.source}]${c.x}`);

    if (APPLY) {
      for (const l of losers) {
        await sql`UPDATE constraints SET superseded_by = ${keeper.id} WHERE id = ${l.id}`;
        // Re-point any satisfies edges at the keeper so no booking loses its reason.
        await sql`
          UPDATE satisfies SET constraint_id = ${keeper.id}
          WHERE constraint_id = ${l.id}
            AND NOT EXISTS (
              SELECT 1 FROM satisfies s2
              WHERE s2.commitment_id = satisfies.commitment_id AND s2.constraint_id = ${keeper.id})`;
        await sql`DELETE FROM satisfies WHERE constraint_id = ${l.id}`;
        removed++;
      }
    } else {
      removed += losers.length;
    }
  }

  console.log(`${c.d}──────────────────────────────────────────────────────────${c.x}`);
  console.log(APPLY
    ? `  ${c.g}${removed} duplicates superseded.${c.x} ${c.d}Nothing deleted; history intact.${c.x}`
    : `  ${c.y}${removed} duplicates would be superseded.${c.x} ${c.d}Re-run with --apply.${c.x}`);
  console.log();
})().catch((e) => { console.error(`${c.r}${e.message}${c.x}`); process.exit(1); });
