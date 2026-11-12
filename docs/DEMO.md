# Public read-only demo

The dashboard can be hosted on its own. The deployment at
[veyrix-khushi491s-projects.vercel.app](https://veyrix-khushi491s-projects.vercel.app)
shows a committed snapshot of real engine output for two local fixtures: a vulnerable
document assistant and a hardened document assistant. It does not run FastAPI,
PostgreSQL, Redis, or the worker, and it never exposes `VEYRIX_DEV_MODE`.

Create, register, run, and triage controls are hidden or disabled. Scores, findings,
and traces come from `veyrix.engine.run_scenario`, `veyrix.scoring.calculate_score`,
and `veyrix.findings.verified_result`. The snapshot covers the 12 local scenarios.
The six MCP stdio scenarios still run through the local worker. They are not part of
this static snapshot. The `llm` adapter is not part of the snapshot either.

## Regenerate the snapshot

From the repository root, after engine, scenario, or scoring changes. Use the project
virtualenv so the command imports the local package:

```sh
make demo-snapshot
```

That writes `apps/web/demo/snapshot.json`. Do not edit scores, findings, or traces in
that file by hand. `tests/test_demo_snapshot.py` checks the file against a fresh run,
`calculate_score`, and `verified_result`.

## Deploy on Vercel

1. Import `https://github.com/khushi491/Veyrix` into a Vercel Hobby project. Do not add a database, Redis, blob store, or any paid integration.
2. Set **Root Directory** to `apps/web`.
3. Framework preset: **Next.js**.
4. Node.js version: **22.x**.
5. Install command: `npm ci` (also set in `apps/web/vercel.json`).
6. Build command: `npm run build` (this is `next build --webpack`, matching CI).
7. Leave the output directory on the Next.js default. Do not set a custom Output Directory.
8. Add environment variable `NEXT_PUBLIC_VEYRIX_DEMO` with value `true` for Production. Add it for Preview as well if preview deployments should be the demo. The value is inlined at **build** time, so change it and redeploy rather than expecting a runtime toggle.
9. Do not set `VEYRIX_DEV_MODE`, `DATABASE_URL`, or `REDIS_URL`.

A Vercel build also turns demo mode on when `VERCEL=1`, even if the variable above
is missing. That keeps `/api` from being rewritten to FastAPI. Local `npm run build`
stays in API mode unless `NEXT_PUBLIC_VEYRIX_DEMO=true`.

## Check the demo build locally

```sh
cd apps/web
NEXT_PUBLIC_VEYRIX_DEMO=true npm run build
npm run start
```

Open http://127.0.0.1:3000. The dev server can use the same variable:
`NEXT_PUBLIC_VEYRIX_DEMO=true npm run dev`.
