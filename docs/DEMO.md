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

## Always-on red-team kit

`/kit` is the public readout of the GitHub Action. It shows the latest scan of the
deliberately vulnerable local fixture beside the hardened fixture: score, verified
findings, one full ordered evidence trace, engine version, scoring version, and the
scan time. The vulnerable fixture is a sample target. The findings are not
vulnerabilities in the Veyrix product.

Freshness does not commit to `main` and does not need a new secret or a Vercel
deploy hook.

1. [`.github/workflows/veyrix-scan.yml`](../.github/workflows/veyrix-scan.yml) already
   scans both fixtures on pull requests, daily at `17 6 * * *` UTC, and
   `workflow_dispatch`.
2. The `publish-kit-scan` job runs only for that schedule or a manual run when the
   ref is `refs/heads/main`. It wraps the two JSON artifacts and pushes `latest.json`
   to the branch `kit-scans`. The push refspec is `refs/heads/kit-scans`. Pull
   requests do not publish.
3. The job uses the built-in `GITHUB_TOKEN` with `contents: write`. There is no
   repository secret to create. If the token cannot create that branch, the job
   records the failure and the workflow stays green (`continue-on-error`). The page
   keeps working.
4. The dashboard fetches
   `https://raw.githubusercontent.com/khushi491/Veyrix/kit-scans/latest.json`
   and revalidates it every 15 minutes. A publication for the same commit as the
   deployment is preferred. Otherwise a newer publication is used when the engine
   and scoring versions match. Links in that file are shown only when they point
   at this repository or GitHub's code-scanning docs.
5. If the fetch fails, the file is invalid, or it is older than the copy shipped
   with the deployment, `/kit` renders `apps/web/demo/kit-scan.json`. That file is
   `veyrix scan` output. Regenerate it with `make kit-snapshot` after engine or
   scoring changes. Do not edit scores or traces by hand.
6. On Vercel (`VERCEL=1`), the web build also tries to run `veyrix scan` when the
   repository root and Python 3.12 are available. Install or scan failures are
   logged and ignored. The Hobby project root is `apps/web`. If files outside that
   directory are not visible to the build, this step skips. It is optional. The
   scheduled JSON is the freshness path.

Nothing else has to be created. After this workflow is on `main`, the next scheduled
run or a `workflow_dispatch` on `main` creates `kit-scans`. Until then the committed
snapshot is the page. `VEYRIX_DEV_MODE` is not set on the deployment.

## Check the demo build locally

```sh
cd apps/web
NEXT_PUBLIC_VEYRIX_DEMO=true npm run build
npm run start
```

Open http://127.0.0.1:3000. The dev server can use the same variable:
`NEXT_PUBLIC_VEYRIX_DEMO=true npm run dev`.
