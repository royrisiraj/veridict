# VERIDICT — Vercel production-preview deployment

**Don't just trust the warning. Verify the evidence.** Powered by **EVIDENCE//GATE**.

Readiness: ready for a **fixture-backed production preview**, subject to actually building/deploying on Vercel. No push, commit, external deployment, paid resource, public-chain transaction or live-provider call was performed during preparation.

## A. Prerequisites and selected architecture

- GitHub repository `veridict`; import the same repository as two Vercel projects.
- Frontend root **`frontend`**, Next.js, Node **24.x**; existing pnpm **11.24.0** lockfile.
- Backend root **`backend`**, FastAPI, Python **3.12** selected by `.python-version`.
- No database, wallet, API key, external RPC or persistent Python process is required for this preview.
- Choose the free/hackathon-appropriate account settings yourself. Do not enable paid add-ons. Platform usage limits still apply.

```text
Browser → Next.js /api/... → BACKEND_BASE_URL → FastAPI Python Function
                                                ↓
                          packaged reports + separate fixture reference roots
```

The native application needs durable SQLite and independent process-local/development-chain state. The Vercel profile replaces only that storage/anchor lifecycle with immutable, explicitly labeled fixture assets. Collection, canonicalization, leaf hashing, Merkle rules, risk classification and Solidity are preserved. Custom live scanning is disabled on the public preview.

Official guidance verified 10 November 2026:

- [FastAPI entrypoints and lifespans](https://vercel.com/docs/frameworks/backend/fastapi): `app/main.py` exporting `app` is supported. Existing `backend/app/main.py:app` is selected explicitly in `[tool.vercel]`.
- [Python runtime](https://vercel.com/docs/functions/runtimes/python): Python 3.12, `pyproject.toml`, `uv.lock`, ASGI and streaming responses are supported. These support the chosen topology; an actual remote build is still required to establish platform success.
- [Python version selection](https://vercel.com/docs/functions/runtimes/python/python-version): `.python-version` pins 3.12 without changing dependency versions.
- [Package managers](https://vercel.com/docs/package-managers): Vercel supports pnpm; explicitly selecting the repository's version avoids lockfile-version inference selecting a different major.

No extra `requirements.txt`, root package manifest, static export or `vercel.json` is needed. All runtime fixture inputs, passports and references are committed inside `backend/app/demo/`; files outside the backend project root are not required at runtime. These approximately 124 KB of release assets are intentional source inputs, not disposable build output.

Deployment blockers resolved: repository-writable SQLite → read-only release assets; process-local anchors → separate packaged root manifest; outside-root fixtures → backend-contained copies; implicit localhost proxy → required explicit origin; mandatory Docker rehearsal → native CI; ambiguous chain labels → explicit fixture/public/unavailable indicators. Cryptographic primitives, risk rules, dependencies and Solidity were not changed.

## B. Backend project — deploy first

1. In Vercel, choose **Add New → Project → Import Git Repository → veridict**.
2. Name the project, for example, **veridict-api**.
3. Set **Root Directory: `backend`** and **Framework Preset: FastAPI**. Keep automatic Python dependency installation; do not set a Uvicorn start command for a Vercel Function.
4. Keep **Build Command** and **Output Directory** at framework defaults. Do not run the packaging script as a runtime/startup task; assets are already committed and CI checks reproducibility.
5. Set these environment variables for **Production and Preview**:

   | Variable | Value / purpose |
   |---|---|
   | `RUNTIME_MODE` | `serverless` |
   | `CHAIN_MODE` | `demo_fixture` |
   | `LIVE_CHECKS` | `false` |
   | `CORS_ORIGINS` | Optional exact frontend HTTPS origin; server-to-server proxying does not need browser CORS permission |

6. Leave `DATABASE_PATH`, `RPC_URL`, `CONTRACT_ADDRESS`, `CHAIN_ID`, `CHAIN_PRIVATE_KEY`, `OPENAI_API_KEY`, `OPENAI_MODEL`, and `GOOGLE_SAFE_BROWSING_KEY` unset for the preview. Do not copy native `.env` wholesale into Vercel.
7. Publish through the Vercel dashboard after reviewing the code. Record the stable backend production origin, such as `https://your-veridict-api.vercel.app`.
8. Visit **`https://<backend-domain>/health`**. Expected fields include:

```json
{
  "status": "ok",
  "service": "veridict-api",
  "version": "1",
  "chain_connected": false,
  "contract_address": "",
  "chain_mode": "fixture",
  "runtime_mode": "serverless",
  "verification_mode": "DEMO_FIXTURE",
  "live_scanning_enabled": false,
  "report_storage": "packaged-read-only"
}
```

The endpoint uses no AI, feed download or RPC call. False chain connectivity is expected in this profile. `UNAVAILABLE` means the verification source/configuration needs correction.

**Deployment Protection:** a protected backend can return a Vercel login page instead of API JSON. For the intended public demo, configure backend access accordingly. If retaining Deployment Protection, create an automation bypass secret in Vercel and set it only as frontend **`BACKEND_PROTECTION_BYPASS`**. The proxy sends `x-vercel-protection-bypass` server-side. Never put the bypass secret in a URL, browser script or `NEXT_PUBLIC_` variable. Direct health/smoke requests must also be authorized using your approved Vercel access method; the unauthenticated smoke script expects public origins.

## C. Frontend project — same repository

1. Import `veridict` again as a separate project, for example **veridict**.
2. **Root Directory: `frontend`**; **Framework Preset: Next.js**; **Node.js: 24.x**.
3. Use these explicit version-pinned commands, which invoke the existing scripts and lockfile:

   | Setting | Value |
   |---|---|
   | Install Command | `npx --yes pnpm@11.24.0 install --frozen-lockfile` |
   | Build Command | `npx --yes pnpm@11.24.0 build` |
   | Output Directory | Leave default; do not enter `out`, `dist` or `.next/standalone` |

4. Set **`BACKEND_BASE_URL=https://<backend-domain>`** in both Production and Preview. Use an origin only: no `/api`, trailing path, query, embedded credentials or frontend URL. Optional `BACKEND_PROTECTION_BYPASS` stays server-side.
5. Keep AI keys, RPC credentials, signer keys and `DATABASE_PATH` out of the frontend project. There is no required `NEXT_PUBLIC_` setting.
6. Deploy through the dashboard. Open **`https://<frontend-domain>`**. The page must display:

   > Demo fixture mode — public blockchain anchoring is not enabled.

7. Confirm `/api/health` returns the backend's `DEMO_FIXTURE` state. The browser should only request same-origin `/api/...`; the server connects to the backend. `BACKEND_URL` remains an explicit legacy alias, but the documented deployment setting is `BACKEND_BASE_URL`.

The frontend build performs no backend request. Home and report data are fetched at runtime. `/report/[id]` remains a dynamic App Router route; static export is incompatible with this proxy and must stay disabled. Existing standalone output is usable for native smoke tests; Vercel's Next.js framework preset handles deployment output itself.

A frontend-only import can build and show the application shell without backend configuration. It cannot investigate or verify: missing `BACKEND_BASE_URL` deliberately returns a clear 503 and loading/failure states. Deploy Project B for the functional fixture demo; no frontend-only successful reports are fabricated.

## D. First-deployment verification

After you deploy both projects, run from the repository root in PowerShell:

```powershell
.\.tools\bin\uv.exe run --directory backend python ../scripts/deployment_smoke.py --frontend-url https://YOUR-FRONTEND.vercel.app --backend-url https://YOUR-BACKEND.vercel.app
```

With global uv, replace `.\.tools\bin\uv.exe` with `uv`. The script requires explicit origins and has no localhost default. It checks the homepage, independent backend health, frontend API proxy, six cases, expected verdicts including `INCONCLUSIVE`, report route/data, reference-root verification, TLS tampering and clean recovery. It does not deploy, sign transactions, call paid AI or contact fixture destinations. The report HTML check establishes a route/shell response; browser rendering is a separate check.

Browser checks:

1. Click suspicious-1. The gate shows recorded fixture inspection, a deterministic verdict, and the fixture-reference label.
2. Open the Evidence Passport. Confirm real evidence cards/citations, reference root, **no transaction**, and `PUBLIC-CHAIN ANCHOR: NOT ENABLED`.
3. Verify independently. `SUPPORTED` means the candidate matches the packaged release reference and its claims are grounded.
4. Change the TLS fingerprint (`TAMPERED`), remove threat intelligence (`NOT_SUPPORTED` and root mismatch), alter a redirect, and inject a missing citation. Reset after each; the source report must remain unchanged.
5. Copy the fixture report URL into a new browser session and refresh. Its stable ID is a packaged asset, so another invocation can retrieve it.
6. Confirm benign-1 is `LOW_RISK` and benign-3 is `INCONCLUSIVE`. Unavailable intelligence has `matched: null`.
7. In browser Network tools, confirm requests use your frontend origin, with no `localhost:8000`, `127.0.0.1:8000`, `backend:8000` or local Hardhat endpoint.
8. Check frontend deployment settings and downloaded client chunks for accidental secrets. The local browser test injects a server-only canary and verifies it is absent from client chunks. This does not substitute for checking your actual Vercel secret configuration.
9. A preview with no `BACKEND_BASE_URL` must show a configuration error, never a successful report. Do not remove the variable from the working production project merely to test this; use a separate preview configuration if needed.

**No remote Vercel smoke has been executed by the coding agent.** Run this section after your authorized deployment.

## E. Environment modes and public blockchain honesty

| Capability | Selected Vercel preview | Existing native runtime |
|---|---|---|
| Six deterministic cases | Yes, read-only release assets | Yes, existing pipeline |
| Custom URL/message investigation | Disabled, returns 403 | Existing collector pipeline; optional live checks |
| AI explanations | Explicit deterministic fixture synthesis | Optional configured OpenAI model, with grounding/retry/fallback |
| Live threat intelligence | No | OpenPhish cache and optional Google provider |
| Merkle integrity and claim grounding | Yes, independently fetched packaged references | Existing reference/EVM verification |
| Public blockchain transactions | No | Only with real configured public registry, signer and RPC |
| On-chain verification | No | Real RPC readback for actual EVM receipts |
| Shareable report links | Six stable fixture links, stable within the release | SQLite history, subject to original anchor availability |
| New durable/live report storage | No | Existing SQLite on a persistent native filesystem |

The fixture root manifest is a trusted deployment reference, not a public blockchain. A missing manifest/root produces unavailable verification. Runtime code cannot register new roots in this read-only adapter. No function invocation silently creates a memory registry and advertises it as a chain.

Existing native environment names remain supported:

| Category | Variables / behavior |
|---|---|
| Runtime/origins | `RUNTIME_MODE=native`, `CORS_ORIGINS`; `DATABASE_PATH` for existing durable native SQLite |
| Optional AI | `OPENAI_API_KEY` and `OPENAI_MODEL`; absent values use labeled deterministic synthesis |
| Intelligence | `LIVE_CHECKS`, `OPENPHISH_CACHE_PATH`, `OPENPHISH_CACHE_MAX_AGE`, optional `GOOGLE_SAFE_BROWSING_KEY` |
| Public EVM | `CHAIN_MODE=public_chain`, HTTPS `RPC_URL`, `CONTRACT_ADDRESS`, expected numeric `CHAIN_ID`, `CHAIN_PRIVATE_KEY` |
| Local EVM | Existing `CHAIN_MODE=evm`; never point a Vercel deployment to a development RPC |
| Explicit unavailable | `CHAIN_MODE=unavailable`; no new roots or supported assurances |

Public-chain mode requires a real deployed compatible registry, matching chain ID and server-side funded signer because the current pipeline registers reports. The adapter checks code/chain before use and reads actual roots; receipts are real. No public-chain deployment or transaction was attempted here. In the serverless profile, selecting `evm`/`public_chain` yields **UNAVAILABLE**, rather than pretending that new live reports have durable storage. Keep this preview in `demo_fixture` mode.

Do not enable public-chain/live registration on this serverless preview by just adding secrets. A durable report-storage design and appropriate public-scanner abuse controls would be required. They are intentionally outside the deadline changes. No database, authentication service, queue or alternate cloud infrastructure was introduced.

## F. Troubleshooting

| Symptom | Check / correction |
|---|---|
| Backend 404, including `/health` | Project root must be `backend`, framework FastAPI, entrypoint `app.main:app`. No `/api` prefix on `/health`. |
| Frontend report/API 404 | Root must be `frontend`, preset Next.js, output default, no static export. Report IDs must be one of the returned stable fixture IDs. |
| Backend 500 or import error | Read Vercel logs. Python must be 3.12, `pyproject.toml` and `uv.lock` present. Do not launch Uvicorn inside the function. |
| Missing dependencies | Use framework-managed Python installation. Do not point backend build at frontend packages or add an unrelated requirements file. Check platform Linux wheel/build errors explicitly. |
| Frontend install/build failure | Node 24; use the pinned pnpm install/build commands above and frozen committed lockfile. Build needs no running backend. |
| Missing fixture/passport files | Commit all `backend/app/demo/inputs`, `reports`, and `reference-roots.json`. Run `python scripts/package_demo.py --check` from backend. No files outside project root are needed at runtime. |
| Backend URL missing/invalid | Proxy returns JSON 503. Set `BACKEND_BASE_URL` to the backend HTTPS origin and redeploy that frontend environment. No localhost fallback exists in the route handler. |
| Backend returns HTML, 401 or 403 | Check project domain and Deployment Protection. Configure public API access or the server-only bypass header secret. Proxy does not follow redirects to login pages. |
| 502/504 or timeout | Inspect backend health/logs, cold starts, protection, domain reachability and platform function limits. Proxy has a 55-second upstream deadline; fixture calls should be short. |
| CORS failure | Browser should call frontend `/api`, not backend directly. If direct backend use is intended, set exact allowed frontend origins; avoid wildcard credentials policies. |
| Report missing after refresh | This profile supports only six packaged stable IDs. It does not store newly submitted live reports. Unknown IDs return 404. Native memory-generated IDs are not hosted assets. |
| RPC error or missing contract | Do not set local RPCs on Vercel. Selected preview needs no RPC. Native public mode requires correct HTTPS endpoint, chain ID, deployed bytecode, signer and funding. |
| `UNAVAILABLE` instead of fixture checks | Set serverless + demo_fixture; check reference manifest packaging. Do not turn this into a successful state by trusting the submitted report root. |
| Threat intelligence times out | Native collector coverage stays unavailable/failed and `matched: null`. Missing intelligence never implies safe. Hosted fixture benign-3 demonstrates this honestly. |
| Cold start | Python imports/crypto dependencies may add latency. Loading/error states remain visible; retries do not fabricate success. No warm-instance affinity is required. |
| Oversized requests | Frontend proxy and backend reject JSON bodies over 512 KiB, including chunked requests, before parsing. |

Health exposes non-sensitive mode indicators; it is not a live RPC liveness probe. Hosted scanning/AI spending is disabled. Consider platform firewall/access restrictions if the public endpoint receives abuse; no paid controls were provisioned here.

## G. Local checks and release commands

Native Windows validation, without Docker or an EVM node:

```powershell
backend\.venv\Scripts\python.exe -m pytest -q backend/tests
backend\.venv\Scripts\python.exe backend/scripts/package_demo.py --check
backend\.venv\Scripts\python.exe backend/scripts/export_openapi.py --check
pnpm.cmd --dir frontend schema:check
pnpm.cmd --dir frontend typecheck
pnpm.cmd --dir frontend lint
pnpm.cmd --dir frontend build
pnpm.cmd --dir frontend test:deployment
```

`test:deployment` starts the standalone production Next.js server and a read-only serverless-profile FastAPI process on loopback, opens a real browser, verifies refresh/tamper/reset and checks same-origin networking plus a client-secret canary. This is local runtime validation, not a remote Vercel deployment. Required CI retains backend/contract tests, schema validation, typecheck, lint, build and browser tests, with no container dependency.

Preparation checks actually executed on Windows, 10 November 2026:

| Check | Result |
|---|---|
| Backend pytest, including native regressions and new serverless cases | 116 passed |
| Packaged fixture reproducibility | Passed for all six reports and reference roots |
| OpenAPI export and frontend generated-type drift | Passed |
| Frontend typecheck, ESLint and production build | Passed without a build-time backend dependency |
| Existing browser regressions | 4 passed |
| Serverless-profile production browser smoke | 1 passed; stable refresh, tamper/reset, no public-chain claim, same-origin calls, server-only canary absent from client chunks |
| URL-based deployment smoke | Passed against explicit local origins for all six fixtures |
| Missing backend configuration on a separate production server | Correct HTTP 503 JSON; no localhost fallback |
| Changed-file secret patterns / unwanted generated artifacts / staged files | No findings; no staged files |
| Solidity/contract tests | Not rerun: contract sources/dependencies and Merkle/risk/canonical primitives are unchanged |
| Actual Vercel build, public URL smoke, live providers, public-chain deployment | Not executed; no external deployment authorization |

When root fixtures or pipeline outputs legitimately change, regenerate release assets with `backend\.venv\Scripts\python.exe backend/scripts/package_demo.py`, review the changes, then rerun its drift check. The cryptographic schema identifier remains `sealed-evidence/1`.

Review and run these Git commands **yourself**. None was executed by the coding agent:

```powershell
git status --short
git diff --check
git diff
git add -- .env.example .gitignore .github/workflows/ci.yml README.md VERCEL_DEPLOYMENT.md backend frontend scripts
git diff --cached --stat
git diff --cached
git commit -m "Prepare honest Vercel fixture preview deployment"
git push origin HEAD
```

Review staged files for secrets and generated artifacts before committing. `.env`, `.env.local`, `.vercel`, caches, dependencies, test output and `.next` are ignored. Then import/deploy backend first and frontend second using sections B/C; run section D against the resulting public URLs.
