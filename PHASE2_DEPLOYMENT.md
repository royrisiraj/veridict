# VERIDICT Phase 2 release

This upgrade preserves the six packaged Evidence Passports, existing Merkle rules,
`sealed-evidence/1`, contract ABI, deterministic verdicts and Tamper Studio.
It adds an opt-in live rollout, private durable storage, read-only Sepolia checks,
and a separately protected registration operation. It does not deploy anything.

## Milestone 1: private storage, Preview first

The user has created private store **`veridict-blob`**, connected to backend
project **`veridict`**, with environment prefix **`BLOB`** and connections for
Production and Preview. Frontend project is **`veridict-f`**. These are the current
project names; older implementation notes below refer to the earlier backend
label `veridict-api`. The Alchemy Sepolia endpoint is available to the user, but
no deployment wallet/contract is ready and neither is needed for this milestone.

### Configure only the Preview environment now

In **`veridict` -> Settings -> Environment Variables**, select **Preview**:

| Variable | Exact setting | Classification |
|---|---|---|
| `RUNTIME_MODE` | `serverless` | Required setting |
| `REPORT_STORAGE` | `vercel_blob` | Required setting |
| `CHAIN_MODE` | `demo_fixture` | Required setting; no RPC activity |
| `LIVE_CHECKS` | `false` | Required safety setting |
| `ANCHOR_ENABLED` | `false` | Required safety setting |
| `CORS_ORIGINS` | Exact frontend Preview HTTPS origin, comma-separated if more than one; no wildcard | Explicit origin policy; same-origin proxy does not rely on CORS |
| `BLOB_READ_WRITE_TOKEN` | Keep the private token injected by the connected `veridict-blob` store | Required backend secret for this token-based profile |

The existing pinned Python SDK explicitly resolves **`BLOB_READ_WRITE_TOKEN`**.
`BLOB` is the correct environment prefix; the code does not read a variable named
`BLOB`, and no alias or `NEXT_PUBLIC_` variable is required. Verify that the token
exists for Preview without revealing/copying its value into chat. Do not add
`BLOB_STORE_ID` for this profile: with a Vercel OIDC identity present, setting it
would select OIDC ahead of the token. OIDC remains supported for a later deliberate
configuration; no application change is necessary for read/write-token support.

Leave these **unset in Preview** for Milestone 1: `RPC_URL`, `CHAIN_ID`,
`CONTRACT_ADDRESS`, `CHAIN_PRIVATE_KEY`, `ANCHOR_API_SECRET`, `SEPOLIA_RPC_URL`,
`SEPOLIA_PRIVATE_KEY`, `SCAN_API_SECRET`, and `SCAN_ALLOWED_HOSTS`. Optional
`OPENAI_API_KEY` + `OPENAI_MODEL`, `GOOGLE_SAFE_BROWSING_KEY`, cache settings and
scan/anchor limit overrides are unnecessary while collection/signing are disabled.
Do not change an existing Production setting as part of this Preview preparation.

In **`veridict-f` -> Settings -> Environment Variables**, select **Preview**:

| Variable | Exact setting | Classification |
|---|---|---|
| `BACKEND_BASE_URL` | Backend **Preview** HTTPS origin copied from its deployment, with no path/query/credentials | Required server-side setting |
| `BACKEND_PROTECTION_BYPASS` | Backend project's automation-bypass secret, only if its Preview deployment is protected | Conditional server-only secret |

Do not point Preview at the Production backend. No Blob token, RPC key, signing
key, OpenAI key or `NEXT_PUBLIC_` variable belongs in `veridict-f`. Keep
`SCAN_API_SECRET` unset there for this milestone. Backend root remains `backend`,
entrypoint `app.main:app`, Python 3.12; frontend root remains `frontend`, Node 24,
Next.js, build `pnpm build` and install `pnpm install --frozen-lockfile`.

### Safe actual-store persistence test

There are **no local Blob credentials configured in this session**. Store creation
and connection have been reported by the user, but a real write/read is not yet
verified. Configure the token privately in an operator PowerShell session, without
putting its value in command history or output:

```powershell
$env:BLOB_READ_WRITE_TOKEN = [System.Net.NetworkCredential]::new('', (Read-Host 'Private Blob read/write token' -AsSecureString)).Password
backend\.venv\Scripts\python.exe backend/scripts/storage_smoke.py
Remove-Item Env:BLOB_READ_WRITE_TOKEN
```

This writes one **unique, clearly fixture-labelled diagnostic passport** cloned
from benign-1 plus its independent reference using the real `BlobReportStore`.
It preserves the six source reports, does no live collection, and cannot sign or
contact Sepolia. A separate Python process retrieves the private passport and
reference and verifies Merkle proofs/claim grounding. By default the script
conditionally deletes only the two objects it created, using their write ETags.
A failed write/read/cleanup exits nonzero; no success is inferred from credentials
being present. An interrupted/ambiguous upload may need private operator cleanup.

For the Preview permalink acceptance test, deliberately retain the diagnostic:

```powershell
backend\.venv\Scripts\python.exe backend/scripts/storage_smoke.py --keep-report
```

It prints only the public report ID/root, fixture provenance and lack of public
anchoring, not credentials/Blob URLs/evidence. With the Preview backend configured,
open `/api/reports/<printed-id>` on that backend and `/report/<printed-id>` on the
Preview frontend. Reload and open in another browser. Verification must say
`SUPPORTED` for integrity/grounding and `NOT_CONFIGURED` for public anchoring.
The report is a **storage diagnostic using fixture observations**, not a live scan.
`--keep-report` intentionally leaves the diagnostic available; do not blindly
delete real report/reference paths when removing it later.

The Preview/Production connections currently use the **same store**; application
paths have no environment namespace. Diagnostic IDs are unique, but storage and
future quota/control objects are shared. This milestone does not create leases,
consume scan/signing quotas or modify existing reports. Production traffic stays
on its known-good deployment while Preview is tested.

### Preview release and acceptance sequence (only after deployment approval)

1. Record the current known-good Production deployment URLs/IDs in both projects.
   Keep Production code, variables and aliases unchanged. Local changes are not
   published by configuring environment variables alone.
2. Obtain approval for a Preview release of the reviewed changes. Use the approved
   non-production branch/ref or an explicitly approved Preview deployment; do not
   push to the production branch or use a production deployment command.
3. Deploy backend project `veridict` to **Preview**, with the settings above.
4. Open its `/health`. Expected fields after a successful authenticated Blob read:

   ```json
   {
     "status": "ok",
     "service": "veridict-api",
     "runtime_mode": "serverless",
     "report_storage": "vercel_blob",
     "live_scanning_enabled": false,
     "chain_connected": false,
     "verification_mode": "DEMO_FIXTURE"
   }
   ```

   `report_storage="unavailable"` means the storage read/auth check failed. A 200
   health response alone does not prove write permissions or durable persistence;
   the actual-store smoke above is mandatory for that claim. Health includes
   additional fields, and fixture mode is intentional during this milestone.
5. Set frontend `BACKEND_BASE_URL` to that backend Preview origin, and configure
   its backend protection bypass if needed. Deploy `veridict-f` to Preview after
   approval. Add its exact origin to backend Preview CORS settings; a changed
   deployment setting requires a new deployment to take effect.
6. Check frontend `/api/health`, six fixture launchers, benign-3 INCONCLUSIVE,
   passport refresh/deep link, all four tamper mutations/reset, and custom input
   remaining disabled. Use the retained diagnostic for genuine durable API and
   cross-browser report retrieval without enabling live scanning.
7. Optional automated fixture smoke against the explicit Preview origins:

   ```powershell
   backend\.venv\Scripts\python.exe scripts/deployment_smoke.py --frontend-url $env:FRONTEND_PREVIEW_URL --backend-url $env:BACKEND_PREVIEW_URL
   ```

   If protection blocks automation, set private operator environment variables
   `FRONTEND_PROTECTION_BYPASS` and/or `BACKEND_PROTECTION_BYPASS` before this command.
   These are sent as headers only to their exact configured origins; frontend
   and backend bypass values can differ. The frontend project's application only
   needs the **backend** bypass. Alternatively validate manually in an authenticated
   browser. Never place a bypass token in a URL or disable protection to mask errors.
8. Only after these checks, separately approve Production activation. Update
   Production with the same storage-only flags, its actual frontend CORS origin
   and Production backend URL, then release backend before frontend. No live
   scanning or Sepolia enablement is part of Milestone 1. Do not blindly promote
   an artifact whose server environment still targets Preview.

### DNS diagnosis and immediate rollback

Run `backend\.venv\Scripts\python.exe backend/scripts/dns_diagnostics.py` for a
bounded **DNS-only** comparison against example.com. Local results, including an
outside-sandbox run: Windows `getaddrinfo` returned public IPv4/IPv6 addresses;
direct dnspython **UDP and TCP A/AAAA queries timed out** at configured resolvers.
This narrows the issue to the local direct-resolver path; VPN/firewall policy,
system encrypted DNS or OS caching are possibilities, not confirmed causes.
It does not prove Vercel has the same issue. No alternative resolver, OS fallback,
cached answer, weaker IP validation, or unpinned connection was introduced.
Blob uses the SDK's HTTPS client path; collector DNS failure does not by itself
prove Blob is unreachable. Actual Blob read/write still requires its own test.
Keep `LIVE_CHECKS=false` until the later controlled collector milestone.

If Preview fails, leave it unpromoted: Production is unaffected. If a later
Production rollout fails, use each project's known-good Production deployment
**Instant Rollback** action and restore the matching frontend/backend pair.
Frontend rollback prevents it retaining the wrong backend origin. Do not delete
Blob data or the store. An environment-only rollback profile for a newly approved
deployment is `REPORT_STORAGE=packaged`, `CHAIN_MODE=demo_fixture`,
`RUNTIME_MODE=serverless`, `LIVE_CHECKS=false`, `ANCHOR_ENABLED=false`; this takes
effect only after deployment and is slower than switching back to a known-good
artifact. Dashboard environment changes alone do not alter a running deployment.

References: [Vercel private storage](https://vercel.com/docs/vercel-blob/private-storage),
[environment variables](https://vercel.com/docs/environment-variables),
[automation bypass](https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation),
[Production rollback](https://vercel.com/docs/deployments/rollback-production-deployment).

## Current release status

- No confirmed Sepolia deployment artifact was found. `runtime/deployment.json`
  describes chain **31337**, not Sepolia. No public contract address, deployment
  transaction or deployment block is available from this implementation session.
- No Blob store, RPC credential, signer or scan secret was configured locally.
  Provider mocks verify behavior, not real Blob persistence or Sepolia connectivity.
- The fixture demonstration remains available without these credentials.
- Production services remain at their previously deployed version until you
  authorize publication and redeploy. No push, cloud deployment, contract
  deployment, or on-chain registration was performed.
- The local live probe could not resolve example.com: configured DNS servers
  timed out, including outside the sandbox. Actual collection in Vercel remains
  a required release check. Do not describe it as tested successfully.

Validation recorded on **2026-11-11**:

| Check | Actual result |
|---|---|
| Backend `python -m pytest -q` inside `backend` | **129 passed** (one existing dependency deprecation warning) |
| Hardhat `npm.cmd --prefix contracts test` | **6 passed**, including Python/OpenZeppelin parity |
| Sepolia deployment/fixture script TypeScript check | Passed, no RPC or transactions |
| `package_demo.py --check` | All six packaged reports/inputs/reference roots unchanged |
| OpenAPI export + frontend schema drift check | Passed |
| Frontend typecheck / ESLint / production build | Passed |
| Native `pnpm.cmd --dir frontend test:e2e` | **4 passed** |
| Hosted-profile `pnpm.cmd --dir frontend test:deployment` | **2 passed**; Windows sandbox required manual cleanup of its two test server processes after assertions |
| Existing public deployment fixture smoke | **Passed** homepage, health, proxy, all six verdicts, passport routes/data, tamper/reset; current mode **DEMO_FIXTURE** |
| Actual Blob SDK with no credentials | Honest unavailable-storage health; live disabled; fixture request still succeeds |
| Real public DNS/HEAD/TLS/feed collector probe | **Not passed**: configured DNS timed out, including outside sandbox |
| Actual private Blob round trip / Sepolia RPC / chain transactions | **Not run**: credentials/store/deployment absent |
| Focused changed-file credential scan | No credential-pattern matches; no staged changes, push, commit or deployment |

## Architecture and trust boundaries

```text
Browser -> Next.js /api/* -> FastAPI app.main:app
                           |-> pinned public DNS/HEAD/TLS collectors
                           |-> OpenPhish + optional Safe Browsing
                           |-> deterministic verdict + grounded explanations
                           |-> immutable private Blob passport + separate reference
                           `-> Sepolia registry reads (no signer required)

Operator -> protected FastAPI /anchor -> durable signing intent/lease/budget
                                     -> actual Sepolia transaction
                                     -> receipt + registry root readback
```

Scanning **does not register a transaction** in the hosted runtime. A new passport
has `chain_receipt.mode=unanchored` and nullable transaction fields. `SUPPORTED`
means its evidence/proofs and grounding match its independent release/Blob
reference; `public_chain_status` separately reports `VERIFIED`, `MISMATCH`,
`NOT_ANCHORED`, `UNAVAILABLE`, or `NOT_CONFIGURED`. Blob references are trusted
application records, not a public blockchain or protection against a malicious
storage administrator. A seal or transaction proves integrity, never factual truth.

## 1. Native prerequisites

Use Python 3.12, Node 24, pnpm 11.24.0 and the committed lockfiles. No Docker/WSL.
From the repository root:

```powershell
.tools\bin\uv.exe sync --project backend --frozen
npm.cmd ci --prefix contracts
pnpm.cmd --dir frontend install --frozen-lockfile
```

If the local uv bootstrap is absent, use your existing `uv` installation with the
same arguments. Example environment files are documentation, not automatically
loaded by these Python/Hardhat scripts. Supply credentials through your local
private environment or an approved secret manager; never paste them into chat,
commit them, or enable shell tracing. `.env*`, `.vercel/` and `runtime/` are ignored.

## 2. Prepare and authorize the existing contract deployment

Create a **dedicated testnet-only wallet**, fund it with Sepolia test ETH, and
configure `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY` privately on the operator
workstation. Do not use a wallet with real funds. The network is Ethereum Sepolia,
chain ID **11155111**. Backend reads use the separate existing names `RPC_URL`,
`CHAIN_ID` and `CONTRACT_ADDRESS`.

The Hardhat 3 HTTP network uses lazy configuration variables. No keys are needed
for ordinary compilation or tests. Existing Ignition modules remain usable;
the guarded script additionally creates a real deployment manifest and readback.

**Obtain explicit deployment approval before executing the following command.**
The approval guard is intentionally absent from all environment examples:

```powershell
$env:CONFIRM_SEPOLIA_DEPLOY='11155111'
npm.cmd --prefix contracts run deploy:sepolia
Remove-Item Env:CONFIRM_SEPOLIA_DEPLOY
```

The script checks chain ID, balance, estimated deployment gas, and `MAX_DEPLOY_ETH`
(default `0.02` test ETH), caps the submitted gas/price, waits for two confirmations,
checks bytecode and an ABI read, and writes `runtime/sepolia-deployment.json`.
It refuses to overwrite an existing deployment manifest. After an interruption,
inspect the deployer's Sepolia transaction history before retrying; never deploy
another registry merely because a local manifest is missing.

The successful manifest provides actual `contract_address`, `tx_hash`,
`block_number`, timestamp, ABI reference and `bytecode_confirmed`. Publish those
public values after the real deployment. Explorer forms:

```text
https://sepolia.etherscan.io/address/<actual-contract-address>
https://sepolia.etherscan.io/tx/<actual-transaction-hash>
```

## 3. Anchor the unchanged six fixture passports

The registration script reads **existing** packaged report IDs, bundles and roots.
Python recomputes every root; Ethers independently checks typed leaves and proofs.
It preflights all six IDs for conflicts before submitting anything. Existing
matching records are skipped; mismatches stop the script. Successful registrations
are read back and recorded with their actual transaction/block details.

After separate approval to send fixture registration transactions:

```powershell
$env:CONFIRM_SEPOLIA_ANCHOR='11155111'
npm.cmd --prefix contracts run anchor:fixtures
Remove-Item Env:CONFIRM_SEPOLIA_ANCHOR
```

Default aggregate estimated gas budget: `MAX_FIXTURE_ANCHOR_ETH=0.02` test ETH.
Output: `runtime/sepolia-fixtures.json`. Reports, timestamps and fixtures are not
regenerated. Re-running confirmed registrations is idempotent. If interrupted
with a pending transaction, wait for its outcome before retrying.

## 4. Connect PRIVATE Vercel Blob storage

The user has created/connected private store `veridict-blob` to backend Vercel
project **`veridict`**. No store has been created by this code change; the real
connection has not been tested from this local session. Check account allowances before enabling
usage; no paid resources or charges are authorized by this release.

Backend storage uses the official `vercel-blob==0.5.1` Python SDK's public API:
`from vercel.blob import sync`. It requests `access="private"`, fixed pathnames,
and `allow_overwrite=False` on every write. SDK authentication prefers the Vercel
OIDC identity plus **`BLOB_STORE_ID`** when available; configure the connected
project/store permissions for that identity. The SDK falls back to
**`BLOB_READ_WRITE_TOKEN`** (also supports `VERCEL_BLOB_READ_WRITE_TOKEN`) when
OIDC is unavailable. Do not manually generate or hardcode OIDC JWTs. Local tooling
normally uses a private read/write token. Neither credentials nor Blob URLs are
sent to the browser.

Set `REPORT_STORAGE=vercel_blob`. A report is stored at
`veridict/v1/reports/<report-id>.json`, its trusted reference at
`veridict/v1/references/<report-id>.json`, and confirmed receipt metadata at
`veridict/v1/anchors/<report-id>.json`. Keys are immutable. Conflicts/outages fail
explicitly; no memory or `/tmp` fallback pretends to save a live report. New
instances read the same private objects. Packaged fixtures are checked first.

Before claiming persistence works, test the **actual connected store** with local
credentials (this creates/removes one small private probe object, not a store):

```powershell
backend\.venv\Scripts\python.exe backend/scripts/phase2_probe.py --storage-write-check
```

After real fixture registration, import validated public receipt metadata into
private storage (no chain transactions):

```powershell
backend\.venv\Scripts\python.exe backend/scripts/sync_anchor_manifest.py runtime/sepolia-fixtures.json
```

Configure `RPC_URL`, `CHAIN_ID=11155111`, `CONTRACT_ADDRESS` and Blob credentials
for this command. It validates each root and transaction before writing metadata.
Without imported metadata, actual registry roots can still verify, but no
transaction hash/block is invented for the UI.

## 5. Backend Vercel settings

Keep Root Directory **`backend`**, FastAPI/Python preset, Python **3.12**, existing
`pyproject.toml` + `uv.lock`, and entrypoint **`app.main:app`**. No Uvicorn process,
Hardhat service, custom output directory or Docker startup is needed. Set the
function duration to at least 60 seconds using available project settings; avoid
enabling a paid plan just for this change. Collection has a 45-second application
deadline; individual network operations are bounded. Provider SDK requests may
outlive a disconnected caller, so abandoned durable leases fail closed.

| Variable | Fixture rollback | Controlled live rollout | Sepolia reads / operator anchor |
|---|---|---|---|
| `RUNTIME_MODE` | `serverless` | `serverless` | `serverless` |
| `CHAIN_MODE` | `demo_fixture` | `demo_fixture` until registry ready | `public_chain` |
| `REPORT_STORAGE` | `packaged` | `vercel_blob` | `vercel_blob` for live receipts/signing |
| `LIVE_CHECKS` | `false` | `true` | Independent of chain reads |
| `CORS_ORIGINS` | Frontend HTTPS origin | Same | Same |
| `BLOB_STORE_ID` | Unset | Connected private store ID for OIDC | Same |
| `BLOB_READ_WRITE_TOKEN` | Unset | Fallback if OIDC unavailable | Same |
| `SCAN_API_SECRET` | Unset | Random server-side secret, at least 32 characters | Same |
| `SCAN_ALLOWED_HOSTS` | Unset | `example.com,www.wikipedia.org` initially | Same |
| `SCAN_HOURLY_LIMIT` | Default 20 | Global durable scan budget, max 100 | Same |
| `SCAN_CLIENT_LIMIT` | Default 5 | Per-client hourly budget, max 20 | Same |
| `RPC_URL` | Unset | Optional until chain enabled | Private HTTPS Sepolia RPC |
| `CHAIN_ID` | Unset | Optional | `11155111` |
| `CONTRACT_ADDRESS` | Unset | Optional | Actual deployed EvidenceRegistry |
| `OPENAI_API_KEY`, `OPENAI_MODEL` | Optional | Optional, both required to request AI | Same |
| `GOOGLE_SAFE_BROWSING_KEY` | Optional | Optional | Same |
| `OPENPHISH_CACHE_MAX_AGE` | Default 86400 | Warm-process feed TTL | Same |
| `ANCHOR_ENABLED` | `false` | `false` initially | `true` only after operator approval |
| `ANCHOR_API_SECRET` | Unset | Unset | Separate random operator secret, >=32 chars |
| `CHAIN_PRIVATE_KEY` | Unset | Unset | Dedicated Sepolia signer; optional for reads |
| `ANCHOR_DAILY_LIMIT` | Default 6 | Not used | 1–20 attempted transactions/day |
| `ANCHOR_MAX_FEE_GWEI` | Default 20 | Not used | 1–100 gas-price cap |
| `ANCHOR_MAX_GAS` | Default 150000 | Not used | 50000–200000 gas cap |

Do not set `OPENPHISH_CACHE_PATH` to a supposedly durable deployment file.
Hosted OpenPhish uses a TTL-limited warm-process cache, downloads a bounded public
feed on cold starts, and returns failed/timeout + `matched:null` if unavailable.
No feed fallback or optional API failure becomes a fabricated no-match.
OpenAI absence/failure uses the existing explicitly labelled deterministic
grounded explanation. Urgent wording and valid HTTPS alone do not mean malicious
or safe, respectively.

`GET /health` never needs a signer or optional AI/intelligence keys. It reports
actual chain-ID/code/ABI checks when configured and private-store read readiness.
`live_scanning_enabled` requires collection enabled, storage reachable, a strong
proxy secret and an explicit allowed-host list. It is not a claim that every
collector succeeds. Storage write capability and live collection must also pass
their explicit preflight and deployed smoke checks.

## 6. Frontend Vercel settings

Keep Root Directory **`frontend`**, Next.js preset, Node 24, install
`pnpm install --frozen-lockfile`, build **`pnpm build`**, framework output default.
No static export. All browser calls remain same-origin `/api/...`.

- `BACKEND_BASE_URL=https://veridict-taupe.vercel.app` (or the actual backend origin).
- `SCAN_API_SECRET`: same server-only value as the backend. Never `NEXT_PUBLIC_`.
- Optional `BACKEND_PROTECTION_BYPASS`: backend automation bypass if its Vercel
  Deployment Protection requires one. This is separate from scan authentication.
- Do **not** put RPC credentials, Blob tokens, `ANCHOR_API_SECRET` or
  `CHAIN_PRIVATE_KEY` in the frontend project. The proxy has no signing route;
  `POST /api/reports/<id>/anchor` returns 405 there. Only GET anchor status forwards.

After approval to publish/redeploy, release backend first with live/signing off;
verify fixtures, connect/test Blob, configure controlled scanning and redeploy;
then release frontend with matching proxy secret. Enable `public_chain` only after
the actual registry deployment and read checks. Enable operator signing last.
Environment changes need a redeployment; changing dashboard values alone does
not update an existing deployment. This agent has not run any of those releases.

## 7. Live collection security and operational bounds

- Initial hosted URLs must be credential-free HTTPS on port 443 and an exact
  approved hostname. Redirects remain limited to four, HEAD-only, no HTML/browser
  execution, no credential submission, no unrestricted downloads.
- Every DNS answer is checked; private, loopback, reserved, mapped, metadata,
  multicast and link-local addresses are blocked. Connections use validated
  numeric IPs, original Host/TLS SNI and connected-peer validation. Every redirect
  is revalidated; unapproved rollout hosts are not connected. Ports outside 80/443
  are blocked throughout the connection helper.
- URL maximum 4096 characters, message maximum 12000, JSON request cap 512 KiB,
  stored-object cap 1 MiB. Upstream errors are sanitized. Collection receives only
  redacted inputs; report rows/Blob/LLM do not receive raw query secrets/messages.
- A shared secret authenticates the frontend proxy; CORS is not authentication.
  Client identity headers are advisory. Global durable quotas are authoritative
  even if a client identity is spoofed. Quotas use atomic Blob creates, not memory.
  A global scanner lease limits concurrent collection to one. Exhaustion returns
  429; storage failure closes access. Use Vercel Firewall controls if already
  available. This is a small controlled rollout, not a broad anonymous scanner.
- Quota objects accumulate and are not a distributed transactional database.
  Retain current hour/day records; periodically remove old quota records privately.
  Never delete active quota/lease records to evade an operation's limits.
- If Vercel socket/DNS pinning fails, leave scanning disabled. Move this **same**
  backend to a native Python host only with approval, using build
  `uv sync --frozen` and start
  `uv run uvicorn app.main:app --host 0.0.0.0 --port $PORT --no-access-log`, keeping
  `RUNTIME_MODE=serverless`, Blob and identical protections. Do not bypass TLS,
  DNS validation or peer checks to make the function work.

## 8. Separate, protected live report anchoring

`GET /api/reports/<id>/anchor` and `POST .../verify` are read-only and require no
private key. Root/schema mismatches fail independently from claim grounding.

The direct-backend **POST** anchor endpoint requires the separate
`x-veridict-anchor-secret` and opt-in settings above. It verifies the stored seal,
grounding, chain and existing root; serializes the dedicated signer across
instances; consumes a durable daily slot; checks balance/gas budgets; persists
one signed transaction **before broadcast**; waits for a real receipt; and reads
the registry again. It never runs automatically from scanning or the public UI.
Use only a dedicated wallet with no other writer/process submitting transactions.

After explicit authorization for the transaction, an operator can run (secrets
already privately configured in this terminal, report ID from a genuine scan):

```powershell
$headers = @{ 'x-veridict-anchor-secret' = $env:ANCHOR_API_SECRET }
Invoke-RestMethod -Method Post -Uri "$env:BACKEND_BASE_URL/api/reports/$env:REPORT_ID/anchor" -Headers $headers
```

This is a live transaction command, not a smoke test. A timeout returns `PENDING`
or 503 and retains the same transaction/lease; the sealed report remains stored.
Repeated requests reconcile the persisted hash without signing another nonce.
Existing matching registrations return success without another transaction.
Conflicting report IDs stop. Real receipt metadata is stored separately, keeping
the original passport immutable. Etherscan links appear only for validated actual
transaction metadata. Maximum fee exposure per day is bounded by
`ANCHOR_DAILY_LIMIT * ANCHOR_MAX_GAS * ANCHOR_MAX_FEE_GWEI` (plus no transferred
ETH); attempted slots are consumed even on pre-broadcast failures.

**Crash recovery is intentionally fail-closed:** do not delete a signer lease,
intent or prepared record until the operator has checked the exact transaction,
pending nonce and wallet history. An intent without a prepared transaction,
reverted transaction, or crashed scanner lease needs manual investigation in the
private store. Never automatically expire a signer lease while a transaction may
be pending. Signed raw transactions are stored privately for identical retries;
they are not exposed by report/status endpoints. Keep all private signing/control
records restricted to operators.

## 9. Validate before calling the upgrade operational

```powershell
# Offline regression and original fixture bytes
.tools\bin\uv.exe run --project backend pytest -c backend/pyproject.toml backend/tests
backend\.venv\Scripts\python.exe backend/scripts/package_demo.py --check
backend\.venv\Scripts\python.exe backend/scripts/export_openapi.py --check
pnpm.cmd --dir frontend schema:check
pnpm.cmd --dir frontend typecheck
pnpm.cmd --dir frontend lint
pnpm.cmd --dir frontend build
npm.cmd --prefix contracts test
pnpm.cmd --dir frontend test:deployment

# Actual network/provider checks; do not report them passed unless run successfully
backend\.venv\Scripts\python.exe backend/scripts/phase2_probe.py --collect https://example.com
backend\.venv\Scripts\python.exe backend/scripts/phase2_probe.py --chain
backend\.venv\Scripts\python.exe backend/scripts/phase2_probe.py --storage-write-check

# Existing public fixture smoke (does not sign)
backend\.venv\Scripts\python.exe scripts/deployment_smoke.py --frontend-url https://veridict-vfxw.vercel.app --backend-url https://veridict-taupe.vercel.app
# After live rollout, explicitly opt into one scan (still no transaction)
backend\.venv\Scripts\python.exe scripts/deployment_smoke.py --frontend-url https://veridict-vfxw.vercel.app --backend-url https://veridict-taupe.vercel.app --live-url https://example.com
```

For pytest from root use `uv run --project backend pytest -c backend/pyproject.toml
backend/tests` or run `.venv\Scripts\python.exe -m pytest` inside `backend`; Python
imports must resolve `backend/app`. Existing native CI uses that working directory.

Then use the **deployed** custom form on example.com. Check LIVE evidence,
actual certificate fingerprint/provider timestamps, honest incomplete checks,
deterministic fallback if no OpenAI key, no automatic transaction, and a new
permalink that opens in another browser after a cold start. Run all four tamper
mutations and reset. After separately authorized anchoring, verify the real root
and schema in a fresh request and inspect the actual Sepolia transaction. A local
unit test or successful build does not establish these production outcomes.

## 10. Troubleshooting and rollback

| Symptom | Check / response |
|---|---|
| Fixtures fail after chain configuration | Wrong/missing public-chain config is explicit failure; restore `CHAIN_MODE=demo_fixture`, not a memory registry |
| Live input disabled | `/health`, `LIVE_CHECKS`, Blob readiness, >=32-character matching scan secret, exact allowed hosts |
| 401 scanning | Proxy/backend secrets differ, or direct unauthenticated request; CORS cannot fix authentication |
| 422 scanning | HTTPS/443 required, embedded credentials, unapproved host, invalid input/ID |
| 429 | Hour/client budget exhausted, active scanner lease or pending signer operation; never silently bypass |
| 503 storage / missing live permalink | Store privacy/permissions, OIDC `BLOB_STORE_ID` or token, write/read preflight; do not fall back to process memory |
| 500/import failure | Use committed uv lock and Python 3.12; install the Blob SDK via frozen dependency install |
| 502/504/proxy errors | Backend origin/protection bypass, function duration, upstream cold start; inspection stays blocked |
| Missing fixture files / 404 | Backend root must include committed `app/demo`; route IDs are canonical 0x bytes32, not fixture names |
| CORS | Configure explicit frontend HTTPS origin; same-origin browser proxy normally avoids browser CORS entirely |
| `chain_connected=false` | Verify HTTPS RPC, chain 11155111, actual contract bytecode and ABI; read access requires no signer |
| `NOT_ANCHORED` | Genuine scan is sealed only; no registry entry exists, or fixture registration has not been done |
| Root verified without transaction hash | Registry read succeeded; import real receipt manifest or complete protected registration metadata |
| Collector timeout / provider unavailable | Unknown stays unknown; TLS is not safety, failed intel is not a clean result; retry or keep INCONCLUSIVE |
| Reverted/pending registration | Inspect transaction hash/nonce and private intent records before recovery; never sign repeatedly |
| OIDC unavailable locally | Use a privately configured read/write token; do not expose an OIDC token to client code |
| OIDC identity present but forbidden | Fix the connected store's permissions; to select token authentication explicitly, omit `BLOB_STORE_ID` while configuring the private read/write token |

Rollback: set backend `RUNTIME_MODE=serverless`, `REPORT_STORAGE=packaged`,
`CHAIN_MODE=demo_fixture`, `LIVE_CHECKS=false`, `ANCHOR_ENABLED=false`, remove the
frontend scan secret if desired, and redeploy the approved version. Do not delete
Blob passports or chain records. Fixture IDs, bundle bytes and reference roots
remain unchanged and need no storage, optional APIs or blockchain credentials.

Official references: [Vercel private Blob](https://vercel.com/docs/vercel-blob/private-storage),
[Vercel Python runtime](https://vercel.com/docs/functions/runtimes/python),
[Hardhat 3 configuration](https://hardhat.org/docs/reference/configuration).
