# SEALED//EVIDENCE + TRUST//INTERCEPT — Implementation Plan

## 1. HackMatrix Requirement-to-Module Traceability Matrix

| HackMatrix Requirement | Target Module(s) | Verification / Acceptance Test |
|---|---|---|
| **URL & Domain Investigation** (IDNA normalization, punycode, typosquatting, homograph indicators) | `backend/app/security/url.py` | `backend/tests/test_fixtures_e2e.py` |
| **SSRF & Redirect Safety** (Block RFC1918, loopback, link-local, metadata IP `169.254.169.254`, per-hop validation) | `backend/app/security/ssrf.py`, `backend/app/security/redirects.py` | `backend/tests/test_ssrf_and_redact.py` |
| **Off-Chain Privacy & Secret Redaction** (Strip tokens, passwords, seed phrases, PII before hashing/LLM/DB) | `backend/app/security/redact.py` | `backend/tests/test_ssrf_and_redact.py` |
| **TLS X.509 Inspection** (SAN/hostname match, expiry, issuer, SHA-256 fingerprint) | `backend/app/security/tls.py` | `backend/tests/test_fixtures_e2e.py` |
| **External Threat Intelligence** (OpenPhish feed + optional Google Safe Browsing v5 with timestamp/source) | `backend/app/intel/openphish.py`, `backend/app/intel/safebrowsing.py` | `backend/tests/test_fixtures_e2e.py` |
| **Scam-Message AI Analysis** (Untrusted input isolation, strict `evidence_ids` citation, semantic type-gate) | `backend/app/ai/analyzer.py`, `backend/app/verifier.py` | `backend/tests/test_ai_grounding.py` |
| **Deterministic 5-State Risk Engine** (`LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, `CONFIRMED_MALICIOUS`, `INCONCLUSIVE`) | `backend/app/risk.py` | `backend/tests/test_risk.py` |
| **Canonical Evidence Bundle & Merkle Sealing** (RFC 8785 canonical JSON, typed double-hashed leaves, sorted pairs) | `backend/app/canonical.py`, `backend/app/merkle.py` | `backend/tests/test_merkle_and_canonical.py` |
| **On-Chain Registry** (Attests integrity/history via `reportId`, `merkleRoot`, `schemaHash`, `timestamp`) | `contracts/contracts/EvidenceRegistry.sol`, `backend/app/chain/registry.py` | `contracts/test/EvidenceRegistry.ts` |
| **Independent Verifier & Tamper Demo** (`SUPPORTED`, `TAMPERED`, `NOT_SUPPORTED` across 4 mutations) | `backend/app/verifier.py`, `frontend/components/TamperPanel.tsx` | `backend/tests/test_tamper_mutations.py` |
| **Pre-Navigation Interception Gate & Dashboard** (`TRUST//INTERCEPT` modal + `EvidencePassport` UI) | `frontend/components/InterceptGate.tsx`, `frontend/components/EvidencePassport.tsx` | `pnpm --dir frontend build` |
| **Mandatory 6 Fixtures** (3 suspicious + 3 benign, including `INCONCLUSIVE` on missing coverage) | `fixtures/suspicious-1..3.json`, `fixtures/benign-1..3.json` | `backend/tests/test_fixtures_e2e.py` |

## 2. Resolved Integration Decisions

- VERIDICT is the product name; cryptographic schema remains `sealed-evidence/1`.
- Grounding failure takes `NOT_SUPPORTED` precedence over `TAMPERED`; independent fields expose both failures.
- A typosquat alone is `HIGH_RISK`; incomplete custom investigations never borrow fixture results.
- All bundle metadata, AI indicators, limitations and provenance are committed in the metadata leaf.
- Use original sealed inclusion proofs when checking candidate leaves. Reordering evidence is canonicalized by ID.
- Fixture data is explicitly simulated; memory anchors never claim EVM transactions. Existing reports retain their original anchor source.
- Offline custom URLs run local checks and preserve unknown mandatory coverage. Optional unconfigured Safe Browsing does not invalidate completed OpenPhish coverage.
- The web sandbox never navigates to fixture destinations. This is a local demo, not a browser extension or hosted deployment.

## 3. Locked Execution Order
0. **Phase 0 (Setup):** Expand traceability, establish strict API models, dependency manifests, environment, Compose and CI.
1. **Phase 1 (Contracts):** Compile and test `EvidenceRegistry.sol` with Hardhat 3 (`npx hardhat test`).
2. **Phase 2 (Backend Core & Security):** Build around `canonical.py` and `merkle.py` seed primitives. Pass all `pytest` suites including `test_merkle_and_canonical.py`.
3. **Phase 3 (Frontend UI):** Build Next.js 16.4 App Router views and connect to `/api/investigate`, `/api/reports/{id}/verify`, and `/api/reports/{id}/tamper-demo`.
4. **Phase 4 (Integration & Demo):** Verify end-to-end flow across all 6 fixtures and 4 non-destructive tamper mutations.

## 4. Gate Results

| Gate | Result |
|---|---|
| Seed primitive smoke check | Passed: Ethereum Keccak empty vector, sorted JSON, proofs for 1–7 leaves |
| Phase 0 | Complete: manifests/locks, strict models, environment, Dockerfiles, Compose and CI |
| Gate 1 | Passed: 6 Hardhat tests with Solidity 0.8.38 and OpenZeppelin cross-language proof parity |
| Gate 2 | Passed: 106 backend tests, all seed assertions retained |
| Gate 3 | Passed: OpenAPI/TypeScript drift, typecheck, lint, production build, 4 Chromium integration tests against standalone output |
| Gate 4 | Native rehearsal passed: 6 real EVM registrations, direct root/schema/timestamp readback, 24 mutations and 6 clean resets. Compose configuration validates; container runtime rehearsal blocked by host virtualization. |

Build phases advance only after the preceding gate passes. No placeholder collectors, invented safety results, or weakened seed assertions.

### Verification environment and limits (10 November 2026)

- Node 24.20.0; managed Python 3.12.16; uv 0.13.7; pnpm 11.24.0.
- Next.js 16.4.5 / React 19.3.1; Hardhat 3.21.2; solc 0.8.38.
- Native real-chain rehearsal used an actually deployed EvidenceRegistry on local chain 31337. No provider keys or live malicious destinations were needed.
- Docker Desktop's engine cannot start: its host log reports `Virtual Machine Platform not enabled` and `No virtualization available`; WSL reports it is not installed. Docker API requests return HTTP 500. No Windows features, firmware settings or reboot were changed. Container image builds and the Compose runtime rehearsal remain unverified here; Linux CI includes them.
- Windows sandbox and host test processes have separate temp/cache permissions. The uv gate uses a fresh workspace-local `--basetemp` and disables pytest's optional cache when run outside the sandbox; no tests are skipped.
- Live OpenAI/Google calls were not made. Adapters are exercised with controlled protocol responses; offline fixture operation is fully tested.
- Dependency review applied scoped `tmp` 0.2.7 and `serialize-javascript` >=7.1.3 patches. Contract tooling retains 17 npm audit findings (13 high), primarily upstream Zod 3 and Mocha dependencies; compatible audit fixes did not resolve them. No incompatible Zod/Hardhat upgrade or Solidity downgrade was forced. The development chain remains local-only.
