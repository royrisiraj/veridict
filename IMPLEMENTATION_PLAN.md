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

## 2. Locked Execution Order
1. **Phase 1 (Contracts):** Compile and test `EvidenceRegistry.sol` with Hardhat 3 (`npx hardhat test`).
2. **Phase 2 (Backend Core & Security):** Build around `canonical.py` and `merkle.py` seed primitives. Pass all `pytest` suites including `test_merkle_and_canonical.py`.
3. **Phase 3 (Frontend UI):** Build Next.js 16.4 App Router views and connect to `/api/investigate`, `/api/reports/{id}/verify`, and `/api/reports/{id}/tamper-demo`.
4. **Phase 4 (Integration & Demo):** Verify end-to-end flow across all 6 fixtures and 4 non-destructive tamper mutations.
