"""Shared, closed API contracts. Only redacted data may enter these objects."""
from __future__ import annotations

from typing import Annotated, Literal
from enum import StrEnum
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints, model_validator

def normalize_hash(value):
    if isinstance(value, str):
        value = value.lower()
        return value if value.startswith("0x") else "0x" + value
    return value


Hash32 = Annotated[str, BeforeValidator(normalize_hash), StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
EvidenceId = Annotated[str, StringConstraints(pattern=r"^[a-z]+:[0-9]+$", max_length=64)]
Mode = Literal["fixture", "live", "local"]
Status = Literal["COMPLETE", "INCOMPLETE", "TIMEOUT", "FAILED", "UNCONFIGURED"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RiskClass(StrEnum):
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"


class URLData(StrictModel):
    normalized_url: str
    hostname: str
    typosquat_target: str | None = None
    homograph_detected: bool = False
    confirmed_impersonation: bool = False
    brand_impersonation: bool = False
    suspicious_tld: bool = False
    obfuscated: bool = False


class TLSData(StrictModel):
    hostname_ok: bool | None = None
    expired: bool | None = None
    self_signed: bool | None = None
    trusted: bool | None = None
    issuer: str | None = None
    cert_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | None = None
    not_before: str | None = None
    not_after: str | None = None


class ThreatData(StrictModel):
    provider: Literal["openphish", "google_safe_browsing"]
    matched: bool | None = None
    queried_at: str


class RedirectData(StrictModel):
    chain: list[str] = Field(max_length=5)
    cross_domain_hops: int = Field(default=0, ge=0, le=4)
    untrusted_destination: bool = False
    ssrf_blocked: bool = False
    loop_detected: bool = False
    limit_reached: bool = False


class MessageData(StrictModel):
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    pattern_type: Literal["urgency", "credential_harvesting", "otp_request", "seed_phrase_request", "payment_lure", "brand_impersonation"]
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    redacted_excerpt: str = Field(max_length=600)


class EvidenceBase(StrictModel):
    id: EvidenceId
    status: Status
    mode: Mode


class URLEvidence(EvidenceBase):
    type: Literal["url"] = "url"
    data: URLData


class TLSEvidence(EvidenceBase):
    type: Literal["tls"] = "tls"
    data: TLSData


class ThreatEvidence(EvidenceBase):
    type: Literal["threat_intel"] = "threat_intel"
    data: ThreatData

    @model_validator(mode="after")
    def unavailable_is_unknown(self):
        if self.status != "COMPLETE" and self.data.matched is not None:
            raise ValueError("Unavailable intelligence must have matched=null")
        if self.status == "COMPLETE" and self.data.matched is None:
            raise ValueError("Complete intelligence requires a result")
        return self


class RedirectEvidence(EvidenceBase):
    type: Literal["redirect"] = "redirect"
    data: RedirectData


class MessageSpanEvidence(EvidenceBase):
    type: Literal["message_span"] = "message_span"
    data: MessageData


Evidence = Annotated[URLEvidence | TLSEvidence | ThreatEvidence | RedirectEvidence | MessageSpanEvidence, Field(discriminator="type")]


class Claim(StrictModel):
    id: EvidenceId
    text: str = Field(min_length=1, max_length=700)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=20)
    confidence: Literal["low", "medium", "high"] = "medium"


class SocialIndicator(StrictModel):
    type: str = Field(max_length=80)
    evidence_ids: list[EvidenceId] = Field(min_length=1, max_length=20)


class Analysis(StrictModel):
    claims: list[Claim] = Field(min_length=1, max_length=30)
    social_engineering_indicators: list[SocialIndicator] = Field(max_length=30)
    limitations: list[str] = Field(max_length=15)


class CoverageMap(StrictModel):
    url: Status
    tls: Status
    threat_intel: Status
    redirects: Status


class Provenance(StrictModel):
    collection: Mode
    analyzer: Literal["fixture", "deterministic", "openai"]
    fixture_id: str | None = None


class EvidenceBundle(StrictModel):
    schema_version: Literal["sealed-evidence/1"] = Field(default="sealed-evidence/1", alias="schema")
    report_id: Hash32
    created_at: str
    normalized_url: str
    risk: RiskClass
    evidence: list[Evidence] = Field(max_length=100)
    ai_claims: list[Claim] = Field(max_length=30)
    coverage: CoverageMap
    provenance: Provenance
    social_engineering_indicators: list[SocialIndicator] = Field(default_factory=list, max_length=30)
    limitations: list[str] = Field(default_factory=list, max_length=15)

    @model_validator(mode="after")
    def unique_ids(self):
        ids = [e.id for e in self.evidence] + [c.id for c in self.ai_claims]
        if len(ids) != len(set(ids)) or any(i in {"cov:1", "meta:1"} for i in ids):
            raise ValueError("IDs must be unique and cannot use reserved leaves")
        return self


class MerkleLeaf(StrictModel):
    id: str
    type: str
    payload: dict
    hash: Hash32


class MerkleReport(StrictModel):
    root: Hash32
    leaves: list[MerkleLeaf]
    proofs_by_id: dict[str, list[Hash32]]


class ChainReceipt(StrictModel):
    tx_hash: Hash32 | None
    block_number: int | None
    contract_address: str | None
    network: str
    mode: Literal["evm", "fixture", "unanchored"]


class VerificationFailure(StrictModel):
    code: str
    leaf_id: str | None = None


class VerificationResponse(StrictModel):
    status: Literal["SUPPORTED", "TAMPERED", "NOT_SUPPORTED"]
    report_id: Hash32
    expected_root: Hash32
    computed_root: Hash32
    root_match: bool
    target_leaf_valid: bool | None
    claim_grounding: bool
    schema_match: bool
    failures: list[VerificationFailure]
    leaf_validity: dict[str, bool]
    public_chain_status: Literal["VERIFIED", "MISMATCH", "NOT_ANCHORED", "UNAVAILABLE", "NOT_CONFIGURED"] | None = Field(default=None, exclude_if=lambda v: v is None)


class InvestigationReport(StrictModel):
    bundle: EvidenceBundle
    merkle: MerkleReport
    chain_receipt: ChainReceipt
    verification: VerificationResponse


class InvestigateRequest(StrictModel):
    url: str = Field(min_length=1, max_length=4096)
    message: str | None = Field(default=None, max_length=12000)
    fixture_id: str | None = Field(default=None, max_length=64)


class VerifyRequest(StrictModel):
    evidence_id: str | None = Field(default=None, max_length=64)
    candidate_bundle: EvidenceBundle | None = None


class TamperRequest(StrictModel):
    mutation: Literal["tls_cert", "drop_threat_intel", "alter_redirect", "unground_ai_claim"]
    evidence_id: str | None = Field(default=None, max_length=64)


class TamperResponse(StrictModel):
    mutated_bundle: EvidenceBundle
    mutated_merkle: MerkleReport
    verification: VerificationResponse
    tampered_leaf_id: str
    expected_root: Hash32
    computed_root: Hash32


class FixtureMetadata(StrictModel):
    fixture_id: str
    title: str
    expected_risk: RiskClass
    input: InvestigateRequest


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    service: Literal["veridict-api"] = "veridict-api"
    version: Literal["1"] = "1"
    chain_connected: bool
    contract_address: str
    chain_mode: Literal["evm", "fixture", "unavailable"]
    runtime_mode: Literal["native", "serverless"] = "native"
    verification_mode: Literal["DEMO_FIXTURE", "PUBLIC_CHAIN", "LOCAL_DEVELOPMENT", "UNAVAILABLE"] = "LOCAL_DEVELOPMENT"
    live_scanning_enabled: bool = True
    report_storage: Literal["sqlite", "packaged-read-only", "vercel_blob", "unavailable"] = "sqlite"


class AnchorResponse(StrictModel):
    report_id: Hash32
    status: Literal["VERIFIED", "MISMATCH", "NOT_ANCHORED", "UNAVAILABLE", "NOT_CONFIGURED", "PENDING"]
    chain_id: int = 11155111
    contract_address: str | None = None
    receipt: ChainReceipt | None = None
    explorer_url: str | None = None
