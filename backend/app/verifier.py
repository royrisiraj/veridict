"""Candidate verification against independently fetched anchors and original proofs."""
from app.ai.analyzer import verify_claim_grounding
from app.canonical import SCHEMA_HASH_HEX
from app.chain.registry import AnchorUnavailableError
from app.merkle import verify_leaf
from app.models import EvidenceBundle, InvestigationReport, TamperResponse, VerificationFailure, VerificationResponse
from app.sealing import seal_bundle


class Verifier:
    def __init__(self, database, registry):
        self.database = database
        self.registry = registry

    def verify_bundle(self, report_id: str, candidate_bundle: EvidenceBundle, target_evidence_id: str | None = None, genuine: InvestigationReport | None = None) -> VerificationResponse:
        original = genuine or self.database.get(report_id)
        if not original:
            raise LookupError("Report not found")
        receipt = original.chain_receipt
        if receipt.mode != self.registry.mode or (receipt.mode == "evm" and (receipt.contract_address != self.registry.address or receipt.network != f"evm:{self.registry.chain_id}")):
            raise AnchorUnavailableError("Original anchor source is unavailable")
        anchor = self.registry.read(report_id)
        merkle = seal_bundle(candidate_bundle)
        root_match = merkle.root == anchor.root
        schema_match = anchor.schema_hash == SCHEMA_HASH_HEX
        by_id = {e.id: e for e in candidate_bundle.evidence}
        failures = []
        grounded = True
        for claim in [*candidate_bundle.ai_claims, *candidate_bundle.social_engineering_indicators]:
            if not verify_claim_grounding(claim, by_id):
                grounded = False
                failures.append(VerificationFailure(code="CLAIM_GROUNDING_FAILED", leaf_id=getattr(claim, "id", "meta:1")))
        candidate_leaves = {leaf.id: leaf for leaf in merkle.leaves}
        validity = {}
        for leaf_id in set(original.merkle.proofs_by_id) | set(candidate_leaves):
            leaf = candidate_leaves.get(leaf_id)
            proof = original.merkle.proofs_by_id.get(leaf_id)
            validity[leaf_id] = bool(leaf and proof is not None and verify_leaf(anchor.root, leaf.hash, proof))
        target_valid = validity.get(target_evidence_id, False) if target_evidence_id else None
        if not root_match:
            failures.append(VerificationFailure(code="ROOT_MISMATCH"))
        if target_valid is False:
            failures.append(VerificationFailure(code="LEAF_PROOF_FAILED", leaf_id=target_evidence_id))
        elif target_evidence_id is None:
            failures.extend(VerificationFailure(code="LEAF_PROOF_FAILED", leaf_id=eid) for eid, valid in validity.items() if not valid)
        if not schema_match:
            failures.append(VerificationFailure(code="SCHEMA_MISMATCH"))
        status = "NOT_SUPPORTED" if not grounded else ("TAMPERED" if not root_match or not schema_match or target_valid is False or not all(validity.values()) else "SUPPORTED")
        return VerificationResponse(status=status, report_id=report_id, expected_root=anchor.root, computed_root=merkle.root,
            root_match=root_match, target_leaf_valid=target_valid, claim_grounding=grounded, schema_match=schema_match,
            failures=failures, leaf_validity=dict(sorted(validity.items())))

    def tamper(self, report_id: str, mutation: str, evidence_id: str | None = None) -> TamperResponse:
        original = self.database.get(report_id)
        if not original:
            raise LookupError("Report not found")
        candidate = original.bundle.model_copy(deep=True)
        kinds = {"tls_cert": "tls", "drop_threat_intel": "threat_intel", "alter_redirect": "redirect"}
        if mutation == "unground_ai_claim":
            claim = next((c for c in candidate.ai_claims if not evidence_id or c.id == evidence_id), None)
            if not claim:
                raise ValueError("Requested claim is unavailable")
            claim.evidence_ids = ["missing:999"]
            changed_id = claim.id
        else:
            item = next((e for e in candidate.evidence if e.type == kinds[mutation] and (not evidence_id or e.id == evidence_id)), None)
            if not item:
                raise ValueError("Requested evidence type is unavailable")
            changed_id = item.id
            if mutation == "tls_cert":
                item.data.cert_sha256 = "f" * 64 if item.data.cert_sha256 != "f" * 64 else "0" * 64
            elif mutation == "drop_threat_intel":
                candidate.evidence = [e for e in candidate.evidence if e.id != item.id]
            else:
                item.data.chain[-1] = "https://altered.example/tampered"
        verification = self.verify_bundle(report_id, candidate, changed_id)
        return TamperResponse(mutated_bundle=candidate, mutated_merkle=seal_bundle(candidate), verification=verification, tampered_leaf_id=changed_id,
            expected_root=verification.expected_root, computed_root=verification.computed_root)
