"""Independent immutable reference verification plus separate public-chain checks."""
from app.chain.registry import AnchorUnavailableError
from app.deployment import FixtureRegistry
from app.models import AnchorResponse, VerificationFailure
from app.verifier import Verifier


class ReferenceRegistry:
    mode = "fixture"
    address = ""
    health_connected = False

    def __init__(self, store):
        self.store = store

    def read(self, report_id):
        return self.store.reference(report_id) if hasattr(self.store, "reference") else FixtureRegistry().read(report_id)


class ProductionVerifier(Verifier):
    def __init__(self, store, chain=None, require_chain=False):
        super().__init__(store, ReferenceRegistry(store))
        self.chain = chain
        self.require_chain = require_chain

    def anchor_status(self, report_id, root):
        if self.chain is None:
            return AnchorResponse(report_id=report_id, status="NOT_CONFIGURED")
        return self.chain.status(report_id, root, self.database)

    def verify_bundle(self, report_id, candidate_bundle, target_evidence_id=None, genuine=None):
        if self.require_chain and self.chain is None:
            raise AnchorUnavailableError("Explicit public registry is not configured")
        original = genuine or self.database.get(report_id)
        if original is None:
            raise LookupError("Report not found")
        # Core verifier keeps its original, byte-exact hashing/proof/grounding path.
        # This copy selects the independent release/Blob reference, never a receipt
        # returned to clients or a newly synthesized blockchain record.
        reference_copy = original.model_copy(update={"chain_receipt": original.chain_receipt.model_copy(update={"mode": "fixture"})})
        checked = super().verify_bundle(report_id, candidate_bundle, target_evidence_id, reference_copy)
        chain_status = self.anchor_status(report_id, checked.computed_root)
        checked.public_chain_status = chain_status.status
        if chain_status.status == "MISMATCH":
            checked.failures.append(VerificationFailure(code="PUBLIC_CHAIN_ROOT_OR_SCHEMA_MISMATCH"))
            if checked.status != "NOT_SUPPORTED":
                checked.status = "TAMPERED"
        return checked
