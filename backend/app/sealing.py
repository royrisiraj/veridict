"""One canonical leaf assembly shared by sealing and independent verification."""
from app.models import EvidenceBundle, MerkleLeaf, MerkleReport
from app.merkle import build_merkle, leaf_hash


def seal_bundle(bundle: EvidenceBundle) -> MerkleReport:
    objects = [(item.id, item.type, item.model_dump(mode="json")) for item in sorted(bundle.evidence, key=lambda e: e.id)]
    objects += [(claim.id, "ai_claim", claim.model_dump(mode="json")) for claim in sorted(bundle.ai_claims, key=lambda c: c.id)]
    coverage = {"id": "cov:1", "type": "coverage", "data": bundle.coverage.model_dump(mode="json")}
    meta = bundle.model_dump(mode="json", by_alias=True, exclude={"evidence", "ai_claims", "coverage", "normalized_url"})
    meta["redacted_url"] = bundle.normalized_url
    objects += [("cov:1", "coverage", coverage), ("meta:1", "meta", {"id": "meta:1", "type": "meta", "data": meta})]
    hashes = [leaf_hash(kind, payload) for _, kind, payload in objects]
    tree = build_merkle(hashes)
    return MerkleReport(root=tree.root_hex, leaves=[MerkleLeaf(id=eid, type=kind, payload=payload, hash="0x" + digest.hex()) for (eid, kind, payload), digest in zip(objects, hashes)],
        proofs_by_id={eid: proof for (eid, _, _), proof in zip(objects, tree.proofs_hex)})
