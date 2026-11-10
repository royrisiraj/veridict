"""Export cross-language vectors using the actual seeded Python primitives."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.canonical import canonical_json
from app.merkle import build_merkle, leaf_hash

vectors = []
for count in [1, 2, 3, 4, 5, 7]:
    payloads = [{"id": f"tls:{i + 1}", "type": "tls", "data": {"hostname_ok": True, "issuer": "Référence"}} for i in range(count)]
    hashes = [leaf_hash("tls", p) for p in payloads]
    tree = build_merkle(hashes)
    vectors.append({"root": tree.root_hex, "leaves": [
        {"type": "tls", "canonical": canonical_json(p).decode(), "hash": "0x" + h.hex()}
        for p, h in zip(payloads, hashes)
    ], "proofs": tree.proofs_hex})
destination = Path(__file__).resolve().parents[2] / "contracts/test/merkle-vectors.json"
destination.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
