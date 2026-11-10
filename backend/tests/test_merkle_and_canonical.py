"""Seed unit tests for canonical JSON serialization and OpenZeppelin-compatible Merkle proofs."""
import math
import pytest

from app.canonical import SCHEMA_HASH, SCHEMA_HASH_HEX, canonical_json
from app.merkle import build_merkle, leaf_hash, parent_hash, verify_leaf


def test_canonical_json_key_order_invariance():
    payload_a = {
        "id": "tls:1",
        "type": "tls",
        "data": {"hostname_ok": True, "cert_sha256": "abc123", "issuer": "Let's Encrypt"},
    }
    payload_b = {
        "type": "tls",
        "data": {"issuer": "Let's Encrypt", "cert_sha256": "abc123", "hostname_ok": True},
        "id": "tls:1",
    }
    assert canonical_json(payload_a) == canonical_json(payload_b)
    assert leaf_hash("tls", payload_a) == leaf_hash("tls", payload_b)


def test_canonical_json_rejects_nan_and_infinity():
    with pytest.raises(ValueError):
        canonical_json({"bad": math.nan})
    with pytest.raises(ValueError):
        canonical_json({"bad": math.inf})


def test_schema_hash_is_32_bytes():
    assert len(SCHEMA_HASH) == 32
    assert SCHEMA_HASH_HEX.startswith("0x") and len(SCHEMA_HASH_HEX) == 66


def test_typed_leaf_hash_domain_separation():
    payload = {"id": "item:1", "matched": True}
    assert leaf_hash("tls", payload) != leaf_hash("threat_intel", payload)


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 5, 6, 7])
def test_merkle_build_and_verify_across_even_and_odd_leaf_counts(leaf_count: int):
    leaves = [
        leaf_hash("evidence", {"id": f"ev:{i}", "index": i})
        for i in range(leaf_count)
    ]
    tree = build_merkle(leaves)
    assert len(tree.root) == 32

    for i, leaf in enumerate(leaves):
        assert verify_leaf(tree.root, leaf, tree.proofs[i]) is True
        assert verify_leaf(tree.root_hex, tree.leaves_hex[i], tree.proofs_hex[i]) is True


def test_tampered_leaf_breaks_verification_while_siblings_remain_valid():
    tls_payload = {"id": "tls:1", "cert_sha256": "001122334455", "hostname_ok": True}
    ti_payload = {"id": "ti:1", "provider": "openphish", "matched": True}
    redir_payload = {"id": "redir:1", "chain": ["https://a.test", "https://b.test"]}

    leaves = [
        leaf_hash("tls", tls_payload),
        leaf_hash("threat_intel", ti_payload),
        leaf_hash("redirect", redir_payload),
    ]
    tree = build_merkle(leaves)

    # Mutate TLS certificate fingerprint
    tampered_tls = {"id": "tls:1", "cert_sha256": "ff9988776655", "hostname_ok": True}
    tampered_tls_hash = leaf_hash("tls", tampered_tls)

    # Tampered leaf MUST fail against anchored root
    assert verify_leaf(tree.root, tampered_tls_hash, tree.proofs[0]) is False

    # Unaltered leaves MUST still verify against anchored root
    assert verify_leaf(tree.root, leaves[1], tree.proofs[1]) is True
    assert verify_leaf(tree.root, leaves[2], tree.proofs[2]) is True


@pytest.mark.parametrize("bad", ["0xzz", "0x" + "g" * 64, "0x1234", "", None, 17])
def test_invalid_hex_returns_false(bad):
    good = leaf_hash("x", {"id": "ev:1"})
    assert verify_leaf(bad, good, []) is False
    assert verify_leaf(good, good, [bad]) is False


def test_hex_case_normalization_and_altered_proof():
    leaves = [leaf_hash("x", {"id": str(i)}) for i in range(3)]
    tree = build_merkle(leaves)
    assert verify_leaf(tree.root_hex.upper(), tree.leaves_hex[0].upper(), [p.upper() for p in tree.proofs_hex[0]])
    assert not verify_leaf(tree.root, leaves[0], [b"\x00" * 32])
