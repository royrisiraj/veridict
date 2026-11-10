"""OpenZeppelin-compatible typed Merkle tree builder and independent proof verifier."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.canonical import canonical_json, keccak256


def _abi_encode_two_bytes32(a: bytes, b: bytes) -> bytes:
    """Equivalent to Solidity abi.encode(bytes32 a, bytes32 b) -> 64 bytes concatenation."""
    if len(a) != 32 or len(b) != 32:
        raise ValueError("Both inputs to _abi_encode_two_bytes32 must be exactly 32 bytes.")
    return a + b


def leaf_hash(kind: str, payload: dict[str, Any]) -> bytes:
    """Compute typed leaf hash: keccak256(abi.encode(keccak256(utf8(kind)), keccak256(canonical_json(payload)))).

    Double-hashing produces a 32-byte digest from a 64-byte ABI-encoded preimage, preventing
    64-byte internal-node second-preimage collisions warned against by OpenZeppelin MerkleProof.
    """
    type_hash = keccak256(kind.encode("utf-8"))
    payload_hash = keccak256(canonical_json(payload))
    return keccak256(_abi_encode_two_bytes32(type_hash, payload_hash))


def parent_hash(a: bytes, b: bytes) -> bytes:
    """Commutative sorted-pair parent hash matching OpenZeppelin standard MerkleProof."""
    if len(a) != 32 or len(b) != 32:
        raise ValueError("Merkle node hashes must be exactly 32 bytes.")
    x, y = (a, b) if a <= b else (b, a)
    return keccak256(x + y)


@dataclass(frozen=True)
class MerkleTreeResult:
    root: bytes
    root_hex: str
    leaves_hex: list[str]
    proofs: list[list[bytes]]
    proofs_hex: list[list[str]]


def build_merkle(leaves: list[bytes]) -> MerkleTreeResult:
    """Build a deterministic Merkle tree using sorted sibling pairs and odd-leaf promotion.

    - If `leaves` is empty, raises ValueError.
    - At any level with an odd number of nodes, the trailing node is promoted directly to the
      next level without duplicating or self-hashing, so every inclusion proof contains only
      genuine sibling hashes.
    """
    if not leaves:
        raise ValueError("Cannot build a Merkle tree with zero leaves.")
    for leaf in leaves:
        if len(leaf) != 32:
            raise ValueError("Each leaf must be a 32-byte hash.")

    n = len(leaves)
    proofs: list[list[bytes]] = [[] for _ in range(n)]

    # Track (node_hash, original_leaf_indices_covered_by_this_node)
    current_level: list[tuple[bytes, list[int]]] = [
        (leaf, [idx]) for idx, leaf in enumerate(leaves)
    ]

    while len(current_level) > 1:
        next_level: list[tuple[bytes, list[int]]] = []
        i = 0
        while i < len(current_level):
            if i + 1 < len(current_level):
                left_hash, left_indices = current_level[i]
                right_hash, right_indices = current_level[i + 1]
                for idx in left_indices:
                    proofs[idx].append(right_hash)
                for idx in right_indices:
                    proofs[idx].append(left_hash)
                combined = parent_hash(left_hash, right_hash)
                next_level.append((combined, left_indices + right_indices))
                i += 2
            else:
                # Odd trailing node promoted directly
                next_level.append(current_level[i])
                i += 1
        current_level = next_level

    root = current_level[0][0]
    return MerkleTreeResult(
        root=root,
        root_hex="0x" + root.hex(),
        leaves_hex=["0x" + l.hex() for l in leaves],
        proofs=proofs,
        proofs_hex=[["0x" + p.hex() for p in proof] for proof in proofs],
    )


def verify_leaf(root: bytes | str, leaf: bytes | str, proof: list[bytes | str]) -> bool:
    """Independently verify that `leaf` belongs to `root` via `proof` using sorted-pair folding."""
    root_bytes = bytes.fromhex(root.removeprefix("0x")) if isinstance(root, str) else root
    acc = bytes.fromhex(leaf.removeprefix("0x")) if isinstance(leaf, str) else leaf
    if len(root_bytes) != 32 or len(acc) != 32:
        return False

    for sibling in proof:
        sib_bytes = (
            bytes.fromhex(sibling.removeprefix("0x"))
            if isinstance(sibling, str)
            else sibling
        )
        if len(sib_bytes) != 32:
            return False
        acc = parent_hash(acc, sib_bytes)

    return acc == root_bytes
