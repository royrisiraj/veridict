"""Deterministic RFC 8785-style canonical JSON serialization and Ethereum Keccak-256 hashing."""
from __future__ import annotations

import hashlib
import json
from typing import Any

try:
    from eth_utils import keccak as _eth_keccak

    def keccak256(data: bytes) -> bytes:
        return bytes(_eth_keccak(data))
except ImportError:
    def keccak256(data: bytes) -> bytes:
        """Zero-dependency Ethereum Keccak-256 (0x01 padding) fallback matching Solidity keccak256."""
        rc = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
            0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ]
        rot = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14],
        ]
        mask64 = (1 << 64) - 1
        rol = lambda x, s: ((x << s) | (x >> (64 - s))) & mask64

        rate = 136
        padded = bytearray(data)
        padded.append(0x01)
        while len(padded) % rate != 0:
            padded.append(0x00)
        padded[-1] ^= 0x80

        state = [[0] * 5 for _ in range(5)]
        for offset in range(0, len(padded), rate):
            block = padded[offset : offset + rate]
            for i in range(17):
                lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
                state[i % 5][i // 5] ^= lane
            for r in range(24):
                c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
                d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
                state = [[state[x][y] ^ d[x] for y in range(5)] for x in range(5)]
                b = [[0] * 5 for _ in range(5)]
                for x in range(5):
                    for y in range(5):
                        b[y][(2 * x + 3 * y) % 5] = rol(state[x][y], rot[x][y])
                state = [
                    [b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
                    for x in range(5)
                ]
                state[0][0] ^= rc[r]

        out = bytearray()
        for y in range(5):
            for x in range(5):
                if len(out) < 32:
                    out.extend(state[x][y].to_bytes(8, "little"))
        return bytes(out[:32])


SCHEMA_VERSION = "sealed-evidence/1"
SCHEMA_HASH: bytes = keccak256(SCHEMA_VERSION.encode("utf-8"))
SCHEMA_HASH_HEX: str = "0x" + SCHEMA_HASH.hex()


def canonical_json(obj: Any) -> bytes:
    """Serialize any JSON-compatible Python object into deterministic UTF-8 bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(text: str) -> str:
    """Return lowercase hex SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
