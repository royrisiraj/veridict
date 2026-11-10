// SPDX-License-Identifier: MIT
pragma solidity ^0.8.38;

/// @title EvidenceRegistry
/// @notice Tamper-evident on-chain registry anchoring Evidence Passport Merkle roots.
/// @dev Attests strictly to report integrity and timestamped history, never raw PII or truth.
contract EvidenceRegistry {
    struct Record {
        bytes32 root;
        bytes32 schemaHash;
        uint64 timestamp;
    }

    mapping(bytes32 => Record) public reports;

    event Registered(
        bytes32 indexed reportId,
        bytes32 root,
        bytes32 schemaHash,
        uint64 timestamp
    );

    error ReportAlreadyExists(bytes32 reportId);
    error InvalidRoot();

    /// @notice Anchor a new Evidence Passport Merkle root on-chain.
    /// @param id Deterministic 32-byte report identifier.
    /// @param root 32-byte Merkle root of the canonical EvidenceBundle.
    /// @param schemaHash keccak256("sealed-evidence/1") schema identifier.
    function register(bytes32 id, bytes32 root, bytes32 schemaHash) external {
        if (root == bytes32(0)) revert InvalidRoot();
        if (reports[id].timestamp != 0) revert ReportAlreadyExists(id);

        uint64 ts = uint64(block.timestamp);
        reports[id] = Record({
            root: root,
            schemaHash: schemaHash,
            timestamp: ts
        });

        emit Registered(id, root, schemaHash, ts);
    }

    /// @notice Independently verify whether a candidate Merkle root matches the anchored record.
    function verifyRoot(bytes32 id, bytes32 candidateRoot) external view returns (bool) {
        Record memory rec = reports[id];
        return rec.timestamp != 0 && rec.root == candidateRoot;
    }
}
