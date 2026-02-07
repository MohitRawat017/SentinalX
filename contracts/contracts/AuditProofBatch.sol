// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AuditProofBatch
 * @author SentinelX Team
 * @notice Gas-efficient Merkle root storage for batched security event audit trails.
 *         Only the Merkle root is stored on-chain (~$0.05 per 1000 events).
 *         Individual event inclusion is verified off-chain using Merkle proofs.
 */
contract AuditProofBatch {
    // ─── State ──────────────────────────────────────────────────────
    address public owner;
    uint256 public batchCount;

    struct Batch {
        bytes32 merkleRoot;
        uint256 eventCount;
        uint256 timestamp;
        address submitter;
    }

    // batchId => Batch
    mapping(uint256 => Batch) public batches;

    // merkleRoot => exists
    mapping(bytes32 => bool) public rootExists;

    // merkleRoot => batchId
    mapping(bytes32 => uint256) public rootToBatchId;

    // ─── Events ─────────────────────────────────────────────────────
    event BatchStored(
        uint256 indexed batchId,
        bytes32 indexed merkleRoot,
        uint256 eventCount,
        uint256 timestamp,
        address submitter
    );

    event InclusionVerified(
        bytes32 indexed merkleRoot,
        bytes32 indexed leaf,
        bool valid
    );

    // ─── Modifiers ──────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    // ─── Constructor ────────────────────────────────────────────────
    constructor() {
        owner = msg.sender;
        batchCount = 0;
    }

    // ─── Core Functions ─────────────────────────────────────────────

    /**
     * @notice Store a Merkle root on-chain for a batch of security events
     * @param root The Merkle root of the event batch
     * @param eventCount Number of events in this batch
     */
    function storeBatch(bytes32 root, uint256 eventCount) external onlyOwner {
        require(root != bytes32(0), "Empty root");
        require(!rootExists[root], "Root already stored");
        require(eventCount > 0, "No events");

        batchCount++;

        batches[batchCount] = Batch({
            merkleRoot: root,
            eventCount: eventCount,
            timestamp: block.timestamp,
            submitter: msg.sender
        });

        rootExists[root] = true;
        rootToBatchId[root] = batchCount;

        emit BatchStored(batchCount, root, eventCount, block.timestamp, msg.sender);
    }

    /**
     * @notice Verify that a leaf (event hash) is included in a stored Merkle root
     * @param leaf The event hash to verify
     * @param proof Array of sibling hashes forming the Merkle proof
     * @param root The Merkle root to verify against
     * @return valid Whether the proof is valid
     */
    function verifyInclusion(
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes32 root
    ) external returns (bool valid) {
        require(rootExists[root], "Root not found");

        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        valid = computedHash == root;
        emit InclusionVerified(root, leaf, valid);
    }

    /**
     * @notice Get batch details by ID
     */
    function getBatch(uint256 batchId) external view returns (
        bytes32 merkleRoot,
        uint256 eventCount,
        uint256 timestamp,
        address submitter
    ) {
        require(batchId > 0 && batchId <= batchCount, "Invalid batch ID");
        Batch memory b = batches[batchId];
        return (b.merkleRoot, b.eventCount, b.timestamp, b.submitter);
    }

    /**
     * @notice Check if a Merkle root has been stored
     */
    function isRootStored(bytes32 root) external view returns (bool) {
        return rootExists[root];
    }

    /**
     * @notice Transfer ownership
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
