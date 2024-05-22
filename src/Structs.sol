// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

struct MerkelStatementProof {
    uint256[] merkleView;
    uint256[] initialMerkleQueue;
    uint256 height;
    uint256 expectedRoot;
    bytes32 factHash;
}

struct MerkleStatementProofVerificationClaim {
    MerkelStatementProof proof;
    bool isValid;
    address verifiedBy;
    uint verificationTimestamp;
}

struct FriProof {
    uint256[] proof;
    uint256[] friQueue;
    uint256 evaluationPoint;
    uint256 friStepSize;
    uint256 expectedRoot;
}

struct FriProofVerificationClaim {
    FriProof proof;
    bool isValid;
    address verifiedBy;
    uint verificationTimestamp;
}
struct GPSProof {
    uint256[] proofParams;
    uint256[] proof;
    uint256[] taskMetadata;
    uint256[] cairoAuxInput;
    uint256 cairoVerifierId;
}

struct GPSProofVerificationClaim {
    GPSProof proof;
    bool isValid;
    address verifiedBy;
    uint verificationTimestamp;
}

struct ContinuousMemoryPageProof {
    uint256 startAddr;
    uint256[] values;
    uint256 z;
    uint256 alpha;
    uint256 prime;
}

struct ContinuousMemoryPageProofVerificationClaim {
    ContinuousMemoryPageProof proof;
    bool isValid;
    address verifiedBy;
    uint verificationTimestamp;
}

struct GPSProofData {
    uint256[] proofParams;
    uint256[] proof;
    uint256[] taskMetadata;
    uint256[] cairoAuxInput;
    uint256 cairoVerifierId;
}
