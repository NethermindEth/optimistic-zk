// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./Interfaces.sol";
import "./Structs.sol";

contract ProofRegistry {
    IMerkleStatementContract public merkleStatementContract;
    IFriStatementContract public friStatementContract;
    IGPSStatementVerification public gpsStatementVerification;
    IMemoryPageFactRegistry public memoryPageFactRegistry;

    uint public immutable CHALLENGE_PERIOD;

    enum PROOF_STATUS {
        RECEIVED,
        FINALISED
    }

    mapping(bytes32 => MerkleStatementProofVerificationClaim)
        public verificationClaims;
    mapping(bytes32 => FriProofVerificationClaim) public friVerificationClaims;
    mapping(bytes32 => GPSProofVerificationClaim) public gpsVerificationClaims;
    mapping(bytes32 => ContinuousMemoryPageProofVerificationClaim)
        public continuousMemoryPageVerificationClaims;
    mapping(address => uint256) public challengerRewards;

    event ProofRegistered(
        bytes32 indexed proofId,
        address indexed verifier,
        string proofType
    );
    event ProofChallenged(
        bytes32 indexed proofId,
        address indexed challenger,
        bool indexed isValid,
        string proofType
    );
    event RewardClaimed(address indexed challenger, uint256 amount);
    event ProofRefunded(
        bytes32 indexed proofId,
        address indexed claimer,
        uint256 amount
    );

    error ProofAlreadyRegistered();
    error ProofNotRegistered();
    error ProofVerifiedOnChain();
    error ChallengePeriodPassed();
    error ChallengerSameAsVerifier();
    error NoRewardsAvailable();
    error InvalidChallenge();

    constructor(
        IMerkleStatementContract _merkleStatementContract,
        IFriStatementContract _friStatementContract,
        IGPSStatementVerification _gpsStatementVerification,
        IMemoryPageFactRegistry _memoryPageFactRegistry,
        uint _challengePeriod
    ) {
        CHALLENGE_PERIOD = _challengePeriod;
        merkleStatementContract = _merkleStatementContract;
        friStatementContract = _friStatementContract;
        gpsStatementVerification = _gpsStatementVerification;
        memoryPageFactRegistry = _memoryPageFactRegistry;
    }

    /**
     * @dev Registers a new Merkle proof and its verification claim.
     * @param merkleView The Merkle view of the proof.
     * @param initialMerkleQueue The initial Merkle queue of the proof.
     * @param height The height of the Merkle tree.
     * @param expectedRoot The expected Merkle root.
     * @param factHash The hash of the fact associated with the proof.
     * @param isValid The validity of the proof.
     */
    function registerMerkleProof(
        uint256[] calldata merkleView,
        uint256[] calldata initialMerkleQueue,
        uint256 height,
        uint256 expectedRoot,
        bytes32 factHash,
        bool isValid
    ) public {
        MerkelStatementProof memory proof = MerkelStatementProof(
            merkleView,
            initialMerkleQueue,
            height,
            expectedRoot,
            factHash
        );
        bytes32 proofId = keccak256(abi.encode(proof));
        if (verificationClaims[proofId].verifiedBy != address(0)) {
            revert ProofAlreadyRegistered();
        }

        verificationClaims[proofId] = MerkleStatementProofVerificationClaim(
            proof,
            isValid,
            msg.sender,
            block.timestamp
        );
        emit ProofRegistered(proofId, msg.sender, "MERKLE");
    }

    function registerFriProof(
        uint256[] calldata proof,
        uint256[] calldata friQueue,
        uint256 evaluationPoint,
        uint256 friStepSize,
        uint256 expectedRoot,
        bool isValid
    ) public {
        FriProof memory friProof = FriProof(
            proof,
            friQueue,
            evaluationPoint,
            friStepSize,
            expectedRoot
        );
        bytes32 proofId = keccak256(abi.encode(friProof));
        if (friVerificationClaims[proofId].verifiedBy != address(0)) {
            revert ProofAlreadyRegistered();
        }

        friVerificationClaims[proofId] = FriProofVerificationClaim(
            friProof,
            isValid,
            msg.sender,
            block.timestamp
        );
        emit ProofRegistered(proofId, msg.sender, "FRI");
    }

    function registerGPSProof(
        uint256[] calldata proofParams,
        uint256[] calldata proof,
        uint256[] calldata taskMetadata,
        uint256[] calldata cairoAuxInput,
        uint256 cairoVerifierId,
        bool isValid
    ) public {
        GPSProof memory gpsProof = GPSProof(
            proofParams,
            proof,
            taskMetadata,
            cairoAuxInput,
            cairoVerifierId
        );
        bytes32 proofId = keccak256(abi.encode(gpsProof));
        if (gpsVerificationClaims[proofId].verifiedBy != address(0)) {
            revert ProofAlreadyRegistered();
        }

        gpsVerificationClaims[proofId] = GPSProofVerificationClaim(
            gpsProof,
            isValid,
            msg.sender,
            block.timestamp
        );
        emit ProofRegistered(proofId, msg.sender, "GPS");
    }

    function registerContinuousMemoryPageProof(
        uint256 startAddr,
        uint256[] memory values,
        uint256 z,
        uint256 alpha,
        uint256 prime,
        bool isValid
    ) public {
        ContinuousMemoryPageProof memory proof = ContinuousMemoryPageProof(
            startAddr,
            values,
            z,
            alpha,
            prime
        );
        bytes32 proofId = keccak256(abi.encode(proof));
        if (
            continuousMemoryPageVerificationClaims[proofId].verifiedBy !=
            address(0)
        ) {
            revert ProofAlreadyRegistered();
        }

        continuousMemoryPageVerificationClaims[
            proofId
        ] = ContinuousMemoryPageProofVerificationClaim(
            proof,
            isValid,
            msg.sender,
            block.timestamp
        );
        emit ProofRegistered(proofId, msg.sender, "CMPP");
    }

    /**
     * @dev Challenges a registered proof verification claim.
     * @param proofId The ID of the proof to challenge.
     */
    function challengeMerkleProof(bytes32 proofId) external {
        MerkleStatementProofVerificationClaim
            storage claim = verificationClaims[proofId];
        if (claim.verifiedBy == address(0)) {
            revert ProofNotRegistered();
        }
        if (claim.verifiedBy == address(0x1)) {
            revert ProofVerifiedOnChain();
        }
        if (block.timestamp >= claim.verificationTimestamp + CHALLENGE_PERIOD) {
            revert ChallengePeriodPassed();
        }
        if (msg.sender == claim.verifiedBy) {
            revert ChallengerSameAsVerifier();
        }

        bool challengerVote = merkleStatementContract.verifyMerkle(
            claim.proof.merkleView,
            claim.proof.initialMerkleQueue,
            claim.proof.height,
            claim.proof.expectedRoot
        );

        if (challengerVote != claim.isValid) {
            slash(claim.verifiedBy);
            claim.isValid = challengerVote;
            claim.verifiedBy = msg.sender;
            claim.verificationTimestamp = block.timestamp;
            uint256 rewardAmount = calculateReward();
            challengerRewards[msg.sender] += rewardAmount;
            emit ProofChallenged(proofId, msg.sender, challengerVote, "MERKLE");
        } else {
            revert InvalidChallenge();
        }
    }

    function challengeFriProof(bytes32 proofId) external {
        FriProofVerificationClaim storage claim = friVerificationClaims[
            proofId
        ];
        if (claim.verifiedBy == address(0)) {
            revert ProofNotRegistered();
        }
        if (claim.verifiedBy == address(0x1)) {
            revert ProofVerifiedOnChain();
        }
        if (block.timestamp >= claim.verificationTimestamp + CHALLENGE_PERIOD) {
            revert ChallengePeriodPassed();
        }
        if (msg.sender == claim.verifiedBy) {
            revert ChallengerSameAsVerifier();
        }

        bool challengerVote = friStatementContract.verifyFRI(
            claim.proof.proof,
            claim.proof.friQueue,
            claim.proof.evaluationPoint,
            claim.proof.friStepSize,
            claim.proof.expectedRoot
        );

        if (challengerVote != claim.isValid) {
            slash(claim.verifiedBy);
            claim.isValid = challengerVote;
            claim.verifiedBy = msg.sender;
            claim.verificationTimestamp = block.timestamp;
            uint256 rewardAmount = calculateReward();
            challengerRewards[msg.sender] += rewardAmount;
            emit ProofChallenged(proofId, msg.sender, challengerVote, "FRI");
        } else {
            revert InvalidChallenge();
        }
    }

    function challengeGPSProof(bytes32 proofId) external {
        GPSProofVerificationClaim storage claim = gpsVerificationClaims[
            proofId
        ];
        if (claim.verifiedBy == address(0)) {
            revert ProofNotRegistered();
        }
        if (claim.verifiedBy == address(0x1)) {
            revert ProofVerifiedOnChain();
        }
        if (block.timestamp >= claim.verificationTimestamp + CHALLENGE_PERIOD) {
            revert ChallengePeriodPassed();
        }
        if (msg.sender == claim.verifiedBy) {
            revert ChallengerSameAsVerifier();
        }

        bool challengerVote = gpsStatementVerification.verifyProofAndRegister(
            claim.proof.proofParams,
            claim.proof.proof,
            claim.proof.taskMetadata,
            claim.proof.cairoAuxInput,
            claim.proof.cairoVerifierId
        );

        if (challengerVote != claim.isValid) {
            slash(claim.verifiedBy);
            claim.isValid = challengerVote;
            claim.verifiedBy = msg.sender;
            claim.verificationTimestamp = block.timestamp;
            uint256 rewardAmount = calculateReward();
            challengerRewards[msg.sender] += rewardAmount;
            emit ProofChallenged(proofId, msg.sender, challengerVote, "GPS");
        } else {
            revert InvalidChallenge();
        }
    }
    function challengeContinuousMemoryPageProof(bytes32 proofId) external {
        ContinuousMemoryPageProofVerificationClaim
            storage claim = continuousMemoryPageVerificationClaims[proofId];
        if (claim.verifiedBy == address(0)) {
            revert ProofNotRegistered();
        }
        if (claim.verifiedBy == address(0x1)) {
            revert ProofVerifiedOnChain();
        }
        if (block.timestamp >= claim.verificationTimestamp + CHALLENGE_PERIOD) {
            revert ChallengePeriodPassed();
        }
        if (msg.sender == claim.verifiedBy) {
            revert ChallengerSameAsVerifier();
        }

        (bool challengerVote, , ) = memoryPageFactRegistry
            .registerContinuousMemoryPage(
                claim.proof.startAddr,
                claim.proof.values,
                claim.proof.z,
                claim.proof.alpha,
                claim.proof.prime
            );

        if (challengerVote != claim.isValid) {
            slash(claim.verifiedBy);
            claim.isValid = challengerVote;
            claim.verifiedBy = msg.sender;
            claim.verificationTimestamp = block.timestamp;
            uint256 rewardAmount = calculateReward();
            challengerRewards[msg.sender] += rewardAmount;
            emit ProofChallenged(proofId, msg.sender, challengerVote, "CMPP");
        } else {
            revert InvalidChallenge();
        }
    }

    /**
     * @dev Calculates the reward amount for a successful challenge.
     * @return The reward amount.
     */
    function calculateReward() internal view returns (uint256) {
        // Implement the reward calculation logic here
    }

    /**
     * @dev Allows a challenger to claim their earned rewards.
     */
    function claimReward() external {
        uint256 rewardAmount = challengerRewards[msg.sender];
        if (rewardAmount == 0) {
            revert NoRewardsAvailable();
        }
        challengerRewards[msg.sender] = 0;
        payable(msg.sender).transfer(rewardAmount);
        emit RewardClaimed(msg.sender, rewardAmount);
    }

    /**
     * @dev Slashes a malicious proposer.
     * @param maliciousProposer The address of the malicious proposer.
     */
    function slash(address maliciousProposer) internal {
        // Implement the slashing logic here
    }

    /**
     * @dev Verifies a Merkle proof and returns its status.
     * @param merkleView The Merkle view of the proof.
     * @param initialMerkleQueue The initial Merkle queue of the proof.
     * @param height The height of the Merkle tree.
     * @param expectedRoot The expected Merkle root.
     * @param factHash The hash of the fact associated with the proof.
     * @return isValid The validity of the proof.
     * @return status The status of the proof (RECEIVED or FINALISED).
     */
    function verifyMerkle(
        uint256[] calldata merkleView,
        uint256[] calldata initialMerkleQueue,
        uint256 height,
        uint256 expectedRoot,
        bytes32 factHash
    ) external payable returns (bool, PROOF_STATUS) {
        uint reward = msg.value;
        MerkelStatementProof memory proof = MerkelStatementProof(
            merkleView,
            initialMerkleQueue,
            height,
            expectedRoot,
            factHash
        );
        bytes32 proofId = keccak256(abi.encode(proof));

        if (verificationClaims[proofId].verifiedBy == address(0)) {
            bool isValid = merkleStatementContract.verifyMerkle(
                merkleView,
                initialMerkleQueue,
                height,
                expectedRoot
            );
            if (!isValid) {
                payable(msg.sender).transfer(reward);
                emit ProofRefunded(proofId, msg.sender, reward);
                return (false, PROOF_STATUS.FINALISED);
            }
            registerMerkleProof(
                merkleView,
                initialMerkleQueue,
                height,
                expectedRoot,
                factHash,
                isValid
            );
            return (isValid, PROOF_STATUS.FINALISED);
        } else {
            MerkleStatementProofVerificationClaim
                memory claim = verificationClaims[proofId];
            if (
                block.timestamp >=
                claim.verificationTimestamp + CHALLENGE_PERIOD
            ) {
                return (claim.isValid, PROOF_STATUS.FINALISED);
            } else {
                challengerRewards[claim.verifiedBy] += reward;
                return (claim.isValid, PROOF_STATUS.RECEIVED);
            }
        }
    }
    function verifyFri(
        uint256[] calldata proof,
        uint256[] calldata friQueue,
        uint256 evaluationPoint,
        uint256 friStepSize,
        uint256 expectedRoot
    ) external payable returns (bool, PROOF_STATUS) {
        uint reward = msg.value;
        FriProof memory friProof = FriProof(
            proof,
            friQueue,
            evaluationPoint,
            friStepSize,
            expectedRoot
        );
        bytes32 proofId = keccak256(abi.encode(friProof));

        if (friVerificationClaims[proofId].verifiedBy == address(0)) {
            bool isValid = friStatementContract.verifyFRI(
                proof,
                friQueue,
                evaluationPoint,
                friStepSize,
                expectedRoot
            );
            if (!isValid) {
                payable(msg.sender).transfer(reward);
                emit ProofRefunded(proofId, msg.sender, reward);
                return (false, PROOF_STATUS.FINALISED);
            }
            registerFriProof(
                proof,
                friQueue,
                evaluationPoint,
                friStepSize,
                expectedRoot,
                isValid
            );
            return (isValid, PROOF_STATUS.FINALISED);
        } else {
            FriProofVerificationClaim memory claim = friVerificationClaims[
                proofId
            ];
            if (
                block.timestamp >=
                claim.verificationTimestamp + CHALLENGE_PERIOD
            ) {
                return (claim.isValid, PROOF_STATUS.FINALISED);
            } else {
                challengerRewards[claim.verifiedBy] += reward;
                return (claim.isValid, PROOF_STATUS.RECEIVED);
            }
        }
    }

function verifyGPS(GPSProofData calldata gpsProofData) external payable returns (bool, PROOF_STATUS) {
    uint reward = msg.value;
    GPSProof memory gpsProof = GPSProof(
        gpsProofData.proofParams,
        gpsProofData.proof,
        gpsProofData.taskMetadata,
        gpsProofData.cairoAuxInput,
        gpsProofData.cairoVerifierId
    );
    bytes32 proofId = keccak256(abi.encode(gpsProof));

    if (gpsVerificationClaims[proofId].verifiedBy == address(0)) {
        return _verifyGPSOnChain(gpsProofData, reward, proofId);
    } else {
        return _verifyGPSOffChain(proofId, reward);
    }
}

function _verifyGPSOnChain(GPSProofData calldata gpsProofData, uint reward, bytes32 proofId) internal returns (bool, PROOF_STATUS) {
    bool isValid = gpsStatementVerification.verifyProofAndRegister(
        gpsProofData.proofParams,
        gpsProofData.proof,
        gpsProofData.taskMetadata,
        gpsProofData.cairoAuxInput,
        gpsProofData.cairoVerifierId
    );
    if (!isValid) {
        payable(msg.sender).transfer(reward);
        emit ProofRefunded(proofId, msg.sender, reward);
        return (false, PROOF_STATUS.FINALISED);
    }
    registerGPSProof(
        gpsProofData.proofParams,
        gpsProofData.proof,
        gpsProofData.taskMetadata,
        gpsProofData.cairoAuxInput,
        gpsProofData.cairoVerifierId,
        isValid
    );
    return (isValid, PROOF_STATUS.FINALISED);
}

function _verifyGPSOffChain(bytes32 proofId, uint reward) internal returns (bool, PROOF_STATUS) {
    GPSProofVerificationClaim memory claim = gpsVerificationClaims[proofId];
    if (block.timestamp >= claim.verificationTimestamp + CHALLENGE_PERIOD) {
        return (claim.isValid, PROOF_STATUS.FINALISED);
    } else {
        challengerRewards[claim.verifiedBy] += reward;
        return (claim.isValid, PROOF_STATUS.RECEIVED);
    }
}
    function verifyContinuousMemoryPage(
        uint256 startAddr,
        uint256[] memory values,
        uint256 z,
        uint256 alpha,
        uint256 prime
    ) external payable returns (bool, PROOF_STATUS) {
        uint reward = msg.value;
        ContinuousMemoryPageProof memory proof = ContinuousMemoryPageProof(
            startAddr,
            values,
            z,
            alpha,
            prime
        );
        bytes32 proofId = keccak256(abi.encode(proof));

        if (
            continuousMemoryPageVerificationClaims[proofId].verifiedBy ==
            address(0)
        ) {
            (bool isValid, , ) = memoryPageFactRegistry
                .registerContinuousMemoryPage(
                    startAddr,
                    values,
                    z,
                    alpha,
                    prime
                );
            if (!isValid) {
                payable(msg.sender).transfer(reward);
                emit ProofRefunded(proofId, msg.sender, reward);
                return (false, PROOF_STATUS.FINALISED);
            }
            registerContinuousMemoryPageProof(
                startAddr,
                values,
                z,
                alpha,
                prime,
                isValid
            );
            return (isValid, PROOF_STATUS.FINALISED);
        } else {
            ContinuousMemoryPageProofVerificationClaim
                memory claim = continuousMemoryPageVerificationClaims[proofId];
            if (
                block.timestamp >=
                claim.verificationTimestamp + CHALLENGE_PERIOD
            ) {
                return (claim.isValid, PROOF_STATUS.FINALISED);
            } else {
                challengerRewards[claim.verifiedBy] += reward;
                return (claim.isValid, PROOF_STATUS.RECEIVED);
            }
        }
    }
}
