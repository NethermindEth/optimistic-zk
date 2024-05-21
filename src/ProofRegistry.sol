// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ProofRegistry {
    enum PROOF_STATUS {
        RECEIVED,
        FINALISED
    }

    struct ProofData {
        uint256[] _publicInputs;
        uint256[] _proof;
        uint256[] _recursiveAggregationInput;
    }

    struct ProofVerificationClaim {
        ProofData proof;
        bool isValid;
        address verifiedBy;
        uint256 verificationTimestamp;
    }

    struct RewardData {
        uint256 reward;
        // token address(0x0) is considered as ETH
        ERC20 token;
        uint256 finalisationTimestamp;
    }

    event ProofVerificationClaimEvent(bytes32 proofHash, uint256 reward, ERC20 token, uint256 finalisationTimestamp);

    uint256 public immutable CHALLENGE_PERIOD;
    // Only opt-ed Ethereum validators can vote on the verification
    mapping(address => bool) public canVote;
    // proof => (is proof valid, address of the validator that voted, timestamp that they voted)
    // address(0x1) and timestamp = 1, indicate that the proof was verified on-chain
    mapping(bytes32 => ProofVerificationClaim) public isValidProof;
    // proof => address of validator that voted => (reward for verifying the proof, finalisation timestamp of proof)
    mapping(bytes32 => mapping(address => RewardData)) public claims;

    constructor(uint256 challengePeriod) {
        CHALLENGE_PERIOD = challengePeriod;
    }

    // Restaked Ethereum Validators can use this function to update the registry
    function voteValidProof(bytes calldata proof, bool isValid) external {
        address proofVerifier = msg.sender;

        bytes32 proofHash = keccak256(proof);
        ProofVerificationClaim memory proofWitness = isValidProof[proofHash];
        (bool _, address verifiedBy, uint256 verificationTimestamp) =
            (proofWitness.isValid, proofWitness.verifiedBy, proofWitness.verificationTimestamp);

        if (canVote[proofVerifier] && verifiedBy == address(0x0) && verificationTimestamp == 0) {
            isValidProof[proofHash] = ProofVerificationClaim({
                isValid: isValid,
                verifiedBy: proofVerifier,
                verificationTimestamp: block.timestamp
            });
        }
    }

    function verifyERC20(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof,
        uint256[] calldata _recursiveAggregationInput,
        ERC20 token,
        uint256 reward
    ) external payable returns (bool, PROOF_STATUS) {
        ProofData memory proof = ProofData(_publicInputs, _proof, _recursiveAggregationInput);

        bytes32 proofId = keccak256(proof);

        if (isValidProof[proofId].verifiedBy == address(0x0) && isValidProof[proofId].verificationTimestamp == 0) {
            IVerifier verifier = getProofVerificationContract();
            bool isValid = verifier.verify(_publicInputs, _proof, _recursiveAggregationInput);

            isValidProof[proofId] = ProofVerificationClaim({
                ProofData: proof,
                isValid: isValid,
                verifiedBy: msg.sender,
                verificationTimestamp: 1
            });

            emit ProofVerificationClaimEvent(proofId, isValid, reward, token, block.timestamp + CHALLENGE_PERIOD);
            return (isValid, PROOF_STATUS.FINALISED);
        } else {
            // Escrow the reward in ERC20 token from the prover in the ProofRegistry
            token.transferFrom(msg.sender, address(this), reward);

            ProofVerificationClaim memory proofWitness = isValidProof[proofId];
            (bool isValid, address verifiedBy, uint256 verificationTimestamp) =
                (proofWitness.isValid, proofWitness.verifiedBy, proofWitness.verificationTimestamp);

            if (verifiedBy == address(0x1) && verificationTimestamp == 1) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else if (block.timestamp >= verificationTimestamp + CHALLENGE_PERIOD) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else {
                claims[proofId][verifiedBy] = RewardData({
                    reward: reward,
                    token: token,
                    finalisationTimestamp: verificationTimestamp + CHALLENGE_PERIOD
                });
                return (isValid, PROOF_STATUS.RECEIVED);
            }
        }
    }

    // Restaked Ethereum Validators can use this function to update the registry
    function voteValidProof(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof,
        uint256[] calldata _recursiveAggregationInput,
        bool isValid
    ) external {
        address proofVerifier = msg.sender;
        ProofData memory proof = ProofData(_publicInputs, _proof, _recursiveAggregationInput);
        bytes32 proofId = keccak256(proof);
        ProofVerificationClaim memory proofWitness = isValidProof[proofId];
        (bool _, address verifiedBy, uint256 verificationTimestamp) =
            (proofWitness.isValid, proofWitness.verifiedBy, proofWitness.verificationTimestamp);

        if (canVote[proofVerifier] && verifiedBy == address(0x0) && verificationTimestamp == 0) {
            isValidProof[proofHash] = ProofVerificationClaim({
                isValid: isValid,
                verifiedBy: proofVerifier,
                verificationTimestamp: block.timestamp
            });
        }
    }

    function challenge(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof,
        uint256[] calldata _recursiveAggregationInput
    ) external {
        ProofData memory proof = ProofData(_publicInputs, _proof, _recursiveAggregationInput);
        bytes32 proofId = keccak256(proof);

        ProofVerificationClaim memory proofWitness = isValidProof[proofId];
        (bool originalProofVote, address originalVerifier, uint256 originalVerificationTimestamp) =
            (, proofWitness.isValid, proofWitness.verifiedBy, proofWitness.verificationTimestamp);

        if (originalVerifier == address(0x0) && originalVerificationTimestamp == 0) {
            revert("No past vote");
        }

        if (originalVerifier == address(0x1) && originalVerificationTimestamp == 1) {
            revert("Proof was verified on-chain, cannot be challenged");
        }

        if (block.timestamp > CHALLENGE_PERIOD + originalVerificationTimestamp) {
            revert("Challenge period past");
        }

        IVerifier verifier = getProofVerificationContract();

        bool challengerVote = verifier.verify();
        address challengerAddress = msg.sender;

        if (challengerVote == originalProofVote) {
            revert("Challenger vote same as original verifier");
        }
        // Original proposer lied about the verification of the proof
        isValidProof[proofId] =
            ProofVerificationClaim({isValid: challengerVote, verifiedBy: address(0x1), verificationTimestamp: 1});

        token.transfer(challengerAddress, bid);

        slash(originalVerifier);
    }

    function claimReward(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof,
        uint256[] calldata _recursiveAggregationInput
    ) external {
        ProofData memory proof = ProofData(_publicInputs, _proof, _recursiveAggregationInput);
        bytes32 proofId = keccak256(proof);
        if (claims[proofId][msg.sender].finalisationTimestamp == 0 && claims[proofId][msg.sender].reward == 0) {
            revert("not a valid claim");
        }

        (uint256 bid, ERC20 token, uint256 finalisationTimestamp) = (
            claims[proofId][msg.sender].reward,
            claims[proofId][msg.sender].token,
            claims[proofId][msg.sender].finalisationTimestamp
        );

        if (block.timestamp < finalisationTimestamp) {
            revert("proof not finalised");
        }

        token.transfer(msg.sender, bid);
    }

    function getProofVerificationContract() internal pure returns (IVerifier) {
        // returns the contract address of a verifier contract based on the type of proof
        // the address is for zksync diamond contract
        address _verifierContract = IGetVerifier(0x32400084C286CF3E17e7B677ea9583e60a000324).getVerifier();
        return IVerifier(_verifierContract);
    }

    function slash(address maliciousProposer) internal {
        // penalises the maliciousProposer and evicts them from the precompile service
        // eigenlayer slashing
    }
}

interface IVerifier {
    function verify(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof,
        uint256[] calldata _recursiveAggregationInput
    ) external view returns (bool);
}

interface IGetVerifier {
    function getVerifier() external returns (address);
}
