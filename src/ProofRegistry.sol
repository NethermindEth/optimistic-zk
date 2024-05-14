// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract ProofRegistry {
    enum PROOF_STATUS {
        RECEIVED,
        FINALISED
    }

    struct ProofVerificationClaim {
        bool isValid;
        address verifiedBy;
        uint verificationTimestamp;
    }

    struct RewardData {
        uint256 reward;
        // token address(0x0) is considered as ETH
        ERC20 token;
        uint256 finalisationTimestamp;
    }

    event ProofVerificationClaimEvent(
        bytes32 proofHash,
        uint reward,
        ERC20 token,
        uint finalisationTimestamp
    );

    uint public immutable CHALLENGE_PERIOD;
    // Only opt-ed Ethereum validators can vote on the verification
    mapping(address validator => bool) public canVote;
    // proof => (is proof valid, address of the validator that voted, timestamp that they voted)
    // address(0x1) and timestamp = 1, indicate that the proof was verified on-chain
    mapping(bytes32 proofHash => ProofVerificationClaim) public isValidProof;
    // proof => address of validator that voted => (reward for verifying the proof, finalisation timestamp of proof)
    mapping(bytes32 proofHash => mapping(address proofVerifier => RewardData))
        public claims;

    constructor(uint challengePeriod) {
        CHALLENGE_PERIOD = challengePeriod;
    }

    // Restaked Ethereum Validators can use this function to update the registry
    function voteValidProof(bytes calldata proof, bool isValid) external {
        address proofVerifier = msg.sender;

        bytes32 proofHash = keccak256(proof);
        ProofVerificationClaim memory proofWitness = isValidProof[
                proofHash
            ];
        (bool _, address verifiedBy, uint verificationTimestamp) = (
                proofWitness.isValid,
                proofWitness.verifiedBy,
                proofWitness.verificationTimestamp
        );

        if (canVote[proofVerifier] && verifiedBy == address(0x0) && verificationTimestamp == 0) {
            isValidProof[proofHash] = ProofVerificationClaim({
                isValid: isValid,
                verifiedBy: proofVerifier,
                verificationTimestamp: block.timestamp
            });
        }
    }

    function verifyERC20(
        bytes calldata proof,
        ERC20 token,
        uint reward
    ) external payable returns (bool, PROOF_STATUS) {
        bytes32 proofHash = keccak256(proof);
        if (
            isValidProof[proofHash].verifiedBy == address(0x0) &&
            isValidProof[proofHash].verificationTimestamp == 0
        ) {
            IVerifier verifier = getProofVerificationContract(proof);
            bool isValid = verifier.verify(proof);

            isValidProof[proofHash] = ProofVerificationClaim({
                isValid: isValid,
                verifiedBy: address(0x1),
                verificationTimestamp: 1
            });

            emit ProofVerificationClaimEvent(
                proofHash,
                isValid,
                reward,
                token,
                block.timestamp + CHALLENGE_PERIOD
            );
            return (isValid, PROOF_STATUS.FINALISED);
        } else {
            // Escrow the reward in ERC20 token from the prover in the ProofRegistry
            token.transferFrom(msg.sender, address(this), reward);

            ProofVerificationClaim memory proofWitness = isValidProof[
                proofHash
            ];
            (bool isValid, address verifiedBy, uint verificationTimestamp) = (
                proofWitness.isValid,
                proofWitness.verifiedBy,
                proofWitness.verificationTimestamp
            );

            if (verifiedBy == address(0x1) && verificationTimestamp == 1) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else if (
                block.timestamp >= verificationTimestamp + CHALLENGE_PERIOD
            ) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else {
                claims[proofHash][verifiedBy] = RewardData({
                    reward: reward,
                    token: token,
                    finalisationTimestamp: verificationTimestamp +
                        CHALLENGE_PERIOD
                });
                return (isValid, PROOF_STATUS.RECEIVED);
            }
        }
    }

    function verify(
        bytes calldata proof
    ) external payable returns (bool, PROOF_STATUS) {
        uint reward = msg.value;
        bytes32 proofHash = keccak256(proof);
        if (
            isValidProof[proofHash].verifiedBy == address(0x0) &&
            isValidProof[proofHash].verificationTimestamp == 0
        ) {
            // return the bid since no record for the proof in the registry
            payable(msg.sender).transfer(reward);

            IVerifier verifier = getProofVerificationContract(proof);
            bool isValid = verifier.verify(proof);

            isValidProof[proofHash] = ProofVerificationClaim({
                isValid: isValid,
                verifiedBy: address(0x1),
                verificationTimestamp: 1
            });

            emit ProofVerificationClaimEvent(
                proofHash,
                isValid,
                reward,
                ERC20(address(0x0)),
                block.timestamp + CHALLENGE_PERIOD
            );
            return (isValid, PROOF_STATUS.FINALISED);
        } else {
            ProofVerificationClaim memory proofWitness = isValidProof[
                proofHash
            ];
            (bool isValid, address verifiedBy, uint verificationTimestamp) = (
                proofWitness.isValid,
                proofWitness.verifiedBy,
                proofWitness.verificationTimestamp
            );

            if (verifiedBy == address(0x1) && verificationTimestamp == 1) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else if (
                block.timestamp >= verificationTimestamp + CHALLENGE_PERIOD
            ) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else {
                claims[proofHash][verifiedBy] = RewardData({
                    reward: reward,
                    token: ERC20(address(0x0)),
                    finalisationTimestamp: verificationTimestamp +
                        CHALLENGE_PERIOD
                });
                return (isValid, PROOF_STATUS.RECEIVED);
            }
        }
    }

    function challenge(bytes calldata proof) external {
        bytes32 proofHash = keccak256(proof);
        ProofVerificationClaim memory proofWitness = isValidProof[proofHash];
        (
            bool originalProofVote,
            address originalVerifier,
            uint originalVerificationTimestamp
        ) = (
                proofWitness.isValid,
                proofWitness.verifiedBy,
                proofWitness.verificationTimestamp
            );

        if (
            originalVerifier == address(0x0) &&
            originalVerificationTimestamp == 0
        ) {
            revert("No past vote");
        }

        if (
            originalVerifier == address(0x1) &&
            originalVerificationTimestamp == 1
        ) {
            revert("Proof was verified on-chain, cannot be challenged");
        }

        if (
            block.timestamp > CHALLENGE_PERIOD + originalVerificationTimestamp
        ) {
            revert("Challenge period past");
        }

        IVerifier verifier = getProofVerificationContract(proof);

        bool challengerVote = verifier.verify(proof);
        address challengerAddress = msg.sender;

        RewardData memory rewardData = claims[proofHash][originalVerifier];
        (uint bid, ERC20 token) = (rewardData.reward, rewardData.token);

        if (challengerVote == originalProofVote) {
            revert("Challenger vote same as original verifier");
        }

        // Original proposer lied about the verification of the proof
        // removing the reward data 
        address _initialVerifier = isValidProof[proofHash].verifiedBy;

        

        isValidProof[proofHash] = ProofVerificationClaim({
            isValid: challengerVote,
            verifiedBy: address(0x1),
            verificationTimestamp: 1
        });

        
        // Pay the challenger
        if (token != ERC20(address(0x0))) {
            token.transfer(challengerAddress, bid);
        } else {
            payable(challengerAddress).transfer(bid);
        }
        claims[proofHash][_initialVerifier] = RewardData({
            reward:0,
            token:address(0x0),
            finalisationTimestamp:block.timestamp
        });
        // Penalise the original verifier
        slash(originalVerifier);
    }

    function claimReward(bytes calldata proof) external {
        bytes32 proofHash = keccak256(proof);
        if (
            claims[proofHash][msg.sender].finalisationTimestamp == 0 &&
            claims[proofHash][msg.sender].reward == 0
        ) {
            revert("not a valid claim");
        }

        (uint bid, ERC20 token, uint finalisationTimestamp) = (
            claims[proofHash][msg.sender].reward,
            claims[proofHash][msg.sender].token,
            claims[proofHash][msg.sender].finalisationTimestamp
        );

        if (block.timestamp < finalisationTimestamp) {
            revert("proof not finalised");
        }

        // collect reward for verifying proof off-chain
        if (token != ERC20(address(0x0))) {
            token.transfer(msg.sender, bid);
        } else {
            payable(msg.sender).transfer(bid);
        }
    }

    function getProofVerificationContract(
        bytes calldata proof
    ) internal pure returns (IVerifier) {
        // returns the contract address of a verifier contract based on the type of proof
        return IVerifier(address(0x0));
    }

    function slash(address maliciousProposer) internal {
        // penalises the maliciousProposer and evicts them from the precompile service
        // eigenlayer slashing
    }
}

interface IVerifier {
    function verify(bytes calldata proof) external returns (bool);
}
