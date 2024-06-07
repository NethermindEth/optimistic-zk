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
    mapping(address validator => bool) public canVote;
    // proof => (is proof valid, address of the validator that voted, timestamp that they voted)
    // address(0x1) and timestamp = 1, indicate that the proof was verified on-chain
    mapping(bytes32 proofHash => ProofVerificationClaim) public isValidProof;
    // proof => address of validator that voted => (reward for verifying the proof, finalisation timestamp of proof)
    mapping(bytes32 proofHash => mapping(address proofVerifier => RewardData)) public claims;

    constructor(uint256 challengePeriod) {
        CHALLENGE_PERIOD = challengePeriod;
    }



    function verifyERC20(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof,
        uint256[] calldata _recursiveAggregationInput,
        ERC20 token,
        uint256 reward
    ) external payable returns (bool, PROOF_STATUS) {
        // ProofData memory proof = ProofData(_publicInputs, _proof, _recursiveAggregationInput);
  bytes memory proof = abi.encode(_publicInputs, _proof, _recursiveAggregationInput);
        bytes32 proofHash = keccak256(proof);

        if (isValidProof[proofHash].verifiedBy == address(0x0) && isValidProof[proofHash].verificationTimestamp == 0) {
            IVerifier verifier = getProofVerificationContract();
            bool isValid = verifier.verify(_publicInputs, _proof, _recursiveAggregationInput);

            isValidProof[proofHash] = ProofVerificationClaim({
             
                isValid: isValid,
                verifiedBy: address(0x1),
                verificationTimestamp: 1
            });

            emit ProofVerificationClaimEvent(proofHash, reward, token, block.timestamp + CHALLENGE_PERIOD);
            return (isValid, PROOF_STATUS.FINALISED);
        } else {
            // Escrow the reward in ERC20 token from the prover in the ProofRegistry
            token.transferFrom(msg.sender, address(this), reward);

            ProofVerificationClaim memory proofWitness = isValidProof[proofHash];
            (bool isValid, address verifiedBy, uint256 verificationTimestamp) =
                (proofWitness.isValid, proofWitness.verifiedBy, proofWitness.verificationTimestamp);

            if (verifiedBy == address(0x1) && verificationTimestamp == 1) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else if (block.timestamp >= verificationTimestamp + CHALLENGE_PERIOD) {
                return (isValid, PROOF_STATUS.FINALISED);
            } else {
                claims[proofHash][verifiedBy] = RewardData({
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
        bytes memory proof = abi.encode(_publicInputs, _proof, _recursiveAggregationInput);
        bytes32 proofHash = keccak256(proof);
        ProofVerificationClaim memory proofWitness = isValidProof[proofHash];
        (, address verifiedBy, uint256 verificationTimestamp) =
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
        bytes memory proof = abi.encode(_publicInputs, _proof, _recursiveAggregationInput);
        bytes32 proofHash = keccak256(proof);

        ProofVerificationClaim memory proofWitness = isValidProof[proofHash];
        (bool originalProofVote, address originalVerifier, uint256 originalVerificationTimestamp) =
            ( proofWitness.isValid, proofWitness.verifiedBy, proofWitness.verificationTimestamp);

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

        bool challengerVote = verifier.verify(_publicInputs, _proof, _recursiveAggregationInput);
        address challengerAddress = msg.sender;

    RewardData memory rewardData = claims[proofHash][originalVerifier];
        (uint bid, ERC20 token) = (rewardData.reward, rewardData.token);

        if (challengerVote == originalProofVote) {
            revert("Challenger vote same as original verifier");
        }
        // Original proposer lied about the verification of the proof
        isValidProof[proofHash] =
            ProofVerificationClaim({isValid: challengerVote, verifiedBy: address(0x1), verificationTimestamp: 1});

        token.transfer(challengerAddress, bid);

        slash(originalVerifier);
    }

    function claimReward(
        uint256[] calldata _publicInputs,
        uint256[] calldata _proof,
        uint256[] calldata _recursiveAggregationInput
    ) external {
        bytes memory proof = abi.encode(_publicInputs, _proof, _recursiveAggregationInput);
        bytes32 proofHash = keccak256(proof);
        if (claims[proofHash][msg.sender].finalisationTimestamp == 0 && claims[proofHash][msg.sender].reward == 0) {
            revert("not a valid claim");
        }

        (uint256 bid, ERC20 token, uint256 finalisationTimestamp) = (
            claims[proofHash][msg.sender].reward,
            claims[proofHash][msg.sender].token,
            claims[proofHash][msg.sender].finalisationTimestamp
        );

        if (block.timestamp < finalisationTimestamp) {
            revert("proof not finalised");
        }

        token.transfer(msg.sender, bid);
    }

    function getProofVerificationContract() internal returns (IVerifier) {
        // returns the contract address of a verifier contract based on the type of proof
        // the address is for zksync diamond contract
        address _verifierContract = IGetVerifier(0x32400084C286CF3E17e7B677ea9583e60a000324).getVerifier();
        return IVerifier(_verifierContract);
    }

    function slash(address maliciousProposer) internal {

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
interface IEigenLayer{
    function isOperator(address _operator) external returns(bool);
}

interface IEigenLayerSlasher{
    function optIntoSlashing () external {

    }
}