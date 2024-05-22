// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.24;

interface IMerkleStatementContract {
    function verifyMerkle(
        uint256[] calldata merkleView,
        uint256[] calldata initialMerkleQueue,
        uint256 height,
        uint256 expectedRoot
    ) external view returns (bool);
}

interface IFriStatementContract {
    function verifyFRI(
        uint256[] calldata proof,
        uint256[] calldata friQueue,
        uint256 evaluationPoint,
        uint256 friStepSize,
        uint256 expectedRoot
    ) external view returns (bool);
}

interface IGPSStatementVerification {
    function verifyProofAndRegister(
        uint256[] calldata proofParams,
        uint256[] calldata proof,
        uint256[] calldata taskMetadata,
        uint256[] calldata cairoAuxInput,
        uint256 cairoVerifierId
    ) external view returns (bool);
}

interface IMemoryPageFactRegistry {
    function registerContinuousMemoryPage(
        uint256 startAddr,
        uint256[] calldata values,
        uint256 z,
        uint256 alpha,
        uint256 prime
    ) external returns (bool, uint256, uint256);
}
