// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./ISignatureUtils.sol";

interface IEigenServiceManager {
    // Below 3 functions are just proxies to the same-named functions in the AVSDirectory
    function registerOperatorToAVS(
        address operator,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature
    ) external;

    function deregisterOperatorFromAVS(address operator) external;

    function updateAVSMetadataURI(string calldata metadataURI) external;

    // Below 2 functions are needed for your AVS to appear correctly on the UI
    function getOperatorRestakedStrategies(address operator) external returns (address[] memory);

    function getRestakeableStrategies() external returns (address[] memory);
}
