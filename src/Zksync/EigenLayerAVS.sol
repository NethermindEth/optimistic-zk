// SPDX-License-Identifier:MIT
pragma solidity ^0.8.13;

import "./interface/IEigenServiceManager.sol";
import "./interface/IEigenLayer.sol";
import "./interface/ISignatureUtilsData.sol";
// import "./interface/IStrategy.sol";
import {ServiceManagerBase} from "lib/eigenlayer-middleware/src/ServiceManagerBase.sol";
import {IAVSDirectory} from "lib/eigenlayer-contracts/src/contracts/interfaces/IAVSDirectory.sol";
import {IStrategy} from "lib/eigenlayer-contracts/src/contracts/interfaces/IStrategy.sol";
import {IStakeRegistry} from "lib/eigenlayer-middleware/src/interfaces/IStakeRegistry.sol";
import {IRegistryCoordinator} from "lib/eigenlayer-middleware/src/interfaces/IRegistryCoordinator.sol";
import {IServiceManager} from "lib/eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {IRewardsCoordinator} from "lib/eigenlayer-contracts/src/contracts/interfaces/IRewardsCoordinator.sol";
import {ISignatureUtils} from "lib/eigenlayer-contracts/src/contracts/interfaces/ISignatureUtils.sol";

contract EigenLayerAVS is ServiceManagerBase {

    // EigenLayer core AVSDirectory
    IAVSDirectory internal avsDirectory;
    // eigen Layer contract 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A
    IEigenLayer internal eigenLayer;

    mapping(address operator => bool) operatorActive;

    constructor(
        IAVSDirectory _avsDirectory,
        IRewardsCoordinator _rewardsCoordinator,
        IRegistryCoordinator _registryCoordinator,
        IStakeRegistry _stakeRegistry,
        IEigenLayer _eigenLayer
    ) ServiceManagerBase(_avsDirectory, _rewardsCoordinator, _registryCoordinator, _stakeRegistry) {
        avsDirectory = _avsDirectory;
        eigenLayer = _eigenLayer;
    }

    function updateAVSMetadataURI(string memory metadataURI_) public override onlyOwner {
        require(bytes(metadataURI_).length > 0, "INVALID_METADATA");
        avsDirectory.updateAVSMetadataURI(metadataURI_);
    }

    function checkOperator(address operator_) internal returns (bool) {
        return eigenLayer.isOperator(operator_);
    }

    function registerOperatorToAVS(
        address operator_,
        ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature_
    ) public override {
        // must be a registered operator on Eigen
    

        avsDirectory.registerOperatorToAVS(operator_, operatorSignature_);
        // white list the operator on my contract
        operatorActive[operator_] = true;
    }

    function deregisterOperatorFromAVS(address operator_) public override {

        avsDirectory.deregisterOperatorFromAVS(operator_);
        operatorActive[operator_] = false;
    }
}
