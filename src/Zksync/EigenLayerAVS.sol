// SPDX-License-Identifier:MIT
pragma solidity ^0.8.13;

import "./interface/IEigenServiceManager.sol";
import "./interface/ISignatureUtils.sol";
import "./interface/IEigenLayer.sol";

contract EigenLayerAVS {
    // EigenLayer core AVSDirectory
    IEigenServiceManager internal _serviceManager;

    mapping(address operator => bool) operatorActive;

    constructor(address serviceManager_) {
        _serviceManager = IEigenServiceManager(serviceManager_);
    }


    function updateMetadataURI(string calldata metadataURI_) external {
        require(bytes(metadataURI_).length > 0, "INVALID_METADATA");
        _serviceManager.updateAVSMetadataURI(metadataURI_);
    }


    function checkOperator(address operator_) internal returns (bool) {

        return IEigenLayer(0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A).isOperator(operator_);
    }


    function registerOperator(address operator_, ISignatureUtils.SignatureWithSaltAndExpiry memory operatorSignature_)
        external
    {
        // must be a registered operator on Eigen
        require(operator_ == msg.sender, "NOT_OPERATOR");
        bool eigenOperator = checkOperator(operator_);
        require(eigenOperator, "NOT_AN_OPERATOR");
        _serviceManager.registerOperatorToAVS(operator_, operatorSignature_);
        // white list the operator on my contract
        operatorActive[operator_] = true;
    }



    function deregisterOperator(address operator_) external {
        // must be a registered operator on Eigen
        // must be whitelisted on my contract
        require(operator_ == msg.sender, "NOT_OPERATOR");
        bool eigenOperator = checkOperator(operator_);
        require(eigenOperator, "NOT_AN_OPERATOR");
        _serviceManager.deregisterOperatorFromAVS(operator_);
        operatorActive[operator_] = false;
    }



    function getOperatorRestakedStrategies(address operator) external returns (address[] memory) {
        return _serviceManager.getOperatorRestakedStrategies(operator);
    }



    function getRestakeableStrategies() external returns (address[] memory) {
        return _serviceManager.getRestakeableStrategies();
    }


}
