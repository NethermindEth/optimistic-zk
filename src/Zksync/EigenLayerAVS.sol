// SPDX-License-Identifier:MIT
pragma solidity ^0.8.13;

import "./interface/IEigenServiceManager.sol";
import "./interface/ISignatureUtils.sol";
import "./interface/IEigenLayer.sol";
import "./interface/IStrategy.sol";

contract EigenLayerAVS {

         /**
     * @notice Represents a single supported strategy.
     * @custom:field strategy   The strategy contract
     * @custom:field multiplier The stake multiplier, to weight strategy against others
     */
    struct StrategyParam {
        IStrategy strategy;
        uint96 multiplier;
    }
    StrategyParam[] internal _strategyParams;

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

    function getOperatorRestakedStrategies(address operator) external view returns (address[] memory) {
        require(operatorActive[operator], "NOT_OPERATOR");
        return _getRestakeableStrategies();
    }

        /**
     * @notice Set the strategy parameters.
     * @param params The strategy parameters
     */
    function setStrategyParams(StrategyParam[] calldata params) external {
        _setStrategyParams(params);
    }
        
        function _setStrategyParams(StrategyParam[] calldata params) internal {
        delete _strategyParams;

        for (uint256 i = 0; i < params.length;) {
            require(address(params[i].strategy) != address(0), "ZERO_ADDRESS_CANNOT_BE_STRATEGY_ADDRES");
            require(params[i].multiplier > 0, "NO_ZERO_MULTIPLIERS");

            // ensure no duplicates
            for (uint256 j = i + 1; j < params.length;) {
                require(address(params[i].strategy) != address(params[j].strategy), "NO_DUPLICATE_STARTEGY");
                unchecked {
                    j++;
                }
            }

            _strategyParams.push(params[i]);
            unchecked {
                i++;
            }
        }

        // emit StrategyParamsSet(params);
    }


    function getRestakeableStrategies() external view returns (address[] memory) {
        return _getRestakeableStrategies();
    }

       /**
     * @notice Returns the list of restakeable strategy addresses
     */
    function _getRestakeableStrategies() internal view returns (address[] memory) {
        address[] memory strategies = new address[](_strategyParams.length);
        for (uint256 i = 0; i < _strategyParams.length;) {
            strategies[i] = address(_strategyParams[i].strategy);
            unchecked {
                i++;
            }
        }
        return strategies;
    }
}
