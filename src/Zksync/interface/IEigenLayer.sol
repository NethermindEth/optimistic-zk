// SPDX-License-Identifier:MIT

pragma solidity ^0.8.13;

interface IEigenLayer {
    function isOperator(address _operator) external returns (bool);
}
