// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeCreditHistory {
    function addCreditHistory(address _spender, uint256 _price, uint256 _quantity, uint256 _type) external;

    function consumeCredits(address _spender, uint256 _type, uint256 _quantity) external returns (uint256);
}
