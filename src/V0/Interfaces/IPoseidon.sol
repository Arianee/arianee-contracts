// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IPoseidon {
    function poseidon(
        bytes32[1] memory input
    ) external pure returns (bytes32);
    function poseidon(
        uint256[1] memory input
    ) external pure returns (uint256);
}
