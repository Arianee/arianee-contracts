// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test } from "forge-std/Test.sol";

/**
 * @title ProverTestContext
 * @notice Contract that holds a shared Prover context for all prover-related tests
 */
abstract contract ProverTestContext is Test {
    uint256 internal issuerProxyDeployerPk =
        uint256(keccak256(abi.encodePacked("proverFfiHelper_issuerProxyDeployerPk")));
    /**
     * @dev This address must be used to deploy the ArianeeIssuerProxy proxy contract if you want to have a matching Prover context
     */
    address internal issuerProxyDeployerAddr = vm.addr(issuerProxyDeployerPk);

    uint256 internal signerPk = uint256(keccak256(abi.encodePacked("proverFfiHelper_signerPk")));

    string internal protocolVersion = "1.6";
    uint256 internal chainId = 1337;

    address internal aria = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_aria"))));
    address internal creditHistory = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_creditHistory"))));
    address internal arianeeEvent = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_arianeeEvent"))));
    address internal identity = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_identity"))));
    address internal smartAsset = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_smartAsset"))));
    address internal store = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_store"))));
    address internal lost = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_lost"))));
    address internal whitelist = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_whitelist"))));
    address internal arianeeMessage = vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_arianeeMessage"))));
    address internal smartAssetUpdate =
        vm.addr(uint256(keccak256(abi.encodePacked("proverFfiHelper_smartAssetUpdate"))));
    address internal issuerProxy = vm.computeCreateAddress(issuerProxyDeployerAddr, 1);
}
