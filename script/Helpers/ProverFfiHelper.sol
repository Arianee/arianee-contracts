// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";

/**
 * @title ProverFfiHelper
 * @notice Helper contract to interact with the Prover from `@arianee/privacy-circuits` through FFI
 * @dev WARNING: It is not recommended to add fuzzy tests on tests contracts that inherit from this helper as it may be particularly slow
 */
abstract contract ProverFfiHelper is Script {
    function proverFfi(string memory command, string memory args) internal returns (bytes memory) {
        return proverFfi(command, "", args);
    }

    function proverFfi(string memory cmd, string memory subCmd, string memory args) internal returns (bytes memory) {
        bool anySubCmd = bytes(subCmd).length > 0;
        string[] memory inputs = new string[](9 + (anySubCmd ? 1 : 0));
        inputs[0] = "npm";
        inputs[1] = "run";
        inputs[2] = "--silent";
        inputs[3] = "prover";
        inputs[4] = cmd;
        if (anySubCmd) {
            inputs[5] = subCmd;
            inputs[6] = args;
            inputs[7] = "--";
            inputs[8] = "--log-level";
            inputs[9] = "6";
        } else {
            inputs[5] = args;
            inputs[6] = "--";
            inputs[7] = "--log-level";
            inputs[8] = "6";
        }
        return vm.ffi(inputs);
    }

    function initProver(
        uint256 signerPk,
        string memory protocolVersion,
        uint256 chainId,
        address aria,
        address creditHistory,
        address arianeeEvent,
        address identity,
        address smartAsset,
        address store,
        address lost,
        address whitelist,
        address arianeeMessage,
        address smartAssetUpdate,
        address issuerProxy
    ) internal {
        bytes memory res = proverFfi(
            "init",
            vm.toString(
                abi.encode(
                    signerPk,
                    protocolVersion,
                    chainId,
                    aria,
                    creditHistory,
                    arianeeEvent,
                    identity,
                    smartAsset,
                    store,
                    lost,
                    whitelist,
                    arianeeMessage,
                    smartAssetUpdate,
                    issuerProxy
                )
            )
        );
        bool success = abi.decode(res, (bool));
        vm.assertTrue(success, "Prover init failed"); // Doesn't matter if only the first assert is successful
    }

    function stopProver() internal {
        bytes memory res = proverFfi("stop", "");
        bool success = abi.decode(res, (bool));
        vm.assertTrue(success, "Prover stop failed");
    }
}
