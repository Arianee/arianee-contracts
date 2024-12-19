// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { OwnershipProof } from "@arianee/V0/ArianeePrivacy/ArianeeIssuerProxy.sol";
import { ProverFfiHelper } from "../../../script/Helpers/ProverFfiHelper.sol";
import { ProverTestContext } from "../../ProverTestContext.sol";

contract ProverFfiHelperTest is Test, ProverFfiHelper, ProverTestContext {
    /**
     * @notice This function showcase how to initialize the Prover from inside a test
     * @dev Its actually not called because we need a shared Prover instance for all tests files, so the Prover is initialized inside the `run-test-with-prover.sh` script
     */
    function showcase_initProver_fromSetUp() internal {
        super.initProver(
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
        );
    }

    function test_a_displayInitArgs() public view {
        // Dummy test to display `initArgs` used in the script `run-test-with-prover.sh`
        console.log(
            "InitArgs: %s",
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
    }

    function test_issuerProxy_computeCommitmentHash() public {
        uint256 tokenId = 123;
        bytes memory res =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(res, (uint256));
        assertEq(
            commitmentHash,
            19_990_083_318_013_431_793_927_421_178_965_138_769_335_300_019_042_084_671_558_202_108_662_908_139_393
        );
    }

    function test_issuerProxy_computeIntentHash() public {
        string memory fragment = "hydrateToken";

        address creditNotePool = address(0);
        uint256 commitmentHash =
            19_990_083_318_013_431_793_927_421_178_965_138_769_335_300_019_042_084_671_558_202_108_662_908_139_393;
        uint256 tokenId = 123;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address encryptedInitialKey = address(0);
        uint256 tokenRecoveryTimestamp = 0;
        bool initialKeyIsRequestKey = false;
        address nmpProvider = address(0);

        bytes memory values = abi.encode(
            creditNotePool,
            commitmentHash,
            tokenId,
            imprint,
            uri,
            encryptedInitialKey,
            tokenRecoveryTimestamp,
            initialKeyIsRequestKey,
            nmpProvider
        );
        string[] memory valuesTypes = new string[](9);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";
        valuesTypes[6] = "uint256";
        valuesTypes[7] = "bool";
        valuesTypes[8] = "address";

        bool needsCreditNoteProof = true;

        bytes memory res = super.proverFfi(
            "exec",
            "issuerProxy_computeIntentHash",
            vm.toString(abi.encode(fragment, valuesTypes, values, needsCreditNoteProof))
        );
        string memory intentHash = abi.decode(res, (string));
        assertEq(intentHash, "15031138045807712444003939045070684639770841660221804962640238267352455450456");
    }

    function test_issuerProxy_generateProof() public {
        uint256 tokenId = 123;
        string memory intentHash = "15031138045807712444003939045070684639770841660221804962640238267352455450456";

        bytes memory res =
            super.proverFfi("exec", "issuerProxy_generateProof", vm.toString(abi.encode(tokenId, intentHash)));
        OwnershipProof memory proof = abi.decode(res, (OwnershipProof));
        assertGt(proof._pA[0], 0);
        assertGt(proof._pA[1], 0);
        assertGt(proof._pB[0][0], 0);
        assertGt(proof._pB[0][1], 0);
        assertGt(proof._pB[1][0], 0);
        assertGt(proof._pB[1][1], 0);
        assertGt(proof._pC[0], 0);
        assertGt(proof._pC[1], 0);
        assertGt(proof._pubSignals[0], 0);
        assertGt(proof._pubSignals[1], 0);
        assertGt(proof._pubSignals[2], 0);
    }
}
