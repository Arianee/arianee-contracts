// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ProverFfiHelper } from "./ProverFfiHelper.sol";

// TODO: Will move this once ArianeeIssuerProxy is migrated
struct OwnershipProof {
    uint256[2] _pA; // 64 bytes
    uint256[2][2] _pB; // 128 bytes
    uint256[2] _pC; // 64 bytes
    uint256[3] _pubSignals; // 96 bytes
} // Total: 352 bytes

contract ProverFfiHelperTest is Test, ProverFfiHelper {
    using Strings for uint256;

    uint256 signerPk = 123;

    string protocolVersion = "1.0";
    uint256 chainId = 1337;

    address aria = address(1);
    address creditHistory = address(2);
    address arianeeEvent = address(3);
    address identity = address(4);
    address smartAsset = address(5);
    address store = address(6);
    address lost = address(7);
    address whitelist = address(8);
    address arianeeMessage = address(9);
    address smartAssetUpdate = address(10);
    address issuerProxy = address(11);

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

    function test_issuerProxy_computeCommitmentHash() public {
        uint256 tokenId = 123;
        bytes memory res =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(res, (uint256));
        assertEq(
            commitmentHash,
            9_454_446_621_308_206_716_865_009_959_322_521_105_197_305_289_912_882_804_219_617_500_120_200_299_789
        );
    }

    function test_issuerProxy_computeIntentHash() public {
        string memory fragment = "hydrateToken";

        address creditNotePool = address(0);
        uint256 commitmentHash = 0;
        uint256 tokenId = 123;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address encryptedInitialKey = address(0);
        uint256 tokenRecoveryTimestamp = 0;
        bool initialKeyIsRequestKey = false;
        address walletProvider = address(0);

        bytes memory values = abi.encode(
            creditNotePool,
            commitmentHash,
            tokenId,
            imprint,
            uri,
            encryptedInitialKey,
            tokenRecoveryTimestamp,
            initialKeyIsRequestKey,
            walletProvider
        );

        bool needsCreditNoteProof = true;

        bytes memory res = super.proverFfi(
            "exec", "issuerProxy_computeIntentHash", vm.toString(abi.encode(fragment, values, needsCreditNoteProof))
        );
        string memory intentHash = abi.decode(res, (string));
        assertEq(intentHash, "328043857320579633236278839090936276180185263485624913289048988456355199828");
    }

    function test_issuerProxy_generateProof() public {
        uint256 tokenId = 123;
        string memory intentHash = "328043857320579633236278839090936276180185263485624913289048988456355199828";

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
