// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";

import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";

import { ProverFfiHelper } from "../Helpers/ProverFfiHelper.sol";

import { ArianeeStore } from "@arianee/V0/ArianeeStore/ArianeeStore.sol";
import { ArianeeCreditHistory } from "@arianee/V0/ArianeeStore/ArianeeCreditHistory.sol";
import { ArianeeSmartAsset } from "@arianee/V0/ArianeeSmartAsset.sol";
import {
    ArianeeIssuerProxy,
    OwnershipProof,
    TokenCommitmentUpdated
} from "@arianee/V0/ArianeePrivacy/ArianeeIssuerProxy.sol";
import { CreditNoteProof } from "@arianee/V0/Interfaces/IArianeeCreditNotePool.sol";
import { CREDIT_TYPE_CERTIFICATE } from "@arianee/V0/Constants.sol";

contract UpdateCommitmentScript is Script, ProverFfiHelper {
    IERC20 aria;
    ArianeeStore store;
    ArianeeCreditHistory creditHistory;
    ArianeeSmartAsset smartAsset;
    ArianeeIssuerProxy issuerProxy;

    bool broadcast;
    uint256 chainId;

    // Account configuration
    uint256 issuerPk;
    uint256 adminPk;

    address issuerAddr;
    address adminAddr;

    // Protocol version
    string protocolVersion;

    // Protocol contract addresses
    address ariaAddr;
    address issuerProxyAddr;
    address creditHistoryAddr;
    address arianeeEventAddr;
    address identityAddr;
    address smartAssetAddr;
    address storeAddr;
    address lostAddr;
    address whitelistAddr;
    address arianeeMessageAddr;
    address smartAssetUpdateAddr;

    // ArianeeIssuerProxy specific
    bool testRun;
    uint256 testRunTokenCount;
    uint256[] tokenIds;

    CreditNoteProof DefaultCreditNoteProof = CreditNoteProof({
        _pA: [uint256(0), uint256(0)],
        _pB: [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
        _pC: [uint256(0), uint256(0)],
        _pubSignals: [uint256(0), uint256(0), uint256(0), uint256(0)]
    });

    function setUp() public {
        // Getting configuration from environment variables
        broadcast = vm.envBool("BROADCAST");
        console.log("Broadcast: %s", broadcast);

        chainId = vm.envUint("CHAIN_ID");
        vm.assertEq(chainId, block.chainid, "ChainId mismatch");
        console.log("ChainId: %d", chainId);

        issuerPk = vm.envUint("ISSUER_PRIVATE_KEY");
        adminPk = vm.envUint("ADMIN_PRIVATE_KEY");

        issuerAddr = vm.addr(issuerPk);
        adminAddr = vm.addr(adminPk);
        console.log("Issuer: %s", issuerAddr);
        console.log("Admin: %s", adminAddr);

        protocolVersion = vm.envString("ARIANEE_PROTOCOL_VERSION");
        console.log("ProtocolVersion: %s", protocolVersion);

        ariaAddr = vm.envAddress("ARIANEE_ARIA");
        issuerProxyAddr = vm.envAddress("ARIANEE_ISSUER_PROXY");
        creditHistoryAddr = vm.envAddress("ARIANEE_CREDIT_HISTORY");
        arianeeEventAddr = vm.envAddress("ARIANEE_EVENT");
        identityAddr = vm.envAddress("ARIANEE_IDENTITY");
        smartAssetAddr = vm.envAddress("ARIANEE_SMART_ASSET");
        storeAddr = vm.envAddress("ARIANEE_STORE");
        lostAddr = vm.envAddress("ARIANEE_LOST");
        whitelistAddr = vm.envAddress("ARIANEE_WHITELIST");
        arianeeMessageAddr = vm.envAddress("ARIANEE_MESSAGE");
        smartAssetUpdateAddr = vm.envAddress("ARIANEE_SMART_ASSET_UPDATE");

        console.log("Aria: %s", ariaAddr);
        console.log("ArianeeIssuerProxy: %s", issuerProxyAddr);
        console.log("ArianeeCreditHistory: %s", creditHistoryAddr);
        console.log("ArianeeEvent: %s", arianeeEventAddr);
        console.log("ArianeeIdentity: %s", identityAddr);
        console.log("ArianeeSmartAsset: %s", smartAssetAddr);
        console.log("ArianeeStore: %s", storeAddr);
        console.log("ArianeeLost: %s", lostAddr);
        console.log("ArianeeWhitelist: %s", whitelistAddr);
        console.log("ArianeeMessage: %s", arianeeMessageAddr);
        console.log("ArianeeSmartAssetUpdate: %s", smartAssetUpdateAddr);

        testRun = vm.envBool("TEST_RUN");
        console.log("TestRun: %s", testRun);
        if (testRun) {
            testRunTokenCount = vm.envUint("TEST_RUN_TOKEN_COUNT");
            console.log("TestRunTokenCount: %d", testRunTokenCount);
            vm.assertFalse(broadcast, "Test run and broadcast cannot be enabled at the same time");
        } else {
            tokenIds = vm.envUint("TOKEN_IDS", ",");
            console.log("TokenIdsLength: %d", tokenIds.length);
        }
        console.log("\r");

        // Attaching to the existing Aria contract
        aria = IERC20(ariaAddr);

        // Attaching to the existing ArianeeStore contract
        store = ArianeeStore(storeAddr);

        // Attaching to the existing ArianeeCreditHistory contract
        creditHistory = ArianeeCreditHistory(creditHistoryAddr);

        // Attaching to the existing ArianeeSmartAsset contract
        smartAsset = ArianeeSmartAsset(smartAssetAddr);

        // Attaching to the existing ArianeeIssuerProxy contract
        issuerProxy = ArianeeIssuerProxy(issuerProxyAddr);

        // Starting the Prover server
        super.initProver(
            issuerPk,
            protocolVersion,
            chainId,
            ariaAddr,
            creditHistoryAddr,
            arianeeEventAddr,
            identityAddr,
            smartAssetAddr,
            storeAddr,
            lostAddr,
            whitelistAddr,
            arianeeMessageAddr,
            smartAssetUpdateAddr,
            issuerProxyAddr
        );

        if (testRun) {
            setUp_testRun();
        }
    }

    function setUp_testRun() public {
        // Mocking the Aria contract to avoid dealing with tokens for this test run
        vm.mockCall(ariaAddr, abi.encodeWithSelector(IERC20.transferFrom.selector), abi.encode(true));
        vm.mockCall(ariaAddr, abi.encodeWithSelector(IERC20.transfer.selector), abi.encode(true));

        // Buy some credits for the ArianeeIssuerProxy contract
        uint256 quantity = testRunTokenCount;
        store.buyCredit(CREDIT_TYPE_CERTIFICATE, quantity, issuerProxyAddr);
        vm.assertEq(creditHistory.balanceOf(issuerProxyAddr, CREDIT_TYPE_CERTIFICATE), quantity);

        // Adding the script sender to the `creditFreeSenders` list
        vm.prank(adminAddr);
        issuerProxy.addCreditFreeSender(address(this));

        // Hydrate and reserve on-the-fly the test tokens
        for (uint256 i = 0; i < testRunTokenCount; i++) {
            uint256 tokenId;
            uint256 maxRetries = 3; // Maximum number of attempts to find a unique tokenId
            uint256 retries = 0;

            bool tokenExists;
            do {
                tokenId = vm.randomUint();
                retries++;
                if (retries > maxRetries) {
                    revert("Failed to generate a unique `tokenId` after maximum retries");
                }

                try smartAsset.ownerOf(tokenId) {
                    tokenExists = true;
                } catch {
                    tokenExists = false;
                }
            } while (tokenExists);

            bytes memory computeCommitmentHashRes =
                super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
            uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

            string memory fragment = "hydrateToken";

            address creditNotePool = address(0);
            bytes32 imprint = bytes32(0);
            string memory uri = "https://arianee.org";
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

            bytes memory computeIntentHashRes = super.proverFfi(
                "exec",
                "issuerProxy_computeIntentHash",
                vm.toString(abi.encode(fragment, valuesTypes, values, needsCreditNoteProof))
            );
            string memory intentHash = abi.decode(computeIntentHashRes, (string));

            bytes memory generateProofRes =
                super.proverFfi("exec", "issuerProxy_generateProof", vm.toString(abi.encode(tokenId, intentHash)));
            OwnershipProof memory ownershipProof = abi.decode(generateProofRes, (OwnershipProof));

            issuerProxy.hydrateToken(
                ownershipProof,
                DefaultCreditNoteProof,
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
            console.log("Token %d hydrated", tokenId);

            // Adding the `tokenId` to the list of tokens to update
            tokenIds.push(tokenId);
        }
    }

    function run() public {
        if (!testRun) {
            vm.startBroadcast(adminPk);
        } else {
            vm.startPrank(adminAddr);
        }

        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 tokenId = tokenIds[i];

            // Compute the new version of the commitment hash
            bytes memory computeCommitmentHashV2Res =
                super.proverFfi("exec", "issuerProxy_computeCommitmentHashV2", vm.toString(abi.encode(tokenId)));
            uint256 newCommitmentHash = abi.decode(computeCommitmentHashV2Res, (uint256));

            string memory fragment = "updateCommitment";
            bytes memory values = abi.encode(tokenId, newCommitmentHash);
            string[] memory valuesTypes = new string[](2);
            valuesTypes[0] = "uint256";
            valuesTypes[1] = "uint256";

            bool needsCreditNoteProof = false;

            bytes memory computeIntentHashRes = super.proverFfi(
                "exec",
                "issuerProxy_computeIntentHash",
                vm.toString(abi.encode(fragment, valuesTypes, values, needsCreditNoteProof))
            );
            string memory intentHash = abi.decode(computeIntentHashRes, (string));

            bytes memory generateProofRes =
                super.proverFfi("exec", "issuerProxy_generateProof", vm.toString(abi.encode(tokenId, intentHash)));
            OwnershipProof memory ownershipProof = abi.decode(generateProofRes, (OwnershipProof));

            vm.expectEmit(false, true, true, false);
            emit TokenCommitmentUpdated(0, newCommitmentHash, tokenId);
            issuerProxy.updateCommitment(ownershipProof, tokenId, newCommitmentHash);
            console.log("Commitment updated for token %d", tokenId);
        }

        if (!testRun) {
            vm.stopBroadcast(); // Stopping the broadcast with the `adminPk`
        } else {
            vm.stopPrank();
        }

        // Stopping the Prover server
        super.stopProver();
    }
}
