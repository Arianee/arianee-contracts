// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console, Vm } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { IArianeeStore } from "@arianee/V0/Interfaces/IArianeeStore.sol";
import { IArianeeSmartAsset } from "@arianee/V0/Interfaces/IArianeeSmartAsset.sol";
import { IArianeeCreditNotePool, CreditNoteProof } from "@arianee/V0/Interfaces/IArianeeCreditNotePool.sol";
import {
    ArianeeIssuerProxy,
    OwnershipProof,
    TokenCommitmentRegistered,
    CreditFreeSenderLog
} from "@arianee/V0/ArianeePrivacy/ArianeeIssuerProxy.sol";
import { OwnershipVerifier } from "@arianee/V0/ArianeePrivacy/Verifiers/OwnershipVerifier.sol";
import { IPoseidon } from "@arianee/V0/Interfaces/IPoseidon.sol";
import {
    ROLE_ADMIN,
    CREDIT_TYPE_CERTIFICATE,
    CREDIT_TYPE_MESSAGE,
    CREDIT_TYPE_EVENT,
    CREDIT_TYPE_UPDATE
} from "@arianee/V0/Constants.sol";
import { ByteUtils } from "@arianee/ByteUtils.sol";
import { DeployBytecodeHelper } from "../../script/Helpers/DeployBytecodeHelper.sol";
import { ProverFfiHelper } from "../../script/Helpers/ProverFfiHelper.sol";
import { ProverTestContext } from "../ProverTestContext.sol";
import { POSEIDON_BYTECODE } from "../../script/Constants.sol";

/**
 * @dev WARNING: Don't use fuzzy tests in this test file
 * See {ProverFfiHelper}
 */
contract ArianeeIssuerProxyTest is Test, DeployBytecodeHelper, ProverFfiHelper, ProverTestContext {
    using ByteUtils for bytes;

    address proxyAdmin = vm.addr(1);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    // The addresses `store`, `smartAsset`, `arianeeEvent`, `lost` and `issuerProxy` are already defined in {ProverTestContext}
    // We will use and (if needed) etch them in this test in order to keep the same addresses and have a matching Prover context with the `run-test-with-prover.sh` script
    address forwarder = vm.addr(2);

    address unknown = vm.addr(3);
    address creditFreeSender = vm.addr(4);

    OwnershipVerifier verifier;
    IPoseidon poseidon;

    address arianeeIssuerImplAddr;
    ArianeeIssuerProxy arianeeIssuerProxy;

    CreditNoteProof DefaultCreditNoteProof = CreditNoteProof({
        _pA: [uint256(0), uint256(0)],
        _pB: [[uint256(0), uint256(0)], [uint256(0), uint256(0)]],
        _pC: [uint256(0), uint256(0)],
        _pubSignals: [uint256(0), uint256(0), uint256(0), uint256(0)]
    });

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        // Deploying the OwnershipVerifier contract
        verifier = new OwnershipVerifier();

        // Deploying the Poseidon contract
        address poseidonAddr = deployBytecode(POSEIDON_BYTECODE);
        poseidon = IPoseidon(poseidonAddr);

        vm.startPrank(issuerProxyDeployerAddr);
        address arianeeIssuerProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeIssuerProxy.sol:ArianeeIssuerProxy",
            proxyAdmin,
            abi.encodeCall(
                ArianeeIssuerProxy.initialize,
                (admin, store, smartAsset, arianeeEvent, lost, address(verifier), poseidonAddr)
            ),
            opts
        );
        assertEq(
            arianeeIssuerProxyAddr,
            issuerProxy,
            "`arianeeIssuerProxyAddr` not match with `ProverTestContext.issuerProxy`"
        );
        arianeeIssuerProxy = ArianeeIssuerProxy(arianeeIssuerProxyAddr);
        arianeeIssuerImplAddr = Upgrades.getImplementationAddress(arianeeIssuerProxyAddr);
        vm.stopPrank();

        // Add `creditFreeSender` in the "credit free sender" whitelist so we can bypass the credit note proof check (i.e using `DefaultCreditNoteProof`) for this test
        vm.startPrank(admin);
        arianeeIssuerProxy.addCreditFreeSender(creditFreeSender);
        vm.stopPrank();
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("Store: %s", store);
        console.log("SmartAsset: %s", smartAsset);
        console.log("ArianeeEvent: %s", arianeeEvent);
        console.log("Lost: %s", lost);
        console.log("Unknown: %s", unknown);
        console.log("CreditFreeSender: %s", creditFreeSender);
        // Contracts
        console.log("OwnershipVerifier: %s", address(verifier));
        console.log("Poseidon: %s", address(poseidon));
        console.log("ArianeeIssuerProxy: %s", address(arianeeIssuerProxy));
        console.log("ArianeeIssuerImpl: %s", arianeeIssuerImplAddr);
    }

    // Initializer

    function test_initialize() public view {
        assertEq(arianeeIssuerProxy.getStoreAddress(), store);
    }

    // Commitment and proof tests

    function test_shouldBeAble_to_reserveAToken_withA_nonUsedCommitmentHash() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());

        vm.expectEmit();
        emit TokenCommitmentRegistered(commitmentHash, tokenId);
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        uint256 registeredCommitmentHash = arianeeIssuerProxy.commitmentHashes(tokenId);
        assertEq(registeredCommitmentHash, commitmentHash);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldntBeAble_to_reserveAToken_thatWasAlreadyReserved() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());

        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        vm.expectRevert("ArianeeIssuerProxy: A commitment has already been registered for this SmartAsset");
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldBeAble_to_hydrateAPreviouslyReservedToken() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "hydrateToken";

        address creditNotePool = address(0);
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address encryptedInitialKey = address(0);
        uint256 tokenRecoveryTimestamp = 0;
        bool initialKeyIsRequestKey = false;
        address nmpProvider = address(0);

        bytes memory values = abi.encode(
            creditNotePool,
            uint256(0), // We don't need to provide the commitment hash as we will pre-reserve the SmartAsset before hydrating it
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

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.hydrateToken.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Hydrate token
        vm.expectEmit();
        emit CreditFreeSenderLog(creditFreeSender, CREDIT_TYPE_CERTIFICATE);
        arianeeIssuerProxy.hydrateToken(
            ownershipProof,
            DefaultCreditNoteProof,
            creditNotePool,
            uint256(0), // We don't need to provide the commitment hash as we have pre-reserved the SmartAsset
            tokenId,
            imprint,
            uri,
            encryptedInitialKey,
            tokenRecoveryTimestamp,
            initialKeyIsRequestKey,
            nmpProvider
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldBeAble_to_hydrateAndReserve_onTheFly_aToken() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "hydrateToken";

        address creditNotePool = address(0);
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address encryptedInitialKey = address(0);
        uint256 tokenRecoveryTimestamp = 0;
        bool initialKeyIsRequestKey = false;
        address nmpProvider = address(0);

        bytes memory values = abi.encode(
            creditNotePool,
            commitmentHash, // We need to provide the commitment hash as the SmartAsset is not registered and will be reserved on-the-fly
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

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.hydrateToken.selector), abi.encode());

        // Hydrate token
        vm.expectEmit();
        emit CreditFreeSenderLog(creditFreeSender, CREDIT_TYPE_CERTIFICATE);
        arianeeIssuerProxy.hydrateToken(
            ownershipProof,
            DefaultCreditNoteProof,
            creditNotePool,
            commitmentHash, // We need to provide the commitment hash as the SmartAsset is not registered and will be reserved on-the-fly
            tokenId,
            imprint,
            uri,
            encryptedInitialKey,
            tokenRecoveryTimestamp,
            initialKeyIsRequestKey,
            nmpProvider
        );
    }

    function test_shouldBeAble_to_addATokenAccess_withAValidProof() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "addTokenAccess";
        address key = address(0);
        bool enable = true;
        uint256 accessType = 1;

        bytes memory values = abi.encode(tokenId, key, enable, accessType);
        string[] memory valuesTypes = new string[](4);
        valuesTypes[0] = "uint256";
        valuesTypes[1] = "address";
        valuesTypes[2] = "bool";
        valuesTypes[3] = "uint256";

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

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.addTokenAccess.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Add token access
        arianeeIssuerProxy.addTokenAccess(ownershipProof, tokenId, key, enable, accessType);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldBeAble_to_createAnEvent_withAValidProof() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "createEvent";
        address creditNotePool = address(0);
        uint256 eventId = 1;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address nmpProvider = address(0);

        bytes memory values = abi.encode(creditNotePool, tokenId, eventId, imprint, uri, nmpProvider);
        string[] memory valuesTypes = new string[](6);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";

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

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        vm.expectEmit();
        emit CreditFreeSenderLog(creditFreeSender, CREDIT_TYPE_EVENT);
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldntBeAble_to_createAnEvent_withAnInvalidProof_invalidFragment() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "acceptEvent"; // We use the wrong fragment here
        uint256 eventId = 1;
        address walletProvider = address(0);

        bytes memory values = abi.encode(tokenId, eventId, walletProvider);
        string[] memory valuesTypes = new string[](3);
        valuesTypes[0] = "uint256";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "address";

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

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        vm.expectRevert("ArianeeIssuerProxy: Proof intent does not match the function call");
        arianeeIssuerProxy.createEvent(
            ownershipProof,
            DefaultCreditNoteProof,
            address(0),
            tokenId,
            eventId,
            bytes32(0),
            "https://example.com",
            address(0)
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldntBeAble_to_createAnEvent_withAnInvalidProof_invalidValues() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "createEvent";
        address creditNotePool = address(0);
        uint256 eventId = 1;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address nmpProvider = address(0);

        bytes memory values = abi.encode(
            creditNotePool,
            tokenId,
            eventId,
            bytes32(0x1212121212121212121212121212121212121212121212121212121212121212),
            uri,
            nmpProvider
        );
        string[] memory valuesTypes = new string[](6);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";

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

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        vm.expectRevert("ArianeeIssuerProxy: Proof intent does not match the function call");
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldntBeAble_to_createAnEvent_withAnInvalidProof_invalidNonce() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "createEvent";
        address creditNotePool = address(0);
        uint256 eventId = 1;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address nmpProvider = address(0);

        bytes memory values = abi.encode(creditNotePool, tokenId, eventId, imprint, uri, nmpProvider);
        string[] memory valuesTypes = new string[](6);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";

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

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );

        // We try to create the same event again with the proof (thus the same nonce)
        vm.expectRevert("ArianeeIssuerProxy: Proof nonce has already been used");
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // TODO: Move `shouldn't be able to create an event with an invalid proof (invalid commitmentHash)` to `@arianee/privacy-circuits` tests but not priority

    function test_shouldntBeAble_to_createAnEvent_withAnInvalidProof_invalidCallData() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "createEvent";
        address creditNotePool = address(0);
        uint256 eventId = 1;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address nmpProvider = address(0);

        bytes memory values = abi.encode(creditNotePool, tokenId, eventId, imprint, uri, nmpProvider);
        string[] memory valuesTypes = new string[](6);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";

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

        // We temper the ownershipProof callData
        ownershipProof._pA[0] = (ownershipProof._pA[0] / 1000) * 1000 + 123;

        vm.startPrank(creditFreeSender);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        vm.expectRevert("ArianeeIssuerProxy: OwnershipProof verification failed");
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // IArianeeCreditNotePool management tests

    function test_shouldntBeAble_to_createAnEvent_withA_NonWhitelisted_IArianeeCreditNotePool() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "createEvent";
        address creditNotePool = vm.addr(123); // We use a non-whitelisted address here
        uint256 eventId = 1;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address nmpProvider = address(0);

        bytes memory values = abi.encode(creditNotePool, tokenId, eventId, imprint, uri, nmpProvider);
        string[] memory valuesTypes = new string[](6);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";

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

        vm.startPrank(unknown); // We don't use `creditFreeSender` here as we want to test the whitelist
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        vm.expectRevert("ArianeeIssuerProxy: Target IArianeeCreditNotePool is not whitelisted");
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_shouldBeAble_to_createAnEvent_withA_Whitelisted_IArianeeCreditNotePool() public {
        // Add the IArianeeCreditNotePool to the whitelist
        address creditNotePool = vm.addr(123);
        vm.startPrank(admin);
        arianeeIssuerProxy.addCreditNotePool(creditNotePool);
        vm.stopPrank();

        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "createEvent";
        uint256 eventId = 1;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address nmpProvider = address(0);

        bytes memory values = abi.encode(creditNotePool, tokenId, eventId, imprint, uri, nmpProvider);
        string[] memory valuesTypes = new string[](6);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";

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

        vm.startPrank(unknown); // We don't use `creditFreeSender` here as we want to test the whitelist
        vm.mockCall(creditNotePool, abi.encodeWithSelector(IArianeeCreditNotePool.spend.selector), abi.encode()); // Mock the call to `IArianeeCreditNotePool.spend`
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        vm.recordLogs(); // Start the logs recorder
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );
        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertEq(
            entries.length,
            0,
            "There should be no `CreditFreeSenderLog` and `Spent` logs emitted as we use a whitelisted IArianeeCreditNotePool mock"
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Credit free sender management tests

    function test_shouldntBeAble_to_createAnEvent_withA_NonWhitelisted_CreditFreeSender() public {
        uint256 tokenId = 123;
        bytes memory computeCommitmentHashRes =
            super.proverFfi("exec", "issuerProxy_computeCommitmentHash", vm.toString(abi.encode(tokenId)));
        uint256 commitmentHash = abi.decode(computeCommitmentHashRes, (uint256));

        string memory fragment = "createEvent";
        address creditNotePool = vm.addr(123); // We use a non-whitelisted address here
        uint256 eventId = 1;
        bytes32 imprint = bytes32(0);
        string memory uri = "https://example.com";
        address nmpProvider = address(0);

        bytes memory values = abi.encode(creditNotePool, tokenId, eventId, imprint, uri, nmpProvider);
        string[] memory valuesTypes = new string[](6);
        valuesTypes[0] = "address";
        valuesTypes[1] = "uint256";
        valuesTypes[2] = "uint256";
        valuesTypes[3] = "bytes32";
        valuesTypes[4] = "string";
        valuesTypes[5] = "address";

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

        vm.startPrank(unknown); // We don't use `creditFreeSender` here
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.reserveToken.selector, tokenId), abi.encode());
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeStore.createEvent.selector), abi.encode());

        // Reserve token first
        arianeeIssuerProxy.reserveToken(commitmentHash, tokenId);

        // Create event
        // The internal function `trySpendCredit` will fallback to try to spent the `DefaultCreditNoteProof` arg as `unknown` is not a whitelisted credit free sender
        vm.expectRevert("ArianeeIssuerProxy: Target IArianeeCreditNotePool is not whitelisted");
        arianeeIssuerProxy.createEvent(
            ownershipProof, DefaultCreditNoteProof, creditNotePool, tokenId, eventId, imprint, uri, nmpProvider
        );

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // TODO: Add some tests for `updateCommitment` and `updateCommitmentBatch`
}
