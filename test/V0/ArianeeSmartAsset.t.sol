// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import {
    ArianeeSmartAsset,
    Hydrated,
    TokenRecovered,
    RecoveryRequestUpdated,
    TokenURIUpdated,
    TokenDestroyed,
    SetNewUriBase
} from "@arianee/V0/ArianeeSmartAsset.sol";
import { IArianeeStore } from "@arianee/V0/Interfaces/IArianeeStore.sol";
import { IArianeeWhitelist } from "@arianee/V0/Interfaces/IArianeeWhitelist.sol";
import {
    ROLE_ADMIN,
    ROLE_ARIANEE_STORE,
    ERC721_NAME,
    ERC721_SYMBOL,
    URI_BASE,
    ACCESS_TYPE_VIEW,
    ACCESS_TYPE_TRANSFER
} from "@arianee/V0/Constants.sol";
import { ArianeeUtils } from "../Utils.sol";

contract ArianeeSmartAssetTest is Test {
    using Strings for uint256;

    address proxyAdmin = vm.addr(1);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(2);
    address store = vm.addr(3);
    address whitelist = vm.addr(4);

    address unknown = vm.addr(5);
    address issuer1 = vm.addr(6);
    address user1 = vm.addr(7);

    address arianeeSmartAssetImplAddr;
    ArianeeSmartAsset arianeeSmartAssetProxy;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeSmartAssetProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeSmartAsset.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeSmartAsset.initialize, (admin, store, whitelist)),
            opts
        );
        arianeeSmartAssetProxy = ArianeeSmartAsset(arianeeSmartAssetProxyAddr);
        arianeeSmartAssetImplAddr = Upgrades.getImplementationAddress(arianeeSmartAssetProxyAddr);

        arianeeSmartAssetProxy.grantRole(ROLE_ARIANEE_STORE, store);
        vm.mockCall(store, abi.encodeWithSelector(IArianeeStore.dispatchRewardsAtFirstTransfer.selector), abi.encode());

        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("Store: %s", store);
        console.log("Whitelist: %s", whitelist);
        console.log("Unknown: %s", unknown);
        console.log("Issuer1: %s", issuer1);
        console.log("User1: %s", user1);
        // Contracts
        console.log("ArianeeSmartAssetProxy: %s", address(arianeeSmartAssetProxy));
        console.log("ArianeeSmartAssetImpl: %s", arianeeSmartAssetImplAddr);
    }

    modifier assumeIsNotKnownOrZeroAddress(
        address addr
    ) {
        vm.assume(addr != address(0)); // Make sure `addr` is not the zero address
        vm.assume(addr != msg.sender); // Make sure `addr` is not the default address

        vm.assume(addr != proxyAdmin); // Make sure `addr` is not the proxy admin address
        vm.assume(addr != admin); // Make sure `addr` is not the admin address

        vm.assume(addr != forwarder); // Make sure `addr` is not the forwarder address
        vm.assume(addr != store); // Make sure `addr` is not the store address
        vm.assume(addr != whitelist); // Make sure `addr` is not the whitelist address

        vm.assume(addr != unknown); // Make sure `addr` is not the unknown address
        vm.assume(addr != issuer1); // Make sure `addr` is not the first issuer address
        vm.assume(addr != user1); // Make sure `addr` is not the first user address

        vm.assume(addr != address(arianeeSmartAssetProxy)); // Make sure `addr` is not the ArianeeSmartAsset proxy address
        vm.assume(addr != arianeeSmartAssetImplAddr); // Make sure `addr` is not the ArianeeSmartAsset implementation address
        _;
    }

    // Initializer

    function test_initialize() public view {
        assertFalse(arianeeSmartAssetProxy.paused());
        assertTrue(arianeeSmartAssetProxy.hasRole(ROLE_ADMIN, admin));
        assertEq(arianeeSmartAssetProxy.name(), ERC721_NAME);
        assertEq(arianeeSmartAssetProxy.symbol(), ERC721_SYMBOL);
    }

    // Reserve SmartAsset

    function test_reserveToken(uint256 tokenId, address to) public assumeIsNotKnownOrZeroAddress(to) {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, to);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), to);
        vm.stopPrank();
    }

    function test_reserveToken_err_onlyStore(uint256 tokenId, address to) public assumeIsNotKnownOrZeroAddress(to) {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeSmartAssetProxy.reserveToken(tokenId, to);
        vm.stopPrank();
    }

    // Hydrate SmartAsset

    function test_hydrateToken(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        vm.expectEmit();
        emit Hydrated(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, block.timestamp
        );
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );

        assertEq(arianeeSmartAssetProxy.issuerOf(tokenId), issuer1);
        assertEq(arianeeSmartAssetProxy.tokenCreation(tokenId), block.timestamp);
        assertEq(arianeeSmartAssetProxy.tokenRecoveryDate(tokenId), tokenRecoveryTimestamp);
        assertEq(arianeeSmartAssetProxy.tokenImprint(tokenId), imprint);
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_VIEW), initialKey);
        assertEq(arianeeSmartAssetProxy.isSoulbound(tokenId), false);
        if (initialKeyIsRequestKey) {
            assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKey);
        }
        vm.stopPrank();
    }

    function test_hydrateToken_err_isOperator(
        uint256 tokenId,
        address to,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public assumeIsNotKnownOrZeroAddress(to) {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, to); // Reserve token to `to` instead of `issuer1`
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), to);

        vm.expectRevert("ArianeeSmartAsset: Not an operator");
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();
    }

    function test_hydrateToken_err_alreadyHydrated(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        vm.expectEmit();
        emit Hydrated(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, block.timestamp
        );
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );

        vm.expectRevert("ArianeeSmartAsset: SmartAsset already hydrated");
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();
    }

    function test_hydrateToken_err_onlyStore(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();
    }

    // Request SmartAsset

    function test_requestToken(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );

        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHash, keepCurrentAccess, newOwner, signature);
        assertEq(
            arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER),
            keepCurrentAccess ? initialKeyAddr : address(0)
        );
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);
        vm.stopPrank();
    }

    function test_requestToken_initialKeyIsNotRequestKey(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = false; // Initial key is not the request key
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );

        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("ArianeeSmartAsset: Invalid `_hash` or `_signature`"); // Expect revert because initial key is not the request key
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHash, keepCurrentAccess, newOwner, signature);
        vm.stopPrank();
    }

    function test_requestToken_err_invalidHash(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );

        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        bytes32 requestTokenMsgHashInvalid = requestTokenMsgHash ^ bytes32(uint256(1)); // Invalid hash (bit flipped)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHashInvalid); // Also sign with invalid hash
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("ArianeeSmartAsset: Invalid `_hash`");
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHashInvalid, keepCurrentAccess, newOwner, signature);
        vm.stopPrank();
    }

    function test_requestToken_err_invalidSignature(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );

        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes memory signatureInvalid = new bytes(signature.length);
        for (uint256 i = 0; i < signature.length; i++) {
            signatureInvalid[i] = signature[i];
        }
        signatureInvalid[0] = bytes1(uint8(signatureInvalid[0]) ^ 0x01); // Flip the first bit

        vm.expectRevert("ArianeeSmartAsset: Invalid `_hash` or `_signature`");
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHash, keepCurrentAccess, newOwner, signatureInvalid);
        vm.stopPrank();
    }

    function test_requestToken_err_onlyStore(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(unknown);
        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHash, keepCurrentAccess, newOwner, signature);
        vm.stopPrank();
    }

    // Add SmartAsset access

    function test_addTokenAccess_enable(
        uint256 tokenId,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKeyAddr); // Assert that initial key is the request key
        vm.stopPrank();

        vm.startPrank(issuer1);
        (address newKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool enable = true;
        arianeeSmartAssetProxy.addTokenAccess(tokenId, newKeyAddr, enable, ACCESS_TYPE_TRANSFER);
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), newKeyAddr); // Assert that new key is the request key
        vm.stopPrank();
    }

    function test_addTokenAccess_disable(
        uint256 tokenId,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKeyAddr); // Assert that initial key is the request key
        vm.stopPrank();

        vm.startPrank(issuer1);
        (address newKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool enable = false; // Disable access
        arianeeSmartAssetProxy.addTokenAccess(tokenId, newKeyAddr, enable, ACCESS_TYPE_TRANSFER);
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), address(0)); // Assert that new key is not the request key
        vm.stopPrank();
    }

    function test_addTokenAccess_err_isOperator(
        uint256 tokenId,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKeyAddr); // Assert that initial key is the request key
        vm.stopPrank();

        vm.startPrank(unknown);
        (address newKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool enable = true;
        vm.expectRevert("ArianeeSmartAsset: Not an operator");
        arianeeSmartAssetProxy.addTokenAccess(tokenId, newKeyAddr, enable, ACCESS_TYPE_TRANSFER);
        vm.stopPrank();
    }

    // Recover SmartAsset

    function test_recoverTokenToIssuer(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        address newOwner
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.assume(tokenRecoveryTimestamp > block.timestamp); // Make sure token is recoverable (recovery timestamp is in the future)

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.transferFrom(issuer1, newOwner, tokenId); // Transfer token to `newOwner` to prepare it for recovery
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);

        vm.expectEmit();
        emit TokenRecovered(tokenId);
        arianeeSmartAssetProxy.recoverTokenToIssuer(tokenId);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);
        vm.stopPrank();
    }

    function test_recoverTokenToIssuer_err_recoveryTimestampReached(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        address newOwner
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.assume(tokenRecoveryTimestamp <= block.timestamp); // Make sure token is not recoverable (recovery timestamp is in the past or current block)

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.transferFrom(issuer1, newOwner, tokenId); // Transfer token to `newOwner` to prepare it for recovery
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);

        vm.expectRevert("ArianeeSmartAsset: Recovery timestamp reached");
        arianeeSmartAssetProxy.recoverTokenToIssuer(tokenId);
        vm.stopPrank();
    }

    function test_recoverTokenToIssuer_err_issuerAlreadyOwner(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.assume(tokenRecoveryTimestamp > block.timestamp); // Make sure token is recoverable (recovery timestamp is in the future)

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1); // Assert that `issuer1` is the admin
        vm.stopPrank();

        vm.startPrank(issuer1);
        vm.expectRevert("ArianeeSmartAsset: Issuer is already the owner");
        arianeeSmartAssetProxy.recoverTokenToIssuer(tokenId);
        vm.stopPrank();
    }

    function test_recoverTokenToIssuer_err_isIssuer(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.assume(tokenRecoveryTimestamp > block.timestamp); // Make sure token is recoverable (recovery timestamp is in the future)

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1); // Assert that `issuer1` is the admin
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.expectRevert("ArianeeSmartAsset: Not the issuer");
        arianeeSmartAssetProxy.recoverTokenToIssuer(tokenId);
        vm.stopPrank();
    }

    // Recovery request

    function test_updateRecoveryRequest_err_isIssuer(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.assume(tokenRecoveryTimestamp <= block.timestamp); // Make sure token is not recoverable (recovery timestamp is in the past or current block)

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(unknown);
        bool active = true;
        vm.expectRevert("ArianeeSmartAsset: Not the issuer");
        arianeeSmartAssetProxy.updateRecoveryRequest(tokenId, active);
        vm.stopPrank();
    }

    function test_validRecoveryRequest(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        address newOwner
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.assume(tokenRecoveryTimestamp <= block.timestamp); // Make sure token is not recoverable (recovery timestamp is in the past or current block)

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.transferFrom(issuer1, newOwner, tokenId); // Transfer token to `newOwner` to prepare it for recovery
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);

        bool active = true;
        arianeeSmartAssetProxy.updateRecoveryRequest(tokenId, active);
        assertTrue(arianeeSmartAssetProxy.recoveryRequestOpen(tokenId));
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectEmit();
        emit IERC721.Transfer(newOwner, issuer1, tokenId);
        vm.expectEmit();
        emit RecoveryRequestUpdated(tokenId, false);
        vm.expectEmit();
        emit TokenRecovered(tokenId);
        arianeeSmartAssetProxy.validRecoveryRequest(tokenId);

        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);
        vm.stopPrank();
    }

    function test_validRecoveryRequest_err_onlyAdmin(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        address newOwner
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.assume(tokenRecoveryTimestamp <= block.timestamp); // Make sure token is not recoverable (recovery timestamp is in the past or current block)

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.transferFrom(issuer1, newOwner, tokenId); // Transfer token to `newOwner` to prepare it for recovery
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);

        bool active = true;
        arianeeSmartAssetProxy.updateRecoveryRequest(tokenId, active);
        assertTrue(arianeeSmartAssetProxy.recoveryRequestOpen(tokenId));
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeSmartAssetProxy.validRecoveryRequest(tokenId);
        vm.stopPrank();
    }

    // Update SmartAsset URI

    function test_updateTokenURI(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        string calldata newUri
    ) public {
        vm.assume(bytes(newUri).length > 0); // Make sure `newUri` is not empty otherwise `tokenURI` will return `string.concat($.baseURI, tokenId.toString())`

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        vm.expectEmit();
        emit TokenURIUpdated(tokenId, newUri);
        arianeeSmartAssetProxy.updateTokenURI(tokenId, newUri);
        assertEq(arianeeSmartAssetProxy.tokenURI(tokenId), newUri);
        vm.stopPrank();
    }

    function test_updateTokenURI_err_isIssuer(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        string calldata newUri
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.expectRevert("ArianeeSmartAsset: Not the issuer");
        arianeeSmartAssetProxy.updateTokenURI(tokenId, newUri);
        vm.stopPrank();
    }

    // Destroy SmartAsset

    function test_destroyToken(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        // vm.expectEmit();
        // emit TokenDestroyed(tokenId);

        vm.expectRevert("ArianeeSmartAsset: Destroy disabled");
        arianeeSmartAssetProxy.destroy(tokenId);
        vm.stopPrank();
    }

    // Set URI base

    function test_setUriBase(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        string calldata newBaseUri
    ) public {
        vm.assume(bytes(newBaseUri).length > 0); // Make sure `newBaseUri` is not empty

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId,
            imprint,
            "", // Make sure URI is empty for this test
            initialKey,
            tokenRecoveryTimestamp,
            initialKeyIsRequestKey,
            issuer1,
            false
        );
        vm.stopPrank();

        vm.startPrank(admin);
        string memory originalTokenUri = arianeeSmartAssetProxy.tokenURI(tokenId);
        assertEq(originalTokenUri, string.concat(URI_BASE, tokenId.toString()));

        vm.expectEmit();
        emit SetNewUriBase(newBaseUri);
        arianeeSmartAssetProxy.setUriBase(newBaseUri);

        string memory newTokenUri = arianeeSmartAssetProxy.tokenURI(tokenId);
        assertEq(newTokenUri, string.concat(newBaseUri, tokenId.toString()));
        vm.stopPrank();
    }

    function test_setUriBase_err_onlyAdmin(
        string calldata newBaseUri
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeSmartAssetProxy.setUriBase(newBaseUri);
        vm.stopPrank();
    }

    // Transfer access reset

    function test_resetTransferAccessOnUpdate(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, false
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.transferFrom(issuer1, user1, tokenId);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), user1);
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), address(0));
        assertFalse(arianeeSmartAssetProxy.isRequestable(tokenId));
        vm.stopPrank();
    }
}
