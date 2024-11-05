// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { IERC721Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {
    ArianeeSmartAsset,
    Hydrated,
    TokenRecovered,
    RecoveryRequestUpdated,
    TokenURIUpdated,
    TokenDestroyed,
    SetNewUriBase,
    SetAddress
} from "@arianee/ArianeeSmartAsset.sol";
import {
    ROLE_SMART_ASSET_MANAGER,
    ERC721_NAME,
    ERC721_SYMBOL,
    URI_BASE,
    ACCESS_TYPE_VIEW,
    ACCESS_TYPE_TRANSFER
} from "@arianee/Constants.sol";
import { ArianeeUtils } from "./Utils.sol";

contract ArianeeSmartAssetTest is Test {
    using Strings for uint256;

    address owner = address(this); // Owner is likely the "Arianee Foundation"
    address unknown = vm.addr(1);
    address issuer1 = vm.addr(2);
    address user1 = vm.addr(3);

    address arianeeSmartAssetImplAddr;
    ArianeeSmartAsset arianeeSmartAssetProxy;

    function setUp() public {
        address arianeeWhitelistAddr = address(0);
        address forwarderAddr = address(0);
        bool isSoulbound = false;

        address arianeeSmartAssetProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeSmartAsset.sol",
            owner,
            abi.encodeCall(ArianeeSmartAsset.initialize, (arianeeWhitelistAddr, forwarderAddr, isSoulbound))
        );
        arianeeSmartAssetProxy = ArianeeSmartAsset(arianeeSmartAssetProxyAddr);
        arianeeSmartAssetImplAddr = Upgrades.getImplementationAddress(arianeeSmartAssetProxyAddr);
    }

    // Initializer

    function test_Initialize() public view {
        assertFalse(arianeeSmartAssetProxy.paused());
        assertTrue(arianeeSmartAssetProxy.isRoleActive(ROLE_SMART_ASSET_MANAGER));
        assertEq(arianeeSmartAssetProxy.name(), ERC721_NAME);
        assertEq(arianeeSmartAssetProxy.symbol(), ERC721_SYMBOL);
        assertEq(arianeeSmartAssetProxy.owner(), owner);
    }

    // Reserve token

    function test_deactivateRole_reserveToken(uint256 tokenId, address to) public {
        vm.assume(to != address(0)); // Make sure `to` is not the zero address

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(unknown);
        arianeeSmartAssetProxy.reserveToken(tokenId, to);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), to);
        vm.stopPrank();
    }

    // Hydrate token

    function test_deactivateRole_hydrateToken(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        vm.expectEmit();
        emit Hydrated(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, block.timestamp
        );
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );

        assertEq(arianeeSmartAssetProxy.issuerOf(tokenId), issuer1);
        assertEq(arianeeSmartAssetProxy.tokenCreation(tokenId), block.timestamp);
        assertEq(arianeeSmartAssetProxy.tokenRecoveryDate(tokenId), tokenRecoveryTimestamp);
        assertEq(arianeeSmartAssetProxy.tokenImprint(tokenId), imprint);
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_VIEW), initialKey);
        if (initialKeyIsRequestKey) {
            assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKey);
        }
        vm.stopPrank();
    }

    function test_deactivateRole_hydrateToken_err_isOperator(
        uint256 tokenId,
        address to,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.assume(to != address(0)); // Make sure `to` is not the zero address
        vm.assume(to != issuer1); // Make sure `to` is different from `issuer1`

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, to); // Reserve token to `to` instead of `issuer1`
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), to);

        vm.expectRevert("ArianeeSmartAsset: Not an operator");
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        vm.stopPrank();
    }

    function test_deactivateRole_hydrateToken_err_alreadyHydrated(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        vm.expectEmit();
        emit Hydrated(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, block.timestamp
        );
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );

        vm.expectRevert("ArianeeSmartAsset: SmartAsset already hydrated");
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        vm.stopPrank();
    }

    // Request token

    function test_deactivateRole_requestToken(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.assume(newOwner != address(0)); // Make sure `newOwner` is not the zero address

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        vm.stopPrank();

        vm.startPrank(unknown);
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

    function test_deactivateRole_requestToken_initialKeyIsNotRequestKey(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.assume(newOwner != address(0)); // Make sure `newOwner` is not the zero address

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = false; // Initial key is not the request key
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        vm.stopPrank();

        vm.startPrank(unknown);
        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("ArianeeSmartAsset: Invalid `_hash` or `_signature`"); // Expect revert because initial key is not the request key
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHash, keepCurrentAccess, newOwner, signature);
        vm.stopPrank();
    }

    function test_deactivateRole_requestToken_err_invalidHash(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        vm.stopPrank();

        vm.startPrank(unknown);
        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        bytes32 requestTokenMsgHashInvalid = requestTokenMsgHash ^ bytes32(uint256(1)); // Invalid hash (bit flipped)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHashInvalid); // Also sign with invalid hash
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("ArianeeSmartAsset: Invalid `_hash`");
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHashInvalid, keepCurrentAccess, newOwner, signature);
        vm.stopPrank();
    }

    function test_deactivateRole_requestToken_err_invalidSignature(
        uint256 tokenId,
        bool keepCurrentAccess,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        vm.stopPrank();

        vm.startPrank(unknown);
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

    // Add token access

    function test_addTokenAccess_enable(
        uint256 tokenId,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKeyAddr); // Assert that initial key is the request key

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
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKeyAddr); // Assert that initial key is the request key

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
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
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

    // Recover token

    function test_recoverTokenToIssuer(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        address newOwner
    ) public {
        vm.assume(newOwner != address(0)); // Make sure `newOwner` is not the zero address
        vm.assume(newOwner != issuer1); // Make sure `newOwner` is different from `issuer1`
        vm.assume(tokenRecoveryTimestamp > block.timestamp); // Make sure token is recoverable (recovery timestamp is in the future)

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
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
    ) public {
        vm.assume(newOwner != address(0)); // Make sure `newOwner` is not the zero address
        vm.assume(newOwner != issuer1); // Make sure `newOwner` is different from `issuer1`
        vm.assume(tokenRecoveryTimestamp <= block.timestamp); // Make sure token is not recoverable (recovery timestamp is in the past or current block)

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
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

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1); // Assert that `issuer1` is the owner

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

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1); // Assert that `issuer1` is the owner
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

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
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
    ) public {
        vm.assume(newOwner != address(0)); // Make sure `newOwner` is not the zero address
        vm.assume(newOwner != issuer1); // Make sure `newOwner` is different from `issuer1`
        vm.assume(tokenRecoveryTimestamp <= block.timestamp); // Make sure token is not recoverable (recovery timestamp is in the past or current block)

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        arianeeSmartAssetProxy.transferFrom(issuer1, newOwner, tokenId); // Transfer token to `newOwner` to prepare it for recovery
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);

        bool active = true;
        arianeeSmartAssetProxy.updateRecoveryRequest(tokenId, active);
        assertTrue(arianeeSmartAssetProxy.recoveryRequestOpen(tokenId));
        vm.stopPrank();

        vm.startPrank(owner);
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

    function test_validRecoveryRequest_err_onlyOwner(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey,
        address newOwner
    ) public {
        vm.assume(newOwner != address(0)); // Make sure `newOwner` is not the zero address
        vm.assume(newOwner != issuer1); // Make sure `newOwner` is different from `issuer1`
        vm.assume(tokenRecoveryTimestamp <= block.timestamp); // Make sure token is not recoverable (recovery timestamp is in the past or current block)

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        arianeeSmartAssetProxy.transferFrom(issuer1, newOwner, tokenId); // Transfer token to `newOwner` to prepare it for recovery
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);

        bool active = true;
        arianeeSmartAssetProxy.updateRecoveryRequest(tokenId, active);
        assertTrue(arianeeSmartAssetProxy.recoveryRequestOpen(tokenId));
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, unknown));
        arianeeSmartAssetProxy.validRecoveryRequest(tokenId);
        vm.stopPrank();
    }

    // Update token URI

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

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );

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
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.expectRevert("ArianeeSmartAsset: Not the issuer");
        arianeeSmartAssetProxy.updateTokenURI(tokenId, newUri);
        vm.stopPrank();
    }

    // Destroy token

    function test_destroyToken(
        uint256 tokenId,
        bytes32 imprint,
        address initialKey,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1
        );

        vm.expectEmit();
        emit TokenDestroyed(tokenId);
        arianeeSmartAssetProxy.destroy(tokenId);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, tokenId));
        arianeeSmartAssetProxy.issuerOf(tokenId);
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

        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        arianeeSmartAssetProxy.hydrateToken(
            tokenId,
            imprint,
            "", // Make sure URI is empty for this test
            initialKey,
            tokenRecoveryTimestamp,
            initialKeyIsRequestKey,
            issuer1
        );
        vm.stopPrank();

        vm.startPrank(owner);
        string memory originalTokenUri = arianeeSmartAssetProxy.tokenURI(tokenId);
        assertEq(originalTokenUri, string.concat(URI_BASE, tokenId.toString()));

        vm.expectEmit();
        emit SetNewUriBase(newBaseUri);
        arianeeSmartAssetProxy.setUriBase(newBaseUri);

        string memory newTokenUri = arianeeSmartAssetProxy.tokenURI(tokenId);
        assertEq(newTokenUri, string.concat(newBaseUri, tokenId.toString()));
        vm.stopPrank();
    }

    function test_setUriBase_err_onlyOwner(
        string calldata newBaseUri
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, unknown));
        arianeeSmartAssetProxy.setUriBase(newBaseUri);
        vm.stopPrank();
    }

    // Set ArianeeStore address

    function test_setStoreAddress(
        address newStoreAddr
    ) public {
        vm.startPrank(owner);
        vm.expectEmit();
        emit SetAddress("storeAddress", newStoreAddr);
        arianeeSmartAssetProxy.setStoreAddress(newStoreAddr);
        vm.stopPrank();
    }

    function test_setStoreAddress_err_onlyOwner(
        address newStoreAddr
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, unknown));
        arianeeSmartAssetProxy.setStoreAddress(newStoreAddr);
        vm.stopPrank();
    }

    // Set ArianeeWhitelist address

    function test_setWhitelistAddress(
        address newWhitelistAddr
    ) public {
        vm.startPrank(owner);
        vm.expectEmit();
        emit SetAddress("whitelistAddress", newWhitelistAddr);
        arianeeSmartAssetProxy.setWhitelistAddress(newWhitelistAddr);
        vm.stopPrank();
    }

    function test_setWhitelistAddress_err_onlyOwner(
        address newWhitelistAddr
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, unknown));
        arianeeSmartAssetProxy.setWhitelistAddress(newWhitelistAddr);
        vm.stopPrank();
    }

    // Role activation

    function test_activateRole() public {
        vm.startPrank(owner);
        arianeeSmartAssetProxy.activateRole(ROLE_SMART_ASSET_MANAGER);
        assertTrue(arianeeSmartAssetProxy.isRoleActive(ROLE_SMART_ASSET_MANAGER));
        vm.stopPrank();
    }

    function test_activateRole_err_onlyOwner() public {
        vm.startPrank(unknown);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, unknown));
        arianeeSmartAssetProxy.activateRole(ROLE_SMART_ASSET_MANAGER);
        vm.stopPrank();
    }

    function test_deactivateRole() public {
        vm.startPrank(owner);
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);
        assertFalse(arianeeSmartAssetProxy.isRoleActive(ROLE_SMART_ASSET_MANAGER));
        vm.stopPrank();
    }

    function test_deactivateRole_err_onlyOwner() public {
        vm.startPrank(unknown);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, unknown));
        arianeeSmartAssetProxy.deactivateRole(ROLE_SMART_ASSET_MANAGER);
        vm.stopPrank();
    }

    // TODO: Add tests without the `deactivateRole` call for the following functions: `reserveToken`, `hydrateToken` and `requestToken` (require ArianeeStore)
    // TODO: Make another test file for Soulbound cases
    // TODO: Add a test for `transferFrom` in the Soulbound case
}
