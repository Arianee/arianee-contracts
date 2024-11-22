// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { IERC721Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
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

contract ArianeeSmartAsseSoulboundTest is Test {
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
    }

    // Request SmartAsset

    function test_requestToken_err_isSoulbound(
        uint256 tokenId,
        address newOwner,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp
    ) public {
        vm.assume(newOwner != address(0)); // Make sure `newOwner` is not the zero address

        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        bool soulbound = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, soulbound
        );

        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool keepCurrentAccess = true; // Keep current transfer access, should fail because token is soulbound
        vm.expectRevert("ArianeeSmartAsset: Forbidden to keep the transfer access on a soulbound SmartAsset");
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHash, keepCurrentAccess, newOwner, signature);
        vm.stopPrank();
    }

    // Add SmartAsset transfer access

    function test_addTransferAccess(
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
        bool soulbound = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, soulbound
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

    function test_addTransferAccess_err_onlyIssuer(
        uint256 tokenId,
        bytes32 imprint,
        string calldata addrAndKeySeed,
        string calldata uri,
        uint256 tokenRecoveryTimestamp,
        address newOwner
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), issuer1);

        (address initialKeyAddr, uint256 initialKeyPk) = makeAddrAndKey(addrAndKeySeed);
        bool initialKeyIsRequestKey = true;
        bool soulbound = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKeyAddr, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, soulbound
        );
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(tokenId, ACCESS_TYPE_TRANSFER), initialKeyAddr); // Assert that initial key is the request key

        bytes32 requestTokenMsgHash = ArianeeUtils.getRequestTokenMsgHash(tokenId, newOwner);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(initialKeyPk, requestTokenMsgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        bool keepCurrentAccess = false;
        arianeeSmartAssetProxy.requestToken(tokenId, requestTokenMsgHash, keepCurrentAccess, newOwner, signature);
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), newOwner);
        vm.stopPrank();

        vm.startPrank(newOwner);
        (address newKeyAddr,) = makeAddrAndKey(addrAndKeySeed);
        bool enable = true;
        vm.expectRevert("ArianeeSmartAsset: Only the issuer can add a transfer access to a soulbound SmartAsset");
        arianeeSmartAssetProxy.addTokenAccess(tokenId, newKeyAddr, enable, ACCESS_TYPE_TRANSFER);
        vm.stopPrank();
    }

    // Transfer from

    function test_transferFrom_err_tokenOwnerIsNotFrom(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        bool soulbound = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, soulbound
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        vm.expectRevert("ArianeeSmartAsset: Transfer not allowed (`tokenOwner` != `_from`)");
        arianeeSmartAssetProxy.transferFrom(user1, unknown, tokenId);
        vm.stopPrank();
    }

    function test_transferFrom_err_tokenOwnerIsTokenIssuer(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        address initialKey,
        uint256 tokenRecoveryTimestamp,
        bool initialKeyIsRequestKey
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(tokenId, issuer1);
        bool soulbound = true;
        arianeeSmartAssetProxy.hydrateToken(
            tokenId, imprint, uri, initialKey, tokenRecoveryTimestamp, initialKeyIsRequestKey, issuer1, soulbound
        );
        vm.stopPrank();

        vm.startPrank(issuer1);
        arianeeSmartAssetProxy.transferFrom(issuer1, user1, tokenId); // Should work because the token owner is the token issuer
        assertEq(arianeeSmartAssetProxy.ownerOf(tokenId), user1);
        vm.stopPrank();

        vm.startPrank(user1);
        vm.expectRevert("ArianeeSmartAsset: Only the issuer can transfer a soulbound SmartAsset");
        arianeeSmartAssetProxy.transferFrom(user1, unknown, tokenId); // Should fail because the token owner is not the token issuer
        vm.stopPrank();
    }
}
