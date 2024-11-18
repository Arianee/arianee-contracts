// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import {
    ArianeeLost,
    Missing,
    UnMissing,
    NewManagerIdentity,
    AuthorizedIdentityAdded,
    AuthorizedIdentityRemoved,
    Stolen,
    UnStolen
} from "@arianee/V0/ArianeeLost.sol";
import { IArianeeSmartAsset } from "@arianee/V0/Interfaces/IArianeeSmartAsset.sol";

contract ArianeeLostTest is Test {
    address proxyAdmin = vm.addr(1);
    address admin = address(this);
    address forwarder = vm.addr(2);
    address smartAsset = vm.addr(3);
    address unknown = vm.addr(4);
    address manager = vm.addr(5);

    ArianeeLost arianeeLostProxy;
    address arianeeLostImplAddr;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeLostProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeLost.sol", proxyAdmin, abi.encodeCall(ArianeeLost.initialize, (smartAsset, manager)), opts
        );

        arianeeLostProxy = ArianeeLost(arianeeLostProxyAddr);
        arianeeLostImplAddr = Upgrades.getImplementationAddress(arianeeLostProxyAddr);
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("SmartAsset: %s", smartAsset);
        console.log("Unknown: %s", unknown);
    }

    function test_initialize() public view {
        assertEq(arianeeLostProxy.getManagerIdentity(), manager, "Manager identity not initialized");
    }

    function test_set_missing_status() public {
        uint256 tokenId = 1;

        vm.prank(admin);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));

        vm.expectEmit();
        emit Missing(tokenId);
        arianeeLostProxy.setMissingStatus(tokenId);

        // bool isMissing = arianeeLostProxy.tokenMissingStatus(tokenId); // TODO why is this not working ?
        bool isMissing = arianeeLostProxy.isMissing(tokenId);
        assertTrue(isMissing, "Token missing status not set.");

        vm.clearMockedCalls();

        vm.stopPrank();
    }

    function test_set_notAdmin_missing_status() public {
        uint256 tokenId = 1;

        vm.prank(unknown);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));
        vm.expectRevert("Not authorized because not the owner");
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.clearMockedCalls();

        vm.stopPrank();
    }

    function test_err_missing_twice_status() public {
        uint256 tokenId = 1;

        vm.prank(admin);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.expectRevert("The token must not be marked as missing.");
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.clearMockedCalls();

        vm.stopPrank();
    }

    function test_unset_missing_status() public {
        uint256 tokenId = 1;

        vm.prank(admin);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.expectEmit();
        emit UnMissing(tokenId);

        arianeeLostProxy.unsetMissingStatus(tokenId);

        bool isMissing = arianeeLostProxy.isMissing(tokenId);
        assertFalse(isMissing, "Token missing status not set.");

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_err_unset_missing_status() public {
        uint256 tokenId = 1;

        vm.prank(admin);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));

        vm.expectRevert("The token must be marked as missing.");
        arianeeLostProxy.unsetMissingStatus(tokenId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_set_stolen_status() public {
        uint256 tokenId = 1;
        address authorizedIdentity = vm.addr(5);

        vm.prank(admin);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));

        arianeeLostProxy.setMissingStatus(tokenId);
        vm.stopPrank();

        vm.prank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);

        vm.expectEmit();
        emit Stolen(tokenId);
        vm.stopPrank();

        vm.prank(authorizedIdentity);
        arianeeLostProxy.setStolenStatus(tokenId);

        bool isStolen = arianeeLostProxy.isStolen(tokenId);
        assertTrue(isStolen, "Token stolen status not set.");
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_err_notMissing_set_stolen_status() public {
        uint256 tokenId = 1;
        address authorizedIdentity = vm.addr(5);

        vm.prank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);
        vm.stopPrank();

        vm.prank(authorizedIdentity);
        vm.expectRevert();
        arianeeLostProxy.setStolenStatus(tokenId);

        vm.stopPrank();
    }

    function test_err_unauthorized_set_stolen_status() public {
        uint256 tokenId = 1;

        vm.prank(admin);

        vm.expectRevert("Caller must be an authorized identity.");

        arianeeLostProxy.setStolenStatus(tokenId);
    }

    function test_unsetStolen_status() public {
        uint256 tokenId = 1;
        address authorizedIdentity = vm.addr(5);

        vm.prank(admin);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));

        arianeeLostProxy.setMissingStatus(tokenId);
        vm.stopPrank();

        vm.prank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);
        vm.stopPrank();

        vm.prank(authorizedIdentity);
        arianeeLostProxy.setStolenStatus(tokenId);

        vm.prank(authorizedIdentity);
        arianeeLostProxy.unsetStolenStatus(tokenId);

        bool isStolen = arianeeLostProxy.isStolen(tokenId);
        assertFalse(isStolen, "Token stolen status not set to false after unstolen.");
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_err_notAuthorized_unsetStolen_status() public {
        uint256 tokenId = 1;
        address authorizedIdentity = vm.addr(5);

        vm.prank(admin);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(admin));

        arianeeLostProxy.setMissingStatus(tokenId);
        vm.stopPrank();

        vm.prank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);
        vm.stopPrank();

        vm.prank(authorizedIdentity);
        arianeeLostProxy.setStolenStatus(tokenId);

        vm.prank(unknown);
        vm.expectRevert("Caller must be an authorized identity or the manager.");
        arianeeLostProxy.unsetStolenStatus(tokenId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_set_manager_identity() public {
        address newManager = vm.addr(6);

        vm.prank(admin);
        arianeeLostProxy.setManagerIdentity(newManager);

        assertEq(arianeeLostProxy.getManagerIdentity(), newManager, "Manager identity not set.");
        vm.stopPrank();
    }

    function test_err_notOwner_set_manager_identity() public {
        address newManager = vm.addr(6);

        vm.prank(unknown);

        vm.expectRevert();
        arianeeLostProxy.setManagerIdentity(newManager);

        vm.stopPrank();
    }

    function test_unsetAuthorizedIdentity() public {
        address authorizedIdentity = vm.addr(5);

        vm.prank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);

        vm.prank(manager);
        vm.expectEmit();
        emit AuthorizedIdentityRemoved(authorizedIdentity);
        arianeeLostProxy.unsetAuthorizedIdentity(authorizedIdentity);

        bool isAuthorized = arianeeLostProxy.isAddressAuthorized(authorizedIdentity);
        assertFalse(isAuthorized, "Authorized identity not unset.");
        vm.stopPrank();
    }
}
