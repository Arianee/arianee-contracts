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
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(2);
    address smartAsset = vm.addr(3);

    address unknown = vm.addr(4);
    address manager = vm.addr(5);
    address user1 = vm.addr(6);

    ArianeeLost arianeeLostProxy;
    address arianeeLostImplAddr;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeLostProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeLost.sol", proxyAdmin, abi.encodeCall(ArianeeLost.initialize, (admin, smartAsset, manager)), opts
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
        console.log("Manager: %s", manager);
        console.log("User1: %s", user1);
        // Contracts
        console.log("ArianeeLostProxy: %s", address(arianeeLostProxy));
        console.log("ArianeeLostImpl: %s", arianeeLostImplAddr);
    }

    modifier assumeIsNotKnownOrZeroAddress(
        address addr
    ) {
        vm.assume(addr != address(0)); // Make sure `addr` is not the zero address
        vm.assume(addr != msg.sender); // Make sure `addr` is not the default address

        vm.assume(addr != proxyAdmin); // Make sure `addr` is not the proxy admin address
        vm.assume(addr != admin); // Make sure `addr` is not the admin address

        vm.assume(addr != forwarder); // Make sure `addr` is not the forwarder address
        vm.assume(addr != smartAsset); // Make sure `addr` is not the smartAsset address

        vm.assume(addr != unknown); // Make sure `addr` is not the unknown address
        vm.assume(addr != manager); // Make sure `addr` is not the manager address
        vm.assume(addr != user1); // Make sure `addr` is not the first user address

        vm.assume(addr != address(arianeeLostProxy)); // Make sure `addr` is not the ArianeeLost proxy address
        vm.assume(addr != arianeeLostImplAddr); // Make sure `addr` is not the ArianeeLost implementation address
        _;
    }

    // Initializer

    function test_initialize() public view {
        assertEq(arianeeLostProxy.owner(), admin, "Owner not initialized");
        assertEq(arianeeLostProxy.getManagerIdentity(), manager, "Manager identity not initialized");
    }

    // Set missing status

    function test_set_missing_status(
        uint256 tokenId
    ) public {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));

        vm.expectEmit();
        emit Missing(tokenId);
        arianeeLostProxy.setMissingStatus(tokenId);

        bool isMissing = arianeeLostProxy.isMissing(tokenId);
        assertTrue(isMissing, "Token missing status not set");

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_set_notAdmin_missing_status(
        uint256 tokenId
    ) public {
        vm.startPrank(unknown);

        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));
        vm.expectRevert("ArianeeLost: Not authorized because not the SmartAsset owner");
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_err_missing_twice_status(
        uint256 tokenId
    ) public {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.expectRevert("ArianeeLost: The SmartAsset must not be marked as missing");
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Unset missing status

    function test_unset_missing_status(
        uint256 tokenId
    ) public {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));
        arianeeLostProxy.setMissingStatus(tokenId);

        vm.expectEmit();
        emit UnMissing(tokenId);
        arianeeLostProxy.unsetMissingStatus(tokenId);

        bool isMissing = arianeeLostProxy.isMissing(tokenId);
        assertFalse(isMissing, "Token missing status not set");

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_err_unset_missing_status(
        uint256 tokenId
    ) public {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));

        vm.expectRevert("ArianeeLost: The SmartAsset must be marked as missing");
        arianeeLostProxy.unsetMissingStatus(tokenId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Set stolen status

    function test_set_stolen_status(
        uint256 tokenId,
        address authorizedIdentity
    ) public assumeIsNotKnownOrZeroAddress(authorizedIdentity) {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));
        arianeeLostProxy.setMissingStatus(tokenId);
        vm.stopPrank();

        vm.startPrank(manager);
        vm.expectEmit();
        emit AuthorizedIdentityAdded(authorizedIdentity);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);
        vm.stopPrank();

        vm.startPrank(authorizedIdentity);
        vm.expectEmit();
        emit Stolen(tokenId);
        arianeeLostProxy.setStolenStatus(tokenId);

        bool isStolen = arianeeLostProxy.isStolen(tokenId);
        assertTrue(isStolen, "Token stolen status not set");
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_err_notMissing_set_stolen_status(
        uint256 tokenId,
        address authorizedIdentity
    ) public assumeIsNotKnownOrZeroAddress(authorizedIdentity) {
        vm.startPrank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);
        vm.stopPrank();

        vm.startPrank(authorizedIdentity);
        vm.expectRevert();
        arianeeLostProxy.setStolenStatus(tokenId);
        vm.stopPrank();
    }

    function test_err_unauthorized_set_stolen_status(
        uint256 tokenId
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert("ArianeeLost: Caller must be an authorized identity");
        arianeeLostProxy.setStolenStatus(tokenId);
    }

    // Unset stolen status

    function test_unsetStolen_status(
        uint256 tokenId,
        address authorizedIdentity
    ) public assumeIsNotKnownOrZeroAddress(authorizedIdentity) {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));

        arianeeLostProxy.setMissingStatus(tokenId);
        vm.stopPrank();

        vm.startPrank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);
        vm.stopPrank();

        vm.startPrank(authorizedIdentity);
        arianeeLostProxy.setStolenStatus(tokenId);
        arianeeLostProxy.unsetStolenStatus(tokenId);

        bool isStolen = arianeeLostProxy.isStolen(tokenId);
        assertFalse(isStolen, "Token stolen status not set to false after unstolen");
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_err_notAuthorized_unsetStolen_status(
        uint256 tokenId,
        address authorizedIdentity
    ) public assumeIsNotKnownOrZeroAddress(authorizedIdentity) {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(user1));

        arianeeLostProxy.setMissingStatus(tokenId);
        vm.stopPrank();

        vm.startPrank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);
        vm.stopPrank();

        vm.startPrank(authorizedIdentity);
        arianeeLostProxy.setStolenStatus(tokenId);
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.expectRevert("ArianeeLost: Not the issuer nor the manager");
        arianeeLostProxy.unsetStolenStatus(tokenId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Set manager identity

    function test_set_manager_identity(
        address newManager
    ) public {
        vm.startPrank(admin);
        arianeeLostProxy.setManagerIdentity(newManager);
        assertEq(arianeeLostProxy.getManagerIdentity(), newManager, "Manager identity not set");
        vm.stopPrank();
    }

    function test_err_notOwner_set_manager_identity(
        address newManager
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert();
        arianeeLostProxy.setManagerIdentity(newManager);
        vm.stopPrank();
    }

    // Unset authorized identity

    function test_unsetAuthorizedIdentity(
        address authorizedIdentity
    ) public {
        vm.startPrank(manager);
        arianeeLostProxy.setAuthorizedIdentity(authorizedIdentity);

        vm.startPrank(manager);
        vm.expectEmit();
        emit AuthorizedIdentityRemoved(authorizedIdentity);
        arianeeLostProxy.unsetAuthorizedIdentity(authorizedIdentity);

        bool isAuthorized = arianeeLostProxy.isAddressAuthorized(authorizedIdentity);
        assertFalse(isAuthorized, "Authorized identity not unset");
        vm.stopPrank();
    }
}
