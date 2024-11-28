// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import {
    ArianeeSmartAssetUpdate, SmartAssetUpdated, SmartAssetUpdateReaded
} from "@arianee/V0/ArianeeSmartAssetUpdate.sol";
import { IArianeeSmartAsset } from "@arianee/V0/Interfaces/IArianeeSmartAsset.sol";
import { ROLE_ADMIN, ROLE_ARIANEE_STORE } from "@arianee/V0/Constants.sol";

contract ArianeeSmartAssetUpdateTest is Test {
    address proxyAdmin = vm.addr(1);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(2);
    address smartAsset = vm.addr(3);
    address store = vm.addr(4);

    address unknown = vm.addr(5);

    address arianeeSmartAssetUpdateImplAddr;
    ArianeeSmartAssetUpdate arianeeSmartAssetUpdateProxy;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeSmartAssetUpdateProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeSmartAssetUpdate.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeSmartAssetUpdate.initialize, (admin, smartAsset, store)),
            opts
        );
        arianeeSmartAssetUpdateProxy = ArianeeSmartAssetUpdate(arianeeSmartAssetUpdateProxyAddr);
        arianeeSmartAssetUpdateImplAddr = Upgrades.getImplementationAddress(arianeeSmartAssetUpdateProxyAddr);

        arianeeSmartAssetUpdateProxy.grantRole(ROLE_ARIANEE_STORE, store);
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("SmartAsset: %s", smartAsset);
        console.log("Store: %s", store);
        console.log("Unknown: %s", unknown);
    }

    modifier assumeIsNotKnownAddress(
        address addr
    ) {
        vm.assume(addr != address(0)); // Make sure `addr` is not the zero address
        vm.assume(addr != msg.sender); // Make sure `addr` is not the default address

        vm.assume(addr != proxyAdmin); // Make sure `addr` is not the proxy admin address
        vm.assume(addr != admin); // Make sure `addr` is not the admin address

        vm.assume(addr != forwarder); // Make sure `addr` is not the forwarder address
        vm.assume(addr != smartAsset); // Make sure `addr` is not the smartAsset address
        vm.assume(addr != store); // Make sure `addr` is not the store address

        vm.assume(addr != unknown); // Make sure `addr` is not the unknown address
        _;
    }

    // Initializer

    function test_initialize() public view {
        assertFalse(arianeeSmartAssetUpdateProxy.paused());
    }

    // Update SmartAsset

    function test_updateSmartAsset(
        uint256 tokenId,
        bytes32 imprint,
        address issuer,
        uint256 rewards
    ) public assumeIsNotKnownAddress(issuer) {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector), abi.encode(issuer));
        vm.expectEmit();
        emit SmartAssetUpdated(tokenId, imprint);
        arianeeSmartAssetUpdateProxy.updateSmartAsset(tokenId, imprint, issuer, rewards);

        assertEq(arianeeSmartAssetUpdateProxy.getImprint(tokenId), imprint);
        assertEq(arianeeSmartAssetUpdateProxy.getUpdatedImprint(tokenId), imprint);

        bytes32 mockOriginalImprint = keccak256(abi.encodePacked(uint256(123)));
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.tokenImprint.selector),
            abi.encode(mockOriginalImprint)
        );
        (bool isUpdated, bytes32 lastUpdatedImprint, bytes32 originalImprint, uint256 updateTimestamp) =
            arianeeSmartAssetUpdateProxy.getUpdate(tokenId);
        assertTrue(isUpdated);
        assertEq(lastUpdatedImprint, imprint);
        assertEq(originalImprint, mockOriginalImprint);
        assertEq(updateTimestamp, block.timestamp);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_updateSmartAsset_err_isIssuer(
        uint256 tokenId,
        bytes32 imprint,
        address issuer,
        uint256 rewards
    ) public assumeIsNotKnownAddress(issuer) {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector), abi.encode(address(0))); // Mock issuerOf to return zero address instead of issuer
        vm.expectRevert("ArianeeSmartAssetUpdate: Invalid `_issuer`");
        arianeeSmartAssetUpdateProxy.updateSmartAsset(tokenId, imprint, issuer, rewards);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_updateSmartAsset_err_onlyStore(
        uint256 tokenId,
        bytes32 imprint,
        address issuer,
        uint256 rewards
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeSmartAssetUpdateProxy.updateSmartAsset(tokenId, imprint, issuer, rewards);
        vm.stopPrank();
    }

    // Read SmartAsset Update

    function test_readUpdateSmartAsset(
        uint256 tokenId,
        bytes32 imprint,
        address issuer,
        uint256 rewards,
        address from
    ) public assumeIsNotKnownAddress(issuer) assumeIsNotKnownAddress(from) {
        vm.startPrank(store);

        // Update a SmartAsset first to add some rewards
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector), abi.encode(issuer));
        arianeeSmartAssetUpdateProxy.updateSmartAsset(tokenId, imprint, issuer, rewards);

        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector), abi.encode(true));
        vm.expectEmit();
        emit SmartAssetUpdateReaded(tokenId);
        uint256 rewardsRes = arianeeSmartAssetUpdateProxy.readUpdateSmartAsset(tokenId, from);
        assertEq(rewards, rewardsRes);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_readUpdateSmartAsset_isOperator(uint256 tokenId, address from) public assumeIsNotKnownAddress(from) {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector), abi.encode(false)); // Mock canOperate to return false
        vm.expectRevert("ArianeeSmartAssetUpdate: Not an operator");
        arianeeSmartAssetUpdateProxy.readUpdateSmartAsset(tokenId, from);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_readUpdateSmartAsset_onlyStore(uint256 tokenId, address from) public assumeIsNotKnownAddress(from) {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeSmartAssetUpdateProxy.readUpdateSmartAsset(tokenId, from);
        vm.stopPrank();
    }
}
