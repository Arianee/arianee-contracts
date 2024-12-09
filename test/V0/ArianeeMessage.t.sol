// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ArianeeMessage, Message, MessageSent, MessageRead } from "@arianee/V0/ArianeeMessage.sol";
import { IArianeeSmartAsset } from "@arianee/V0/Interfaces/IArianeeSmartAsset.sol";
import { IArianeeStore } from "@arianee/V0/Interfaces/IArianeeStore.sol";
import { IArianeeWhitelist } from "@arianee/V0/Interfaces/IArianeeWhitelist.sol";
import { ROLE_ADMIN, ROLE_ARIANEE_STORE } from "@arianee/V0/Constants.sol";

contract ArianeeMessageTest is Test {
    address proxyAdmin = vm.addr(1);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(2);
    address smartAsset = vm.addr(3);
    address store = vm.addr(4);
    address whitelist = vm.addr(5);

    address unknown = vm.addr(6);

    address arianeeMessageImplAddr;
    ArianeeMessage arianeeMessageProxy;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeMessageProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeMessage.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeMessage.initialize, (admin, smartAsset, store, whitelist)),
            opts
        );
        arianeeMessageProxy = ArianeeMessage(arianeeMessageProxyAddr);
        arianeeMessageImplAddr = Upgrades.getImplementationAddress(arianeeMessageProxyAddr);
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("SmartAsset: %s", smartAsset);
        console.log("Store: %s", store);
        console.log("Whitelist: %s", whitelist);
        console.log("Unknown: %s", unknown);
        // Contracts
        console.log("ArianeeMessageProxy: %s", address(arianeeMessageProxy));
        console.log("ArianeeMessageImpl: %s", arianeeMessageImplAddr);
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
        vm.assume(addr != store); // Make sure `addr` is not the store address
        vm.assume(addr != whitelist); // Make sure `addr` is not the whitelist address

        vm.assume(addr != unknown); // Make sure `addr` is not the unknown address

        vm.assume(addr != address(arianeeMessageProxy)); // Make sure `addr` is not the ArianeeMessage proxy address
        vm.assume(addr != arianeeMessageImplAddr); //  Make sure `addr` is not the ArianeeMessage implementation address
        _;
    }

    // Initializer

    function test_initialize() public view {
        assertTrue(arianeeMessageProxy.hasRole(ROLE_ADMIN, admin));
        assertTrue(arianeeMessageProxy.hasRole(ROLE_ARIANEE_STORE, store));
    }

    // Send message

    function test_sendMessage(
        uint256 messageId,
        uint256 tokenId,
        bytes32 imprint,
        address owner,
        address from,
        uint256 rewards
    ) public assumeIsNotKnownOrZeroAddress(owner) assumeIsNotKnownOrZeroAddress(from) {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(owner));
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.isAuthorized.selector), abi.encode(true));

        vm.expectEmit();
        emit MessageSent(owner, from, tokenId, messageId);
        arianeeMessageProxy.sendMessage(messageId, tokenId, imprint, from, rewards);

        Message memory message = arianeeMessageProxy.messages(messageId);
        assertEq(message.imprint, imprint);
        assertEq(message.sender, from);
        assertEq(message.to, owner);
        assertEq(message.tokenId, tokenId);

        assertEq(arianeeMessageProxy.messageLengthByReceiver(owner), 1);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_sendMessage_err_messageAlreadyExist(
        uint256 messageId,
        uint256 tokenId,
        bytes32 imprint,
        address owner,
        address from,
        uint256 rewards
    ) public assumeIsNotKnownOrZeroAddress(owner) assumeIsNotKnownOrZeroAddress(from) {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(owner));
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.isAuthorized.selector), abi.encode(true));

        vm.expectEmit();
        emit MessageSent(owner, from, tokenId, messageId);
        arianeeMessageProxy.sendMessage(messageId, tokenId, imprint, from, rewards);

        vm.expectRevert("ArianeeMessage: Message already exists");
        arianeeMessageProxy.sendMessage(messageId, tokenId, imprint, from, rewards);

        assertEq(arianeeMessageProxy.messageLengthByReceiver(owner), 1);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_sendMessage_err_notAuthorized() public {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(address(0)));
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.isAuthorized.selector), abi.encode(false));

        vm.expectRevert("ArianeeMessage: Not authorized");
        arianeeMessageProxy.sendMessage(uint256(0), uint256(0), bytes32(0), address(0), uint256(0));

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_sendMessage_err_onlyStore() public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeMessageProxy.sendMessage(uint256(0), uint256(0), bytes32(0), address(0), uint256(0));
        vm.stopPrank();
    }

    // Read message

    function test_readMessage(
        uint256 messageId,
        uint256 tokenId,
        bytes32 imprint,
        address owner,
        address from,
        uint256 rewards
    ) public assumeIsNotKnownOrZeroAddress(owner) assumeIsNotKnownOrZeroAddress(from) {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(owner));
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.isAuthorized.selector), abi.encode(true));

        // Send a message first
        arianeeMessageProxy.sendMessage(messageId, tokenId, imprint, from, rewards);

        // Read the message
        vm.expectEmit();
        emit MessageRead(owner, from, messageId);
        uint256 rewardsRes = arianeeMessageProxy.readMessage(messageId, owner);
        assertEq(rewards, rewardsRes);
        assertEq(arianeeMessageProxy.messageLengthByReceiver(owner), 1);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_readMessage_err_notAuthorized(
        uint256 messageId,
        uint256 tokenId,
        bytes32 imprint,
        address owner,
        address from,
        uint256 rewards
    ) public assumeIsNotKnownOrZeroAddress(owner) assumeIsNotKnownOrZeroAddress(from) {
        vm.startPrank(store);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(owner));
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.isAuthorized.selector), abi.encode(true));

        // Send a message first
        arianeeMessageProxy.sendMessage(messageId, tokenId, imprint, from, rewards);

        // Read the message
        vm.expectRevert("ArianeeMessage: Not authorized");
        arianeeMessageProxy.readMessage(messageId, unknown); // `unknown` is not the owner

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_readMessage_err_onlyStore() public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeMessageProxy.readMessage(uint256(0), address(0));
        vm.stopPrank();
    }
}
