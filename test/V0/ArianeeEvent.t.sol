// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import {
    ArianeeEvent,
    EventCreated,
    EventAccepted,
    EventRefused,
    EventDestroyed,
    DestroyRequestUpdated,
    EventDestroyDelayUpdated
} from "@arianee/V0/ArianeeEvent.sol";
import { IArianeeSmartAsset } from "@arianee/V0/Interfaces/IArianeeSmartAsset.sol";
import { IArianeeStore } from "@arianee/V0/Interfaces/IArianeeStore.sol";
import { IArianeeWhitelist } from "@arianee/V0/Interfaces/IArianeeWhitelist.sol";
import { ROLE_ADMIN, ROLE_ARIANEE_STORE, EVENT_DESTROY_DELAY } from "@arianee/V0/Constants.sol";

contract ArianeeEventTest is Test {
    address proxyAdmin = vm.addr(1);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(2);
    address smartAsset = vm.addr(3);
    address store = vm.addr(4);
    address whitelist = vm.addr(5);

    address unknown = vm.addr(6);

    address arianeeEventImplAddr;
    ArianeeEvent arianeeEventProxy;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeEventProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeEvent.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeEvent.initialize, (admin, smartAsset, store, whitelist)),
            opts
        );
        arianeeEventProxy = ArianeeEvent(arianeeEventProxyAddr);
        arianeeEventImplAddr = Upgrades.getImplementationAddress(arianeeEventProxyAddr);

        arianeeEventProxy.grantRole(ROLE_ARIANEE_STORE, store);
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
        console.log("ArianeeEventProxy: %s", address(arianeeEventProxy));
        console.log("ArianeeEventImpl: %s", arianeeEventImplAddr);
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

        vm.assume(addr != address(arianeeEventProxy)); // Make sure `addr` is not the ArianeeEvent proxy address
        vm.assume(addr != arianeeEventImplAddr); //  Make sure `addr` is not the ArianeeEvent implementation address
        _;
    }

    // Initializer

    function test_initialize() public view {
        assertFalse(arianeeEventProxy.paused());
    }

    // Create event

    function test_createEvent(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider
    ) public assumeIsNotKnownOrZeroAddress(provider) {
        vm.startPrank(store);
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        vm.expectEmit();
        emit EventCreated(tokenId, eventId, imprint, uri, provider);
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);

        (string memory eventUri, bytes32 eventImprint, address eventProvider, uint256 eventDestroyLimitTimestamp) =
            arianeeEventProxy.getEvent(eventId);
        assertEq(eventUri, uri);
        assertEq(eventImprint, imprint);
        assertEq(eventProvider, provider);
        assertEq(eventDestroyLimitTimestamp, block.timestamp + EVENT_DESTROY_DELAY); // Should be the default value

        assertEq(arianeeEventProxy.pendingEventsLength(tokenId), 1);
        assertEq(arianeeEventProxy.eventsLength(tokenId), 0);
        assertEq(arianeeEventProxy.eventIdToToken(eventId), tokenId);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_createEvent_err_eventAlreadyExist(
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider
    ) public assumeIsNotKnownOrZeroAddress(provider) {
        vm.startPrank(store);
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );

        uint256 eventId = 123;
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);

        vm.expectRevert("ArianeeEvent: Event already exists");
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_createEvent_err_tokenNotExist(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider
    ) public {
        vm.startPrank(store);
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(uint256(0))
        );
        vm.expectRevert("ArianeeEvent: SmartAsset does not exist");
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_createEvent_err_onlyStore(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        vm.stopPrank();
    }

    // Accept event

    function test_acceptEvent(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);

        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        vm.expectEmit();
        emit EventAccepted(eventId, sender);
        uint256 rewardsRes = arianeeEventProxy.accept(eventId, sender);
        assertEq(rewards, rewardsRes);

        assertEq(arianeeEventProxy.pendingEventsLength(tokenId), 0);
        assertEq(arianeeEventProxy.eventsLength(tokenId), 1);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_acceptEvent_err_notPending(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);

        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);

        // Try to accept the same event again
        vm.expectRevert("ArianeeEvent: Event is not pending");
        arianeeEventProxy.accept(eventId, sender);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_acceptEvent_twice_err_notPending(
        uint256 eventId,
        uint256 eventId2,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.assume(eventId != eventId2); // Make sure `eventId` and `eventId2` are different

        vm.startPrank(store);
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        // Create an event first
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Create another event
        arianeeEventProxy.create(eventId2, tokenId, imprint, uri, rewards, provider);

        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        // Accept the first event
        arianeeEventProxy.accept(eventId, sender);

        // Try to accept the same event again
        vm.expectRevert("ArianeeEvent: Event is not pending");
        arianeeEventProxy.accept(eventId, sender);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_acceptEvent_err_isOperator(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);

        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(false)
        ); // Mock canOperate to return false
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector, tokenId), abi.encode(false)
        ); // Mock issuerOf to return false
        vm.expectRevert("ArianeeEvent: Not an operator nor the issuer");
        arianeeEventProxy.accept(eventId, sender);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_acceptEvent_err_onlyStore(uint256 eventId, address sender) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();
    }

    // Refuse event

    function test_refuseEvent(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);

        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.expectEmit();
        emit EventDestroyed(eventId);
        emit EventRefused(eventId, sender);
        uint256 missedRewardsRes = arianeeEventProxy.refuse(eventId, sender);
        assertEq(rewards, missedRewardsRes);

        assertEq(arianeeEventProxy.pendingEventsLength(tokenId), 0);
        assertEq(arianeeEventProxy.eventsLength(tokenId), 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_refuseEvent_isOperator(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);

        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(false)
        ); // Mock canOperate to return false
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector, tokenId), abi.encode(false)
        ); // Mock issuerOf to return false
        vm.expectRevert("ArianeeEvent: Not an operator nor the issuer");
        arianeeEventProxy.refuse(eventId, sender);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_refuseEvent_err_onlyStore(uint256 eventId, address sender) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeEventProxy.refuse(eventId, sender);
        vm.stopPrank();
    }

    // Destroy event

    function test_destroyEvent(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(provider);
        vm.expectEmit();
        emit EventDestroyed(eventId);
        arianeeEventProxy.destroy(eventId);

        vm.expectRevert("ArianeeEvent: Event does not exist");
        arianeeEventProxy.getEvent(eventId);

        assertEq(arianeeEventProxy.pendingEventsLength(tokenId), 0);
        assertEq(arianeeEventProxy.eventsLength(tokenId), 0);
        assertEq(arianeeEventProxy.eventIdToToken(eventId), 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_destroyEvent_err_isProviderOrIssuer(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector, tokenId),
            abi.encode(address(0)) // Mock issuerOf to return the zero address otherwise the call will revert
        );
        vm.expectRevert("ArianeeEvent: Not the provider nor the issuer");
        arianeeEventProxy.destroy(eventId);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_destroyEvent_err_destroyLimitReached(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(provider);
        vm.warp(block.timestamp + EVENT_DESTROY_DELAY); // Warp the VM to the destroy limit timestamp
        vm.expectRevert("ArianeeEvent: Destroy limit timestamp reached");
        arianeeEventProxy.destroy(eventId);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_destroyEvent_err_stillPending(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Doesn't accept nor refuse the event...
        vm.stopPrank();

        vm.startPrank(provider);
        vm.expectRevert("ArianeeEvent: Event is still pending");
        arianeeEventProxy.destroy(eventId);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Destroy request

    function test_updateDestroyRequest_asProvider(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender,
        bool active
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(provider);
        vm.expectEmit();
        emit DestroyRequestUpdated(eventId, active);
        arianeeEventProxy.updateDestroyRequest(eventId, active);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_updateDestroyRequest_asIssuer(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address issuer,
        address sender,
        bool active
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(issuer);
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector, tokenId), abi.encode(issuer)
        );
        vm.expectEmit();
        emit DestroyRequestUpdated(eventId, active);
        arianeeEventProxy.updateDestroyRequest(eventId, active);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_updateDestroyRequest_err_isProviderOrIssuer(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender,
        bool active
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(unknown);
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.issuerOf.selector, tokenId),
            abi.encode(address(0)) // Mock issuerOf to return the zero address otherwise the call will revert
        );
        vm.expectRevert("ArianeeEvent: Not the provider nor the issuer");
        arianeeEventProxy.updateDestroyRequest(eventId, active);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_updateDestroyRequest_err_stillPending(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender,
        bool active
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        // Doesn't accept nor refuse the event...
        vm.stopPrank();

        vm.startPrank(provider);
        vm.expectRevert("ArianeeEvent: Event is still pending");
        arianeeEventProxy.updateDestroyRequest(eventId, active);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_validDestroyRequest(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(provider);
        // Set an active destroy request
        bool active = true;
        arianeeEventProxy.updateDestroyRequest(eventId, active);
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectEmit();
        emit EventDestroyed(eventId);
        arianeeEventProxy.validDestroyRequest(eventId);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_validDestroyRequest_err_notActive(
        uint256 eventId,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Accept the event
        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        arianeeEventProxy.accept(eventId, sender);
        vm.stopPrank();

        vm.startPrank(provider);
        // Set an inactive destroy request (same behavior if we do nothing, but let's be explicit)
        bool active = false;
        arianeeEventProxy.updateDestroyRequest(eventId, active);
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectRevert("ArianeeEvent: No active destroy request for this event");
        arianeeEventProxy.validDestroyRequest(eventId);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_validDestroyRequest_err_onlyAdmin(
        uint256 eventId
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeEventProxy.validDestroyRequest(eventId);
        vm.stopPrank();
    }

    // Update destroy delay

    function test_updateEventDestroyDelay(
        uint256 newEventDestroyDelay
    ) public {
        vm.startPrank(admin);
        vm.expectEmit();
        emit EventDestroyDelayUpdated(newEventDestroyDelay);
        arianeeEventProxy.updateEventDestroyDelay(newEventDestroyDelay);
        vm.stopPrank();
    }

    function test_updateEventDestroyDelay_err_onlyAdmin(
        uint256 newEventDestroyDelay
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeEventProxy.updateEventDestroyDelay(newEventDestroyDelay);
        vm.stopPrank();
    }

    // Set ArianeeStore address

    function test_setStoreAddress(
        address newStoreAddr
    ) public {
        vm.startPrank(admin);
        arianeeEventProxy.setStoreAddress(newStoreAddr);
        vm.stopPrank();
    }

    function test_setStoreAddress_err_onlyAdmin(
        address newStoreAddr
    ) public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeEventProxy.setStoreAddress(newStoreAddr);
        vm.stopPrank();
    }

    // Is pending

    function test_isPending(
        uint256 eventId,
        uint256 eventId2,
        uint256 tokenId,
        bytes32 imprint,
        string calldata uri,
        uint256 rewards,
        address provider,
        address sender
    ) public assumeIsNotKnownOrZeroAddress(provider) assumeIsNotKnownOrZeroAddress(sender) {
        vm.assume(eventId != eventId2); // Make sure `eventId` and `eventId2` are different

        vm.startPrank(store);
        // Create an event first
        vm.mockCall(
            smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.tokenCreation.selector), abi.encode(block.timestamp)
        );
        arianeeEventProxy.create(eventId, tokenId, imprint, uri, rewards, provider);
        // Create another event
        arianeeEventProxy.create(eventId2, tokenId, imprint, uri, rewards, provider);

        assertEq(arianeeEventProxy.pendingEventsLength(tokenId), 2);
        assertEq(arianeeEventProxy.eventsLength(tokenId), 0);

        vm.mockCall(
            smartAsset,
            abi.encodeWithSelector(IArianeeSmartAsset.canOperate.selector, tokenId, sender),
            abi.encode(true)
        );
        vm.mockCall(whitelist, abi.encodeWithSelector(IArianeeWhitelist.addWhitelistedAddress.selector), abi.encode());
        // Accept the first event
        arianeeEventProxy.accept(eventId, sender);
        assertEq(arianeeEventProxy.pendingEventsLength(tokenId), 1);
        assertEq(arianeeEventProxy.eventsLength(tokenId), 1);
        assertFalse(arianeeEventProxy.isPending(eventId));
        assertTrue(arianeeEventProxy.isPending(eventId2));

        // Accept the second event
        arianeeEventProxy.accept(eventId2, sender);
        assertEq(arianeeEventProxy.pendingEventsLength(tokenId), 0);
        assertEq(arianeeEventProxy.eventsLength(tokenId), 2);
        assertFalse(arianeeEventProxy.isPending(eventId2));
        assertFalse(arianeeEventProxy.isPending(eventId));

        vm.clearMockedCalls();
        vm.stopPrank();
    }
}
