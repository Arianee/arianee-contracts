// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import {
    ArianeeStore,
    CreditBought,
    CreditSpended,
    SetAddress,
    NewCreditPrice
} from "@arianee/V0/ArianeeStore/ArianeeStore.sol";
import { ArianeeCreditHistory } from "@arianee/V0/ArianeeStore/ArianeeCreditHistory.sol";
import { ArianeeRewardsHistory } from "@arianee/V0/ArianeeStore/ArianeeRewardsHistory.sol";
import { IArianeeSmartAsset } from "@arianee/V0/Interfaces/IArianeeSmartAsset.sol";
import { IArianeeSmartAssetUpdate } from "@arianee/V0/Interfaces/IArianeeSmartAssetUpdate.sol";
import { IArianeeEvent } from "@arianee/V0/Interfaces/IArianeeEvent.sol";
import { IArianeeMessage } from "@arianee/V0/Interfaces/IArianeeMessage.sol";
import {
    ROLE_ADMIN,
    CREDIT_TYPE_CERTIFICATE,
    CREDIT_TYPE_MESSAGE,
    CREDIT_TYPE_EVENT,
    CREDIT_TYPE_UPDATE
} from "@arianee/V0/Constants.sol";
import { MockERC20 } from "../Mocks/MockERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

contract ArianeeStoreTest is Test {
    address deployer = vm.addr(1);

    address proxyAdmin = vm.addr(2);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(3);
    address smartAsset = vm.addr(4);
    address smartAssetUpdate = vm.addr(5);
    address arianeeEvent = vm.addr(6);
    address arianeeMessage = vm.addr(7);

    address unknown = vm.addr(8);
    address nmpProvider = vm.addr(9);
    address walletProvider = vm.addr(10);
    address protocolInfraAddress = vm.addr(11);
    address arianeeProjectAddress = vm.addr(12);
    address issuer1 = vm.addr(13);
    address user1 = vm.addr(14);

    uint256 ariaUSDExchange = 100_000_000_000_000_000; // 0.01 USD = 0.1 ARIA
    uint256 creditPricesUSD0 = 10; // 1 Credit = 0.1 USD
    uint256 creditPricesUSD1 = 10; // 1 Credit = 0.1 USD
    uint256 creditPricesUSD2 = 10; // 1 Credit = 0.1 USD
    uint256 creditPricesUSD3 = 10; // 1 Credit = 0.1 USD

    uint8 dispatchPercent0 = 10;
    uint8 dispatchPercent1 = 20;
    uint8 dispatchPercent2 = 20;
    uint8 dispatchPercent3 = 40;
    uint8 dispatchPercent4 = 10;

    MockERC20 aria;

    ArianeeStore arianeeStoreProxy;
    address arianeeStoreImplAddr;

    ArianeeCreditHistory arianeeCreditHistoryProxy;
    address arianeeCreditHistoryImplAddr;

    ArianeeRewardsHistory arianeeRewardsHistoryProxy;
    address arianeeRewardsHistoryImplAddr;

    function setUp() public {
        vm.startPrank(deployer);

        // Deploying the Aria token mock
        aria = new MockERC20("Aria", "ARIA");

        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        // We need to precompute the address of the ArianeeStore proxy contract to pass it to the ArianeeCreditHistory and ArianeeRewardsHistory contracts
        address arianeeStoreProxyPreComputedAddr = vm.computeCreateAddress(deployer, 6);

        address arianeeCreditHistoryProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeCreditHistory.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeCreditHistory.initialize, (arianeeStoreProxyPreComputedAddr)),
            opts
        );
        arianeeCreditHistoryProxy = ArianeeCreditHistory(arianeeCreditHistoryProxyAddr);
        arianeeCreditHistoryImplAddr = Upgrades.getImplementationAddress(arianeeCreditHistoryProxyAddr);

        address arianeeRewardsHistoryProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeRewardsHistory.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeCreditHistory.initialize, (arianeeStoreProxyPreComputedAddr)),
            opts
        );
        arianeeRewardsHistoryProxy = ArianeeRewardsHistory(arianeeRewardsHistoryProxyAddr);
        arianeeRewardsHistoryImplAddr = Upgrades.getImplementationAddress(arianeeRewardsHistoryProxyAddr);

        address arianeeStoreProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeStore.sol",
            proxyAdmin,
            abi.encodeCall(
                ArianeeStore.initialize,
                (
                    admin,
                    address(aria),
                    smartAsset,
                    smartAssetUpdate,
                    arianeeEvent,
                    arianeeMessage,
                    arianeeCreditHistoryProxyAddr,
                    arianeeRewardsHistoryProxyAddr,
                    ariaUSDExchange,
                    creditPricesUSD0,
                    creditPricesUSD1,
                    creditPricesUSD2,
                    creditPricesUSD3
                )
            ),
            opts
        );
        arianeeStoreProxy = ArianeeStore(arianeeStoreProxyAddr);
        arianeeStoreImplAddr = Upgrades.getImplementationAddress(arianeeStoreProxyAddr);

        assertEq(
            arianeeStoreProxyPreComputedAddr,
            arianeeStoreProxyAddr,
            "Precomputed ArianeeStore proxy address is not matching the actual proxy address"
        );
        vm.stopPrank();

        vm.startPrank(admin);
        // Setting dispatch percentages per actor
        arianeeStoreProxy.setDispatchPercent(
            dispatchPercent0, dispatchPercent1, dispatchPercent2, dispatchPercent3, dispatchPercent4
        );
        // Settings addresses
        arianeeStoreProxy.setProtocolInfraAddress(protocolInfraAddress);
        arianeeStoreProxy.setArianeeProjectAddress(arianeeProjectAddress);
        vm.stopPrank();
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("Deployer: %s", deployer);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("SmartAsset: %s", smartAsset);
        console.log("SmartAssetUpdate: %s", smartAssetUpdate);
        console.log("ArianeeEvent: %s", arianeeEvent);
        console.log("ArianeeMessage: %s", arianeeMessage);
        console.log("Unknown: %s", unknown);
        console.log("NmpProvider: %s", nmpProvider);
        console.log("WalletProvider: %s", walletProvider);
        console.log("Issuer1: %s", issuer1);
        console.log("User1: %s", user1);
        // Contracts
        console.log("Aria: %s", address(aria));
        console.log("ArianeeStoreProxy: %s", address(arianeeStoreProxy));
        console.log("ArianeeStoreImpl: %s", arianeeStoreImplAddr);
        console.log("ArianeeCreditHistoryProxy: %s", address(arianeeCreditHistoryProxy));
        console.log("ArianeeCreditHistoryImpl: %s", arianeeCreditHistoryImplAddr);
        console.log("ArianeeRewardsHistoryProxy: %s", address(arianeeRewardsHistoryProxy));
        console.log("ArianeeRewardsHistoryImpl: %s", arianeeRewardsHistoryImplAddr);
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
        vm.assume(addr != smartAssetUpdate); // Make sure `addr` is not the smartAssetUpdate address
        vm.assume(addr != arianeeEvent); // Make sure `addr` is not the arianeeEvent address
        vm.assume(addr != arianeeMessage); // Make sure `addr` is not the arianeeMessage address

        vm.assume(addr != unknown); // Make sure `addr` is not the unknown address
        vm.assume(addr != nmpProvider); // Make sure `addr` is not the nmpProvider address
        vm.assume(addr != walletProvider); // Make sure `addr` is not the walletProvider address
        vm.assume(addr != issuer1); // Make sure `addr` is not the issuer1 address

        vm.assume(addr != address(aria)); // Make sure `addr` is not the Aria token address
        vm.assume(addr != address(arianeeStoreProxy)); // Make sure `addr` is not the ArianeeStore proxy address
        vm.assume(addr != arianeeStoreImplAddr); // Make sure `addr` is not the ArianeeStore implementation address
        vm.assume(addr != address(arianeeCreditHistoryProxy)); // Make sure `addr` is not the ArianeeCreditHistory proxy address
        vm.assume(addr != arianeeCreditHistoryImplAddr); // Make sure `addr` is not the ArianeeCreditHistory implementation address
        vm.assume(addr != address(arianeeRewardsHistoryProxy)); // Make sure `addr` is not the ArianeeRewardsHistory proxy address
        vm.assume(addr != arianeeRewardsHistoryImplAddr); // Make sure `addr` is not the ArianeeRewardsHistory implementation address
        _;
    }

    modifier buyCreditFor(address addr, uint256 creditType) {
        uint256 quantity = 1;

        vm.startPrank(unknown);
        uint256 requiredAria = arianeeStoreProxy.getCreditPrice(creditType) * quantity;
        aria.mint(unknown, requiredAria); // The account `unknown` will pay for the credit on behalf of the `addr`
        aria.approve(address(arianeeStoreProxy), requiredAria);

        vm.expectEmit();
        emit IERC20.Transfer(unknown, address(arianeeStoreProxy), requiredAria);
        vm.expectEmit();
        emit CreditBought(unknown, addr, creditType, quantity);
        arianeeStoreProxy.buyCredit(creditType, quantity, addr);

        assertEq(arianeeCreditHistoryProxy.balanceOf(addr, creditType), quantity);
        vm.stopPrank();
        _;
    }

    // Initializer

    function test_initialize() public view {
        assertFalse(arianeeStoreProxy.paused());
        assertEq(arianeeStoreProxy.creditPriceUSD(0), creditPricesUSD0);
        assertEq(arianeeStoreProxy.creditPriceUSD(1), creditPricesUSD1);
        assertEq(arianeeStoreProxy.creditPriceUSD(2), creditPricesUSD2);
        assertEq(arianeeStoreProxy.creditPriceUSD(3), creditPricesUSD3);
        assertEq(arianeeStoreProxy.getCreditPrice(0), creditPricesUSD0 * ariaUSDExchange);
        assertEq(arianeeStoreProxy.getCreditPrice(1), creditPricesUSD1 * ariaUSDExchange);
        assertEq(arianeeStoreProxy.getCreditPrice(2), creditPricesUSD2 * ariaUSDExchange);
        assertEq(arianeeStoreProxy.getCreditPrice(3), creditPricesUSD3 * ariaUSDExchange);
    }

    // Dispatch percentages

    function test_percentOfDispatch() public view {
        assertEq(arianeeStoreProxy.percentOfDispatch(0), dispatchPercent0);
        assertEq(arianeeStoreProxy.percentOfDispatch(1), dispatchPercent1);
        assertEq(arianeeStoreProxy.percentOfDispatch(2), dispatchPercent2);
        assertEq(arianeeStoreProxy.percentOfDispatch(3), dispatchPercent3);
        assertEq(arianeeStoreProxy.percentOfDispatch(4), dispatchPercent4);
    }

    // Buy credit

    function test_buyCredit(uint256 creditType, uint256 quantity) public {
        creditType = bound(creditType, CREDIT_TYPE_CERTIFICATE, CREDIT_TYPE_UPDATE); // Bound to the available credit types
        quantity = bound(quantity, 1, type(uint256).max / arianeeStoreProxy.getCreditPrice(creditType)); // Prevent overflow

        vm.startPrank(unknown);
        uint256 requiredAria = arianeeStoreProxy.getCreditPrice(creditType) * quantity;
        aria.mint(unknown, requiredAria); // The account `unknown` will pay for the credit on behalf of the issuer
        aria.approve(address(arianeeStoreProxy), requiredAria);

        vm.expectEmit();
        emit IERC20.Transfer(unknown, address(arianeeStoreProxy), requiredAria);
        vm.expectEmit();
        emit CreditBought(unknown, issuer1, creditType, quantity);
        arianeeStoreProxy.buyCredit(creditType, quantity, issuer1);

        assertEq(arianeeCreditHistoryProxy.balanceOf(issuer1, creditType), quantity);
        vm.stopPrank();
    }

    function test_buyCredit_err_transferFailed(uint256 creditType, uint256 quantity) public {
        creditType = bound(creditType, CREDIT_TYPE_CERTIFICATE, CREDIT_TYPE_UPDATE); // Bound to the available credit types
        quantity = bound(quantity, 1, type(uint256).max / arianeeStoreProxy.getCreditPrice(creditType)); // Prevent overflow

        vm.startPrank(unknown);
        uint256 requiredAria = (arianeeStoreProxy.getCreditPrice(creditType) * quantity);
        uint256 mintQty = requiredAria - 1;
        aria.mint(unknown, mintQty); // The account `issuer1` will not have enough Aria to pay for the credit
        aria.approve(address(arianeeStoreProxy), requiredAria);

        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, unknown, mintQty, requiredAria)
        );
        arianeeStoreProxy.buyCredit(creditType, quantity, issuer1);

        assertEq(arianeeCreditHistoryProxy.balanceOf(issuer1, creditType), 0);
        vm.stopPrank();
    }

    // Spend credit (through ArianeeCreditHistory)

    function test_consumeCredits_err_notEnoughCredit(uint256 creditType, uint256 quantity) public {
        creditType = bound(creditType, CREDIT_TYPE_CERTIFICATE, CREDIT_TYPE_UPDATE); // Bound to the available credit types
        quantity = bound(quantity, 1, type(uint256).max - 1); // Prevent overflow

        vm.startPrank(address(arianeeStoreProxy));
        // Add some credit history to the issuer
        uint256 creditPrice = 1;
        arianeeCreditHistoryProxy.addCreditHistory(issuer1, creditPrice, quantity, creditType);

        // Try to consume more credit than the issuer has
        vm.expectRevert("ArianeeCreditHistory: Not enough credit");
        arianeeCreditHistoryProxy.consumeCredits(issuer1, creditType, quantity + 1);
        vm.stopPrank();
    }

    // Reserve SmartAsset

    function test_reserveToken(
        address to
    ) public assumeIsNotKnownOrZeroAddress(to) {
        vm.startPrank(issuer1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.reserveToken.selector), abi.encode());
        uint256 tokenId = 1;
        arianeeStoreProxy.reserveToken(tokenId, to);
        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Hydrate SmartAsset

    function test_hydrateToken() public buyCreditFor(issuer1, CREDIT_TYPE_CERTIFICATE) {
        vm.startPrank(issuer1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), abi.encode(issuer1));
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.hydrateToken.selector), abi.encode());

        vm.expectEmit();
        emit CreditSpended(CREDIT_TYPE_CERTIFICATE, 1);
        uint256 tokenId = 1;
        arianeeStoreProxy.hydrateToken(tokenId, bytes32(0), "", address(0), uint256(0), false, nmpProvider, false);

        // Assert credit history logic has been updated
        assertEq(arianeeCreditHistoryProxy.balanceOf(issuer1, CREDIT_TYPE_CERTIFICATE), 0);
        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(nmpProvider) > 0);
        assertTrue(aria.balanceOf(protocolInfraAddress) > 0);
        assertTrue(aria.balanceOf(arianeeProjectAddress) > 0);
        // Assert rewards history logic has been updated
        assertTrue(arianeeRewardsHistoryProxy.getTokenReward(tokenId) > 0);
        assertEq(arianeeRewardsHistoryProxy.getTokenNmpProvider(tokenId), nmpProvider);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_hydrateToken_with_reserveToken() public buyCreditFor(issuer1, CREDIT_TYPE_CERTIFICATE) {
        vm.startPrank(issuer1);
        vm.mockCallRevert(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.ownerOf.selector), "MOCK_CALL_REVERT");
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.hydrateToken.selector), abi.encode());
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.reserveToken.selector), abi.encode());

        vm.expectEmit();
        emit CreditSpended(CREDIT_TYPE_CERTIFICATE, 1);
        uint256 tokenId = 1;
        arianeeStoreProxy.hydrateToken(tokenId, bytes32(0), "", address(0), uint256(0), false, nmpProvider, false);

        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(nmpProvider) > 0);
        assertTrue(aria.balanceOf(protocolInfraAddress) > 0);
        assertTrue(aria.balanceOf(arianeeProjectAddress) > 0);
        // Assert rewards history logic has been updated
        assertTrue(arianeeRewardsHistoryProxy.getTokenReward(tokenId) > 0);
        assertEq(arianeeRewardsHistoryProxy.getTokenNmpProvider(tokenId), nmpProvider);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Request SmartAsset

    function test_requestToken() public {
        vm.startPrank(user1);
        vm.mockCall(smartAsset, abi.encodeWithSelector(IArianeeSmartAsset.requestToken.selector), abi.encode());
        uint256 tokenId = 1;
        arianeeStoreProxy.requestToken(tokenId, bytes32(0), false, walletProvider, new bytes(0), address(0));

        // Assert rewards history logic has been updated
        assertEq(arianeeRewardsHistoryProxy.getTokenWalletProvider(tokenId), walletProvider);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Update SmartAsset

    function test_updateSmartAsset() public buyCreditFor(issuer1, CREDIT_TYPE_UPDATE) {
        vm.startPrank(issuer1);
        vm.mockCall(
            smartAssetUpdate, abi.encodeWithSelector(IArianeeSmartAssetUpdate.updateSmartAsset.selector), abi.encode()
        );

        vm.expectEmit();
        emit CreditSpended(CREDIT_TYPE_UPDATE, 1);
        uint256 tokenId = 1;
        arianeeStoreProxy.updateSmartAsset(tokenId, bytes32(0), nmpProvider);

        // Assert credit history logic has been updated
        assertEq(arianeeCreditHistoryProxy.balanceOf(issuer1, CREDIT_TYPE_UPDATE), 0);
        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(nmpProvider) > 0);
        assertTrue(aria.balanceOf(protocolInfraAddress) > 0);
        assertTrue(aria.balanceOf(arianeeProjectAddress) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Read SmartAsset update

    function test_readUpdateSmartAsset() public {
        vm.startPrank(user1);
        uint256 rewards = 100 ^ 18;
        aria.mint(address(arianeeStoreProxy), rewards);

        vm.mockCall(
            smartAssetUpdate,
            abi.encodeWithSelector(IArianeeSmartAssetUpdate.readUpdateSmartAsset.selector),
            abi.encode(rewards)
        );
        uint256 tokenId = 1;
        arianeeStoreProxy.readUpdateSmartAsset(tokenId, walletProvider);

        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(walletProvider) > 0);
        assertTrue(aria.balanceOf(user1) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Create event

    function test_createEvent() public buyCreditFor(issuer1, CREDIT_TYPE_EVENT) {
        vm.startPrank(issuer1);
        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeEvent.create.selector), abi.encode());

        vm.expectEmit();
        emit CreditSpended(CREDIT_TYPE_EVENT, 1);
        uint256 eventId = 1;
        uint256 tokenId = 1;
        arianeeStoreProxy.createEvent(eventId, tokenId, bytes32(0), "", nmpProvider);

        // Assert credit history logic has been updated
        assertEq(arianeeCreditHistoryProxy.balanceOf(issuer1, CREDIT_TYPE_EVENT), 0);
        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(nmpProvider) > 0);
        assertTrue(aria.balanceOf(protocolInfraAddress) > 0);
        assertTrue(aria.balanceOf(arianeeProjectAddress) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Accept event

    function test_acceptEvent() public {
        vm.startPrank(user1);
        uint256 rewards = 100 ^ 18;
        aria.mint(address(arianeeStoreProxy), rewards);

        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeEvent.accept.selector), abi.encode(rewards));
        uint256 eventId = 1;
        arianeeStoreProxy.acceptEvent(eventId, walletProvider);

        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(walletProvider) > 0);
        assertTrue(aria.balanceOf(user1) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Refuse event

    function test_refuseEvent() public {
        vm.startPrank(user1);
        uint256 rewards = 100 ^ 18;
        aria.mint(address(arianeeStoreProxy), rewards);

        vm.mockCall(arianeeEvent, abi.encodeWithSelector(IArianeeEvent.refuse.selector), abi.encode(rewards));
        uint256 eventId = 1;
        arianeeStoreProxy.refuseEvent(eventId, walletProvider);

        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(walletProvider) > 0);
        assertTrue(aria.balanceOf(user1) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Create message

    function test_createMessage() public buyCreditFor(issuer1, CREDIT_TYPE_MESSAGE) {
        vm.startPrank(issuer1);
        vm.mockCall(arianeeMessage, abi.encodeWithSelector(IArianeeMessage.sendMessage.selector), abi.encode());

        vm.expectEmit();
        emit CreditSpended(CREDIT_TYPE_MESSAGE, 1);
        uint256 messageId = 1;
        uint256 tokenId = 1;
        arianeeStoreProxy.createMessage(messageId, tokenId, bytes32(0), nmpProvider);

        // Assert credit history logic has been updated
        assertEq(arianeeCreditHistoryProxy.balanceOf(issuer1, CREDIT_TYPE_MESSAGE), 0);
        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(nmpProvider) > 0);
        assertTrue(aria.balanceOf(protocolInfraAddress) > 0);
        assertTrue(aria.balanceOf(arianeeProjectAddress) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Read message

    function test_readMessage() public {
        vm.startPrank(user1);
        uint256 rewards = 100 ^ 18;
        aria.mint(address(arianeeStoreProxy), rewards);

        vm.mockCall(arianeeMessage, abi.encodeWithSelector(IArianeeMessage.readMessage.selector), abi.encode(rewards));
        uint256 messageId = 1;
        arianeeStoreProxy.readMessage(messageId, walletProvider);

        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(walletProvider) > 0);
        assertTrue(aria.balanceOf(user1) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    // Admin functions

    function test_setAuthorizedExchangeAddress(
        address newAuthorizedExchangeAddress
    ) public assumeIsNotKnownOrZeroAddress(newAuthorizedExchangeAddress) {
        vm.startPrank(admin);
        vm.expectEmit();
        emit SetAddress("authorizedExchange", newAuthorizedExchangeAddress);
        arianeeStoreProxy.setAuthorizedExchangeAddress(newAuthorizedExchangeAddress);
        vm.stopPrank();
    }

    function test_setAuthorizedExchangeAddress_err_onlyAdmin(
        address newAuthorizedExchangeAddress
    ) public assumeIsNotKnownOrZeroAddress(newAuthorizedExchangeAddress) {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeStoreProxy.setAuthorizedExchangeAddress(newAuthorizedExchangeAddress);
        vm.stopPrank();
    }

    function test_setProtocolInfraAddress(
        address newProtocolInfraAddress
    ) public assumeIsNotKnownOrZeroAddress(newProtocolInfraAddress) {
        vm.startPrank(admin);
        vm.expectEmit();
        emit SetAddress("protocolInfra", newProtocolInfraAddress);
        arianeeStoreProxy.setProtocolInfraAddress(newProtocolInfraAddress);
        vm.stopPrank();
    }

    function test_setProtocolInfraAddress_err_onlyAdmin(
        address newProtocolInfraAddress
    ) public assumeIsNotKnownOrZeroAddress(newProtocolInfraAddress) {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeStoreProxy.setProtocolInfraAddress(newProtocolInfraAddress);
        vm.stopPrank();
    }

    function test_setArianeeProjectAddress(
        address newArianeeProjectAddress
    ) public assumeIsNotKnownOrZeroAddress(newArianeeProjectAddress) {
        vm.startPrank(admin);
        vm.expectEmit();
        emit SetAddress("arianeeProject", newArianeeProjectAddress);
        arianeeStoreProxy.setArianeeProjectAddress(newArianeeProjectAddress);
        vm.stopPrank();
    }

    function test_setArianeeProjectAddress_err_onlyAdmin(
        address newArianeeProjectAddress
    ) public assumeIsNotKnownOrZeroAddress(newArianeeProjectAddress) {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeStoreProxy.setArianeeProjectAddress(newArianeeProjectAddress);
        vm.stopPrank();
    }

    function test_setCreditPrice(uint256 creditType, uint256 price) public {
        creditType = bound(creditType, CREDIT_TYPE_CERTIFICATE, CREDIT_TYPE_UPDATE); // Bound to the available credit types
        price = bound(price, 1, 10_000); // Bound to a high but realistic price range

        vm.startPrank(admin);
        vm.expectEmit();
        emit NewCreditPrice(creditType, price);
        arianeeStoreProxy.setCreditPrice(creditType, price);
        vm.stopPrank();
    }

    function test_setCreditPrice_err_onlyAdmin(uint256 creditType, uint256 price) public {
        creditType = bound(creditType, CREDIT_TYPE_CERTIFICATE, CREDIT_TYPE_UPDATE); // Bound to the available credit types
        price = bound(price, 1, 10_000); // Bound to a high but realistic price range

        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeStoreProxy.setCreditPrice(creditType, price);
        vm.stopPrank();
    }

    function test_setDispatchPercent_err_onlyAdmin() public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeStoreProxy.setDispatchPercent(0, 0, 0, 0, 0);
        vm.stopPrank();
    }

    function test_withdrawAll() public {
        address withdrawAddress = vm.addr(uint256(keccak256(abi.encodePacked("test_withdrawAll"))));

        vm.startPrank(admin);
        uint256 ethQty = 1000 ether;
        vm.deal(address(arianeeStoreProxy), ethQty);
        uint256 ariaQty = 10_000 ether;
        aria.mint(address(arianeeStoreProxy), ariaQty);

        assertEq(address(arianeeStoreProxy).balance, ethQty);
        assertEq(aria.balanceOf(address(arianeeStoreProxy)), ariaQty);

        address[] memory tokenAddresses = new address[](1);
        tokenAddresses[0] = address(aria);
        arianeeStoreProxy.withdrawAll(withdrawAddress, tokenAddresses);

        assertEq(withdrawAddress.balance, ethQty);
        assertEq(aria.balanceOf(withdrawAddress), ariaQty);
        vm.stopPrank();
    }

    function test_withdrawAll_err_onlyAdmin() public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ADMIN)
        );
        arianeeStoreProxy.withdrawAll(address(0), new address[](0));
        vm.stopPrank();
    }

    // Dispatch rewards at first transfer

    function test_dispatchRewardsAtFirstTransfer(
        uint256 tokenId,
        address newOwner
    ) public assumeIsNotKnownOrZeroAddress(newOwner) {
        vm.startPrank(address(arianeeStoreProxy));
        uint256 rewards = 100 ^ 18;
        aria.mint(address(arianeeStoreProxy), rewards);

        arianeeRewardsHistoryProxy.setTokenReward(tokenId, rewards);
        arianeeRewardsHistoryProxy.setTokenNmpProvider(tokenId, nmpProvider);
        arianeeRewardsHistoryProxy.setTokenWalletProvider(tokenId, walletProvider);
        vm.stopPrank();

        vm.startPrank(smartAsset);
        arianeeStoreProxy.dispatchRewardsAtFirstTransfer(tokenId, newOwner);

        // Assert token rewards have been reset
        assertEq(arianeeRewardsHistoryProxy.getTokenReward(tokenId), 0);
        // Assert rewards have been distributed
        assertTrue(aria.balanceOf(walletProvider) > 0);
        assertTrue(aria.balanceOf(newOwner) > 0);

        vm.clearMockedCalls();
        vm.stopPrank();
    }

    function test_dispatchRewardsAtFirstTransfer_err_onlySmartAsset() public {
        vm.startPrank(unknown);
        vm.expectRevert("ArianeeStore: This function can only be called by the ArianeeSmartAsset contract");
        arianeeStoreProxy.dispatchRewardsAtFirstTransfer(1, address(0));
        vm.stopPrank();
    }
}
