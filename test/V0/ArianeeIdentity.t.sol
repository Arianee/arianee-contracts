// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import {
    ArianeeIdentity,
    AddressApprovedAdded,
    URIUpdated,
    URIValidate,
    IdentityCompromised,
    SetAddress
} from "@arianee/V0/ArianeeIdentity.sol";

contract ArianeeIdentityTest is Test {
    address proxyAdmin = vm.addr(1);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(2);
    address bouncer = vm.addr(3);

    address unknown = vm.addr(4);
    address user1 = vm.addr(6);

    ArianeeIdentity arianeeIdentityProxy;
    address arianeeIdentityImplAddr;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeIdentityProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeIdentity.sol", proxyAdmin, abi.encodeCall(ArianeeIdentity.initialize, (bouncer, admin)), opts
        );

        arianeeIdentityProxy = ArianeeIdentity(arianeeIdentityProxyAddr);
        arianeeIdentityImplAddr = Upgrades.getImplementationAddress(arianeeIdentityProxyAddr);
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("Bouncer: %s", bouncer);
        console.log("Unknown: %s", unknown);
        console.log("User1: %s", user1);
    }

    modifier assumeIsNotKnownAddress(
        address addr
    ) {
        vm.assume(addr != address(0)); // Make sure `addr` is not the zero address
        vm.assume(addr != msg.sender); // Make sure `addr` is not the default address

        vm.assume(addr != proxyAdmin); // Make sure `addr` is not the proxy admin address
        vm.assume(addr != admin); // Make sure `addr` is not the admin address

        vm.assume(addr != forwarder); // Make sure `addr` is not the forwarder address
        vm.assume(addr != bouncer); // Make sure `addr` is not the bouncer address

        vm.assume(addr != unknown); // Make sure `addr` is not the unknown address
        vm.assume(addr != user1); // Make sure `addr` is not the first user address
        _;
    }

    function test_initialize() public view {
        assertEq(arianeeIdentityProxy.owner(), admin, "Owner not initialized");
    }

    function test_addAddressToApprovedList(
        address _newIdentity
    ) public assumeIsNotKnownAddress(_newIdentity) {
        vm.startPrank(bouncer);

        bytes3 addressId = arianeeIdentityProxy.addAddressToApprovedList(_newIdentity);

        assertEq(arianeeIdentityProxy.addressIsApproved(_newIdentity), true, "Address not added to approved list");

        assertEq(arianeeIdentityProxy.addressFromId(addressId), _newIdentity, "Short ID does not map to the address");
        vm.stopPrank();
    }

    function test_failUnauthorized_addAddressToApprovedList(address _newIdentity) public assumeIsNotKnownAddress(_newIdentity) {
        vm.startPrank(admin);

        vm.expectRevert();
        arianeeIdentityProxy.addAddressToApprovedList(_newIdentity);

        vm.stopPrank();
    }

    function test_removeAddressFromApprovedList(address _identity) public assumeIsNotKnownAddress(_identity) {
        vm.startPrank(bouncer);

        arianeeIdentityProxy.addAddressToApprovedList(_identity);

        assertEq(arianeeIdentityProxy.addressIsApproved(_identity), true, "Address not added to approved list");

        arianeeIdentityProxy.removeAddressFromApprovedList(_identity);

        assertEq(arianeeIdentityProxy.addressIsApproved(_identity), false, "Address not removed from approved list");
        vm.stopPrank();
    }

    function test_unauthorized_removeAddressFromApprovedList(address _identity) public assumeIsNotKnownAddress(_identity) {
        vm.startPrank(admin);

        vm.expectRevert();
        arianeeIdentityProxy.removeAddressFromApprovedList(_identity);

        vm.stopPrank();
    }

    function test_updateInformations(string calldata _uri, bytes32 _imprint, address _newIdentity) public assumeIsNotKnownAddress(_newIdentity) {
        vm.startPrank(bouncer);
        arianeeIdentityProxy.addAddressToApprovedList(_newIdentity);
        vm.stopPrank();

        vm.startPrank(_newIdentity);

        vm.expectEmit();
        emit URIUpdated(_newIdentity, _uri, _imprint);
        arianeeIdentityProxy.updateInformations(_uri, _imprint);

        // Assertions
        string memory waitingUri = arianeeIdentityProxy.waitingURI(_newIdentity);
        assertEq(waitingUri, _uri, "Waiting URI not updated correctly");

        bytes32 waitingImprint = arianeeIdentityProxy.waitingImprint(_newIdentity);
        assertEq(waitingImprint, _imprint, "Waiting imprint not updated correctly");

        vm.stopPrank();

        // Test Revert Scenarios
        // Ensure non-approved address cannot call the function
        vm.startPrank(address(0x9999));
        vm.expectRevert();
        arianeeIdentityProxy.updateInformations("https://fake-uri.com", keccak256("invalid"));
        vm.stopPrank();
    }

    function test_validateInformations(string calldata _uriToValidate, bytes32 _imprintToValidate, address _newIdentity) public assumeIsNotKnownAddress(_newIdentity) {
        vm.startPrank(bouncer);

        arianeeIdentityProxy.addAddressToApprovedList(_newIdentity);
        vm.stopPrank();

        vm.startPrank(_newIdentity);
        arianeeIdentityProxy.updateInformations(_uriToValidate, _imprintToValidate);
        vm.stopPrank();

        vm.startPrank(admin); // admin is validator

        vm.expectEmit();
        emit URIValidate(_newIdentity, _uriToValidate, _imprintToValidate);

        arianeeIdentityProxy.validateInformation(_newIdentity, _uriToValidate, _imprintToValidate);

        // Assertions
        string memory validatedUri = arianeeIdentityProxy.addressURI(_newIdentity);
        assertEq(validatedUri, _uriToValidate, "Validated URI not updated correctly");

        bytes32 validatedImprint = arianeeIdentityProxy.addressImprint(_newIdentity);
        assertEq(validatedImprint, _imprintToValidate, "Validated imprint not updated correctly");

        string memory clearedUri = arianeeIdentityProxy.waitingURI(_newIdentity);
        assertEq(clearedUri, "", "Waiting URI not cleared after validation");

        bytes32 clearedImprint = arianeeIdentityProxy.waitingImprint(_newIdentity);
        assertEq(clearedImprint, bytes32(0), "Waiting imprint not cleared after validation");

        vm.stopPrank();

        // Test Revert Scenarios
        // Unauthorized caller (non-validator)
        vm.startPrank(address(0x9999));
        vm.expectRevert();
        arianeeIdentityProxy.validateInformation(_newIdentity, _uriToValidate, _imprintToValidate);
        vm.stopPrank();

        // Mismatched URI
        vm.startPrank(admin);
        string memory invalidUri = "https://invalid-uri.com";
        vm.expectRevert();
        arianeeIdentityProxy.validateInformation(_newIdentity, invalidUri, _imprintToValidate);
        vm.stopPrank();

        // Mismatched Imprint
        vm.startPrank(admin);
        bytes32 invalidImprint = keccak256(abi.encodePacked("invalid imprint"));
        vm.expectRevert();
        arianeeIdentityProxy.validateInformation(_newIdentity, _uriToValidate, invalidImprint);
        vm.stopPrank();
    }

    function test_updateCompromiseDate(address _identity, uint256 _compromiseDate) public {
        vm.startPrank(bouncer);
        vm.expectEmit();
        emit IdentityCompromised(_identity, _compromiseDate);
        arianeeIdentityProxy.updateCompromiseDate(_identity, _compromiseDate);

        uint256 storedCompromiseDate = arianeeIdentityProxy.compromiseIdentityDate(_identity);

        assertEq(storedCompromiseDate, _compromiseDate, "Compromise date not updated correctly");

        vm.stopPrank();

        // Test Revert Scenarios
        // Unauthorized caller (non-bouncer)
        vm.startPrank(address(0x9999));
        vm.expectRevert();
        arianeeIdentityProxy.updateCompromiseDate(_identity, _compromiseDate);
        vm.stopPrank();

        // Update with a new compromise date
        vm.startPrank(bouncer);
        uint256 newCompromiseDate = block.timestamp + 3600;
        arianeeIdentityProxy.updateCompromiseDate(_identity, newCompromiseDate);

        // Check that the compromise date is updated
        storedCompromiseDate = arianeeIdentityProxy.compromiseIdentityDate(_identity);
        assertEq(storedCompromiseDate, newCompromiseDate, "New compromise date not updated correctly");

        vm.stopPrank();
    }

    function test_updateBouncerAddress(
        address _newBouncerAddress,
        address _newIdentity
    ) public assumeIsNotKnownAddress(_newIdentity) {
        // try a first call with the original bouncer
        vm.startPrank(bouncer);

        arianeeIdentityProxy.addAddressToApprovedList(_newIdentity);
        vm.stopPrank();

        // change the bouncer
        vm.startPrank(admin);
        vm.expectEmit();
        emit SetAddress("bouncerAddress", _newBouncerAddress);

        arianeeIdentityProxy.updateBouncerAddress(_newBouncerAddress);
        vm.stopPrank();

        // original bouncer should not be able to call the function
        vm.startPrank(bouncer);
        vm.expectRevert();
        arianeeIdentityProxy.addAddressToApprovedList(_newIdentity);
        vm.stopPrank();

        // new bouncer should be able to call the function
        vm.startPrank(_newBouncerAddress);
        arianeeIdentityProxy.addAddressToApprovedList(_newIdentity);
        vm.stopPrank();

        // Test Revert Scenarios
        // Unauthorized caller (non-admin)
        vm.startPrank(address(0x9999));
        vm.expectRevert();
        arianeeIdentityProxy.updateBouncerAddress(_newBouncerAddress);
        vm.stopPrank();
    }

    function test_updateValidatorAddress(
        address _newValidatorAddress
    ) public {
        vm.startPrank(admin);

        vm.expectEmit();
        emit SetAddress("validatorAddress", _newValidatorAddress);

        arianeeIdentityProxy.updateValidatorAddress(_newValidatorAddress);

        // The test passes if the expected event is emitted correctly
    }
}
