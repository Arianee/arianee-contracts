// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { ROLE_ADMIN } from "@arianee/V0/Constants.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { ArianeeWhitelist, WhitelistedAddressAdded, BlacklistedAddresAdded } from "@arianee/V0/ArianeeWhitelist.sol";

contract ArianeeWhitelistTest is Test {
    address proxyAdmin = vm.addr(1);
    address admin = address(this); // Admin is likely the "Arianee Foundation"

    address forwarder = vm.addr(2);
    address whitelistAdmin = vm.addr(3);
    address unknown = vm.addr(6);

    ArianeeWhitelist arianeeWhitelistProxy;
    address arianeeWhitelistImplAddr;

    function setUp() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        address arianeeWhitelistProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeWhitelist.sol", proxyAdmin, abi.encodeCall(ArianeeWhitelist.initialize, (whitelistAdmin)), opts
        );

        arianeeWhitelistProxy = ArianeeWhitelist(arianeeWhitelistProxyAddr);
        arianeeWhitelistImplAddr = Upgrades.getImplementationAddress(arianeeWhitelistProxyAddr);
    }

    function test_a_displayAddresses() public view {
        // Dummy test to display addresses for debugging purposes
        console.log("Default: %s", msg.sender);
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);
        console.log("Forwarder: %s", forwarder);
        console.log("Unknown: %s", unknown);
        console.log("whitelistAdmin: %s", whitelistAdmin);
    }

    modifier assumeIsNotKnownAddress(
        address addr
    ) {
        vm.assume(addr != address(0)); // Make sure `addr` is not the zero address
        vm.assume(addr != msg.sender); // Make sure `addr` is not the default address

        vm.assume(addr != proxyAdmin); // Make sure `addr` is not the proxy admin address
        vm.assume(addr != admin); // Make sure `addr` is not the admin address

        vm.assume(addr != forwarder); // Make sure `addr` is not the forwarder address

        vm.assume(addr != unknown); // Make sure `addr` is not the unknown address
        vm.assume(addr != whitelistAdmin); // Make sure `addr` is not the whitelistAdmin address
        _;
    }

    function test_initialize() public {
        // Check if the initial admin has the ROLE_ADMIN role
        bool isAdmin = arianeeWhitelistProxy.hasRole(ROLE_ADMIN, whitelistAdmin);
        assertTrue(isAdmin, "Initial admin does not have ROLE_ADMIN role");

        // Attempt to reinitialize and expect failure
        vm.expectRevert();
        arianeeWhitelistProxy.initialize(unknown);
    }

    function test_addWhitelistedAddress(uint256 _tokenId, address _address) public assumeIsNotKnownAddress(_address) {
        vm.startPrank(whitelistAdmin);

        vm.expectEmit();
        emit WhitelistedAddressAdded(_tokenId, _address);

        arianeeWhitelistProxy.addWhitelistedAddress(_tokenId, _address);

        bool isWhiteListed = arianeeWhitelistProxy.isWhitelisted(_tokenId, _address);

        assertTrue(isWhiteListed, "Address is not whitelisted");

        vm.stopPrank();

        // Fail case
        vm.startPrank(unknown);

        vm.expectRevert();
        arianeeWhitelistProxy.addWhitelistedAddress(_tokenId, _address);
        vm.stopPrank();
    }

    function test_addBlacklistedAddress(address _sender, uint256 _tokenId) public assumeIsNotKnownAddress(_sender) {
        vm.startPrank(unknown);
        vm.expectEmit();
        emit BlacklistedAddresAdded(_sender, _tokenId, true);

        arianeeWhitelistProxy.addBlacklistedAddress(_sender, _tokenId, true);

        bool isBlackListed = arianeeWhitelistProxy.isBlacklisted(unknown, _sender, _tokenId);

        assertTrue(isBlackListed, "Address is not blacklisted");
        vm.stopPrank();
    }

    function test_isAuthorized(uint256 _tokenId, address _sender) public assumeIsNotKnownAddress(_sender) {
        vm.startPrank(whitelistAdmin);

        vm.expectEmit();
        emit WhitelistedAddressAdded(_tokenId, _sender);

        // Whitelist the sender
        arianeeWhitelistProxy.addWhitelistedAddress(_tokenId, _sender);
        vm.stopPrank();

        vm.startPrank(unknown);

        bool isWhitelisted = arianeeWhitelistProxy.isWhitelisted(_tokenId, _sender);
        assertTrue(isWhitelisted, "Address is not whitelisted");

        // Check authorization before blacklisting
        bool isAuthorized = arianeeWhitelistProxy.isAuthorized(_tokenId, _sender, unknown);
        assertTrue(isAuthorized, "Address is not authorized before blacklisting");

        // Blacklist the sender
        arianeeWhitelistProxy.addBlacklistedAddress(_sender, _tokenId, true);

        bool isBlacklisted = arianeeWhitelistProxy.isBlacklisted(unknown, _sender, _tokenId);
        assertTrue(isBlacklisted, "Address is not blacklisted");

        // Check authorization after blacklisting
        bool isAuthorizedAfterBlacklist = arianeeWhitelistProxy.isAuthorized(_tokenId, _sender, unknown);
        assertFalse(isAuthorizedAfterBlacklist, "Address is still authorized after blacklisting");

        vm.stopPrank();
    }
}
