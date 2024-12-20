// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { ArianeeSmartAssetTest } from "../V0/ArianeeSmartAsset.t.sol";
import { ArianeeSmartAssetV1 } from "@arianee/V1/ArianeeSmartAssetV1.sol";
import {
    ROLE_ADMIN, ROLE_ARIANEE_STORE, URI_BASE, ACCESS_TYPE_VIEW, ACCESS_TYPE_TRANSFER
} from "@arianee/V0/Constants.sol";

contract ArianeeSmartAssetV1Test is ArianeeSmartAssetTest {
    address additionalAdmin = vm.addr(8);

    string stringValue = "Hello, World!";
    string newBaseURI = "https://example-v1.com/";

    address arianeeSmartAssetV1ImplAddr;
    ArianeeSmartAssetV1 arianeeSmartAssetProxyV1;

    function beforeTestSetup(
        bytes4 testSelector
    ) public pure returns (bytes[] memory beforeTestCalldata) {
        if (testSelector == this.test_V1_smartAsset_fromV0_still_working.selector) {
            beforeTestCalldata = new bytes[](2);
            // Hydrate a SmartAsset from V0 before the upgrade to V1
            beforeTestCalldata[0] = abi.encodePacked(this.beforeTestSetup_hydrateSmartAsset.selector);
            beforeTestCalldata[1] = abi.encodePacked(this.beforeTestSetup_upgradeProxyToArianeeSmartAssetV1.selector);
        } else if (testSelector == this.test_V1_smartAsset_fromV1_is_working.selector) {
            beforeTestCalldata = new bytes[](2);
            // Hydrate a SmartAsset from V1 after the upgrade to V1
            beforeTestCalldata[0] = abi.encodePacked(this.beforeTestSetup_upgradeProxyToArianeeSmartAssetV1.selector);
            beforeTestCalldata[1] = abi.encodePacked(this.beforeTestSetup_hydrateSmartAsset.selector);
        } else if (testSelector == super.test_setUriBase.selector) {
            beforeTestCalldata = new bytes[](2);
            // Revert the base URI to the original value before the upgrade to allow the test to pass
            beforeTestCalldata[0] = abi.encodePacked(this.beforeTestSetup_setNewBaseURIToDefault.selector);
            beforeTestCalldata[1] = abi.encodePacked(this.beforeTestSetup_upgradeProxyToArianeeSmartAssetV1.selector);
        } else {
            beforeTestCalldata = new bytes[](1);
            beforeTestCalldata[0] = abi.encodePacked(this.beforeTestSetup_upgradeProxyToArianeeSmartAssetV1.selector);
        }
    }

    function beforeTestSetup_upgradeProxyToArianeeSmartAssetV1() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        vm.startPrank(proxyAdmin);
        Upgrades.upgradeProxy(
            address(arianeeSmartAssetProxy),
            "ArianeeSmartAssetV1.sol",
            abi.encodeCall(ArianeeSmartAssetV1.initializeV1, (additionalAdmin, newBaseURI, stringValue)),
            opts
        );
        arianeeSmartAssetProxyV1 = ArianeeSmartAssetV1(address(arianeeSmartAssetProxy));
        arianeeSmartAssetV1ImplAddr = Upgrades.getImplementationAddress(address(arianeeSmartAssetProxy));
        assertNotEq(arianeeSmartAssetV1ImplAddr, arianeeSmartAssetImplAddr);

        vm.stopPrank();
    }

    uint256 smartAssetTokenId = 1;
    bytes32 smartAssetImprint = 0x000000000000000000000000000000000000000000000000000000000000007b;
    string smartAssetURI = "https://example-before-upgrade.com/";
    address smartAssetInitialKey = address(456);
    uint256 smartAssetTokenRecoveryTimestamp = 789;
    bool smartAssetInitialKeyIsRequestKey = true;

    function beforeTestSetup_hydrateSmartAsset() public {
        vm.startPrank(store);
        arianeeSmartAssetProxy.reserveToken(smartAssetTokenId, issuer1);
        arianeeSmartAssetProxy.hydrateToken(
            smartAssetTokenId,
            smartAssetImprint,
            smartAssetURI,
            smartAssetInitialKey,
            smartAssetTokenRecoveryTimestamp,
            smartAssetInitialKeyIsRequestKey,
            issuer1,
            false
        );

        assertEq(arianeeSmartAssetProxy.issuerOf(smartAssetTokenId), issuer1);
        assertEq(arianeeSmartAssetProxy.tokenCreation(smartAssetTokenId), block.timestamp);
        assertEq(arianeeSmartAssetProxy.tokenRecoveryDate(smartAssetTokenId), smartAssetTokenRecoveryTimestamp);
        assertEq(arianeeSmartAssetProxy.tokenImprint(smartAssetTokenId), smartAssetImprint);
        assertEq(arianeeSmartAssetProxy.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_VIEW), smartAssetInitialKey);
        assertEq(arianeeSmartAssetProxy.isSoulbound(smartAssetTokenId), false);
        assertEq(
            arianeeSmartAssetProxy.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_TRANSFER), smartAssetInitialKey
        );
        vm.stopPrank();
    }

    function beforeTestSetup_setNewBaseURIToDefault() public {
        newBaseURI = URI_BASE;
    }

    function setUp() public virtual override {
        super.setUp();
        // We don't update the proxy to V1 here, because there are tests that require additional setup before the upgrade
        // Take a look at the `beforeTestSetup` function to see how we handle this
    }

    function test_a_displayAddresses() public view virtual override {
        super.test_a_displayAddresses();
        console.log("ArianeeSmartAssetV1Impl: %s", arianeeSmartAssetV1ImplAddr);
    }

    // Initializer

    function test_V1_initializeV1() public view {
        assertTrue(arianeeSmartAssetProxyV1.hasRole(ROLE_ADMIN, additionalAdmin));
        assertEq(arianeeSmartAssetProxyV1.getString(), stringValue);
        assertEq(arianeeSmartAssetProxyV1.getMapping(123), abi.encode(456));
    }

    // Set Uint256

    function test_V1_setUint256(
        uint256 value
    ) public {
        vm.startPrank(store);
        arianeeSmartAssetProxyV1.setUint256(value);
        assertEq(arianeeSmartAssetProxyV1.getUint256(), value);
        vm.stopPrank();
    }

    function test_V1_setUint256_err_onlyStore() public {
        vm.startPrank(unknown);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, unknown, ROLE_ARIANEE_STORE
            )
        );
        arianeeSmartAssetProxyV1.setUint256(123);
        vm.stopPrank();
    }

    // Assert that a SmartAsset created from the V0 contract is still working after the upgrade to V1

    function test_V1_smartAsset_fromV0_still_working() public {
        assertEq(arianeeSmartAssetProxyV1.issuerOf(smartAssetTokenId), issuer1);
        assertEq(arianeeSmartAssetProxyV1.tokenCreation(smartAssetTokenId), block.timestamp);
        assertEq(arianeeSmartAssetProxyV1.tokenRecoveryDate(smartAssetTokenId), smartAssetTokenRecoveryTimestamp);
        assertEq(arianeeSmartAssetProxyV1.tokenImprint(smartAssetTokenId), smartAssetImprint);
        assertEq(arianeeSmartAssetProxyV1.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_VIEW), smartAssetInitialKey);
        assertEq(arianeeSmartAssetProxyV1.isSoulbound(smartAssetTokenId), false);
        assertEq(
            arianeeSmartAssetProxyV1.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_TRANSFER), smartAssetInitialKey
        );

        vm.startPrank(issuer1);
        (address newKeyAddr,) = makeAddrAndKey("newKey");
        bool enable = true;
        arianeeSmartAssetProxyV1.addTokenAccess(smartAssetTokenId, newKeyAddr, enable, ACCESS_TYPE_TRANSFER);
        assertEq(arianeeSmartAssetProxyV1.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_TRANSFER), newKeyAddr); // Assert that new key is the request key
        vm.stopPrank();
    }

    // Assert that a SmartAsset created from the V1 contract is working

    function test_V1_smartAsset_fromV1_is_working() public {
        assertEq(arianeeSmartAssetProxyV1.issuerOf(smartAssetTokenId), issuer1);
        assertEq(arianeeSmartAssetProxyV1.tokenCreation(smartAssetTokenId), block.timestamp);
        assertEq(arianeeSmartAssetProxyV1.tokenRecoveryDate(smartAssetTokenId), smartAssetTokenRecoveryTimestamp);
        assertEq(arianeeSmartAssetProxyV1.tokenImprint(smartAssetTokenId), smartAssetImprint);
        assertEq(arianeeSmartAssetProxyV1.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_VIEW), smartAssetInitialKey);
        assertEq(arianeeSmartAssetProxyV1.isSoulbound(smartAssetTokenId), false);
        assertEq(
            arianeeSmartAssetProxyV1.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_TRANSFER), smartAssetInitialKey
        );

        vm.startPrank(issuer1);
        (address newKeyAddr,) = makeAddrAndKey("newKey");
        bool enable = true;
        arianeeSmartAssetProxyV1.addTokenAccess(smartAssetTokenId, newKeyAddr, enable, ACCESS_TYPE_TRANSFER);
        assertEq(arianeeSmartAssetProxyV1.tokenHashedAccess(smartAssetTokenId, ACCESS_TYPE_TRANSFER), newKeyAddr); // Assert that new key is the request key
        vm.stopPrank();
    }
}
