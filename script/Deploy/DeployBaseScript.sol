// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";

import { ConventionFfiHelper, Convention } from "../Helpers/ConventionFfiHelper.sol";

import { ArianeeIdentity } from "@arianee/V0/ArianeeIdentity.sol";
import { ArianeeWhitelist } from "@arianee/V0/ArianeeWhitelist.sol";
import { ArianeeSmartAsset } from "@arianee/V0/ArianeeSmartAsset.sol";
import { ArianeeSmartAssetUpdate } from "@arianee/V0/ArianeeSmartAssetUpdate.sol";
import { ArianeeEvent } from "@arianee/V0/ArianeeEvent.sol";
import { ArianeeMessage } from "@arianee/V0/ArianeeMessage.sol";
import { ArianeeLost } from "@arianee/V0/ArianeeLost.sol";
import { ArianeeCreditHistory } from "@arianee/V0/ArianeeStore/ArianeeCreditHistory.sol";
import { ArianeeRewardsHistory } from "@arianee/V0/ArianeeStore/ArianeeRewardsHistory.sol";
import { ArianeeStore } from "@arianee/V0/ArianeeStore/ArianeeStore.sol";

contract DeployBaseScript is Script, ConventionFfiHelper {
    ArianeeIdentity identity;
    ArianeeSmartAsset smartAsset;
    ArianeeSmartAssetUpdate smartAssetUpdate;
    ArianeeWhitelist whitelist;
    ArianeeEvent arianeeEvent; // We use `arianeeEvent` to avoid conflict with the reserved keyword `event`
    ArianeeMessage arianeeMessage; // We use `arianeeMessage` to be consistent with `arianeeEvent`
    ArianeeLost lost;
    ArianeeCreditHistory creditHistory;
    ArianeeRewardsHistory rewardsHistory;
    ArianeeStore store;

    string rpcUrl;
    uint256 chainId;

    // Account configuration
    uint256 deployerPk;
    uint256 adminPk;

    address deployerAddr;
    address adminAddr;

    // Admin addresses
    address proxyAdmin;
    address admin;

    // Protocol contract addresses
    address aria;

    // Other addresses
    address forwarder;

    // ArianeeIdentity specific
    address identityBouncer;
    address identityValidator;

    // ArianeeLost specific
    address lostManager;

    // ArianeeStore specific
    address storeProtocolInfraAddress;
    address storeArianeeProjectAddress;
    uint256 storeAriaUSDExchange;
    uint256 storeCreditPricesUSD0;
    uint256 storeCreditPricesUSD1;
    uint256 storeCreditPricesUSD2;
    uint256 storeCreditPricesUSD3;
    uint8 storeDispatchPercent0;
    uint8 storeDispatchPercent1;
    uint8 storeDispatchPercent2;
    uint8 storeDispatchPercent3;
    uint8 storeDispatchPercent4;

    function setUp() public {
        // Getting configuration from environment variables
        rpcUrl = vm.envString("RPC_URL");
        console.log("RpcUrl: %s", rpcUrl);

        chainId = vm.envUint("CHAIN_ID");
        vm.assertEq(chainId, block.chainid, "ChainId mismatch");
        console.log("ChainId: %d", chainId);

        deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        adminPk = vm.envUint("ADMIN_PRIVATE_KEY");

        deployerAddr = vm.addr(deployerPk);
        adminAddr = vm.addr(adminPk);
        console.log("Deployer: %s", deployerAddr);
        console.log("Admin: %s", adminAddr);

        proxyAdmin = vm.envAddress("ARIANEE_PROXY_ADMIN");
        admin = vm.envAddress("ARIANEE_ADMIN");
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);

        aria = vm.envAddress("ARIANEE_ARIA");
        console.log("Aria: %s", aria);

        forwarder = vm.envAddress("ARIANEE_FORWARDER");
        console.log("Forwarder: %s", forwarder);

        identityBouncer = vm.envAddress("ARIANEE_IDENTITY_BOUNCER");
        identityValidator = vm.envAddress("ARIANEE_IDENTITY_VALIDATOR");
        console.log("Identity.Bouncer: %s", identityBouncer);
        console.log("Identity.Validator: %s", identityValidator);

        lostManager = vm.envAddress("ARIANEE_LOST_MANAGER");
        console.log("Lost.Manager: %s", lostManager);

        storeProtocolInfraAddress = vm.envAddress("ARIANEE_STORE_PROTOCOL_INFRA");
        storeArianeeProjectAddress = vm.envAddress("ARIANEE_STORE_PROTOCOL_MAINT");
        console.log("Store.ProtocolInfraAddress: %s", storeProtocolInfraAddress);
        console.log("Store.ArianeeProjectAddress: %s", storeArianeeProjectAddress);

        storeAriaUSDExchange = vm.envUint("ARIANEE_STORE_ARIA_USD_EXCHANGE");
        storeCreditPricesUSD0 = vm.envUint("ARIANEE_STORE_CREDIT_PRICES_USD_0");
        storeCreditPricesUSD1 = vm.envUint("ARIANEE_STORE_CREDIT_PRICES_USD_1");
        storeCreditPricesUSD2 = vm.envUint("ARIANEE_STORE_CREDIT_PRICES_USD_2");
        storeCreditPricesUSD3 = vm.envUint("ARIANEE_STORE_CREDIT_PRICES_USD_3");
        storeDispatchPercent0 = uint8(vm.envUint("ARIANEE_STORE_DISPATCH_PERCENT_0"));
        storeDispatchPercent1 = uint8(vm.envUint("ARIANEE_STORE_DISPATCH_PERCENT_1"));
        storeDispatchPercent2 = uint8(vm.envUint("ARIANEE_STORE_DISPATCH_PERCENT_2"));
        storeDispatchPercent3 = uint8(vm.envUint("ARIANEE_STORE_DISPATCH_PERCENT_3"));
        storeDispatchPercent4 = uint8(vm.envUint("ARIANEE_STORE_DISPATCH_PERCENT_4"));
        console.log("Store.AriaUSDExchange: %d", storeAriaUSDExchange);
        console.log("Store.CreditPricesUSD0: %d", storeCreditPricesUSD0);
        console.log("Store.CreditPricesUSD1: %d", storeCreditPricesUSD1);
        console.log("Store.CreditPricesUSD2: %d", storeCreditPricesUSD2);
        console.log("Store.CreditPricesUSD3: %d", storeCreditPricesUSD3);
        console.log("Store.DispatchPercent0: %d", storeDispatchPercent0);
        console.log("Store.DispatchPercent1: %d", storeDispatchPercent1);
        console.log("Store.DispatchPercent2: %d", storeDispatchPercent2);
        console.log("Store.DispatchPercent3: %d", storeDispatchPercent3);
        console.log("Store.DispatchPercent4: %d", storeDispatchPercent4);
        console.log("\r");
    }

    function run() public {
        // Register the deployer last nonce before any transaction
        uint64 startNonce = vm.getNonce(deployerAddr);

        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        vm.startBroadcast(deployerPk);

        // Pre-compute ArianeeStore address
        // Each `deployTransparentProxy` call will increment the nonce by 2
        // The implementation contract is deployed before the proxy contract
        uint256 targetNonce = startNonce + 19;
        address arianeeStorePreComputedAddr = vm.computeCreateAddress(deployerAddr, targetNonce);

        // ArianeeIdentity
        address arianeeIdentityProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeIdentity.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeIdentity.initialize, (admin, identityBouncer, identityValidator)),
            opts
        );
        identity = ArianeeIdentity(arianeeIdentityProxyAddr);

        // ArianeeWhitelist
        address arianeeWhitelistProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeWhitelist.sol", proxyAdmin, abi.encodeCall(ArianeeWhitelist.initialize, (admin)), opts
        );
        whitelist = ArianeeWhitelist(arianeeWhitelistProxyAddr);

        // ArianeeSmartAsset
        address arianeeSmartAssetProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeSmartAsset.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeSmartAsset.initialize, (admin, arianeeStorePreComputedAddr, address(whitelist))),
            opts
        );
        smartAsset = ArianeeSmartAsset(arianeeSmartAssetProxyAddr);

        // ArianeeSmartAssetUpdate
        address arianeeSmartAssetUpdateProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeSmartAssetUpdate.sol",
            proxyAdmin,
            abi.encodeCall(
                ArianeeSmartAssetUpdate.initialize, (admin, address(smartAsset), arianeeStorePreComputedAddr)
            ),
            opts
        );
        smartAssetUpdate = ArianeeSmartAssetUpdate(arianeeSmartAssetUpdateProxyAddr);

        // ArianeeEvent
        address arianeeEventProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeEvent.sol",
            proxyAdmin,
            abi.encodeCall(
                ArianeeEvent.initialize, (admin, address(smartAsset), arianeeStorePreComputedAddr, address(whitelist))
            ),
            opts
        );
        arianeeEvent = ArianeeEvent(arianeeEventProxyAddr);

        // ArianeeMessage
        address arianeeMessageProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeMessage.sol",
            proxyAdmin,
            abi.encodeCall(
                ArianeeMessage.initialize, (admin, address(smartAsset), arianeeStorePreComputedAddr, address(whitelist))
            ),
            opts
        );
        arianeeMessage = ArianeeMessage(arianeeMessageProxyAddr);

        // ArianeeLost
        address arianeeLostProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeLost.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeLost.initialize, (admin, address(smartAsset), lostManager)),
            opts
        );
        lost = ArianeeLost(arianeeLostProxyAddr);

        // ArianeeCreditHistory
        address arianeeCreditHistoryProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeCreditHistory.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeCreditHistory.initialize, (admin, arianeeStorePreComputedAddr)),
            opts
        );
        creditHistory = ArianeeCreditHistory(arianeeCreditHistoryProxyAddr);

        // ArianeeRewardsHistory
        address arianeeRewardsHistoryProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeRewardsHistory.sol",
            proxyAdmin,
            abi.encodeCall(ArianeeCreditHistory.initialize, (admin, arianeeStorePreComputedAddr)),
            opts
        );
        rewardsHistory = ArianeeRewardsHistory(arianeeRewardsHistoryProxyAddr);

        // ArianeeStore
        address arianeeStoreProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeStore.sol",
            proxyAdmin,
            abi.encodeCall(
                ArianeeStore.initialize,
                (
                    admin,
                    aria,
                    address(smartAsset),
                    address(smartAssetUpdate),
                    address(arianeeEvent),
                    address(arianeeMessage),
                    address(creditHistory),
                    address(rewardsHistory),
                    storeAriaUSDExchange,
                    storeCreditPricesUSD0,
                    storeCreditPricesUSD1,
                    storeCreditPricesUSD2,
                    storeCreditPricesUSD3
                )
            ),
            opts
        );
        store = ArianeeStore(arianeeStoreProxyAddr);
        // Assert that the ArianeeStore pre-computed address was correct
        vm.assertEq(
            arianeeStorePreComputedAddr,
            address(store),
            "Pre-computed ArianeeStore address is not matching the actual address"
        );

        vm.stopBroadcast(); // Stopping the broadcast with the `deployerPk`

        vm.startBroadcast(adminPk);

        // Setting dispatch percentages per actor
        store.setDispatchPercent(
            storeDispatchPercent0,
            storeDispatchPercent1,
            storeDispatchPercent2,
            storeDispatchPercent3,
            storeDispatchPercent4
        );
        // Settings addresses
        store.setProtocolInfraAddress(storeProtocolInfraAddress);
        store.setArianeeProjectAddress(storeArianeeProjectAddress);

        vm.stopBroadcast(); // Stopping the broadcast with the `adminPk`

        Convention memory convention = Convention({
            chainId: chainId,
            rpcUrl: rpcUrl,
            gasStation: string(abi.encodePacked("https://gasstation.arianee.com/", vm.toString(chainId))),
            aria: aria,
            identity: address(identity),
            smartAsset: address(smartAsset),
            updateSmartAssets: address(smartAssetUpdate),
            whitelist: address(whitelist),
            eventArianee: address(arianeeEvent),
            message: address(arianeeMessage),
            lost: address(lost),
            creditHistory: address(creditHistory),
            rewardsHistory: address(rewardsHistory),
            store: address(store),
            staking: address(0),
            userAction: address(0),
            hasher: address(0),
            creditRegister: address(0),
            creditVerifier: address(0),
            creditNotePool: address(0),
            poseidon: address(0),
            ownershipVerifier: address(0),
            issuerProxy: address(0)
        });
        vm.assertTrue(writeConventionFile(convention), "Failed to write convention file");
        console.log("\rINFO: Convention file written successfully!");

        console.log(
            "\rINFO: Arianee base contracts deployed successfully!\nYou can now deploy the privacy extension using the `DeployPrivacyScript` script.\nDon't forget to update the corresponding .env file with the values printed above."
        );
        console.log("\rARIANEE_STORE=\"%s\"", address(store));
        console.log("\rARIANEE_SMART_ASSET=\"%s\"", address(smartAsset));
        console.log("\rARIANEE_EVENT=\"%s\"", address(arianeeEvent));
        console.log("\rARIANEE_LOST=\"%s\"", address(lost));
    }
}
