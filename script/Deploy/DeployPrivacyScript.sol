// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";

import { ConventionFfiHelper, Convention } from "../Helpers/ConventionFfiHelper.sol";
import { DeployBytecodeHelper } from "../Helpers/DeployBytecodeHelper.sol";
import { POSEIDON_BYTECODE } from "../Constants.sol";

import { OwnershipVerifier } from "@arianee/V0/ArianeePrivacy/Verifiers/OwnershipVerifier.sol";
import { IPoseidon } from "@arianee/V0/Interfaces/IPoseidon.sol";
import { ArianeeIssuerProxy } from "@arianee/V0/ArianeePrivacy/ArianeeIssuerProxy.sol";

contract DeployPrivacyScript is Script, ConventionFfiHelper, DeployBytecodeHelper {
    OwnershipVerifier verifier;
    IPoseidon poseidon;
    ArianeeIssuerProxy issuerProxy;

    uint256 chainId;

    // Account configuration
    uint256 deployerPk;

    address deployerAddr;

    // Admin addresses
    address proxyAdmin;
    address admin;

    // Protocol contract addresses
    address store;
    address smartAsset;
    address arianeeEvent;
    address lost;

    // Other addresses
    address forwarder;

    function setUp() public {
        // Getting configuration from environment variables
        chainId = vm.envUint("CHAIN_ID");
        vm.assertEq(chainId, block.chainid, "ChainId mismatch");
        console.log("ChainId: %d", chainId);

        deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");

        deployerAddr = vm.addr(deployerPk);
        console.log("Deployer: %s", deployerAddr);

        proxyAdmin = vm.envAddress("ARIANEE_PROXY_ADMIN");
        admin = vm.envAddress("ARIANEE_ADMIN");
        console.log("ProxyAdmin: %s", proxyAdmin);
        console.log("Admin: %s", admin);

        store = vm.envAddress("ARIANEE_STORE");
        smartAsset = vm.envAddress("ARIANEE_SMART_ASSET");
        arianeeEvent = vm.envAddress("ARIANEE_EVENT");
        lost = vm.envAddress("ARIANEE_LOST");
        console.log("Store: %s", store);
        console.log("SmartAsset: %s", smartAsset);
        console.log("ArianeeEvent: %s", arianeeEvent);
        console.log("Lost: %s", lost);

        forwarder = vm.envAddress("ARIANEE_FORWARDER");
        console.log("Forwarder: %s", forwarder);
        console.log("\r");
    }

    function run() public {
        Options memory opts;
        opts.constructorData = abi.encode(forwarder);

        vm.startBroadcast(deployerPk);

        // OwnershipVerifier
        verifier = new OwnershipVerifier();

        // Poseidon
        address poseidonAddr = deployBytecode(POSEIDON_BYTECODE);
        poseidon = IPoseidon(poseidonAddr);

        // ArianeeIssuerProxy
        address arianeeIssuerProxyAddr = Upgrades.deployTransparentProxy(
            "ArianeeIssuerProxy.sol:ArianeeIssuerProxy",
            proxyAdmin,
            abi.encodeCall(
                ArianeeIssuerProxy.initialize,
                (admin, store, smartAsset, arianeeEvent, lost, address(verifier), address(poseidon))
            ),
            opts
        );
        issuerProxy = ArianeeIssuerProxy(arianeeIssuerProxyAddr);

        vm.stopBroadcast(); // Stopping the broadcast with the `deployerPk`

        Convention memory convention = Convention({
            chainId: chainId,
            rpcUrl: "",
            gasStation: "",
            aria: address(0),
            identity: address(0),
            smartAsset: address(0),
            updateSmartAssets: address(0),
            whitelist: address(0),
            eventArianee: address(0),
            message: address(0),
            lost: address(0),
            creditHistory: address(0),
            rewardsHistory: address(0),
            store: address(0),
            staking: address(0),
            userAction: address(0),
            hasher: address(0),
            creditRegister: address(0),
            creditVerifier: address(0),
            creditNotePool: address(0),
            poseidon: address(poseidon),
            ownershipVerifier: address(verifier),
            issuerProxy: address(issuerProxy)
        });
        vm.assertTrue(writeConventionFile(convention), "Failed to write convention file");
        console.log("\rINFO: Convention file written successfully!");

        console.log(
            "\rINFO: Arianee privacy extension deployed successfully!\nYou can now add some \"credit free sender\" if needed using the `AddCreditFreeSenderScript` script.\nDon't forget to update the corresponding .env file with the values printed above."
        );
        console.log("\rARIANEE_ISSUER_PROXY=\"%s\"", address(issuerProxy));
    }
}
