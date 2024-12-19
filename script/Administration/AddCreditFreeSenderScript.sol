// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";
import { Upgrades } from "@openzeppelin/foundry-upgrades/Upgrades.sol";
import { Options } from "@openzeppelin/foundry-upgrades/Options.sol";

import { ArianeeIssuerProxy } from "@arianee/V0/ArianeePrivacy/ArianeeIssuerProxy.sol";

contract AddCreditFreeSenderScript is Script {
    ArianeeIssuerProxy issuerProxy;

    uint256 chainId;

    // Account configuration
    uint256 adminPk;

    address adminAddr;

    // Protocol contract addresses
    address issuerProxyAddr;

    // ArianeeIssuerProxy specific
    address[] creditFreeSenders;

    function setUp() public {
        // Getting configuration from environment variables
        chainId = vm.envUint("CHAIN_ID");
        vm.assertEq(chainId, block.chainid, "ChainId mismatch");
        console.log("ChainId: %d", chainId);

        adminPk = vm.envUint("ADMIN_PRIVATE_KEY");

        adminAddr = vm.addr(adminPk);
        console.log("Admin: %s", adminAddr);

        issuerProxyAddr = vm.envAddress("ARIANEE_ISSUER_PROXY");
        console.log("ArianeeIssuerProxy: %s", issuerProxyAddr);

        creditFreeSenders = vm.envAddress("CREDIT_FREE_SENDERS", ",");
        for (uint256 i = 0; i < creditFreeSenders.length; i++) {
            console.log("CreditFreeSender(%d): %s", i, creditFreeSenders[i]);
        }
        console.log("\r");
    }

    function run() public {
        // Attaching to the existing ArianeeIssuerProxy contract
        issuerProxy = ArianeeIssuerProxy(issuerProxyAddr);

        vm.startBroadcast(adminPk);

        // Adding credit free senders
        issuerProxy.addCreditFreeSenderBatch(creditFreeSenders); // TODO: If needed, split the array into smaller chunks

        vm.stopBroadcast(); // Stopping the broadcast with the `adminPk`
    }
}
