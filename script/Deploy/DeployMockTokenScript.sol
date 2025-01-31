// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";

import { MockERC20 } from "../../test/Mocks/MockERC20.sol";

contract DeployMockTokenScript is Script {
    MockERC20 mockErc20;

    string rpcUrl;
    uint256 chainId;

    // Account configuration
    uint256 deployerPk;
    address deployerAddr;

    // MockERC20 specific
    string name;
    string symbol;
    uint256 initialSupply;
    address initialRecipient;

    function setUp() public {
        // Getting configuration from environment variables
        rpcUrl = vm.envString("RPC_URL");
        console.log("RpcUrl: %s", rpcUrl);

        chainId = vm.envUint("CHAIN_ID");
        vm.assertEq(chainId, block.chainid, "ChainId mismatch");
        console.log("ChainId: %d", chainId);

        deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        deployerAddr = vm.addr(deployerPk);
        console.log("Deployer: %s", deployerAddr);

        name = vm.envString("MOCK_ERC20_NAME");
        symbol = vm.envString("MOCK_ERC20_SYMBOL");
        console.log("Name: %s", name);
        console.log("Symbol: %s", symbol);

        initialSupply = vm.envUint("MOCK_ERC20_INITIAL_SUPPLY");
        initialRecipient = vm.envAddress("MOCK_ERC20_INITIAL_RECIPIENT");
        console.log("InitialSupply: %d", initialSupply);
        console.log("InitialRecipient: %s", initialRecipient);
        console.log("\r");
    }

    function run() public {
        vm.startBroadcast(deployerPk);

        // MockERC20
        mockErc20 = new MockERC20(name, symbol);

        // Minting some tokens if `initialSupply` is greater than 0
        if (initialSupply > 0) {
            mockErc20.mint(initialRecipient, initialSupply);
            console.log("Minted %d %s tokens to %s", initialSupply, symbol, initialRecipient);
        }

        vm.stopBroadcast(); // Stopping the broadcast with the `deployerPk`
    }
}
