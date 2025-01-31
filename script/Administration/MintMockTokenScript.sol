// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script, console } from "forge-std/Script.sol";

import { MockERC20 } from "../../test/Mocks/MockERC20.sol";

contract MintMockTokenScript is Script {
    MockERC20 mockErc20;

    string rpcUrl;
    uint256 chainId;

    // Account configuration
    uint256 minterPk;
    address minterAddr;

    // MockERC20 specific
    address addr;
    uint256 mintAmount;
    address mintRecipient;

    function setUp() public {
        // Getting configuration from environment variables
        rpcUrl = vm.envString("RPC_URL");
        console.log("RpcUrl: %s", rpcUrl);

        chainId = vm.envUint("CHAIN_ID");
        vm.assertEq(chainId, block.chainid, "ChainId mismatch");
        console.log("ChainId: %d", chainId);

        minterPk = vm.envUint("MINTER_PRIVATE_KEY");
        minterAddr = vm.addr(minterPk);
        console.log("Minter: %s", minterAddr);

        addr = vm.envAddress("MOCK_ERC20_ADDRESS");
        mintAmount = vm.envUint("MOCK_ERC20_MINT_AMOUNT");
        mintRecipient = vm.envAddress("MOCK_ERC20_MINT_RECIPIENT");
        console.log("Address: %s", addr);
        console.log("MintAmount: %d", mintAmount);
        console.log("MintRecipient: %s", mintRecipient);
        console.log("\r");
    }

    function run() public {
        vm.startBroadcast(minterPk);

        // MockERC20
        mockErc20 = MockERC20(addr);
        string memory symbol = mockErc20.symbol();

        mockErc20.mint(mintRecipient, mintAmount);
        console.log("Minted %d %s tokens to %s", mintAmount, symbol, mintRecipient);

        vm.stopBroadcast(); // Stopping the broadcast with the `minterPk`
    }
}
