// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

abstract contract DeployBytecodeHelper {
    /**
     * @dev Deploys a contract using the provided creation bytecode
     * Note: The bytecode provided should be the creation bytecode, not the runtime bytecode
     * @param bytecode The creation bytecode of the contract to be deployed
     * @return The address of the deployed contract
     */
    function deployBytecode(
        bytes memory bytecode
    ) internal returns (address) {
        address addr;
        assembly {
            // create(0, memoryStart, memorySize)
            // memoryStart = add(bytecode, 0x20) -> skip length
            // memorySize = mload(bytecode) -> length of the code
            addr := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        require(addr != address(0), "DeployBytecodeHelper: Create failed");
        return addr;
    }
}
