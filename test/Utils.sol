// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

library ArianeeUtils {
    function getRequestTokenMsgHash(uint256 tokenId, address receiver) public pure returns (bytes32) {
        bytes32 message = keccak256(abi.encode(tokenId, receiver));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", message));
    }
}
