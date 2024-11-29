// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeMessage {
    function readMessage(uint256 _messageId, address _from) external returns (uint256);

    function sendMessage(
        uint256 _messageId,
        uint256 _tokenId,
        bytes32 _imprint,
        address _from,
        uint256 _rewards
    ) external;
}
