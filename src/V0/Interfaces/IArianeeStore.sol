// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeStore {
    function buyCredit(uint256 _creditType, uint256 _quantity, address _to) external;

    function reserveToken(uint256 _tokenId, address _to) external;
    function hydrateToken(
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        address _initialKey,
        uint256 _tokenRecoveryTimestamp,
        bool _initialKeyIsRequestKey,
        address _rewardsReceiver
    ) external;

    function createEvent(
        uint256 _eventId,
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        address _rewardsReceiver
    ) external;

    function updateSmartAsset(uint256 _tokenId, bytes32 _imprint, address _rewardsReceiver) external;
    function readUpdateSmartAsset(uint256 _tokenId, address _rewardsReceiver) external;

    function acceptEvent(uint256 _eventId, address _rewardsReceiver) external;
    function refuseEvent(uint256 _eventId, address _rewardsReceiver) external;

    function createMessage(uint256 _messageId, uint256 _tokenId, bytes32 _imprint, address _rewardsReceiver) external;
    function readMessage(uint256 _messageId, address _rewardsReceiver) external;

    function dispatchRewardsAtFirstTransfer(uint256 _tokenId, address _newOwner) external;

    function getCreditPrice(
        uint256 _creditType
    ) external view returns (uint256);
}
