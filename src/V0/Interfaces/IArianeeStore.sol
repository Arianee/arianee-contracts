// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeStore {
    // TODO: Breaking change, `canTransfer(address _from, address _to, uint256 _tokenId, bool _isSoulbound) external returns (bool)` has been deleted
    // TODO: Breaking change, `canDestroy(uint256 _tokenId, address _sender, bool _isSoulbound) external returns (bool)` has been deleted

    function buyCredit(uint256 _creditType, uint256 _quantity, address _to) external;

    function reserveToken(uint256 _tokenId, address _to) external;
    function hydrateToken(
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        address _initialKey,
        uint256 _tokenRecoveryTimestamp,
        bool _initialKeyIsRequestKey,
        address _rewardsReceiver,
        bool _soulbound // TODO: Breaking change, it's a new param, we'll probably need to change this in the SDK
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
