// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeEvent {
    function create(
        uint256 _eventId,
        uint256 _tokenId,
        bytes32 _imprint,
        string memory _uri,
        uint256 _rewards,
        address _provider
    ) external;

    function accept(uint256 _eventId, address _owner) external returns (uint256);

    function refuse(uint256 _eventId, address _owner) external returns (uint256);

    function destroy(
        uint256 _eventId
    ) external;

    function updateDestroyRequest(uint256 _eventId, bool _active) external;

    function eventIdToToken(
        uint256 _eventId
    ) external view returns (uint256);
}
