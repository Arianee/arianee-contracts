// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeSmartAsset {
    function canOperate(uint256 _tokenId, address _operator) external returns (bool);

    function isAccessValid(
        uint256 _tokenId,
        bytes32 _hash,
        uint256 _accessType,
        bytes memory _signature
    ) external view returns (bool); // TODO: Breaking change, before it was `isTokenValid`, we'll probably need to change this in the SDK (we'll see if it's used)

    function issuerOf(
        uint256 _tokenId
    ) external view returns (address _tokenIssuer);

    function tokenCreation(
        uint256 tokenId
    ) external view returns (uint256 _tokenCreation);

    function ownerOf(
        uint256 _tokenId
    ) external returns (address);

    function tokenImprint(
        uint256 _tokenId
    ) external view returns (bytes32 _imprint);

    function reserveToken(uint256 _tokenId, address _to) external;

    function hydrateToken(
        uint256 _tokenId,
        bytes32 _imprint,
        string memory _uri,
        address _initialKey,
        uint256 _tokenRecoveryTimestamp,
        bool _initialKeyIsRequestKey,
        address _issuer
    ) external;

    function requestToken(
        uint256 _tokenId,
        bytes32 _hash,
        bool _keepCurrentAccess,
        address _newOwner,
        bytes calldata _signature
    ) external;

    function addTokenAccess(uint256 _tokenId, address _key, bool _enable, uint256 _accessType) external;

    function recoverTokenToIssuer(
        uint256 _tokenId
    ) external;

    function updateRecoveryRequest(uint256 _tokenId, bool _active) external;

    function destroy(
        uint256 _tokenId
    ) external;

    function updateTokenURI(uint256 _tokenId, string calldata _uri) external;

    function safeTransferFrom(address _from, address _to, uint256 _tokenId, bytes calldata _data) external;

    function transferFrom(address _from, address _to, uint256 _tokenId) external;

    function approve(address _approved, uint256 _tokenId) external;
}
