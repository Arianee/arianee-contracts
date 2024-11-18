// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeLost {
    /**
     * @notice Sets the missing status for a token
     * @param _tokenId The ID of the token to mark as missing
     */
    function setMissingStatus(
        uint256 _tokenId
    ) external;

    /**
     * @notice Unsets the missing status for a token
     * @param _tokenId The ID of the token to unmark as missing
     */
    function unsetMissingStatus(
        uint256 _tokenId
    ) external;

    /**
     * @notice Checks if a token is marked as missing
     * @param _tokenId The ID of the token to check
     * @return _isMissing True if the token is marked as missing, false otherwise
     */
    function isMissing(
        uint256 _tokenId
    ) external view returns (bool _isMissing);

    /**
     * @notice Marks a token as stolen
     * @param _tokenId The ID of the token to mark as stolen
     */
    function setStolenStatus(
        uint256 _tokenId
    ) external;

    /**
     * @notice Removes the stolen status from a token
     * @param _tokenId The ID of the token to unmark as stolen
     */
    function unsetStolenStatus(
        uint256 _tokenId
    ) external;

    /**
     * @notice Checks if a token is marked as stolen
     * @param _tokenId The ID of the token to check
     * @return _isStolen True if the token is marked as stolen, false otherwise
     */
    function isStolen(
        uint256 _tokenId
    ) external view returns (bool _isStolen);

    /**
     * @notice Sets the manager identity
     * @param _managerIdentity The address of the new manager
     */
    function setManagerIdentity(
        address _managerIdentity
    ) external;

    /**
     * @notice Adds a new authorized identity
     * @param _newIdentityAuthorized The address to authorize
     */
    function setAuthorizedIdentity(
        address _newIdentityAuthorized
    ) external;

    /**
     * @notice Removes an authorized identity
     * @param _newIdentityUnauthorized The address to deauthorize
     */
    function unsetAuthorizedIdentity(
        address _newIdentityUnauthorized
    ) external;

    /**
     * @notice Checks if an address is authorized
     * @param _address The address to check
     * @return _isAuthorized True if the address is authorized, false otherwise
     */
    function isAddressAuthorized(
        address _address
    ) external view returns (bool _isAuthorized);

    /**
     * @notice Returns the manager's address
     * @return _managerIdentity The address of the current manager
     */
    function getManagerIdentity() external view returns (address _managerIdentity);

    /**
     * @notice Emitted when a new manager identity is set
     * @param _newManagerIdentity The address of the new manager
     */
    event NewManagerIdentity(address indexed _newManagerIdentity);

    /**
     * @notice Emitted when a token is declared missing
     * @param _tokenId The ID of the token declared missing
     */
    event Missing(uint256 indexed _tokenId);

    /**
     * @notice Emitted when a token is no longer declared missing
     * @param _tokenId The ID of the token no longer declared missing
     */
    event UnMissing(uint256 indexed _tokenId);

    /**
     * @notice Emitted when a new authorized identity is added
     * @param _newIdentityAuthorized The address of the new authorized identity
     */
    event AuthorizedIdentityAdded(address indexed _newIdentityAuthorized);

    /**
     * @notice Emitted when an authorized identity is removed
     * @param _newIdentityUnauthorized The address of the removed authorized identity
     */
    event AuthorizedIdentityRemoved(address indexed _newIdentityUnauthorized);

    /**
     * @notice Emitted when a token is declared stolen
     * @param _tokenId The ID of the token declared stolen
     */
    event Stolen(uint256 indexed _tokenId);

    /**
     * @notice Emitted when a token is no longer declared stolen
     * @param _tokenId The ID of the token no longer declared stolen
     */
    event UnStolen(uint256 indexed _tokenId);
}
