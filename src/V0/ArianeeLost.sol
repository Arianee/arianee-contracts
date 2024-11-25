// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { console } from "forge-std/Test.sol";

// Stateless
import { IArianeeLost } from "./Interfaces/IArianeeLost.sol";
import { IArianeeSmartAsset } from "./Interfaces/IArianeeSmartAsset.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ERC721_NAME, ERC721_SYMBOL } from "./Constants.sol";
// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// ERC721
import { ERC721Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title ArianeeLost
 * @notice This contract manage the lost status of the SmartAssets.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeLost is IArianeeLost, Initializable, ERC2771ContextUpgradeable, OwnableUpgradeable {
    using Strings for uint256;

    /// @custom:storage-location erc7201:arianeelost.storage.v0
    struct ArianeeLostStorageV0 {
        /**
         * @notice Mapping from SmartAsset ID to missing status
         */
        mapping(uint256 => bool) tokenMissingStatus;
        /**
         * @notice Mapping from SmartAsset ID to stolen status
         */
        mapping(uint256 => bool) tokenStolenStatus;
        /**
         * @notice Mapping from SmartAsset ID to the address of the issuer (the one who declared the SmartAsset as stolen)
         */
        mapping(uint256 => address) tokenStolenIssuer;
        /**
         * @notice Mapping from an address to a boolean that indicates whether the address is authorized to manage stolen statuses or not
         */
        mapping(address => bool) authorizedIdentities;
        /**
         * @notice Address of the manager (the one who can add or remove authorized identities)
         */
        address managerIdentity;
        /**
         * @notice The ArianeeSmartAsset contract
         */
        IArianeeSmartAsset smartAsset;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeelost.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeLostStorageV0Location =
        0x330f3bda9f99a316cfa3447262f2a7a821ef201c407ca28d81f28d8e38ea1e00;

    function _getArianeeLostStorageV0() internal pure returns (ArianeeLostStorageV0 storage $) {
        assembly {
            $.slot := ArianeeLostStorageV0Location
        }
    }

    /**
     * @notice Check if the _msgSender() is the owner of the SmartAsset
     * @param _tokenId SmartAsset ID
     */
    modifier onlyTokenOwner(
        uint256 _tokenId
    ) {
        console.log("MsgSender: %s", _msgSender());
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require(
            $.smartAsset.ownerOf(_tokenId) == _msgSender(),
            "ArianeeLost: Not authorized because not the SmartAsset owner"
        );
        _;
    }

    /**
     * @notice Ensures the specified SmartAsset is marked as missing before proceeding
     * @param _tokenId SmartAsset ID
     */
    modifier onlyHasBeenMissing(
        uint256 _tokenId
    ) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require($.tokenMissingStatus[_tokenId] == true, "ArianeeLost: The SmartAsset must be marked as missing");
        _;
    }

    /**
     * @notice Ensures the specified SmartAsset is not marked as missing before proceeding
     * @param _tokenId SmartAsset ID
     */
    modifier onlyHasNotBeenMissing(
        uint256 _tokenId
    ) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require($.tokenMissingStatus[_tokenId] == false, "ArianeeLost: The SmartAsset must not be marked as missing");
        _;
    }

    /**
     * @notice Ensures that the _msgSender() is the manager before proceeding
     */
    modifier onlyManager() {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require(_msgSender() == $.managerIdentity, "ArianeeLost: Caller must be the Manager");
        _;
    }

    /**
     * @notice Ensures that the _msgSender() is an authorized identity before proceeding
     */
    modifier onlyAuthorizedIdentity() {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require($.authorizedIdentities[_msgSender()], "ArianeeLost: Caller must be an authorized identity");
        _;
    }

    /**
     * @notice Ensures that the _msgSender() is either an authorized identity or the manager before proceeding
     */
    modifier onlyAuthorizedIdentityOrManager() {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require(
            $.authorizedIdentities[_msgSender()] || _msgSender() == $.managerIdentity,
            "ArianeeLost: Caller must be an authorized identity or the Manager"
        );
        _;
    }

    /**
     * @notice You can change the trusted forwarder after initial deployment by overriding the `ERC2771ContextUpgradeable.trustedForwarder()` function
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _trustedForwarder
    ) ERC2771ContextUpgradeable(_trustedForwarder) {
        _disableInitializers();
    }

    function initialize(
        address _initialOwner,
        address _smartAssetAddress,
        address _managerIdentity
    ) public initializer {
        __Ownable_init_unchained(_initialOwner);

        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        $.smartAsset = IArianeeSmartAsset(_smartAssetAddress);
        setManagerIdentity(_managerIdentity);
    }

    /**
     * @notice Sets the missing status for the given SmartAsset ID
     * @dev This can only be called by the SmartAsset owner and the SmartAsset must not already be marked as missing
     */
    function setMissingStatus(
        uint256 _tokenId
    ) external onlyTokenOwner(_tokenId) onlyHasNotBeenMissing(_tokenId) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        $.tokenMissingStatus[_tokenId] = true;
        emit Missing(_tokenId);
    }

    /**
     * @notice Unsets the missing status for the given SmartAsset ID
     * @dev This can only be called by the SmartAsset owner, and the SmartAsset must currently be marked as missing
     */
    function unsetMissingStatus(
        uint256 _tokenId
    ) external onlyTokenOwner(_tokenId) onlyHasBeenMissing(_tokenId) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        $.tokenMissingStatus[_tokenId] = false;
        emit UnMissing(_tokenId);
    }

    /**
     * @notice Returns whether the SmartAsset is marked as missing
     * @return _isMissing True if the SmartAsset is marked as missing, false otherwise
     */
    function isMissing(
        uint256 _tokenId
    ) public view returns (bool _isMissing) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        _isMissing = $.tokenMissingStatus[_tokenId];
    }

    /**
     * @notice Marks the given SmartAsset as stolen
     * @dev Can only be called by an authorized identity, and the SmartAsset must be marked as missing
     */
    function setStolenStatus(
        uint256 _tokenId
    ) external onlyAuthorizedIdentity {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require($.tokenMissingStatus[_tokenId] == true);
        require($.tokenStolenStatus[_tokenId] == false);

        $.tokenStolenStatus[_tokenId] = true;
        $.tokenStolenIssuer[_tokenId] = _msgSender();

        emit Stolen(_tokenId);
    }

    /**
     * @notice Removes the stolen status from the given SmartAsset ID
     * @dev Can only be called by the manager or the identity that initially marked the SmartAsset as stolen
     */
    function unsetStolenStatus(
        uint256 _tokenId
    ) external onlyAuthorizedIdentityOrManager {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        require(_msgSender() == $.tokenStolenIssuer[_tokenId] || _msgSender() == $.managerIdentity);

        $.tokenStolenStatus[_tokenId] = false;
        $.tokenStolenIssuer[_tokenId] = address(0);

        emit UnStolen(_tokenId);
    }

    /**
     * @notice Returns whether the SmartAsset is marked as stolen
     * @return _isStolen True if the SmartAsset is marked as stolen, false otherwise
     */
    function isStolen(
        uint256 _tokenId
    ) external view returns (bool _isStolen) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        return $.tokenStolenStatus[_tokenId];
    }

    /**
     * @notice Sets the manager identity for the contract
     * @dev Can only be called by the contract owner
     */
    function setManagerIdentity(
        address _managerIdentity
    ) public onlyOwner {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        $.managerIdentity = _managerIdentity;
        emit NewManagerIdentity(_managerIdentity);
    }

    /**
     * @notice Adds a new authorized identity to manage stolen statuses
     * @dev Can only be called by the manager
     */
    function setAuthorizedIdentity(
        address _newIdentityAuthorized
    ) external onlyManager {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        $.authorizedIdentities[_newIdentityAuthorized] = true;
        emit AuthorizedIdentityAdded(_newIdentityAuthorized);
    }

    /**
     * @notice Removes an authorized identity from managing stolen statuses
     * @dev Can only be called by the manager
     */
    function unsetAuthorizedIdentity(
        address _newIdentityUnauthorized
    ) external onlyManager {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        $.authorizedIdentities[_newIdentityUnauthorized] = false;
        emit AuthorizedIdentityRemoved(_newIdentityUnauthorized);
    }

    /**
     * @notice Checks if an address is authorized to manage stolen statuses
     * @return _isAuthorized True if the address is authorized, false otherwise
     */
    function isAddressAuthorized(
        address _address
    ) external view returns (bool _isAuthorized) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        return $.authorizedIdentities[_address];
    }

    /**
     * @notice Returns the manager's address
     * @return _managerIdentity The address of the current manager
     */
    function getManagerIdentity() external view returns (address _managerIdentity) {
        ArianeeLostStorageV0 storage $ = _getArianeeLostStorageV0();
        return $.managerIdentity;
    }

    function _contextSuffixLength()
        internal
        view
        override (ERC2771ContextUpgradeable, ContextUpgradeable)
        returns (uint256)
    {
        return ERC2771ContextUpgradeable._contextSuffixLength();
    }

    function _msgData()
        internal
        view
        override (ERC2771ContextUpgradeable, ContextUpgradeable)
        returns (bytes calldata)
    {
        return ERC2771ContextUpgradeable._msgData();
    }

    function _msgSender() internal view override (ERC2771ContextUpgradeable, ContextUpgradeable) returns (address) {
        return ERC2771ContextUpgradeable._msgSender();
    }
}

/**
 * @notice Emitted when a new manager identity is set by the contract owner
 */
event NewManagerIdentity(address indexed _newManagerIdentity);

/**
 * @notice Emitted when a SmartAsset is declared missing by its owner
 */
event Missing(uint256 indexed _tokenId);

/**
 * @notice Emitted when a SmartAsset is declared no longer missing by its owner
 */
event UnMissing(uint256 indexed _tokenId);

/**
 * @notice Emitted when the manager adds a new authorized identity
 */
event AuthorizedIdentityAdded(address indexed _newIdentityAuthorized);

/**
 * @notice Emitted when the manager removes an authorized identity
 */
event AuthorizedIdentityRemoved(address indexed _newIdentityUnauthorized);

/**
 * @notice Emitted when an authorized identity declares a SmartAsset as stolen
 */
event Stolen(uint256 indexed _tokenId);

/**
 * @notice Emitted when an authorized identity declares a SmartAsset as no longer stolen
 */
event UnStolen(uint256 indexed _tokenId);
