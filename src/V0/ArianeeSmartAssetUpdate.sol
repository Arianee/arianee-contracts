// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeSmartAssetUpdate } from "./Interfaces/IArianeeSmartAssetUpdate.sol";
import { IArianeeSmartAsset } from "./Interfaces/IArianeeSmartAsset.sol";
import { IArianeeStore } from "./Interfaces/IArianeeStore.sol";
import { ROLE_ADMIN, ROLE_ARIANEE_STORE } from "./Constants.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

struct Update {
    bytes32 imprint;
    uint256 updateTimestamp;
}

/**
 * @title ArianeeSmartAssetUpdate
 * @notice This contract manage the updates of the SmartAssets. Each update is incremental on top of the parent SmartAsset and the previous update.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeSmartAssetUpdate is
    IArianeeSmartAssetUpdate,
    Initializable,
    ERC2771ContextUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable
{
    /// @custom:storage-location erc7201:arianeesmartassetupdate.storage.v0
    struct ArianeeSmartAssetUpdateStorageV0 {
        /**
         * @notice The ArianeeSmartAsset contract
         */
        IArianeeSmartAsset smartAsset;
        /**
         * @notice The ArianeeStore contract
         */
        IArianeeStore store;
        /**
         * @notice Mapping from SmartAsset ID to its associated rewards
         */
        mapping(uint256 => uint256) idToRewards; // rewards
        /**
         * @notice Mapping from SmartAsset ID to its last update
         */
        mapping(uint256 => Update) idToLastUpdate; // smartAssetUpdate
    }

    // keccak256(abi.encode(uint256(keccak256("arianeesmartassetupdate.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeSmartAssetUpdateStorageV0Location =
        0x14767ed6d2dd5e021cb082325b8af1b056ecc4a79dfabd36e244f0d0d51ef200;

    function _getArianeeSmartAssetUpdateStorageV0()
        internal
        pure
        returns (ArianeeSmartAssetUpdateStorageV0 storage $)
    {
        assembly {
            $.slot := ArianeeSmartAssetUpdateStorageV0Location
        }
    }

    /**
     * @dev You can change the trusted forwarder after initial deployment by overriding the `ERC2771ContextUpgradeable.trustedForwarder()` function
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _trustedForwarder
    ) ERC2771ContextUpgradeable(_trustedForwarder) {
        _disableInitializers();
    }

    function initialize(address _initialAdmin, address _smartAssetAddress, address _storeAddress) public initializer {
        __Pausable_init_unchained();

        _grantRole(ROLE_ADMIN, _initialAdmin);

        ArianeeSmartAssetUpdateStorageV0 storage $ = _getArianeeSmartAssetUpdateStorageV0();
        $.smartAsset = IArianeeSmartAsset(_smartAssetAddress);
        $.store = IArianeeStore(_storeAddress);
    }

    /**
     * @notice Update a smartAsset with a new imprint
     * @dev Must be called by an authorized address
     * @dev Must have an `_issuer` param that is the issuer of the SmartAsset
     * @dev History of the updates can be reconstructed from the `SmartAssetUpdated` event
     * @param _tokenId SmartAsset ID
     * @param _imprint Imprint (hash of the SmartAsset data)
     * @param _issuer Address of the issuer (will fail if not matching `issuerOf(_tokenId)`)
     * @param _rewards Rewards for the action
     */
    function updateSmartAsset(
        uint256 _tokenId,
        bytes32 _imprint,
        address _issuer,
        uint256 _rewards
    ) external onlyRole(ROLE_ARIANEE_STORE) {
        ArianeeSmartAssetUpdateStorageV0 storage $ = _getArianeeSmartAssetUpdateStorageV0();
        require(_issuer == $.smartAsset.issuerOf(_tokenId), "ArianeeSmartAssetUpdate: Invalid `_issuer`");

        $.idToLastUpdate[_tokenId] = Update({ imprint: _imprint, updateTimestamp: block.timestamp });
        $.idToRewards[_tokenId] = _rewards;

        emit SmartAssetUpdated(_tokenId, _imprint);
    }

    /**
     * @notice Set an update as read
     * @dev Must be called by an authorized address
     * @dev Must have a `_from` param that is an operator of the SmartAsset
     * @param _tokenId SmartAsset ID
     * @param _from Address of the operator or owner
     */
    function readUpdateSmartAsset(
        uint256 _tokenId,
        address _from
    ) external onlyRole(ROLE_ARIANEE_STORE) returns (uint256) {
        ArianeeSmartAssetUpdateStorageV0 storage $ = _getArianeeSmartAssetUpdateStorageV0();
        require($.smartAsset.canOperate(_tokenId, _from), "ArianeeSmartAssetUpdate: Not an operator");

        uint256 _rewards = $.idToRewards[_tokenId];
        delete $.idToRewards[_tokenId];

        emit SmartAssetUpdateReaded(_tokenId);
        return _rewards;
    }

    /**
     * @notice Returns the imprint of a SmartAsset (the last updated one if the SmartAsset has at least one update, the original one otherwise)
     * @param _tokenId SmartAsset ID
     * @return bytes32 Imprint (hash of the SmartAsset data)
     */
    function getImprint(
        uint256 _tokenId
    ) public view returns (bytes32) {
        bytes32 updatedImprint = getUpdatedImprint(_tokenId);
        if (updatedImprint == bytes32(0)) {
            ArianeeSmartAssetUpdateStorageV0 storage $ = _getArianeeSmartAssetUpdateStorageV0();
            bytes32 imprint = $.smartAsset.tokenImprint(_tokenId);
            require(imprint != bytes32(0), "ArianeeSmartAssetUpdate: This SmartAsset does not exist");
            return imprint;
        } else {
            return updatedImprint;
        }
    }

    /**
     * @dev Returns the last updated imprint of a SmartAsset
     * @param _tokenId SmartAsset ID
     * @return bytes32 Imprint (hash of the SmartAsset data) or `bytes32(0)` if not updated
     */
    function getUpdatedImprint(
        uint256 _tokenId
    ) public view returns (bytes32) {
        return _getArianeeSmartAssetUpdateStorageV0().idToLastUpdate[_tokenId].imprint;
    }

    /**
     * @notice Returns the last update of a SmartAsset
     * @param _tokenId SmartAsset ID
     * @return bool A flag indicating if the SmartAsset has been updated
     * @return bytes32 Last updated imprint (hash of the SmartAsset data) or `bytes32(0)` if not updated
     * @return bytes32 Original imprint (hash of the SmartAsset data)
     * @return uint256 Timestamp of the last update
     */
    function getUpdate(
        uint256 _tokenId
    ) public view returns (bool, bytes32, bytes32, uint256) {
        ArianeeSmartAssetUpdateStorageV0 storage $ = _getArianeeSmartAssetUpdateStorageV0();
        bytes32 originalImprint = $.smartAsset.tokenImprint(_tokenId);
        require(originalImprint != 0, "ArianeeSmartAssetUpdate: This SmartAsset does not exist");

        bool isUpdated = $.idToLastUpdate[_tokenId].imprint != 0;
        return
            (isUpdated, $.idToLastUpdate[_tokenId].imprint, originalImprint, $.idToLastUpdate[_tokenId].updateTimestamp);
    }

    // Internal Overrides

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
 * @dev This emits when a certificate is updated
 */
event SmartAssetUpdated(uint256 indexed _tokenId, bytes32 indexed _imprint);

/**
 * @dev This emits when a certificate update is read
 */
event SmartAssetUpdateReaded(uint256 indexed _tokenId);
