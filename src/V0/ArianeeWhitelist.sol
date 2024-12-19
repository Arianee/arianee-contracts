// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeWhitelist } from "./Interfaces/IArianeeWhitelist.sol";
import { ROLE_ADMIN, ROLE_WHITELIST_MANAGER } from "./Constants.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

/**
 * @title ArianeeWhitelist
 *  @notice This contract manages the whitelist and blacklist functionalities for SmartAssets within the Arianee Protocol. It enables issuers to define and manage permissions for addresses interacting with specific SmartAsset.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeWhitelist is IArianeeWhitelist, Initializable, ERC2771ContextUpgradeable, AccessControlUpgradeable {
    /// @custom:storage-location erc7201:arianeewhitelist.storage.v0
    struct ArianeeWhitelistStorageV0 {
        /**
         * @notice Tracks addresses that are whitelisted for specific SmartAsset
         */
        mapping(uint256 => mapping(address => bool)) whitelistedAddress;
        /**
         * @notice Tracks addresses blacklisted by SmartAsset owners for specific SmartAsset
         */
        mapping(address => mapping(uint256 => mapping(address => bool))) optOutAddressPerOwner;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeewhitelist.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeWhitelistStorageV0Location =
        0x4765b9a90ccc6c0f74700205e150060852d2779ff79814ceccb7a3dccb624300;

    function _getArianeeWhitelistStorageV0() internal pure returns (ArianeeWhitelistStorageV0 storage $) {
        assembly {
            $.slot := ArianeeWhitelistStorageV0Location
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

    function initialize(
        address _initialAdmin,
        address _arianeeEventAddress,
        address _smartAssetAddress
    ) public initializer {
        _grantRole(ROLE_ADMIN, _initialAdmin);
        _grantRole(ROLE_WHITELIST_MANAGER, _arianeeEventAddress);
        _grantRole(ROLE_WHITELIST_MANAGER, _smartAssetAddress);
    }

    /**
     * @notice Adds an address to the whitelist for a specific SmartAsset
     * @dev Can only be called by contract authorized
     */
    function addWhitelistedAddress(uint256 _tokenId, address _address) external onlyRole(ROLE_WHITELIST_MANAGER) {
        ArianeeWhitelistStorageV0 storage $ = _getArianeeWhitelistStorageV0();
        $.whitelistedAddress[_tokenId][_address] = true;
        emit WhitelistedAddressAdded(_tokenId, _address);
    }

    /**
     * @notice Checks if an address is whitelisted for a specific SmartAsset
     */
    function isWhitelisted(uint256 _tokenId, address _address) public view returns (bool _isWhitelisted) {
        ArianeeWhitelistStorageV0 storage $ = _getArianeeWhitelistStorageV0();
        _isWhitelisted = $.whitelistedAddress[_tokenId][_address];
    }

    /**
     * @notice Adds or removes an address from the blacklist for a specific SmartAsset
     * @dev Blacklisting is managed per owner for the given SmartAsset
     */
    function addBlacklistedAddress(address _sender, uint256 _tokenId, bool _activate) external {
        ArianeeWhitelistStorageV0 storage $ = _getArianeeWhitelistStorageV0();
        $.optOutAddressPerOwner[_msgSender()][_tokenId][_sender] = _activate;
        emit BlacklistedAddresAdded(_sender, _tokenId, _activate);
    }

    /**
     * @notice Checks if an address is blacklisted for a specific SmartAsset
     */
    function isBlacklisted(
        address _owner,
        address _sender,
        uint256 _tokenId
    ) public view returns (bool _isBlacklisted) {
        ArianeeWhitelistStorageV0 storage $ = _getArianeeWhitelistStorageV0();
        _isBlacklisted = $.optOutAddressPerOwner[_owner][_tokenId][_sender];
    }

    /**
     * @notice Checks if an address is authorized to send a message to the owner of a specific SmartAsset
     * @dev Authorization is based on whether the sender is whitelisted and not blacklisted by the SmartAsset owner
     */
    function isAuthorized(uint256 _tokenId, address _sender, address _tokenOwner) external view returns (bool) {
        ArianeeWhitelistStorageV0 storage $ = _getArianeeWhitelistStorageV0();
        return ($.whitelistedAddress[_tokenId][_sender] && !isBlacklisted(_tokenOwner, _sender, _tokenId));
    }

    // Overrides

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
 * @notice This emits when a new address is whitelisted for a SmartAsset
 */
event WhitelistedAddressAdded(uint256 _tokenId, address _address);

/**
 * @notice This emits when an address is blacklisted by a SmartAsset owner on a given token
 */
event BlacklistedAddresAdded(address _sender, uint256 _tokenId, bool _activate);
