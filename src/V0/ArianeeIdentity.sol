// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeIdentity } from "./Interfaces/IArianeeIdentity.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

/**
 * @title ArianeeIdentity
 * @notice This contract manage the identity of an issuer in the Arianee Protocol.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeIdentity is IArianeeIdentity, Initializable, ERC2771ContextUpgradeable, OwnableUpgradeable {
    /// @custom:storage-location erc7201:arianeeidentity.storage.v0
    struct ArianeeIdentityStorageV0 {
        /**
         * @notice Indicates if an address is on the approved list, allowing it to manage its URI and imprint
         */
        mapping(address => bool) approvedList;
        /**
         * @notice Links an address to its corresponding URI
         */
        mapping(address => string) addressToUri;
        /**
         * @notice Links an address to its corresponding imprint (hash of associated data)
         */
        mapping(address => bytes32) addressToImprint;
        /**
         * @notice Stores the pending URI update for an address before validation
         */
        mapping(address => string) addressToWaitingUri;
        /**
         * @notice Stores the pending imprint update for an address before validation
         */
        mapping(address => bytes32) addressToWaitingImprint;
        /**
         * @notice Records the date when an address was marked as compromised
         */
        mapping(address => uint256) compromiseDate;
        /**
         * @notice Maps a short identifier (bytes3) to its corresponding address
         */
        mapping(bytes3 => address) addressListing;
        /**
         * @notice The address of the bouncer, responsible for managing the approved list and compromise dates
         */
        address bouncerAddress;
        /**
         * @notice The address of the validator, responsible for validating pending URI and imprint updates
         */
        address validatorAddress;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeeidentity.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeIdentityStorageV0Location =
        0x752b70e5aa143ce19d2e21e2c2168f140d8d7a955afc6436c3a7cbdb3b137300;

    function _getArianeeIdentityStorageV0() internal pure returns (ArianeeIdentityStorageV0 storage $) {
        bytes32 storageLocation = ArianeeIdentityStorageV0Location;
        assembly {
            $.slot := storageLocation
        }
    }

    /**
     * @notice Ensures that the specified address is on the approved list before executing the function
     * @dev Reverts if the address is not approved. Used to restrict function access to approved identities
     */
    modifier isApproved(
        address _identity
    ) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        require($.approvedList[_identity], "ArianeeIdentity: Address not approved");
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
        address _newBouncerAddress,
        address _newValidatorAddress
    ) public initializer {
        __Ownable_init_unchained(_initialOwner);

        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        $.bouncerAddress = _newBouncerAddress;
        $.validatorAddress = _newValidatorAddress;
    }

    /**
     * @notice Adds a new address to the approved list
     * @notice Enables the address to create or update its URI and imprint
     * @dev Can only be called by the bouncer
     * @return Id for the address in bytes3
     */
    function addAddressToApprovedList(
        address _newIdentity
    ) external returns (bytes3) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        require(_msgSender() == $.bouncerAddress, "ArianeeIdentity: Not the bouncer");
        $.approvedList[_newIdentity] = true;

        bytes memory _bytesAddress = abi.encodePacked(_newIdentity);
        bytes3 _addressId = _convertBytesToBytes3(_bytesAddress);

        $.addressListing[_addressId] = _newIdentity;

        emit AddressApprovedAdded(_newIdentity, _addressId);

        return _addressId;
    }

    /**
     * @notice Removes an address from the approved list
     * @dev Can only be called by the bouncer
     */
    function removeAddressFromApprovedList(
        address _identity
    ) external {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        require(_msgSender() == $.bouncerAddress, "ArianeeIdentity: Not the bouncer");
        $.approvedList[_identity] = false;
        emit AddressApprovedRemoved(_identity);
    }

    /**
     * @notice Checks if an identity address is approved
     */
    function addressIsApproved(
        address _identity
    ) external view returns (bool _isApproved) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        _isApproved = $.approvedList[_identity];
    }

    /**
     * @notice Updates the waiting URI and imprint for the caller
     * @dev Caller must be approved
     */
    function updateInformations(string calldata _uri, bytes32 _imprint) external isApproved(_msgSender()) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        $.addressToWaitingUri[_msgSender()] = _uri;
        $.addressToWaitingImprint[_msgSender()] = _imprint;

        emit URIUpdated(_msgSender(), _uri, _imprint);
    }

    /**
     * @notice Validates the waiting URI and imprint for a given identity
     * @dev Can only be called by the validator
     */
    function validateInformation(
        address _identity,
        string calldata _uriToValidate,
        bytes32 _imprintToValidate
    ) external {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        require(_msgSender() == $.validatorAddress, "ArianeeIdentity: Not the validator");
        require($.addressToWaitingImprint[_identity] == _imprintToValidate, "ArianeeIdentity: No waiting imprint match");
        require(
            keccak256(abi.encodePacked($.addressToWaitingUri[_identity])) == keccak256(abi.encodePacked(_uriToValidate)),
            "ArianeeIdentity: No waiting URI match"
        );

        $.addressToUri[_identity] = $.addressToWaitingUri[_identity];
        $.addressToImprint[_identity] = $.addressToWaitingImprint[_identity];

        emit URIValidate(_identity, $.addressToWaitingUri[_identity], $.addressToWaitingImprint[_identity]);

        delete $.addressToWaitingUri[_identity];
        delete $.addressToWaitingImprint[_identity];
    }

    /**
     * @notice Retrieves the compromise date for an identity
     * @return _compromiseDate The compromise date
     */
    function compromiseIdentityDate(
        address _identity
    ) external view returns (uint256 _compromiseDate) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        _compromiseDate = $.compromiseDate[_identity];
    }

    /**
     * @notice Updates the compromise date for a given identity
     * @dev Can only be called by the bouncer
     */
    function updateCompromiseDate(address _identity, uint256 _compromiseDate) external {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        require(_msgSender() == $.bouncerAddress, "ArianeeIdentity: Not the bouncer");
        $.compromiseDate[_identity] = _compromiseDate;
        emit IdentityCompromised(_identity, _compromiseDate);
    }

    /**
     * @notice Retrieves the URI associated with an identity
     * @return _uri The associated URI
     */
    function addressURI(
        address _identity
    ) external view returns (string memory _uri) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        _uri = $.addressToUri[_identity];
    }

    /**
     * @notice Retrieves the imprint for a given identity
     * @return _imprint The associated imprint
     */
    function addressImprint(
        address _identity
    ) external view returns (bytes32 _imprint) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        _imprint = $.addressToImprint[_identity];
    }

    /**
     * @notice Retrieves the waiting URI for an identity
     * @return _waitingUri The waiting URI
     */
    function waitingURI(
        address _identity
    ) external view returns (string memory _waitingUri) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        _waitingUri = $.addressToWaitingUri[_identity];
    }

    /**
     * @notice Retrieves the waiting imprint for an identity
     * @return _waitingImprint The waiting imprint
     */
    function waitingImprint(
        address _identity
    ) external view returns (bytes32 _waitingImprint) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        _waitingImprint = $.addressToWaitingImprint[_identity];
    }

    /**
     * @notice Retrieves the address associated with a given short ID
     * @return _identity The associated address
     */
    function addressFromId(
        bytes3 _id
    ) external view returns (address _identity) {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        _identity = $.addressListing[_id];
    }

    /**
     * @notice Updates the bouncer address
     */
    function updateBouncerAddress(
        address _newBouncerAddress
    ) public onlyOwner {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        $.bouncerAddress = _newBouncerAddress;
        emit SetAddress("bouncerAddress", _newBouncerAddress);
    }

    /**
     * @notice Updates the validator address
     */
    function updateValidatorAddress(
        address _newValidatorAddress
    ) public onlyOwner {
        ArianeeIdentityStorageV0 storage $ = _getArianeeIdentityStorageV0();
        $.validatorAddress = _newValidatorAddress;
        emit SetAddress("validatorAddress", _newValidatorAddress);
    }

    /**
     * @dev Convert a bytes in bytes3
     * @param _inBytes input bytes
     * @return _outBytes3 output bytes3
     */
    function _convertBytesToBytes3(
        bytes memory _inBytes
    ) internal pure returns (bytes3 _outBytes3) {
        if (_inBytes.length == 0) {
            return 0x0;
        }

        assembly {
            _outBytes3 := mload(add(_inBytes, 32))
        }
    }

    function _contextSuffixLength()
        internal
        view
        override (ContextUpgradeable, ERC2771ContextUpgradeable)
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
 * @notice Emitted when a new address is approved
 */
event AddressApprovedAdded(address _newIdentity, bytes3 _addressId);

/**
 * @notice Emitted when an address is removed from the approved list
 */
event AddressApprovedRemoved(address _newIdentity);

/**
 * @notice Emitted when the URI of an identity is updated
 */
event URIUpdated(address _identity, string _uri, bytes32 _imprint);

/**
 * @notice Emitted when an identity's URI and imprint are validated
 */
event URIValidate(address _identity, string _uri, bytes32 _imprint);

/**
 * @notice Emitted when an identity is compromised, and a compromise date is set
 */
event IdentityCompromised(address _identity, uint256 _compromiseDate);

/**
 * @notice Emitted when a new address is set for a specific role
 */
event SetAddress(string _addressType, address _newAddress);
