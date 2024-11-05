// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless Libraries
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {
    ROLE_SMART_ASSET_MANAGER,
    ERC721_NAME,
    ERC721_SYMBOL,
    URI_BASE,
    ACCESS_TYPE_VIEW,
    ACCESS_TYPE_TRANSFER
} from "./Constants.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
// Access
import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
// ERC721
import { ERC721Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import { ERC721PausableUpgradeable } from
    "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721PausableUpgradeable.sol";
import { ERC721EnumerableUpgradeable } from
    "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";

/**
 * TODO
 * - Add MetaTx (Forwarder)
 * - Add Store and Whitelist contracts
 * - Check if the `approve` calls are needed
 * - Check if the `canTransfer` and `canDestroy` calls are needed (maybe move the logic here)
 */

// TODO: Move struct and events to a separate file
struct Cert {
    address tokenIssuer;
    uint256 tokenCreationDate;
    uint256 tokenRecoveryTimestamp;
}

/**
 * @notice This emits when a new address is set for a given type (e.g. storeAddress, whitelistAddress)
 */
event SetAddress(string _addressType, address _newAddress);

/**
 * @notice This emits when a SmartAsset is hydrated
 */
event Hydrated(
    uint256 indexed _tokenId,
    bytes32 indexed _imprint,
    string _uri,
    address _initialKey,
    uint256 _tokenRecoveryTimestamp,
    bool _initialKeyIsRequestKey,
    uint256 _tokenCreation
);

/**
 * @notice This emits when an issuer request a SmartAsset recovery
 */
event RecoveryRequestUpdated(uint256 indexed _tokenId, bool _active);
/**
 * @notice This emits when a SmartAsset is recovered to the issuer
 */

event TokenRecovered(uint256 indexed _token);

/**
 * @notice This emits when a SmartAsset's URI is udpated
 */
event TokenURIUpdated(uint256 indexed _tokenId, string URI);

/**
 * @notice This emits when a access is added
 */
event TokenAccessAdded(uint256 indexed _tokenId, address _encryptedTokenKey, bool _enable, uint256 _tokenType); // TODO: Do we rename this to `_accessType` ?

/**
 * @notice This emits when a access is destroyed
 */
event TokenDestroyed(uint256 indexed _tokenId);

/**
 * @notice This emits when the base URI is udpated
 */
event SetNewUriBase(string _newUriBase);

contract ArianeeSmartAsset is
    Initializable,
    ContextUpgradeable,
    Ownable2StepUpgradeable,
    AccessControlUpgradeable,
    ERC721Upgradeable,
    ERC721PausableUpgradeable,
    ERC721EnumerableUpgradeable
{
    using Strings for uint256;

    /// @custom:storage-location erc7201:arianeesmartasset.storage.v0
    struct ArianeeSmartAssetStorageV0 {
        /**
         * @notice Mapping from SmartAsset ID to URI
         */
        mapping(uint256 => string) idToUri;
        /**
         * @notice Mapping from SmartAsset ID to access (0 = view, 1 = transfer)
         */
        mapping(uint256 => mapping(uint256 => address)) idToAccess;
        /**
         * @notice Mapping from SmartAsset ID to imprint
         */
        mapping(uint256 => bytes32) idToImprint;
        /**
         * @notice Mapping from SmartAsset ID to recovery request
         */
        mapping(uint256 => bool) idToRecoveryRequest;
        /**
         * @notice Mapping from SmartAsset ID to certificate struct (issuer, creation date, recovery timestamp)
         */
        mapping(uint256 => Cert) idToCertificate;
        /**
         * @notice Mapping from SmartAsset ID to a boolean that indicates whether the first transfer has been done or not
         */
        mapping(uint256 => bool) idToFirstTransfer;
        /**
         * @notice Base URI used to construct the URI of each SmartAsset
         */
        string baseURI;
        /**
         * @notice Flag indicating if the SmartAsset is soulbound (non-transferable)
         */
        bool isSoulbound;
        /**
         * @notice Mapping from a role to its activation status (true = activated, false = deactivated)
         */
        mapping(bytes32 => bool) roleToActivation;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeesmartasset.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeSmartAssetStorageV0Location =
        0xce11c990cebe29c3b1e73f2e04c7eebbd235d66b39e13c6f0bc9dcde9a868500;

    function _getArianeeSmartAssetStorageV0() internal pure returns (ArianeeSmartAssetStorageV0 storage $) {
        assembly {
            $.slot := ArianeeSmartAssetStorageV0Location
        }
    }

    // TODO: IArianeeWhitelist public arianeeWhitelist;
    // TODO: IArianeeStore public store;

    /**
     * @notice Modifier that checks that an account has a specific role, pass if the role is deactivated
     * @param role Role to check
     */
    modifier onlyActivatedRole(
        bytes32 role
    ) {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        if ($.roleToActivation[role] == true) {
            _checkRole(role);
        }
        _;
    }

    /**
     * @notice Check if an address is a valid operator for a given SmartAsset
     * @param _tokenId SmartAsset ID
     * @param _operator Operator address
     */
    modifier isOperator(uint256 _tokenId, address _operator) {
        require(canOperate(_tokenId, _operator), "ArianeeSmartAsset: Not an operator");
        _;
    }

    /**
     * @notice Check if the _msgSender() is the issuer of a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    modifier isIssuer(
        uint256 _tokenId
    ) {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        require(_msgSender() == $.idToCertificate[_tokenId].tokenIssuer, "ArianeeSmartAsset: Not the issuer");
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _arianeeWhitelistAddress, address _forwarder, bool _isSoulbound) public initializer {
        __Ownable_init_unchained(msg.sender);
        __Pausable_init_unchained();
        __ERC721_init_unchained(ERC721_NAME, ERC721_SYMBOL);

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        $.isSoulbound = _isSoulbound;

        setWhitelistAddress(_arianeeWhitelistAddress);
        setUriBase(URI_BASE);

        activateRole(ROLE_SMART_ASSET_MANAGER);

        // TODO: _setTrustedForwarder(_forwarder);
    }

    // TODO: Forwarder
    // function updateForwarderAddress(
    //     address _forwarder
    // ) external onlyOwner {
    //     _setTrustedForwarder(_forwarder);
    // }

    /**
     * @notice Mint a new SmartAsset with a given ID
     * @dev Must be called by an authorized address
     * @param _tokenId SmartAsset ID
     * @param _to Address of the new owner
     */
    function reserveToken(
        uint256 _tokenId,
        address _to
    ) external onlyActivatedRole(ROLE_SMART_ASSET_MANAGER) whenNotPaused {
        _mint(_to, _tokenId);

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        $.idToFirstTransfer[_tokenId] = true;
    }

    /**
     * @notice Hydrate (populate) a SmartAsset with a given set of data
     * @dev Must be called by an authorized address
     * @dev Must be called by an operator
     * @dev Can only be called once
     * @param _tokenId SmartAsset ID
     * @param _imprint Imprint
     * @param _uri URI
     * @param _initialKey Public key of the initial access (derived from a private key or a passphrase)
     * @param _tokenRecoveryTimestamp Maximum timestamp for the recovery of the SmartAsset by the issuer throught the `recoverTokenToIssuer` function
     * @param _initialKeyIsRequestKey Enable the initial key also as a request key
     * @param _issuer Address of the issuer (the one that has `reserveToken` the SmartAsset may not be the issuer)
     */
    function hydrateToken(
        uint256 _tokenId,
        bytes32 _imprint,
        string memory _uri,
        address _initialKey,
        uint256 _tokenRecoveryTimestamp,
        bool _initialKeyIsRequestKey,
        address _issuer
    ) public onlyActivatedRole(ROLE_SMART_ASSET_MANAGER) isOperator(_tokenId, _issuer) whenNotPaused {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        require(!($.idToCertificate[_tokenId].tokenCreationDate > 0), "ArianeeSmartAsset: SmartAsset already hydrated");

        uint256 _tokenCreation = block.timestamp;
        $.idToAccess[_tokenId][ACCESS_TYPE_VIEW] = _initialKey;
        $.idToImprint[_tokenId] = _imprint;
        $.idToUri[_tokenId] = _uri;

        // TODO: arianeeWhitelist.addWhitelistedAddress(_tokenId, _issuer);

        if (_initialKeyIsRequestKey) {
            $.idToAccess[_tokenId][ACCESS_TYPE_TRANSFER] = _initialKey;
        }

        Cert memory _cert = Cert({
            tokenIssuer: _issuer,
            tokenCreationDate: _tokenCreation,
            tokenRecoveryTimestamp: _tokenRecoveryTimestamp
        });

        $.idToCertificate[_tokenId] = _cert;

        emit Hydrated(
            _tokenId, _imprint, _uri, _initialKey, _tokenRecoveryTimestamp, _initialKeyIsRequestKey, _tokenCreation
        );
    }

    /**
     * @notice Transfer the ownership of a SmartAsset to a new owner
     * @dev Must be called with a valid signature according to the current access
     * @dev Must be called by an authorized address
     * @param _tokenId SmartAsset ID
     * @param _hash Keccak256 hash of the SmartAsset ID and the new owner address `keccak256(abi.encode(_tokenId, _newOwner))`
     * @param _keepCurrentAccess Keep the current access after the transfer
     * @param _newOwner Address of the new owner
     */
    function requestToken(
        uint256 _tokenId,
        bytes32 _hash,
        bool _keepCurrentAccess,
        address _newOwner,
        bytes calldata _signature
    ) external onlyActivatedRole(ROLE_SMART_ASSET_MANAGER) whenNotPaused {
        require(
            isAccessValid(_tokenId, _hash, ACCESS_TYPE_TRANSFER, _signature),
            "ArianeeSmartAsset: Invalid `_hash` or `_signature`"
        );

        bytes32 message = keccak256(abi.encode(_tokenId, _newOwner));
        require(MessageHashUtils.toEthSignedMessageHash(message) == _hash, "ArianeeSmartAsset: Invalid `_hash`");

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();

        if (_keepCurrentAccess) {
            require(
                $.isSoulbound == false,
                "ArianeeSmartAsset: Forbidden to keep the current access on a soulbound SmartAsset"
            );
        } else {
            $.idToAccess[_tokenId][ACCESS_TYPE_TRANSFER] = address(0);
        }

        // We do need an approve here because we use the `transferFrom` function instead of the `_transfer` function (which does not require an approval)
        // We use the `transferFrom` function because we want to use our custom logic in the `transferFrom` function override
        _approve(_msgSender(), _tokenId, address(0));

        address tokenOwner = _ownerOf(_tokenId);
        transferFrom(tokenOwner, _newOwner, _tokenId);
    }

    /**
     * @notice Add an access to a given SmartAsset
     * @dev Must be called by an operator
     * @param _tokenId SmartAsset ID
     * @param _key Public key of the new access (derived from a private key or a passphrase)
     * @param _enable Enable or disable the access
     * @param _accessType Type of access (0 = view, 1 = transfer)
     */
    function addTokenAccess(
        uint256 _tokenId,
        address _key,
        bool _enable,
        uint256 _accessType
    ) external isOperator(_tokenId, _msgSender()) whenNotPaused {
        require(_accessType > 0, "ArianeeSmartAsset: Invalid access type");

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();

        bool isTransferTokenAccess = (_accessType == ACCESS_TYPE_TRANSFER);
        if (isTransferTokenAccess && $.isSoulbound) {
            address tokenOwner = _requireOwned(_tokenId);
            address tokenIssuer = $.idToCertificate[_tokenId].tokenIssuer;
            require(
                tokenOwner == tokenIssuer,
                "ArianeeSmartAsset: Only the issuer can add a transfer access to a soulbound SmartAsset"
            );
        }

        if (_enable) {
            $.idToAccess[_tokenId][_accessType] = _key;
        } else {
            $.idToAccess[_tokenId][_accessType] = address(0);
        }

        emit TokenAccessAdded(_tokenId, _key, _enable, _accessType);
    }

    /**
     * @notice Recover a SmartAsset to the issuer
     * @dev Must be called by the issuer and before the recovery timestamp
     * @param _tokenId SmartAsset ID
     */
    function recoverTokenToIssuer(
        uint256 _tokenId
    ) external isIssuer(_tokenId) whenNotPaused {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        require(
            block.timestamp < $.idToCertificate[_tokenId].tokenRecoveryTimestamp,
            "ArianeeSmartAsset: Recovery timestamp reached"
        );

        address tokenIssuer = $.idToCertificate[_tokenId].tokenIssuer;
        address tokenOwner = _requireOwned(_tokenId);
        require(tokenIssuer != tokenOwner, "ArianeeSmartAsset: Issuer is already the owner");

        // _approve(tokenIssuer, _tokenId, address(0)); // TODO: Check if this approve is needed ?
        _transfer(tokenOwner, tokenIssuer, _tokenId);
        emit TokenRecovered(_tokenId);
    }

    /**
     * @notice Update the status of a recovery request
     * @dev Must be called by the issuer
     * @param _tokenId SmartAsset ID
     * @param _active New status of the recovery request
     */
    function updateRecoveryRequest(uint256 _tokenId, bool _active) external isIssuer(_tokenId) whenNotPaused {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        $.idToRecoveryRequest[_tokenId] = _active;

        emit RecoveryRequestUpdated(_tokenId, _active);
    }

    /**
     * @notice Validate a recovery request and transfer the SmartAsset to the issuer
     * @dev Can be only called if a recovery request is active and by the owner of this contract
     * @param _tokenId SmartAsset ID
     */
    function validRecoveryRequest(
        uint256 _tokenId
    ) external onlyOwner {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        require(
            $.idToRecoveryRequest[_tokenId] == true, "ArianeeSmartAsset: No active recovery request for this SmartAsset"
        );
        $.idToRecoveryRequest[_tokenId] = false;

        // _approve(owner(), _tokenId, address(0)); // TODO: Check if this approve is needed ?

        address tokenOwner = _requireOwned(_tokenId);
        address tokenIssuer = $.idToCertificate[_tokenId].tokenIssuer;
        _transfer(tokenOwner, tokenIssuer, _tokenId);

        emit RecoveryRequestUpdated(_tokenId, false);
        emit TokenRecovered(_tokenId);
    }

    /**
     * @notice Update the URI of a given SmartAsset
     * @dev Must be called by the issuer
     * @param _tokenId SmartAsset ID
     * @param _uri New URI
     */
    function updateTokenURI(uint256 _tokenId, string calldata _uri) external isIssuer(_tokenId) whenNotPaused {
        _requireOwned(_tokenId);

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        $.idToUri[_tokenId] = _uri;

        emit TokenURIUpdated(_tokenId, _uri);
    }

    /**
     * @notice Destroy a given SmartAsset
     * @dev Must be called by the issuer
     * @param _tokenId SmartAsset ID
     */
    function destroy(
        uint256 _tokenId
    ) external whenNotPaused {
        // require(store.canDestroy(_tokenId, _msgSender(), isSoulbound)); // TODO: Do we keep this, maybe we move this logic here ?

        _burn(_tokenId);

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        delete $.idToFirstTransfer[_tokenId];
        delete $.idToImprint[_tokenId];
        delete $.idToUri[_tokenId];
        delete $.idToAccess[_tokenId][ACCESS_TYPE_VIEW];
        delete $.idToAccess[_tokenId][ACCESS_TYPE_TRANSFER];
        delete $.idToCertificate[_tokenId];

        emit TokenDestroyed(_tokenId);
    }

    /**
     * @notice Returns the issuer of a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    function issuerOf(
        uint256 _tokenId
    ) external view returns (address _tokenIssuer) {
        _requireOwned(_tokenId);
        _tokenIssuer = _getArianeeSmartAssetStorageV0().idToCertificate[_tokenId].tokenIssuer;
    }

    /**
     * @notice Returns the imprint of a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    function tokenImprint(
        uint256 _tokenId
    ) external view returns (bytes32 _imprint) {
        _requireOwned(_tokenId);
        _imprint = _getArianeeSmartAssetStorageV0().idToImprint[_tokenId];
    }

    /**
     * @notice Returns the creation date of a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    function tokenCreation(
        uint256 _tokenId
    ) external view returns (uint256 _tokenCreation) {
        _requireOwned(_tokenId);
        _tokenCreation = _getArianeeSmartAssetStorageV0().idToCertificate[_tokenId].tokenCreationDate;
    }

    /**
     * @notice Returns the recovery timestamp for a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    function tokenRecoveryDate(
        uint256 _tokenId
    ) external view returns (uint256 _tokenRecoveryTimestamp) {
        _requireOwned(_tokenId);
        _tokenRecoveryTimestamp = _getArianeeSmartAssetStorageV0().idToCertificate[_tokenId].tokenRecoveryTimestamp;
    }

    /**
     * @notice Returns the access of a given SmartAsset for a given type
     * @param _tokenId SmartAsset ID
     * @param _accessType Type of access (0 = view, 1 = transfer)
     */
    function tokenHashedAccess(uint256 _tokenId, uint256 _accessType) external view returns (address _tokenAccess) {
        _requireOwned(_tokenId);
        _tokenAccess = _getArianeeSmartAssetStorageV0().idToAccess[_tokenId][_accessType];
    }

    /**
     * @notice Check if an access is valid
     * @param _tokenId SmartAsset ID
     * @param _hash Keccak256 hash of the SmartAsset ID and the new owner address `keccak256(abi.encode(_tokenId, _newOwner))`
     * @param _accessType Type of access (0 = view, 1 = transfer)
     */
    function isAccessValid(
        uint256 _tokenId,
        bytes32 _hash,
        uint256 _accessType,
        bytes memory _signature
    ) public view returns (bool) {
        (address recovered,,) = ECDSA.tryRecover(_hash, _signature);
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        return recovered == $.idToAccess[_tokenId][_accessType];
    }

    /**
     * @notice Check if a SmartAsset is requestable
     * @param _tokenId SmartAsset ID
     */
    function isRequestable(
        uint256 _tokenId
    ) external view returns (bool) {
        return _getArianeeSmartAssetStorageV0().idToAccess[_tokenId][ACCESS_TYPE_TRANSFER] != address(0);
    }

    /**
     * @notice Returns the recovery request status for a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    function recoveryRequestOpen(
        uint256 _tokenId
    ) external view returns (bool _recoveryRequest) {
        _requireOwned(_tokenId);
        _recoveryRequest = _getArianeeSmartAssetStorageV0().idToRecoveryRequest[_tokenId];
    }

    /**
     * @notice Check if an operator is valid for a given SmartAsset
     * @param _tokenId SmartAsset ID
     * @param _operator Operator address
     * @return true if the operator is valid
     */
    function canOperate(uint256 _tokenId, address _operator) public view returns (bool) {
        address tokenOwner = _ownerOf(_tokenId);
        if (tokenOwner == address(0)) return false;
        return _isAuthorized(tokenOwner, _operator, _tokenId);
    }

    /**
     * @notice Set the base URI for all SmartAssets
     * @param _newURIBase new base URI
     */
    function setUriBase(
        string memory _newURIBase
    ) public onlyOwner {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        $.baseURI = _newURIBase;

        emit SetNewUriBase(_newURIBase);
    }

    /**
     * @notice Set the address of the store contract
     * @param _storeAddress Address of the store contract
     */
    function setStoreAddress(
        address _storeAddress
    ) external onlyOwner {
        // TODO: store = IArianeeStore(address(_storeAddress));
        emit SetAddress("storeAddress", _storeAddress);
    }

    /**
     * @notice Set the address of the whitelist contract
     * @param _whitelistAddres Address of the whitelist contract
     */
    function setWhitelistAddress(
        address _whitelistAddres
    ) public onlyOwner {
        // TODO: arianeeWhitelist = IArianeeWhitelist(address(_whitelistAddres));
        emit SetAddress("whitelistAddress", _whitelistAddres);
    }

    /**
     * @notice Activate a role (will be checked by the `onlyActivatedRole` modifier)
     * @param role Role to activate
     */
    function activateRole(
        bytes32 role
    ) public onlyOwner {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        $.roleToActivation[role] = true;
    }

    /**
     * @notice Deactivate a role (will always pass the `onlyActivatedRole` modifier)
     * @param role Role to deactivate
     */
    function deactivateRole(
        bytes32 role
    ) public onlyOwner {
        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        $.roleToActivation[role] = false;
    }

    /**
     * @notice Returns the activation status of a given role
     * @param role Role to check
     */
    function isRoleActive(
        bytes32 role
    ) public view returns (bool) {
        return _getArianeeSmartAssetStorageV0().roleToActivation[role];
    }

    // Public Overrides

    function tokenURI(
        uint256 tokenId
    ) public view override returns (string memory) {
        _requireOwned(tokenId);

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        if (bytes($.idToUri[tokenId]).length > 0) {
            return $.idToUri[tokenId];
        } else {
            return bytes($.baseURI).length > 0 ? string.concat($.baseURI, tokenId.toString()) : "";
        }
    }

    /**
     * @notice Override of the `transferFrom` function that perform multiple checks depending on the SmartAsset type
     * @dev Require the `IArianeeStore` contract to approve the transfer
     * @dev Dispatch the rewards at the first transfer of a SmartAsset
     */
    function transferFrom(address from, address to, uint256 tokenId) public override (ERC721Upgradeable, IERC721) {
        require(
            // store.canTransfer(from, _to, tokenId, isSoulbound),
            true,
            "ArianeeSmartAsset: Transfer not allowed (`canTransfer(address, address, uint256, bool)` failed)"
        ); // TODO: Do we keep this, maybe we move this logic here ?

        ArianeeSmartAssetStorageV0 storage $ = _getArianeeSmartAssetStorageV0();
        if ($.isSoulbound) {
            address tokenOwner = _requireOwned(tokenId);
            require(tokenOwner == from, "ArianeeSmartAsset: Transfer not allowed (`tokenOwner` != `from`)");

            address tokenIssuer = $.idToCertificate[tokenId].tokenIssuer;

            // If the owner is NOT the issuer, the SmartAsset is soulbound and the transfer can be made only by the issuer to change the owner if needed
            if (tokenOwner != tokenIssuer) {
                require(
                    tokenIssuer == _msgSender(),
                    "ArianeeSmartAsset: Only the issuer can transfer a soulbound smart asset"
                );
            }
            /*
            * If the previous condition has not been hit, the owner IS the issuer and the SmartAsset is not soulbound yet or not anymore for a limited time
            * This is either the first transfer of the SmartAsset to its first "real" owner or a recovery request made by the issuer on the behalf of the owner (i.e the owner lost his wallet and wants to recover his token)
            */
        }

        super.transferFrom(from, to, tokenId);
        // TODO: arianeeWhitelist.addWhitelistedAddress(_tokenId, _to);

        if (_isFirstTransfer(tokenId)) {
            _getArianeeSmartAssetStorageV0().idToFirstTransfer[tokenId] = false;
            // TODO: store.dispatchRewardsAtFirstTransfer(_tokenId, _to);
        }
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override (ERC721EnumerableUpgradeable, ERC721Upgradeable, AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    // Internal Functions & Overrides

    /**
     * @notice Returns a flag indicating if a SmartAsset has already been transferred once
     * @param _tokenId SmartAsset ID
     */
    function _isFirstTransfer(
        uint256 _tokenId
    ) internal view returns (bool) {
        return _getArianeeSmartAssetStorageV0().idToFirstTransfer[_tokenId] == true;
    }

    function _baseURI() internal view override returns (string memory) {
        return _getArianeeSmartAssetStorageV0().baseURI;
    }

    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override (ERC721EnumerableUpgradeable, ERC721PausableUpgradeable, ERC721Upgradeable) returns (address) {
        return super._update(to, tokenId, auth);
    }

    function _increaseBalance(
        address account,
        uint128 amount
    ) internal override (ERC721EnumerableUpgradeable, ERC721Upgradeable) {
        super._increaseBalance(account, amount);
    }
}
