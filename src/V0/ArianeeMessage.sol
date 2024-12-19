// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeMessage } from "./Interfaces/IArianeeMessage.sol";
import { IArianeeSmartAsset } from "./Interfaces/IArianeeSmartAsset.sol";
import { IArianeeStore } from "./Interfaces/IArianeeStore.sol";
import { IArianeeWhitelist } from "./Interfaces/IArianeeWhitelist.sol";
import { ROLE_ADMIN, ROLE_ARIANEE_STORE } from "./Constants.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

struct Message {
    bytes32 imprint;
    address sender;
    address to;
    uint256 tokenId;
}

/**
 * @title ArianeeMessage
 * @notice This contract manage the messages of the SmartAssets.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeMessage is IArianeeMessage, Initializable, ERC2771ContextUpgradeable, AccessControlUpgradeable {
    /// @custom:storage-location erc7201:arianeemessage.storage.v0
    struct ArianeeMessageStorageV0 {
        /**
         * @notice The ArianeeSmartAsset contract
         */
        IArianeeSmartAsset smartAsset;
        /**
         * @notice The ArianeeStore contract
         */
        IArianeeStore store;
        /**
         * @notice The ArianeeWhitelist contract
         */
        IArianeeWhitelist whitelist;
        /**
         * @notice Mapping from receiver address to message IDs
         */
        mapping(address => uint256[]) receiverToMessageIds;
        /**
         * @notice Mapping from message ID to its associated rewards
         */
        mapping(uint256 => uint256) rewards;
        /**
         * @notice Mapping from message ID to its data (imprint, sender, to, tokenId)
         */
        mapping(uint256 => Message) messages;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeemessage.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeMessageStorageV0Location =
        0x72d050199eb260838f1803579a5fe035cabcc640b4d28e5537938b0090f11000;

    function _getArianeeMessageStorageV0() internal pure returns (ArianeeMessageStorageV0 storage $) {
        assembly {
            $.slot := ArianeeMessageStorageV0Location
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
        address _smartAssetAddress,
        address _storeAddress,
        address _whitelistAddress
    ) public initializer {
        _grantRole(ROLE_ADMIN, _initialAdmin);
        _grantRole(ROLE_ARIANEE_STORE, _storeAddress);

        ArianeeMessageStorageV0 storage $ = _getArianeeMessageStorageV0();
        $.smartAsset = IArianeeSmartAsset(_smartAssetAddress);
        $.store = IArianeeStore(_storeAddress);
        $.whitelist = IArianeeWhitelist(_whitelistAddress);
    }

    /**
     * @notice Create a new message for a given SmartAsset
     * @dev Must be called by an authorized address
     * @param _messageId Message ID
     * @param _tokenId SmartAsset ID
     * @param _imprint Imprint (hash of the message data)
     * @param _from Sender address
     * @param _rewards Rewards for the action
     */
    function sendMessage(
        uint256 _messageId,
        uint256 _tokenId,
        bytes32 _imprint,
        address _from,
        uint256 _rewards
    ) public onlyRole(ROLE_ARIANEE_STORE) {
        ArianeeMessageStorageV0 storage $ = _getArianeeMessageStorageV0();
        address owner = $.smartAsset.ownerOf(_tokenId);
        require($.whitelist.isAuthorized(_tokenId, _from, owner), "ArianeeMessage: Not authorized");
        require($.messages[_messageId].sender == address(0), "ArianeeMessage: Message already exists");

        Message memory _message = Message({ imprint: _imprint, sender: _from, to: owner, tokenId: _tokenId });

        $.messages[_messageId] = _message;
        $.receiverToMessageIds[owner].push(_messageId);

        $.rewards[_messageId] = _rewards;

        emit MessageSent(owner, _from, _tokenId, _messageId);
    }

    /**
     * @notice Mark a message as read
     * @dev Must be called by an authorized address
     * @param _messageId Message ID
     * @param _from Sender address
     */
    function readMessage(uint256 _messageId, address _from) public onlyRole(ROLE_ARIANEE_STORE) returns (uint256) {
        ArianeeMessageStorageV0 storage $ = _getArianeeMessageStorageV0();
        uint256 rewards = $.rewards[_messageId];
        address owner = $.messages[_messageId].to;
        require(_from == owner, "ArianeeMessage: Not authorized");

        delete $.rewards[_messageId];

        address sender = $.messages[_messageId].sender;
        emit MessageRead(owner, sender, _messageId);

        return rewards;
    }

    // Getters

    /**
     * @notice Returns the received messages length of a given receiver
     * @param _receiver Receiver address
     */
    function messageLengthByReceiver(
        address _receiver
    ) public view returns (uint256) {
        return _getArianeeMessageStorageV0().receiverToMessageIds[_receiver].length;
    }

    // Auto-generated getters migrated from the legacy version

    function messages(
        uint256 _messageId
    ) public view returns (Message memory) {
        return _getArianeeMessageStorageV0().messages[_messageId];
    }

    function receiverToMessageIds(address _receiver, uint256 _index) public view returns (uint256) {
        return _getArianeeMessageStorageV0().receiverToMessageIds[_receiver][_index];
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
 * @dev This emits when a message is sent
 */
event MessageSent(address indexed _receiver, address indexed _sender, uint256 indexed _tokenId, uint256 _messageId);

/**
 * @dev This emits when a message is read
 */
event MessageRead(address indexed _receiver, address indexed _sender, uint256 indexed _messageId);
