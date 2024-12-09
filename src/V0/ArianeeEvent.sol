// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeEvent } from "./Interfaces/IArianeeEvent.sol";
import { IArianeeSmartAsset } from "./Interfaces/IArianeeSmartAsset.sol";
import { IArianeeStore } from "./Interfaces/IArianeeStore.sol";
import { IArianeeWhitelist } from "./Interfaces/IArianeeWhitelist.sol";
import { ROLE_ADMIN, ROLE_ARIANEE_STORE, EVENT_DESTROY_DELAY } from "./Constants.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

struct Event {
    string URI;
    bytes32 imprint;
    address provider;
    uint256 destroyLimitTimestamp;
}

/**
 * @title ArianeeEvent
 * @notice This contract manage the events of the SmartAssets. Each event is linked to a SmartAsset and can be accepted or refused by the owner of the SmartAsset (or an operator).
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeEvent is
    IArianeeEvent,
    Initializable,
    ERC2771ContextUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable
{
    /// @custom:storage-location erc7201:arianeeevent.storage.v0
    struct ArianeeEventStorageV0 {
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
         * @notice The delay that is added to `block.timestamp` to set the limit timestamp at which an event can be destroyed
         */
        uint256 eventDestroyDelay;
        /**
         * @notice Mapping from SmartAsset ID to its accepted event list
         */
        mapping(uint256 => uint256[]) tokenIdToEventList;
        /**
         * @notice Mapping from event ID to its index in the accepted event list
         */
        mapping(uint256 => uint256) eventIdToEventListIndex;
        /**
         * @notice Mapping from SmartAsset ID to its pending event list
         */
        mapping(uint256 => uint256[]) tokenIdToPendingEventList;
        /**
         * @notice Mapping from event ID to its index in the pending event list
         */
        mapping(uint256 => uint256) eventIdToPendingEventListIndex;
        /**
         * @notice Mapping from event ID to its pending events
         */
        mapping(uint256 => uint256) eventIdToTokenId;
        /**
         * @notice Mapping from event ID to its associated rewards
         */
        mapping(uint256 => uint256) eventIdToRewards;
        /**
         * @notice Mapping from event ID to destroy request
         */
        mapping(uint256 => bool) eventIdToDestroyRequest;
        /**
         * @notice Mapping from event ID to event data
         */
        mapping(uint256 => Event) eventIdToEvent;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeeevent.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeEventStorageV0Location =
        0xe9eed97c86de3cadab117379c038e0d52f54d2544d92c482e0f7d68741c10800;

    function _getArianeeEventStorageV0() internal pure returns (ArianeeEventStorageV0 storage $) {
        assembly {
            $.slot := ArianeeEventStorageV0Location
        }
    }

    /**
     * @notice Check if an operator is valid for a given SmartAsset (lookup with an associated event ID) through the ArianeeSmartAsset contract
     * @param _eventId Event ID
     * @param _operator Operator address
     */
    modifier canOperateOrIssuer(uint256 _eventId, address _operator) {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        uint256 tokenId = $.eventIdToTokenId[_eventId];
        require(
            $.smartAsset.canOperate(tokenId, _operator) || $.smartAsset.issuerOf(tokenId) == _operator,
            "ArianeeEvent: Not an operator nor the issuer"
        );
        _;
    }

    /**
     * @notice Check if the `_msgSender()` is the provider for a given event or the issuer of the SmartAsset
     * @dev The provider is the actor that created the event
     * @param _eventId Event ID
     */
    modifier isProviderOrIssuer(
        uint256 _eventId
    ) {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        require(
            _msgSender() == $.eventIdToEvent[_eventId].provider
                || _msgSender() == $.smartAsset.issuerOf($.eventIdToTokenId[_eventId]),
            "ArianeeEvent: Not the provider nor the issuer"
        );
        _;
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
        __Pausable_init_unchained();

        _grantRole(ROLE_ADMIN, _initialAdmin);
        _grantRole(ROLE_ARIANEE_STORE, _storeAddress);

        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        $.smartAsset = IArianeeSmartAsset(_smartAssetAddress);
        $.store = IArianeeStore(_storeAddress);
        $.whitelist = IArianeeWhitelist(_whitelistAddress);
        $.eventDestroyDelay = EVENT_DESTROY_DELAY; // Default to 1 year
    }

    /**
     * @notice Create a new event for a given SmartAsset
     * @dev Must be called by an authorized address
     * @param _eventId Event ID
     * @param _tokenId SmartAsset ID
     * @param _imprint Imprint (hash of the event data)
     * @param _uri URI
     * @param _rewards Rewards for the action
     * @param _provider Address of the provider (actor that created the event)
     */
    function create(
        uint256 _eventId,
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        uint256 _rewards,
        address _provider
    ) external onlyRole(ROLE_ARIANEE_STORE) whenNotPaused {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        require($.smartAsset.tokenCreation(_tokenId) > 0, "ArianeeEvent: SmartAsset does not exist");
        require($.eventIdToEvent[_eventId].provider == address(0), "ArianeeEvent: Event already exists");

        Event memory _event = Event({
            URI: _uri,
            imprint: _imprint,
            provider: _provider,
            destroyLimitTimestamp: $.eventDestroyDelay + block.timestamp
        });

        $.eventIdToEvent[_eventId] = _event;

        $.tokenIdToPendingEventList[_tokenId].push(_eventId);
        uint256 length = $.tokenIdToPendingEventList[_tokenId].length;
        $.eventIdToPendingEventListIndex[_eventId] = length - 1;

        $.eventIdToTokenId[_eventId] = _tokenId;

        $.eventIdToRewards[_eventId] = _rewards;

        emit EventCreated(_tokenId, _eventId, _imprint, _uri, _provider);
    }

    /**
     * @notice Accept an event (mark it as valid for the end-user apps, before this action the event is pending validation)
     * @dev Must be called by an authorized address
     * @dev Must have a `_sender` param that is an operator of the SmartAsset
     * @param _eventId Event ID
     * @param _sender Address of the sender
     */
    function accept(
        uint256 _eventId,
        address _sender
    ) external onlyRole(ROLE_ARIANEE_STORE) canOperateOrIssuer(_eventId, _sender) whenNotPaused returns (uint256) {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        uint256 tokenId = $.eventIdToTokenId[_eventId];

        require(isPending(_eventId), "ArianeeEvent: Event is not pending");
        uint256 pendingEventToRemoveIndex = $.eventIdToPendingEventListIndex[_eventId];
        uint256 lastPendingIndex = $.tokenIdToPendingEventList[tokenId].length - 1;

        if (lastPendingIndex != pendingEventToRemoveIndex) {
            uint256 lastPendingEvent = $.tokenIdToPendingEventList[tokenId][lastPendingIndex];
            $.tokenIdToPendingEventList[tokenId][pendingEventToRemoveIndex] = lastPendingEvent;
            $.eventIdToPendingEventListIndex[lastPendingEvent] = pendingEventToRemoveIndex;
        }

        $.tokenIdToPendingEventList[tokenId].pop();
        delete $.eventIdToPendingEventListIndex[_eventId];

        $.tokenIdToEventList[tokenId].push(_eventId);
        uint256 length = $.tokenIdToEventList[tokenId].length;
        $.eventIdToEventListIndex[_eventId] = length - 1;

        $.whitelist.addWhitelistedAddress(tokenId, $.eventIdToEvent[_eventId].provider);
        uint256 rewards = $.eventIdToRewards[_eventId];
        delete $.eventIdToRewards[_eventId];

        emit EventAccepted(_eventId, _sender);
        return rewards;
    }

    /**
     * @notice Refuse an event
     * @dev Must be called by an authorized address
     * @dev Must have a `_sender` param that is an operator of the SmartAsset
     * @param _eventId Event ID
     * @param _sender Address of the sender
     */
    function refuse(
        uint256 _eventId,
        address _sender
    ) external onlyRole(ROLE_ARIANEE_STORE) canOperateOrIssuer(_eventId, _sender) whenNotPaused returns (uint256) {
        _destroyPending(_eventId);

        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        uint256 rewards = $.eventIdToRewards[_eventId];
        delete $.eventIdToRewards[_eventId];
        emit EventRefused(_eventId, _sender);

        return rewards;
    }

    /**
     * @notice Destroy an event
     * @dev Must be called by a valid provider
     * @param _eventId Event ID
     */
    function destroy(
        uint256 _eventId
    ) external isProviderOrIssuer(_eventId) whenNotPaused {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        require(
            block.timestamp < $.eventIdToEvent[_eventId].destroyLimitTimestamp,
            "ArianeeEvent: Destroy limit timestamp reached"
        );
        require(!isPending(_eventId), "ArianeeEvent: Event is still pending");
        _destroy(_eventId);
    }

    /**
     * @notice Update the status of a destroy request
     * @dev Must be called by a valid provider
     * @param _eventId Event ID
     * @param _active New status of the destroy request
     */
    function updateDestroyRequest(uint256 _eventId, bool _active) external isProviderOrIssuer(_eventId) whenNotPaused {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        require(!isPending(_eventId), "ArianeeEvent: Event is still pending");

        $.eventIdToDestroyRequest[_eventId] = _active;
        emit DestroyRequestUpdated(_eventId, _active);
    }

    /**
     * @notice Validate a destroy request
     * @dev Can be only called if a destroy request is active and by the `ROLE_ADMIN` of this contract
     * @param _eventId Event ID
     */
    function validDestroyRequest(
        uint256 _eventId
    ) external onlyRole(ROLE_ADMIN) {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        require($.eventIdToDestroyRequest[_eventId] == true, "ArianeeEvent: No active destroy request for this event");
        $.eventIdToDestroyRequest[_eventId] = false;
        _destroy(_eventId);
    }

    /**
     * @notice Update the event destroy delay
     * @param _newEventDestroyDelay New event destroy delay
     */
    function updateEventDestroyDelay(
        uint256 _newEventDestroyDelay
    ) external onlyRole(ROLE_ADMIN) whenNotPaused {
        _getArianeeEventStorageV0().eventDestroyDelay = _newEventDestroyDelay;
        emit EventDestroyDelayUpdated(_newEventDestroyDelay);
    }

    /**
     * @notice Returns an event
     * @param _eventId Event ID
     * @return uri URI
     * @return imprint Imprint (hash of the event data)
     * @return provider Address of the provider (actor that created the event)
     * @return destroyLimitTimestamp Destroy limit timestamp
     */
    function getEvent(
        uint256 _eventId
    ) public view returns (string memory uri, bytes32 imprint, address provider, uint256 destroyLimitTimestamp) {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        require($.eventIdToEvent[_eventId].provider != address(0), "ArianeeEvent: Event does not exist");
        return (
            $.eventIdToEvent[_eventId].URI,
            $.eventIdToEvent[_eventId].imprint,
            $.eventIdToEvent[_eventId].provider,
            $.eventIdToEvent[_eventId].destroyLimitTimestamp
        );
    }

    /**
     * @notice Returns the pending events count of a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    function pendingEventsLength(
        uint256 _tokenId
    ) public view returns (uint256) {
        return _getArianeeEventStorageV0().tokenIdToPendingEventList[_tokenId].length;
    }

    /**
     * @notice Returns the events count of a given SmartAsset
     * @param _tokenId SmartAsset ID
     */
    function eventsLength(
        uint256 _tokenId
    ) public view returns (uint256) {
        return _getArianeeEventStorageV0().tokenIdToEventList[_tokenId].length;
    }

    /**
     * @notice Returns the SmartAsset ID for a given event ID
     * @param _eventId Event ID
     */
    function eventIdToToken(
        uint256 _eventId
    ) public view override returns (uint256) {
        return _getArianeeEventStorageV0().eventIdToTokenId[_eventId];
    }

    /**
     * @notice Returns a flag indicating if an event is pending or not
     * @param _eventId Event ID
     */
    function isPending(
        uint256 _eventId
    ) public view returns (bool) {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        uint256 tokenId = $.eventIdToTokenId[_eventId];
        if ($.tokenIdToPendingEventList[tokenId].length == 0) {
            return false;
        } else {
            uint256 eventListIndex = $.eventIdToPendingEventListIndex[_eventId];
            return $.tokenIdToPendingEventList[tokenId][eventListIndex] == _eventId;
        }
    }

    // Internal Functions & Overrides

    function _destroy(
        uint256 _eventId
    ) internal {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        uint256 tokenId = $.eventIdToTokenId[_eventId];

        uint256 eventIdToRemove = $.eventIdToEventListIndex[_eventId];
        uint256 lastEventId = $.tokenIdToEventList[tokenId].length - 1;

        if (eventIdToRemove != lastEventId) {
            uint256 lastEvent = $.tokenIdToEventList[tokenId][lastEventId];
            $.tokenIdToEventList[tokenId][eventIdToRemove] = lastEvent;
            $.eventIdToEventListIndex[lastEvent] = eventIdToRemove;
        }

        $.tokenIdToEventList[tokenId].pop();
        delete $.eventIdToEventListIndex[_eventId];
        delete $.eventIdToTokenId[_eventId];
        delete $.eventIdToEvent[_eventId];

        emit EventDestroyed(_eventId);
    }

    function _destroyPending(
        uint256 _eventId
    ) internal {
        ArianeeEventStorageV0 storage $ = _getArianeeEventStorageV0();
        uint256 tokenId = $.eventIdToTokenId[_eventId];
        uint256 pendingEventToRemoveIndex = $.eventIdToPendingEventListIndex[_eventId];
        uint256 lastPendingIndex = $.tokenIdToPendingEventList[tokenId].length - 1;

        if (lastPendingIndex != pendingEventToRemoveIndex) {
            uint256 lastPendingEvent = $.tokenIdToPendingEventList[tokenId][lastPendingIndex];
            $.tokenIdToPendingEventList[tokenId][pendingEventToRemoveIndex] = lastPendingEvent;
            $.eventIdToPendingEventListIndex[lastPendingEvent] = pendingEventToRemoveIndex;
        }

        $.tokenIdToPendingEventList[tokenId].pop();

        delete $.eventIdToPendingEventListIndex[_eventId];
        delete $.eventIdToTokenId[_eventId];
        delete $.eventIdToEvent[_eventId];

        emit EventDestroyed(_eventId);
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
 * @dev This emits when an event is created
 */
event EventCreated(
    uint256 indexed _tokenId, uint256 indexed _eventId, bytes32 indexed _imprint, string _uri, address _provider
);

/**
 * @dev This emits when an event is accepted
 */
event EventAccepted(uint256 indexed _eventId, address indexed _sender);

/**
 * @dev This emits when an event is refused
 */
event EventRefused(uint256 indexed _eventId, address indexed _sender);

/**
 * @dev This emits when an event is destroyed
 */
event EventDestroyed(uint256 indexed _eventId);

/**
 * @dev This emits when a destroy request is updated
 */
event DestroyRequestUpdated(uint256 indexed _eventId, bool _active);

/**
 * @dev This emits when the event destroy delay is updated
 */
event EventDestroyDelayUpdated(uint256 _newDelay);
