// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeStore } from "../Interfaces/IArianeeStore.sol";
import { IArianeeSmartAsset } from "../Interfaces/IArianeeSmartAsset.sol";
import { IArianeeEvent } from "../Interfaces/IArianeeEvent.sol";
import { IArianeeLost } from "../Interfaces/IArianeeLost.sol";
import { IArianeeCreditNotePool } from "../Interfaces/IArianeeCreditNotePool.sol";
import { IPoseidon } from "../Interfaces/IPoseidon.sol";
import { CreditNoteProof } from "../Interfaces/IArianeeCreditNotePool.sol";
import { ByteUtils } from "../../ByteUtils.sol";
import {
    ROLE_ADMIN,
    CREDIT_TYPE_CERTIFICATE,
    CREDIT_TYPE_MESSAGE,
    CREDIT_TYPE_EVENT,
    CREDIT_TYPE_UPDATE,
    SELECTOR_SIZE,
    OWNERSHIP_PROOF_SIZE,
    CREDIT_NOTE_PROOF_SIZE
} from "../Constants.sol";

// Unordered Nonce
import { UnorderedNonceUpgradeable } from "../../UnorderedNonceUpgradeable.sol";
// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

interface IOwnershipVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool);
}

/**
 * @notice The OwnershipProof must be the first argument if used in a function
 * This is allowing us to remove the OwnershipProof from `_msgData()` easily
 */
struct OwnershipProof {
    uint256[2] _pA; // 64 bytes
    uint256[2][2] _pB; // 128 bytes
    uint256[2] _pC; // 64 bytes
    uint256[3] _pubSignals; // 96 bytes
} // Total: 352 bytes

contract ArianeeIssuerProxy is
    Initializable,
    ERC2771ContextUpgradeable,
    UnorderedNonceUpgradeable,
    AccessControlUpgradeable
{
    using ByteUtils for bytes;

    /// @custom:storage-location erc7201:arianeeissuerproxy.storage.v0
    struct ArianeeIssuerProxyStorageV0 {
        /**
         * @notice The ArianeeStore contract used to pass issuer intents (can be updated)
         */
        IArianeeStore store;
        /**
         * @notice The ArianeeSmartAsset contract used to pass issuer intents
         */
        IArianeeSmartAsset smartAsset;
        /**
         * @notice The ArianeeEvent contract used to pass issuer intents
         */
        IArianeeEvent arianeeEvent;
        /**
         * @notice The ArianeeLost contract used to pass issuer intents
         */
        IArianeeLost arianeeLost;
        /**
         * @notice The contract used to verify the ownership proofs
         */
        IOwnershipVerifier verifier;
        /**
         * @notice The contract used to compute Poseidon hashes
         */
        IPoseidon poseidon;
        /**
         * @notice The contracts used for credit notes management
         */
        mapping(address => bool) creditNotePools;
        /**
         * @notice The addresses allowed to send intents without a CreditNoteProof
         */
        mapping(address => bool) creditFreeSenders;
        /**
         * @notice Mapping<TokenId, CommitmentHash>
         */
        mapping(uint256 => uint256) commitmentHashes;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeeissuerproxy.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeIssuerProxyStorageV0Location =
        0xdfb471cd3ca022c3d9702e8c5ae7e7c948fe792e47161e5c31b2148652480a00;

    function _getArianeeIssuerProxyStorageV0() internal pure returns (ArianeeIssuerProxyStorageV0 storage $) {
        assembly {
            $.slot := ArianeeIssuerProxyStorageV0Location
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
        address _storeAddress,
        address _smartAssetAddress,
        address _eventAddress,
        address _lostAddress,
        address _verifier,
        address _poseidon
    ) public initializer {
        _grantRole(ROLE_ADMIN, _initialAdmin);

        ArianeeIssuerProxyStorageV0 storage $ = _getArianeeIssuerProxyStorageV0();
        $.store = IArianeeStore(_storeAddress);
        $.smartAsset = IArianeeSmartAsset(_smartAssetAddress);
        $.arianeeEvent = IArianeeEvent(_eventAddress);
        $.arianeeLost = IArianeeLost(_lostAddress);
        $.verifier = IOwnershipVerifier(_verifier);
        $.poseidon = IPoseidon(_poseidon);
    }

    // OwnershipProof

    modifier onlyWithProof(OwnershipProof calldata _ownershipProof, bool needsCreditNoteProof, uint256 _tokenId) {
        _verifyProof(_ownershipProof, needsCreditNoteProof, _tokenId);
        _;
    }

    function _verifyProof(
        OwnershipProof calldata _ownershipProof,
        bool needsCreditNoteProof,
        uint256 _tokenId
    ) internal {
        ArianeeIssuerProxyStorageV0 storage $ = _getArianeeIssuerProxyStorageV0();
        require($.commitmentHashes[_tokenId] != 0, "ArianeeIssuerProxy: No commitment registered for this SmartAsset");

        uint256 pCommitmentHash = _ownershipProof._pubSignals[0];
        require(
            pCommitmentHash == $.commitmentHashes[_tokenId],
            "ArianeeIssuerProxy: Proof commitment does not match the registered commitment for this SmartAsset"
        );

        uint256 pIntentHash = _ownershipProof._pubSignals[1];
        bytes memory msgData = _msgData();

        // Removing the `OwnershipProof` (352 bytes) and if needed the `CreditNoteProof` (384 bytes) from the msg.data before computing the hash to compare
        uint256 msgDataHash = uint256(
            $.poseidon.poseidon(
                [
                    keccak256(
                        abi.encodePacked(
                            bytes.concat(
                                msgData.slice(0, SELECTOR_SIZE),
                                msgData.slice(
                                    SELECTOR_SIZE + OWNERSHIP_PROOF_SIZE
                                        + (needsCreditNoteProof ? CREDIT_NOTE_PROOF_SIZE : 0),
                                    msgData.length
                                )
                            )
                        )
                    )
                ]
            )
        );
        require(pIntentHash == msgDataHash, "ArianeeIssuerProxy: Proof intent does not match the function call");

        uint256 pNonce = _ownershipProof._pubSignals[2];
        require(_useUnorderedNonce(pCommitmentHash, pNonce), "ArianeeIssuerProxy: Proof nonce has already been used");

        require(
            $.verifier.verifyProof(
                _ownershipProof._pA, _ownershipProof._pB, _ownershipProof._pC, _ownershipProof._pubSignals
            ),
            "ArianeeIssuerProxy: OwnershipProof verification failed"
        );
    }

    function tryRegisterCommitment(uint256 _tokenId, uint256 _commitmentHash) internal {
        ArianeeIssuerProxyStorageV0 storage $ = _getArianeeIssuerProxyStorageV0();
        require(
            $.commitmentHashes[_tokenId] == 0,
            "ArianeeIssuerProxy: A commitment has already been registered for this SmartAsset"
        );
        $.commitmentHashes[_tokenId] = _commitmentHash;
        emit TokenCommitmentRegistered(_commitmentHash, _tokenId);
    }

    function tryUnregisterCommitment(
        uint256 _tokenId
    ) internal {
        ArianeeIssuerProxyStorageV0 storage $ = _getArianeeIssuerProxyStorageV0();
        require($.commitmentHashes[_tokenId] != 0, "ArianeeIssuerProxy: No commitment registered for this SmartAsset");
        uint256 commitmentHash = $.commitmentHashes[_tokenId];
        delete $.commitmentHashes[_tokenId];
        emit TokenCommitmentUnregistered(commitmentHash, _tokenId);
    }

    // CreditNoteProof

    function trySpendCredit(
        address _creditNotePool,
        uint256 _creditType,
        CreditNoteProof calldata _creditNoteProof
    ) internal {
        ArianeeIssuerProxyStorageV0 storage $ = _getArianeeIssuerProxyStorageV0();
        if ($.creditFreeSenders[_msgSender()] == true) {
            emit CreditFreeSenderLog(_msgSender(), _creditType);
        } else {
            require(
                $.creditNotePools[_creditNotePool] == true,
                "ArianeeIssuerProxy: Target IArianeeCreditNotePool is not whitelisted"
            );
            IArianeeCreditNotePool(_creditNotePool).spend(_creditNoteProof, _msgData(), _creditType);
        }
    }

    function addCreditNotePool(
        address _creditNotePool
    ) external onlyRole(ROLE_ADMIN) {
        _getArianeeIssuerProxyStorageV0().creditNotePools[_creditNotePool] = true;
        emit CreditNotePoolAdded(_creditNotePool);
    }

    function addCreditFreeSender(
        address _sender
    ) public onlyRole(ROLE_ADMIN) {
        _getArianeeIssuerProxyStorageV0().creditFreeSenders[_sender] = true;
        emit CreditFreeSenderAdded(_sender);
    }

    function addCreditFreeSenderBatch(
        address[] calldata _senders
    ) external onlyRole(ROLE_ADMIN) {
        for (uint256 i = 0; i < _senders.length; i++) {
            addCreditFreeSender(_senders[i]);
        }
    }

    function removeCreditFreeSender(
        address _sender
    ) public onlyRole(ROLE_ADMIN) {
        delete _getArianeeIssuerProxyStorageV0().creditFreeSenders[_sender];
        emit CreditFreeSenderRemoved(_sender);
    }

    function removeCreditFreeSenderBatch(
        address[] calldata _senders
    ) external onlyRole(ROLE_ADMIN) {
        for (uint256 i = 0; i < _senders.length; i++) {
            removeCreditFreeSender(_senders[i]);
        }
    }

    // IArianeeStore (IArianeeSmartAsset related functions)

    function reserveToken(uint256 _commitmentHash, uint256 _tokenId) external {
        tryRegisterCommitment(_tokenId, _commitmentHash);
        _getArianeeIssuerProxyStorageV0().store.reserveToken(_tokenId, address(this));
    }

    function hydrateToken(
        OwnershipProof calldata _ownershipProof,
        CreditNoteProof calldata _creditNoteProof,
        address _creditNotePool,
        uint256 _commitmentHash, // If no proof is provided, this commitment hash is required
        uint256 _tokenId,
        bytes32 _imprint,
        string memory _uri,
        address _encryptedInitialKey,
        uint256 _tokenRecoveryTimestamp,
        bool _initialKeyIsRequestKey,
        address _interfaceProvider
    ) external {
        if (_commitmentHash != 0) {
            // If a commitment hash is provided, we try to register it before hydrating the SmartAsset
            // This can happen if the SmartAsset was not reserved before being hydrated
            tryRegisterCommitment(_tokenId, _commitmentHash);
        }

        // Proof verification is made inline here because we need to do it after the eventual commitment hash registration
        _verifyProof(_ownershipProof, true, _tokenId);

        trySpendCredit(_creditNotePool, CREDIT_TYPE_CERTIFICATE, _creditNoteProof);

        ArianeeIssuerProxyStorageV0 storage $ = _getArianeeIssuerProxyStorageV0();
        $.store.hydrateToken(
            _tokenId,
            _imprint,
            _uri,
            _encryptedInitialKey,
            _tokenRecoveryTimestamp,
            _initialKeyIsRequestKey,
            _interfaceProvider
        );
    }

    // UnorderedNonce

    function invalidateUnorderedNonces(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        uint256 _commitmentHash,
        uint256 _wordPos,
        uint256 _mask
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        invalidateUnorderedNonces(_commitmentHash, _wordPos, _mask);
    }

    // IArianeeSmartAsset

    function addTokenAccess(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        address _key,
        bool _enable,
        uint256 _tokenType
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.addTokenAccess(_tokenId, _key, _enable, _tokenType);
    }

    function recoverTokenToIssuer(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.recoverTokenToIssuer(_tokenId);
    }

    function updateRecoveryRequest(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        bool _active
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.updateRecoveryRequest(_tokenId, _active);
    }

    function destroy(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.destroy(_tokenId);
        // Free the commitment hash when destroying the SmartAsset to allow it to be reused
        tryUnregisterCommitment(_tokenId);
    }

    function updateTokenURI(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        string calldata _uri
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.updateTokenURI(_tokenId, _uri);
    }

    function safeTransferFrom(
        OwnershipProof calldata _ownershipProof,
        address _from,
        address _to,
        uint256 _tokenId,
        bytes calldata _data
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.safeTransferFrom(_from, _to, _tokenId, _data);
    }

    function transferFrom(
        OwnershipProof calldata _ownershipProof,
        address _from,
        address _to,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.transferFrom(_from, _to, _tokenId);
    }

    function approve(
        OwnershipProof calldata _ownershipProof,
        address _approved,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().smartAsset.approve(_approved, _tokenId);
    }

    // IArianeeStore (IArianeeUpdate related functions)

    function updateSmartAsset(
        OwnershipProof calldata _ownershipProof,
        CreditNoteProof calldata _creditNoteProof,
        address _creditNotePool,
        uint256 _tokenId,
        bytes32 _imprint,
        address _interfaceProvider
    ) external onlyWithProof(_ownershipProof, true, _tokenId) {
        trySpendCredit(_creditNotePool, CREDIT_TYPE_UPDATE, _creditNoteProof);
        _getArianeeIssuerProxyStorageV0().store.updateSmartAsset(_tokenId, _imprint, _interfaceProvider);
    }

    // IArianeeStore (IArianeeEvent related functions)

    function createEvent(
        OwnershipProof calldata _ownershipProof,
        CreditNoteProof calldata _creditNoteProof,
        address _creditNotePool,
        uint256 _tokenId,
        uint256 _eventId,
        bytes32 _imprint,
        string calldata _uri,
        address _interfaceProvider
    ) external onlyWithProof(_ownershipProof, true, _tokenId) {
        trySpendCredit(_creditNotePool, CREDIT_TYPE_EVENT, _creditNoteProof);
        _getArianeeIssuerProxyStorageV0().store.createEvent(_eventId, _tokenId, _imprint, _uri, _interfaceProvider);
    }

    function acceptEvent(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        uint256 _eventId,
        address _interfaceProvider
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().store.acceptEvent(_eventId, _interfaceProvider);
    }

    function refuseEvent(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        uint256 _eventId,
        address _interfaceProvider
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().store.refuseEvent(_eventId, _interfaceProvider);
    }

    // IArianeeEvent

    function destroyEvent(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        uint256 _eventId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().arianeeEvent.destroy(_eventId);
    }

    function updateDestroyEventRequest(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        uint256 _eventId,
        bool _active
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().arianeeEvent.updateDestroyRequest(_eventId, _active);
    }

    // IArianeeStore (IArianeeMessage related functions)

    function createMessage(
        OwnershipProof calldata _ownershipProof,
        CreditNoteProof calldata _creditNoteProof,
        address _creditNotePool,
        uint256 _messageId,
        uint256 _tokenId,
        bytes32 _imprint,
        address _interfaceProvider
    ) external onlyWithProof(_ownershipProof, true, _tokenId) {
        trySpendCredit(_creditNotePool, CREDIT_TYPE_MESSAGE, _creditNoteProof);
        _getArianeeIssuerProxyStorageV0().store.createMessage(_messageId, _tokenId, _imprint, _interfaceProvider);
    }

    // IArianeeLost

    function setStolenStatus(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().arianeeLost.setStolenStatus(_tokenId);
    }

    function unsetStolenStatus(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().arianeeLost.unsetStolenStatus(_tokenId);
    }

    function setMissingStatus(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().arianeeLost.setMissingStatus(_tokenId);
    }

    function unsetMissingStatus(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId
    ) external onlyWithProof(_ownershipProof, false, _tokenId) {
        _getArianeeIssuerProxyStorageV0().arianeeLost.unsetMissingStatus(_tokenId);
    }

    // Emergency

    function updateCommitment(
        OwnershipProof calldata _ownershipProof,
        uint256 _tokenId,
        uint256 _newCommitmentHash
    ) public onlyWithProof(_ownershipProof, false, _tokenId) onlyRole(ROLE_ADMIN) {
        ArianeeIssuerProxyStorageV0 storage $ = _getArianeeIssuerProxyStorageV0();
        require($.commitmentHashes[_tokenId] != 0, "ArianeeIssuerProxy: No commitment registered for this SmartAsset");
        uint256 previousCommitmentHash = $.commitmentHashes[_tokenId];
        $.commitmentHashes[_tokenId] = _newCommitmentHash;
        emit TokenCommitmentUpdated(previousCommitmentHash, _newCommitmentHash, _tokenId);
    }

    // Auto-generated getters migrated from the legacy version

    function commitmentHashes(
        uint256 _tokenId
    ) external view returns (uint256) {
        return _getArianeeIssuerProxyStorageV0().commitmentHashes[_tokenId];
    }

    function creditFreeSenders(
        address _sender
    ) external view returns (bool) {
        return _getArianeeIssuerProxyStorageV0().creditFreeSenders[_sender];
    }

    function creditNotePools(
        address _creditNotePool
    ) external view returns (bool) {
        return _getArianeeIssuerProxyStorageV0().creditNotePools[_creditNotePool];
    }

    function poseidon() external view returns (IPoseidon) {
        return _getArianeeIssuerProxyStorageV0().poseidon;
    }

    function verifier() external view returns (IOwnershipVerifier) {
        return _getArianeeIssuerProxyStorageV0().verifier;
    }

    function smartAsset() external view returns (IArianeeSmartAsset) {
        return _getArianeeIssuerProxyStorageV0().smartAsset;
    }

    function store() external view returns (IArianeeStore) {
        return _getArianeeIssuerProxyStorageV0().store;
    }

    function arianeeEvent() external view returns (IArianeeEvent) {
        return _getArianeeIssuerProxyStorageV0().arianeeEvent;
    }

    function arianeeLost() external view returns (IArianeeLost) {
        return _getArianeeIssuerProxyStorageV0().arianeeLost;
    }

    // Store management

    function getStoreAddress() external view returns (address) {
        return address(_getArianeeIssuerProxyStorageV0().store);
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
 * @notice Emitted when a "credit free sender" is sending an intent
 */
event CreditFreeSenderLog(address indexed _sender, uint256 _creditType);
/**
 * @notice Emitted when a "credit free sender" is added
 */

event CreditFreeSenderAdded(address indexed _sender);
/**
 * @notice Emitted when a "credit free sender" is removed
 */

event CreditFreeSenderRemoved(address indexed _sender);

/**
 * @notice Emitted when a CreditNotePool is added
 */
event CreditNotePoolAdded(address indexed _creditNotePool);

/**
 * @notice Emitted when a SmartAsset commitment is registered
 */
event TokenCommitmentRegistered(uint256 indexed _commitmentHash, uint256 indexed _tokenId);
/**
 * @notice Emitted when a SmartAsset commitment is updated
 */

event TokenCommitmentUpdated(
    uint256 indexed _previousCommitmentHash, uint256 indexed _newCommitmentHash, uint256 indexed _tokenId
);
/**
 * @notice Emitted when a SmartAsset commitment is unregistered
 */

event TokenCommitmentUnregistered(uint256 indexed _commitmentHash, uint256 indexed _tokenId);

/**
 * @notice Emitted when the store address is updated
 */
event StoreUpdated(address _oldStore, address _newStore);
