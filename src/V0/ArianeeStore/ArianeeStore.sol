// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { IArianeeStore } from "../Interfaces/IArianeeStore.sol";
import { IArianeeSmartAsset } from "../Interfaces/IArianeeSmartAsset.sol";
import { IArianeeCreditHistory } from "../Interfaces/IArianeeCreditHistory.sol";
import { IArianeeRewardsHistory } from "../Interfaces/IArianeeRewardsHistory.sol";
import { IArianeeEvent } from "../Interfaces/IArianeeEvent.sol";
import { IArianeeMessage } from "../Interfaces/IArianeeMessage.sol";
import { IArianeeSmartAssetUpdate } from "../Interfaces/IArianeeSmartAssetUpdate.sol";
import {
    ROLE_ADMIN,
    CREDIT_TYPE_CERTIFICATE,
    CREDIT_TYPE_MESSAGE,
    CREDIT_TYPE_EVENT,
    CREDIT_TYPE_UPDATE
} from "../Constants.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

/**
 * @title ArianeeStore
 * @notice This contract manages the economic layer of the Arianee Protocol. It is the entry point for most of the interactions with other contracts.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeStore is
    IArianeeStore,
    Initializable,
    ERC2771ContextUpgradeable,
    PausableUpgradeable,
    AccessControlUpgradeable
{
    /// @custom:storage-location erc7201:arianeestore.storage.v0
    struct ArianeeStoreStorageV0 {
        /**
         * @notice The Aria ERC-20 contract
         */
        IERC20 aria;
        /**
         * @notice The ArianeeSmartAsset contract
         */
        IArianeeSmartAsset smartAsset;
        /**
         * @notice The ArianeeSmartAssetUpdate contract
         */
        IArianeeSmartAssetUpdate smartAssetUpdate;
        /**
         * @notice The ArianeeEvent contract
         */
        IArianeeEvent arianeeEvent;
        /**
         * @notice The ArianeeMessage contract
         */
        IArianeeMessage arianeeMessage;
        /**
         * @notice The ArianeeCreditHistory contract
         */
        IArianeeCreditHistory creditHistory;
        /**
         * @notice The ArianeeRewardsHistory contract
         */
        IArianeeRewardsHistory rewardsHistory;
        /**
         * @notice Mapping from credit type to credit price in cents
         */
        mapping(uint256 => uint256) creditPricesUSD;
        /**
         * @notice Mapping from credit type to credit price in Aria
         */
        mapping(uint256 => uint256) creditPrices;
        /**
         * @notice The current exchange rate between Aria and USD
         */
        uint256 ariaUSDExchange;
        /**
         * @notice The different rewards dispatch percent per actor
         */
        mapping(uint8 => uint8) dispatchPercent;
        /**
         * @notice The address of the one who can update the Aria to USD exchange rate
         */
        address authorizedExchangeAddress;
        /**
         * @notice The address of the one who will receive the protocol infrastructure rewards
         */
        address protocolInfraAddress;
        /**
         * @notice The address of the one who will receive the Arianee project rewards
         */
        address arianeeProjectAddress;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeestore.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeStoreStorageV0Location =
        0x9da96567ac42c7396efeaa2daf3b1adf0b1b9d0a94efe4dcb2fbaac986f0ce00;

    function _getArianeeStoreStorageV0() internal pure returns (ArianeeStoreStorageV0 storage $) {
        assembly {
            $.slot := ArianeeStoreStorageV0Location
        }
    }

    /**
     * @notice Check if the _msgSender() is the ArianeeSmartAsset contract
     */
    modifier onlySmartAsset() {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        require(
            _msgSender() == address($.smartAsset),
            "ArianeeStore: This function can only be called by the ArianeeSmartAsset contract"
        );
        _;
    }

    /**
     * @notice Check if the _msgSender() is the authorized exchange address
     */
    modifier onlyAuthorizedExchangeAddress() {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        require(
            _msgSender() == $.authorizedExchangeAddress,
            "ArianeeStore: This function can only be called by the authorized exchange address"
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
        address _ariaAddress,
        address _smartAssetAddress,
        address _smartAssetUpdateAddress,
        address _arianeeEventAddress,
        address _arianeeMessageAddress,
        address _creditHistoryAddress,
        address _rewardsHistoryAddress,
        uint256 _ariaUSDExchange,
        uint256 _creditPricesUSD0,
        uint256 _creditPricesUSD1,
        uint256 _creditPricesUSD2,
        uint256 _creditPricesUSD3
    ) public initializer {
        __Pausable_init_unchained();

        _grantRole(ROLE_ADMIN, _initialAdmin);

        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.aria = IERC20(_ariaAddress);
        $.smartAsset = IArianeeSmartAsset(_smartAssetAddress);
        $.smartAssetUpdate = IArianeeSmartAssetUpdate(_smartAssetUpdateAddress);
        $.arianeeEvent = IArianeeEvent(_arianeeEventAddress);
        $.arianeeMessage = IArianeeMessage(_arianeeMessageAddress);
        $.creditHistory = IArianeeCreditHistory(_creditHistoryAddress);
        $.rewardsHistory = IArianeeRewardsHistory(_rewardsHistoryAddress);

        $.ariaUSDExchange = _ariaUSDExchange;
        $.creditPricesUSD[0] = _creditPricesUSD0;
        $.creditPricesUSD[1] = _creditPricesUSD1;
        $.creditPricesUSD[2] = _creditPricesUSD2;
        $.creditPricesUSD[3] = _creditPricesUSD3;

        _updateCreditPrice();
    }

    /**
     * @notice Buy new credit against Aria tokens
     * @param _creditType Credit type to buy
     * @param _quantity Quantity of credit to buy
     * @param _to Address to grant the credit to
     */
    function buyCredit(uint256 _creditType, uint256 _quantity, address _to) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 tokens = _quantity * $.creditPrices[_creditType];

        // Assert that the buyer transfers the correct amount of Aria
        require($.aria.transferFrom(_msgSender(), address(this), tokens), "ArianeeStore: Transfer failed");
        $.creditHistory.addCreditHistory(_to, $.creditPrices[_creditType], _quantity, _creditType);

        emit CreditBought(_msgSender(), _to, _creditType, _quantity);
    }

    // ArianeeSmartAsset functions

    /**
     * @notice Proxy function to call {ArianeeSmartAsset-reserveToken}
     */
    function reserveToken(uint256 _tokenId, address _to) public whenNotPaused {
        _getArianeeStoreStorageV0().smartAsset.reserveToken(_tokenId, _to);
    }

    /**
     * @notice Proxy function to call {ArianeeSmartAsset-hydrateToken} with additional tokenomics logic
     */
    function hydrateToken(
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        address _initialKey,
        uint256 _tokenRecoveryTimestamp,
        bool _initialKeyIsRequestKey,
        address _rewardsReceiver
    ) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();

        bool tokenExists;
        try $.smartAsset.ownerOf(_tokenId) {
            tokenExists = true;
        } catch {
            tokenExists = false;
        }

        if (tokenExists == false) {
            reserveToken(_tokenId, _msgSender());
        }

        uint256 _rewards = _spendCreditFunction(CREDIT_TYPE_CERTIFICATE, 1, _msgSender());
        _dispatchRewardsAtHydrate(_rewardsReceiver, _rewards);
        $.rewardsHistory.setTokenReward(_tokenId, _rewards);

        $.smartAsset.hydrateToken(
            _tokenId, _imprint, _uri, _initialKey, _tokenRecoveryTimestamp, _initialKeyIsRequestKey, _msgSender(), false
        );
        $.rewardsHistory.setTokenNmpProvider(_tokenId, _rewardsReceiver);
    }

    /**
     * @notice Proxy function to call {ArianeeSmartAsset-requestToken} with additional tokenomics logic
     */
    function requestToken(
        uint256 _tokenId,
        bytes32 _hash,
        bool _keepCurrentAccess,
        address _rewardsReceiver,
        bytes calldata _signature
    ) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.rewardsHistory.setTokenWalletProvider(_tokenId, _rewardsReceiver);
        $.smartAsset.requestToken(_tokenId, _hash, _keepCurrentAccess, _msgSender(), _signature);
    }

    /**
     * @notice Proxy function to call {ArianeeSmartAsset-requestToken} with additional tokenomics logic
     * @dev This function is intended to be called by a custom relayer logic
     */
    function requestToken(
        uint256 _tokenId,
        bytes32 _hash,
        bool _keepCurrentAccess,
        address _rewardsReceiver,
        bytes calldata _signature,
        address _newOwner
    ) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.rewardsHistory.setTokenWalletProvider(_tokenId, _rewardsReceiver);
        $.smartAsset.requestToken(_tokenId, _hash, _keepCurrentAccess, _newOwner, _signature);
    }

    // ArianeeSmartAssetUpdate functions

    /**
     * @notice Proxy function to call {ArianeeSmartAssetUpdate-updateSmartAsset} with additional tokenomics logic
     */
    function updateSmartAsset(uint256 _tokenId, bytes32 _imprint, address _rewardsReceiver) external whenNotPaused {
        uint256 _rewards = _spendCreditFunction(CREDIT_TYPE_UPDATE, 1, _msgSender());
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.smartAssetUpdate.updateSmartAsset(_tokenId, _imprint, _msgSender(), _rewards);
        _dispatchRewardsAtHydrate(_rewardsReceiver, _rewards);
    }

    /**
     * @notice Proxy function to call {ArianeeSmartAssetUpdate-readUpdateSmartAsset} with additional tokenomics logic
     */
    function readUpdateSmartAsset(uint256 _tokenId, address _rewardsReceiver) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 _rewards = $.smartAssetUpdate.readUpdateSmartAsset(_tokenId, _msgSender());
        _dispatchRewardsAtRequest(_rewardsReceiver, _rewards);
    }

    // ArianeeEvent functions

    /**
     * @notice Proxy function to call {ArianeeEvent-create} with additional tokenomics logic
     */
    function createEvent(
        uint256 _eventId,
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        address _rewardsReceiver
    ) external whenNotPaused {
        uint256 _rewards = _spendCreditFunction(CREDIT_TYPE_EVENT, 1, _msgSender());
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.arianeeEvent.create(_eventId, _tokenId, _imprint, _uri, _rewards, _msgSender());
        _dispatchRewardsAtHydrate(_rewardsReceiver, _rewards);
    }

    /**
     * @notice Proxy function to call {ArianeeEvent-accept} with additional tokenomics logic
     */
    function acceptEvent(uint256 _eventId, address _rewardsReceiver) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 _rewards = $.arianeeEvent.accept(_eventId, _msgSender());
        _dispatchRewardsAtRequest(_rewardsReceiver, _rewards);
    }

    /**
     * @notice Proxy function to call {ArianeeEvent-refuse} with additional tokenomics logic
     */
    function refuseEvent(uint256 _eventId, address _rewardsReceiver) external {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 _rewards = $.arianeeEvent.refuse(_eventId, _msgSender());
        _dispatchRewardsAtRequest(_rewardsReceiver, _rewards);
    }

    // ArianeeMessage functions

    /**
     * @notice Proxy function to call {ArianeeMessage-sendMessage} with additional tokenomics logic
     */
    function createMessage(
        uint256 _messageId,
        uint256 _tokenId,
        bytes32 _imprint,
        address _rewardsReceiver
    ) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 _rewards = _spendCreditFunction(CREDIT_TYPE_MESSAGE, 1, _msgSender());
        $.arianeeMessage.sendMessage(_messageId, _tokenId, _imprint, _msgSender(), _rewards);
        _dispatchRewardsAtHydrate(_rewardsReceiver, _rewards);
    }

    /**
     * @notice Proxy function to call {ArianeeMessage-readMessage} with additional tokenomics logic
     */
    function readMessage(uint256 _messageId, address _rewardsReceiver) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 _rewards = $.arianeeMessage.readMessage(_messageId, _msgSender());
        _dispatchRewardsAtRequest(_rewardsReceiver, _rewards);
    }

    // Admin functions

    /**
     * @notice Set the authorized exchange address
     * @param _authorizedExchangeAddress New address to set
     */
    function setAuthorizedExchangeAddress(
        address _authorizedExchangeAddress
    ) external onlyRole(ROLE_ADMIN) {
        _getArianeeStoreStorageV0().authorizedExchangeAddress = _authorizedExchangeAddress;
        emit SetAddress("authorizedExchange", _authorizedExchangeAddress);
    }

    /**
     * @notice Set the protocol infrastructure address
     * @param _protocolInfraAddress New address to set
     */
    function setProtocolInfraAddress(
        address _protocolInfraAddress
    ) external onlyRole(ROLE_ADMIN) {
        _getArianeeStoreStorageV0().protocolInfraAddress = _protocolInfraAddress;
        emit SetAddress("protocolInfra", _protocolInfraAddress);
    }

    /**
     * @notice Set the Arianee project address
     * @param _arianeeProjectAddress New address to set
     */
    function setArianeeProjectAddress(
        address _arianeeProjectAddress
    ) external onlyRole(ROLE_ADMIN) {
        _getArianeeStoreStorageV0().arianeeProjectAddress = _arianeeProjectAddress;
        emit SetAddress("arianeeProject", _arianeeProjectAddress);
    }

    /**
     * @notice Update the USD price of a given credit type
     * @param _creditType Credit type to update
     * @param _price New price in USD
     */
    function setCreditPrice(uint256 _creditType, uint256 _price) external onlyRole(ROLE_ADMIN) {
        _getArianeeStoreStorageV0().creditPricesUSD[_creditType] = _price;
        _updateCreditPrice();

        emit NewCreditPrice(_creditType, _price);
    }

    /**
     * @notice Set the different rewards dispatch percent per actor
     */
    function setDispatchPercent(
        uint8 _percentInfra,
        uint8 _percentBrandsProvider,
        uint8 _percentOwnerProvider,
        uint8 _arianeeProject,
        uint8 _smartAssetHolder
    ) external onlyRole(ROLE_ADMIN) {
        require(
            _percentInfra + _percentBrandsProvider + _percentOwnerProvider + _arianeeProject + _smartAssetHolder == 100,
            "ArianeeStore: Dispatch percent must sum to 100"
        );
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.dispatchPercent[0] = _percentInfra; // Protocol infrastructure
        $.dispatchPercent[1] = _percentBrandsProvider; // NMP provider
        $.dispatchPercent[2] = _percentOwnerProvider; // Wallet provider
        $.dispatchPercent[3] = _arianeeProject; // Protocol maintainer
        $.dispatchPercent[4] = _smartAssetHolder; // SmartAsset holder

        emit NewDispatchPercent(
            _percentInfra, _percentBrandsProvider, _percentOwnerProvider, _arianeeProject, _smartAssetHolder
        );
    }

    /**
     * @notice Withdraw all Ether and ERC-20 tokens from the contract
     * @param withdrawAddress Address to withdraw Ether and ERC-20 tokens to
     * @param tokenAddresses Array of ERC-20 token addresses to withdraw from
     */
    function withdrawAll(address withdrawAddress, address[] calldata tokenAddresses) external onlyRole(ROLE_ADMIN) {
        // Withdraw Ether
        uint256 contractBalance = address(this).balance;
        if (contractBalance > 0) {
            (bool success,) = withdrawAddress.call{ value: contractBalance }("");
            require(success, "Ether transfer failed");
        }

        // Withdraw ERC-20 tokens
        for (uint256 i = 0; i < tokenAddresses.length; i++) {
            IERC20 token = IERC20(tokenAddresses[i]);
            uint256 tokenBalance = token.balanceOf(address(this));
            if (tokenBalance > 0) {
                require(token.transfer(withdrawAddress, tokenBalance), "Token transfer failed");
            }
        }
    }

    // Restricted functions

    /**
     * @notice Set the Aria/USD exchange rate
     * @dev Can only be called by the authorized exchange address
     * @param _ariaUSDExchange New exchange rate
     */
    function setAriaUSDExchange(
        uint256 _ariaUSDExchange
    ) external onlyAuthorizedExchangeAddress {
        _getArianeeStoreStorageV0().ariaUSDExchange = _ariaUSDExchange;
        _updateCreditPrice();

        emit NewAriaUSDExchange(_ariaUSDExchange);
    }

    /**
     * @notice Dispatch rewards to the different actors when the first transfer occurs
     * @dev This function must be called by the ArianeeSmartAsset contract
     * @param _tokenId SmartAsset ID
     * @param _newOwner Address of the new owner
     */
    function dispatchRewardsAtFirstTransfer(uint256 _tokenId, address _newOwner) external onlySmartAsset {
        // The responsability of checking if first transfer rewards are already dispatched is on the ArianeeSmartAsset contract
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 _rewards = $.rewardsHistory.getTokenReward(_tokenId);

        address _nmpProvider = $.rewardsHistory.getTokenNmpProvider(_tokenId);
        address _walletProvider = $.rewardsHistory.getTokenWalletProvider(_tokenId);
        // If there is not wallet provider set, we give the rewards to the NMP provider
        if (_walletProvider == address(0)) {
            if (_nmpProvider != address(0)) {
                _walletProvider = _nmpProvider;
            } else {
                // If there is no NMP Provider set, we give the rewards to the protocol infrastructure
                _walletProvider = $.protocolInfraAddress;
            }
        }

        $.rewardsHistory.resetTokenReward(_tokenId);

        $.aria.transfer(_walletProvider, (_rewards / 100) * $.dispatchPercent[2]);
        $.aria.transfer(_newOwner, (_rewards / 100) * $.dispatchPercent[4]);
    }

    // Getters

    /**
     * @notice Returns the percentage of rewards dispatched to a given actor
     */
    function percentOfDispatch(
        uint8 _actorIndex
    ) external view returns (uint8 _percent) {
        _percent = _getArianeeStoreStorageV0().dispatchPercent[_actorIndex];
    }

    /**
     * @notice Returns the USD price of a given credit type
     */
    function creditPriceUSD(
        uint256 _creditType
    ) external view returns (uint256 _creditPriceUSD) {
        _creditPriceUSD = _getArianeeStoreStorageV0().creditPricesUSD[_creditType];
    }

    /**
     * @notice Returns the Aria price of a given credit type
     */
    function getCreditPrice(
        uint256 _creditType
    ) external view returns (uint256) {
        return _getArianeeStoreStorageV0().creditPrices[_creditType];
    }

    // Internal Functions & Overrides

    /**
     * @notice Update the Aria price of each credit type
     */
    function _updateCreditPrice() internal {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        require(
            $.creditPricesUSD[0] * $.ariaUSDExchange >= 100,
            "ArianeeStore: `creditPricesUSD[0] * ariaUSDExchange` must be > 100"
        );
        require(
            $.creditPricesUSD[1] * $.ariaUSDExchange >= 100,
            "ArianeeStore: `creditPricesUSD[1] * ariaUSDExchange` must be > 100"
        );
        require(
            $.creditPricesUSD[2] * $.ariaUSDExchange >= 100,
            "ArianeeStore: `creditPricesUSD[2] * ariaUSDExchange` must be > 100"
        );
        require(
            $.creditPricesUSD[3] * $.ariaUSDExchange >= 100,
            "ArianeeStore: `creditPricesUSD[3] * ariaUSDExchange` must be > 100"
        );
        $.creditPrices[0] = $.creditPricesUSD[0] * $.ariaUSDExchange;
        $.creditPrices[1] = $.creditPricesUSD[1] * $.ariaUSDExchange;
        $.creditPrices[2] = $.creditPricesUSD[2] * $.ariaUSDExchange;
        $.creditPrices[3] = $.creditPricesUSD[3] * $.ariaUSDExchange;
    }

    /**
     * @notice Spend credits from the credit history contract
     * @param _creditType Credit type to spend
     * @param _quantity Quantity of credit to spend
     * @param _consumer Address of the consumer
     */
    function _spendCreditFunction(
        uint256 _creditType,
        uint256 _quantity,
        address _consumer
    ) internal returns (uint256) {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 rewards = $.creditHistory.consumeCredits(_consumer, _creditType, _quantity);
        emit CreditSpended(_creditType, _quantity);
        return rewards;
    }

    /**
     * @notice Dispatch rewards to the different actors when a SmartAsset is hydrated
     * @param _rewardsReceiver Address of the rewards receiver
     * @param _rewards Amount of rewards to dispatch
     */
    function _dispatchRewardsAtHydrate(address _rewardsReceiver, uint256 _rewards) internal {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.aria.transfer($.protocolInfraAddress, (_rewards / 100) * $.dispatchPercent[0]);
        $.aria.transfer($.arianeeProjectAddress, (_rewards / 100) * $.dispatchPercent[3]);
        $.aria.transfer(_rewardsReceiver, (_rewards / 100) * $.dispatchPercent[1]);
    }

    /**
     * @notice Dispatch rewards to the different actors when a SmartAsset is requested
     * @param _rewardsReceiver Address of the rewards receiver
     * @param _rewards Amount of rewards to dispatch
     */
    function _dispatchRewardsAtRequest(address _rewardsReceiver, uint256 _rewards) internal {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.aria.transfer(_rewardsReceiver, (_rewards / 100) * $.dispatchPercent[2]);
        $.aria.transfer(_msgSender(), (_rewards / 100) * $.dispatchPercent[4]);
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
 * @notice This emits when credits are bought
 */
event CreditBought(address indexed buyer, address indexed _receiver, uint256 indexed _creditType, uint256 quantity);

/**
 * @notice This emits when credits are spended
 */
event CreditSpended(uint256 indexed _type, uint256 _quantity);

/**
 * @notice This emits when a new address is set
 */
event SetAddress(string _addressType, address _newAddress);

/**
 * @notice This emits when a credit type price is changed
 */
event NewCreditPrice(uint256 indexed _creditType, uint256 _price);

/**
 * @notice This emits when the Aria to USD exchange rate is changed
 */
event NewAriaUSDExchange(uint256 _ariaUSDExchange);

/**
 * @notice This emits when a new dispatch percent is set
 */
event NewDispatchPercent(
    uint8 _percentInfra,
    uint8 _percentBrandsProvider,
    uint8 _percentOwnerProvider,
    uint8 _arianeeProject,
    uint8 _assetHolder
);
