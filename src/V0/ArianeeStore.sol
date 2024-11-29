// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IERC20 } from "@openzeppelin/contracts/interfaces/IERC20.sol";
import { IArianeeStore } from "./Interfaces/IArianeeStore.sol";
import { IArianeeSmartAsset } from "./Interfaces/IArianeeSmartAsset.sol";
import { IArianeeCreditHistory } from "./Interfaces/IArianeeCreditHistory.sol";
import { IArianeeRewardsHistory } from "./Interfaces/IArianeeRewardsHistory.sol";
import { IArianeeEvent } from "./Interfaces/IArianeeEvent.sol";
import { IArianeeMessage } from "./Interfaces/IArianeeMessage.sol";
import { IArianeeSmartAssetUpdate } from "./Interfaces/IArianeeSmartAssetUpdate.sol";
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
        uint256 _creditPricesUSD0
    ) public initializer {
        __Pausable_init_unchained();

        _grantRole(ROLE_ADMIN, _initialAdmin);

        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        $.aria = IERC20(_ariaAddress);
        $.smartAsset = IArianeeSmartAsset(_smartAssetAddress);
        $.smartAssetUpdate = IArianeeSmartAssetUpdate(_smartAssetUpdateAddress);
        $.arianeeEvent = IArianeeEvent(_eventAddress);
        $.arianeeMessage = IArianeeMessage(_messageAddress);
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
     * @notice Buy new credit against Aria
     * @param _creditType Credit type to buy
     * @param _quantity Quantity of credit to buy
     * @param _to Address to grant the credit to
     */
    function buyCredit(uint256 _creditType, uint256 _quantity, address _to) external whenNotPaused {
        ArianeeStoreStorageV0 storage $ = _getArianeeStoreStorageV0();
        uint256 tokens = _quantity * $.creditPrices[_creditType];

        // Assert that the buyer transfers the correct amount of Aria
        require(acceptedToken.transferFrom(_msgSender(), address(this), tokens), "ArianeeStore: Transfer failed");
        $.creditHistory.addCreditHistory(_to, creditPrices[_creditType], _quantity, _creditType);

        emit CreditBought(_msgSender(), _to, _creditType, _quantity);
    }

    /**
     * @notice Proxy function to call {ArianeeSmartAsset-hydrateToken} with additional tokenomics logic
     */
    function hydrateToken(
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        address _encryptedInitialKey,
        uint256 _tokenRecoveryTimestamp,
        bool _initialKeyIsRequestKey,
        address _providerBrand
    ) external whenNotPaused {
        bool tokenExists;
        try nonFungibleRegistry.ownerOf(_tokenId) {
            tokenExists = true;
        } catch {
            tokenExists = false;
        }

        if (tokenExists == false) {
            reserveToken(_tokenId, _msgSender());
        }

        uint256 _reward = _spendCreditFunction(0, 1, _msgSender());
        _dispatchRewardsAtHydrate(_providerBrand, _reward);
        rewardsHistory.setTokenRewards(_tokenId, _reward);

        nonFungibleRegistry.hydrateToken(
            _tokenId,
            _imprint,
            _uri,
            _encryptedInitialKey,
            _tokenRecoveryTimestamp,
            _initialKeyIsRequestKey,
            _msgSender()
        );
        rewardsHistory.setTokenNmpProvider(_tokenId, _providerBrand);
    }

    /**
     * @notice Proxy function to call {ArianeeSmartAsset-requestToken} with additional tokenomics logic
     */
    function requestToken(
        uint256 _tokenId,
        bytes32 _hash,
        bool _keepRequestToken,
        address _providerOwner,
        bytes calldata _signature
    ) external whenNotPaused {
        rewardsHistory.setTokenWalletProvider(_tokenId, _providerOwner);
        nonFungibleRegistry.requestToken(_tokenId, _hash, _keepRequestToken, _msgSender(), _signature);
    }

    /**
     * @notice Proxy function to call {ArianeeSmartAsset-requestToken} with additional tokenomics logic
     * @dev This function is intended to be called by a custom relayer logic
     */
    function requestToken(
        uint256 _tokenId,
        bytes32 _hash,
        bool _keepRequestToken,
        address _providerOwner,
        bytes calldata _signature,
        address _newOwner
    ) external whenNotPaused {
        rewardsHistory.setTokenWalletProvider(_tokenId, _providerOwner);
        nonFungibleRegistry.requestToken(_tokenId, _hash, _keepRequestToken, _newOwner, _signature);
    }

    /**
     * @notice Change the percent of rewards per actor.
     * @notice Can only be called by owner.
     * @param _percentInfra Percent get by the infrastructure maintener.
     * @param _percentBrandsProvider Percent get by the brand software provider.
     * @param _percentOwnerProvider Percent get by the owner software provider.
     * @param _arianeeProject Percent get by the Arianee fondation.
     * @param _assetHolder Percent get by the asset owner.
     */
    function setDispatchPercent(
        uint8 _percentInfra,
        uint8 _percentBrandsProvider,
        uint8 _percentOwnerProvider,
        uint8 _arianeeProject,
        uint8 _assetHolder
    ) external onlyOwner {
        require(_percentInfra + _percentBrandsProvider + _percentOwnerProvider + _arianeeProject + _assetHolder == 100);
        dispatchPercent[0] = _percentInfra;
        dispatchPercent[1] = _percentBrandsProvider;
        dispatchPercent[2] = _percentOwnerProvider;
        dispatchPercent[3] = _arianeeProject;
        dispatchPercent[4] = _assetHolder;

        emit NewDispatchPercent(
            _percentInfra, _percentBrandsProvider, _percentOwnerProvider, _arianeeProject, _assetHolder
        );
    }

    /**
     * @notice Get all Arias from the previous store.
     * @notice Can only be called by the owner.
     * @param _oldStoreAddress address of the previous store.
     */
    function getAriaFromOldStore(
        address _oldStoreAddress
    ) external onlyOwner {
        ArianeeStore oldStore = ArianeeStore(address(_oldStoreAddress));
        oldStore.withdrawArias();
    }

    /**
     * @notice Withdraw all arias to the new store.
     * @notice Can only be called by the new store.
     */
    function withdrawArias() external {
        require(address(this) != creditHistory.arianeeStoreAddress());
        require(_msgSender() == creditHistory.arianeeStoreAddress());
        acceptedToken.transfer(address(creditHistory.arianeeStoreAddress()), acceptedToken.balanceOf(address(this)));
    }

    /**
     * @notice Create an event and spend an event credit.
     * @param _tokenId ID concerned by the event.
     * @param _imprint Proof.
     * @param _uri URI of the JSON.
     * @param _providerBrand address of the provider of the interface.
     */
    function createEvent(
        uint256 _eventId,
        uint256 _tokenId,
        bytes32 _imprint,
        string calldata _uri,
        address _providerBrand
    ) external whenNotPaused {
        uint256 _rewards = _spendCreditFunction(2, 1, _msgSender());
        arianeeEvent.create(_eventId, _tokenId, _imprint, _uri, _rewards, _msgSender());
        _dispatchRewardsAtHydrate(_providerBrand, _rewards);
    }

    /**
     * @notice Owner accept an event.
     * @param _eventId event accepted.
     * @param _providerOwner address of the provider of the interface.
     */
    function acceptEvent(uint256 _eventId, address _providerOwner) external whenNotPaused {
        uint256 _rewards = arianeeEvent.accept(_eventId, _msgSender());
        _dispatchRewardsAtRequest(_providerOwner, _rewards);
    }

    /**
     * @notice Owner refuse an event.
     * @param _eventId event accepted.
     * @param _providerOwner address of the provider of the interface.
     */
    function refuseEvent(uint256 _eventId, address _providerOwner) external {
        uint256 _rewards = arianeeEvent.refuse(_eventId, _msgSender());
        _dispatchRewardsAtRequest(_providerOwner, _rewards);
    }

    /**
     * @notice Create a message and spend an Message credit.
     * @param _messageId ID of the message to create
     * @param _tokenId ID concerned by the message.
     * @param _imprint Proof.
     * @param _providerBrand address of the provider of the interface.
     */
    function createMessage(
        uint256 _messageId,
        uint256 _tokenId,
        bytes32 _imprint,
        address _providerBrand
    ) external whenNotPaused {
        uint256 _reward = _spendCreditFunction(1, 1, _msgSender());
        arianeeMessage.sendMessage(_messageId, _tokenId, _imprint, _msgSender(), _reward);

        _dispatchRewardsAtHydrate(_providerBrand, _reward);
    }

    /**
     * @notice Read a message and dispatch rewards.
     * @param _messageId ID of message.
     * @param _walletProvider address of the provider of the wallet
     */
    function readMessage(uint256 _messageId, address _walletProvider) external whenNotPaused {
        uint256 _reward = arianeeMessage.readMessage(_messageId, _msgSender());

        _dispatchRewardsAtRequest(_walletProvider, _reward);
    }

    /**
     * @notice Create/update a smartAsset update and spend an Update Credit.
     * @param _tokenId ID concerned by the message.
     * @param _imprint Imprint of the update.
     * @param _providerBrand address of the provider of the interface.
     */
    function updateSmartAsset(uint256 _tokenId, bytes32 _imprint, address _providerBrand) external whenNotPaused {
        uint256 _reward = _spendCreditFunction(3, 1, _msgSender());
        arianeeUpdate.updateSmartAsset(_tokenId, _imprint, _msgSender(), _reward);
        _dispatchRewardsAtHydrate(_providerBrand, _reward);
    }

    /**
     * @notice Read an update and dispatch rewards.
     * @param _tokenId ID concerned by the update.
     * @param _walletProvider address of the provider of the wallet
     */
    function readUpdateSmartAsset(uint256 _tokenId, address _walletProvider) external whenNotPaused {
        uint256 _reward = arianeeUpdate.readUpdateSmartAsset(_tokenId, _msgSender());

        _dispatchRewardsAtRequest(_walletProvider, _reward);
    }

    /**
     * @notice The USD credit price per type.
     * @param _creditType for which we want the USD price.
     * @return _creditPriceUSD price in USD.
     */
    function creditPriceUSD(
        uint256 _creditType
    ) external view returns (uint256 _creditPriceUSD) {
        _creditPriceUSD = creditPricesUSD[_creditType];
    }

    /**
     * @notice dispatch for rewards.
     * @param _receiver for which we want the % of rewards.
     * @return _percent % of rewards.
     */
    function percentOfDispatch(
        uint8 _receiver
    ) external view returns (uint8 _percent) {
        _percent = dispatchPercent[_receiver];
    }

    /**
     * @notice Send the price a of a credit in aria
     * @param _creditType uint256
     * @return returne the price of the credit type.
     */
    function getCreditPrice(
        uint256 _creditType
    ) external view returns (uint256) {
        return creditPrices[_creditType];
    }

    /**
     * @notice Reserve ArianeeSmartAsset
     * @param _id uint256 id of the NFT
     * @param _to address receiver of the token.
     */
    function reserveToken(uint256 _id, address _to) public whenNotPaused {
        nonFungibleRegistry.reserveToken(_id, _to);
    }

    /**
     * @dev Internal function update creditPrice.
     * @notice creditPrice need to be >100
     */
    function _updateCreditPrice() internal {
        require(creditPricesUSD[0] * ariaUSDExchange >= 100);
        require(creditPricesUSD[1] * ariaUSDExchange >= 100);
        require(creditPricesUSD[2] * ariaUSDExchange >= 100);
        require(creditPricesUSD[3] * ariaUSDExchange >= 100);
        creditPrices[0] = creditPricesUSD[0] * ariaUSDExchange;
        creditPrices[1] = creditPricesUSD[1] * ariaUSDExchange;
        creditPrices[2] = creditPricesUSD[2] * ariaUSDExchange;
        creditPrices[3] = creditPricesUSD[3] * ariaUSDExchange;
    }

    /**
     * @dev Spend credits
     * @param _type credit type used.
     * @param _quantity of credit to spend.
     */
    function _spendCreditFunction(uint256 _type, uint256 _quantity, address consumer) internal returns (uint256) {
        uint256 reward = creditHistory.consumeCredits(consumer, _type, _quantity);
        emit CreditSpended(_type, _quantity);
        return reward;
    }

    /**
     * @dev Dispatch rewards at creation.
     * @param _providerBrand address of the provider of the interface.
     * @param _reward reward for this token.
     */
    function _dispatchRewardsAtHydrate(address _providerBrand, uint256 _reward) internal {
        acceptedToken.transfer(protocolInfraAddress, (_reward / 100) * dispatchPercent[0]);
        acceptedToken.transfer(arianeeProjectAddress, (_reward / 100) * dispatchPercent[3]);
        acceptedToken.transfer(_providerBrand, (_reward / 100) * dispatchPercent[1]);
    }

    /**
     * @dev Dispatch rewards at client reception
     * @param _providerOwner address of the provider of the interface.
     * @param _reward reward for this token.
     */
    function _dispatchRewardsAtRequest(address _providerOwner, uint256 _reward) internal {
        acceptedToken.transfer(_providerOwner, (_reward / 100) * dispatchPercent[2]);
        acceptedToken.transfer(_msgSender(), (_reward / 100) * dispatchPercent[4]);
    }

    /**
     * @dev Dispatch rewards once at first transfer. This function must be called by the ArianeeSmartAsset contract.
     * @param _tokenId id of the token.
     * @param _newOwner address of the new owner.
     */
    function dispatchRewardsAtFirstTransfer(uint256 _tokenId, address _newOwner) external onlySmartAsset {
        // The responsability of checking if first transfer rewards are already dispatched is on the ArianeeSmartAsset contract.
        uint256 _reward = rewardsHistory.getTokenReward(_tokenId);

        address _nmpProvider = rewardsHistory.getTokenNmpProvider(_tokenId);
        address _walletProvider = rewardsHistory.getTokenWalletProvider(_tokenId);
        // If there is not wallet provider set, we give the rewards to the NMP provider.
        if (_walletProvider == address(0)) {
            if (_nmpProvider != address(0)) {
                _walletProvider = _nmpProvider;
            } else {
                // If there is no NMP Provider set, we give the rewards to the protocol infrastructure.
                _walletProvider = protocolInfraAddress;
            }
        }

        rewardsHistory.resetTokenReward(_tokenId);

        acceptedToken.transfer(_walletProvider, (_reward / 100) * dispatchPercent[2]);
        acceptedToken.transfer(_newOwner, (_reward / 100) * dispatchPercent[4]);
    }
}

/**
 * @notice This emits when a new address is set.
 */
event SetAddress(string _addressType, address _newAddress);

/**
 * @notice This emits when a credit's price is changed (in USD)
 */
event NewCreditPrice(uint256 indexed _creditType, uint256 _price);

/**
 * @notice This emits when the Aria/USD price is changed
 */
event NewAriaUSDExchange(uint256 _ariaUSDExchange);

/**
 * @notice This emits when credits are bought
 */
event CreditBought(address indexed buyer, address indexed _receiver, uint256 indexed _creditType, uint256 quantity);

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

/**
 * @notice This emits when credits are spended
 */
event CreditSpended(uint256 indexed _type, uint256 _quantity);
