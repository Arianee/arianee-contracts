// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeStore } from "../Interfaces/IArianeeStore.sol";
import { IArianeeRewardsHistory } from "../Interfaces/IArianeeRewardsHistory.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";

/**
 * @title ArianeeRewardsHistory
 * @notice This contract is used to store the rewards history of the ArianeeStore contract.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeRewardsHistory is IArianeeRewardsHistory, Initializable, ERC2771ContextUpgradeable {
    /// @custom:storage-location erc7201:arianeerewardshistory.storage.v0
    struct ArianeeRewardsHistoryStorageV0 {
        /**
         * @notice The ArianeeStore contract
         */
        IArianeeStore store;
        /**
         * @notice Mapping from SmartAsset ID to the associated rewards
         */
        mapping(uint256 => uint256) tokenToRewards;
        /**
         * @notice Mapping from SmartAsset ID to the address of the NMP provider that facilitated the creation of the SmartAsset
         */
        mapping(uint256 => address) tokenToNmpProvider;
        /**
         * @notice Mapping from SmartAsset ID to the address of the wallet provider that facilitated the request of the SmartAsset
         */
        mapping(uint256 => address) tokenToWalletProvider;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeerewardshistory.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeRewardsHistoryStorageV0Location =
        0x7faf6f74b76958ea97a8c9b56ffb6dd8afa982db0a811ac90b4a5c0398f26a00;

    function _getArianeeRewardsHistoryStorageV0() internal pure returns (ArianeeRewardsHistoryStorageV0 storage $) {
        assembly {
            $.slot := ArianeeRewardsHistoryStorageV0Location
        }
    }

    /**
     * @notice Ensures that the _msgSender() is the ArianeeStore contract
     */
    modifier onlyStore() {
        require(
            msg.sender == address(_getArianeeRewardsHistoryStorageV0().store),
            "ArianeeRewardsHistory: This function can only be called by the ArianeeStore contract"
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
        address _storeAddress
    ) public initializer {
        ArianeeRewardsHistoryStorageV0 storage $ = _getArianeeRewardsHistoryStorageV0();
        $.store = IArianeeStore(_storeAddress);
    }

    // Token rewards

    function setTokenReward(uint256 _tokenId, uint256 _rewards) public onlyStore {
        _getArianeeRewardsHistoryStorageV0().tokenToRewards[_tokenId] = _rewards;
    }

    function getTokenReward(
        uint256 _tokenId
    ) public view returns (uint256) {
        return _getArianeeRewardsHistoryStorageV0().tokenToRewards[_tokenId];
    }

    function resetTokenReward(
        uint256 _tokenId
    ) public onlyStore {
        _getArianeeRewardsHistoryStorageV0().tokenToRewards[_tokenId] = 0;
    }

    // Token NMP provider

    function setTokenNmpProvider(uint256 _tokenId, address _nmpProvider) public onlyStore {
        _getArianeeRewardsHistoryStorageV0().tokenToNmpProvider[_tokenId] = _nmpProvider;
    }

    function getTokenNmpProvider(
        uint256 _tokenId
    ) public view returns (address) {
        return _getArianeeRewardsHistoryStorageV0().tokenToNmpProvider[_tokenId];
    }

    // Token wallet provider

    function setTokenWalletProvider(uint256 _tokenId, address _walletProvider) public onlyStore {
        _getArianeeRewardsHistoryStorageV0().tokenToWalletProvider[_tokenId] = _walletProvider;
    }

    function getTokenWalletProvider(
        uint256 _tokenId
    ) public view returns (address) {
        return _getArianeeRewardsHistoryStorageV0().tokenToWalletProvider[_tokenId];
    }
}
