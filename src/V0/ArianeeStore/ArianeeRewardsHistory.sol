// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeStore } from "../Interfaces/IArianeeStore.sol";
import { IArianeeRewardsHistory } from "../Interfaces/IArianeeRewardsHistory.sol";
import { ROLE_ADMIN, ROLE_ARIANEE_STORE } from "../Constants.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Utils
import { ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";
// Access
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

/**
 * @title ArianeeRewardsHistory
 * @notice This contract is used to store the rewards history of the ArianeeStore contract.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeRewardsHistory is
    IArianeeRewardsHistory,
    Initializable,
    ERC2771ContextUpgradeable,
    AccessControlUpgradeable
{
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
     * @notice You can change the trusted forwarder after initial deployment by overriding the `ERC2771ContextUpgradeable.trustedForwarder()` function
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _trustedForwarder
    ) ERC2771ContextUpgradeable(_trustedForwarder) {
        _disableInitializers();
    }

    function initialize(address _initialAdmin, address _storeAddress) public initializer {
        _grantRole(ROLE_ADMIN, _initialAdmin);
        _grantRole(ROLE_ARIANEE_STORE, _storeAddress);

        ArianeeRewardsHistoryStorageV0 storage $ = _getArianeeRewardsHistoryStorageV0();
        $.store = IArianeeStore(_storeAddress);
    }

    // Token rewards

    function setTokenReward(uint256 _tokenId, uint256 _rewards) public onlyRole(ROLE_ARIANEE_STORE) {
        _getArianeeRewardsHistoryStorageV0().tokenToRewards[_tokenId] = _rewards;
    }

    function getTokenReward(
        uint256 _tokenId
    ) public view returns (uint256) {
        return _getArianeeRewardsHistoryStorageV0().tokenToRewards[_tokenId];
    }

    function resetTokenReward(
        uint256 _tokenId
    ) public onlyRole(ROLE_ARIANEE_STORE) {
        _getArianeeRewardsHistoryStorageV0().tokenToRewards[_tokenId] = 0;
    }

    // Token NMP provider

    function setTokenNmpProvider(uint256 _tokenId, address _nmpProvider) public onlyRole(ROLE_ARIANEE_STORE) {
        _getArianeeRewardsHistoryStorageV0().tokenToNmpProvider[_tokenId] = _nmpProvider;
    }

    function getTokenNmpProvider(
        uint256 _tokenId
    ) public view returns (address) {
        return _getArianeeRewardsHistoryStorageV0().tokenToNmpProvider[_tokenId];
    }

    // Token wallet provider

    function setTokenWalletProvider(uint256 _tokenId, address _walletProvider) public onlyRole(ROLE_ARIANEE_STORE) {
        _getArianeeRewardsHistoryStorageV0().tokenToWalletProvider[_tokenId] = _walletProvider;
    }

    function getTokenWalletProvider(
        uint256 _tokenId
    ) public view returns (address) {
        return _getArianeeRewardsHistoryStorageV0().tokenToWalletProvider[_tokenId];
    }

    // Auto-generated getters migrated from the legacy version

    function storeAddress() public view returns (IArianeeStore) {
        return _getArianeeRewardsHistoryStorageV0().store;
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
