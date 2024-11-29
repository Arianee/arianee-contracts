// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { IArianeeStore } from "../Interfaces/IArianeeStore.sol";
import { IArianeeCreditHistory } from "../Interfaces/IArianeeCreditHistory.sol";

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
// Meta Transactions
import { ERC2771ContextUpgradeable } from "@openzeppelin/contracts-upgradeable/metatx/ERC2771ContextUpgradeable.sol";

struct CreditBuy {
    uint256 price;
    uint256 quantity;
}

/**
 * @title ArianeeCreditHistory
 * @notice This contract is used to store the credit history of the ArianeeStore contract.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
contract ArianeeCreditHistory is IArianeeCreditHistory, Initializable, ERC2771ContextUpgradeable {
    /// @custom:storage-location erc7201:arianeecredithistory.storage.v0
    struct ArianeeCreditHistoryStorageV0 {
        /**
         * @notice The ArianeeStore contract
         */
        IArianeeStore store;
        /**
         * @notice Mapping from an address to an array of creditHistory, categorized by type of credit
         */
        mapping(address => mapping(uint256 => CreditBuy[])) addrToTypeToCreditHistory;
        /**
         * @notice Mapping from an address to a creditHistory index, categorized by type of credit
         */
        mapping(address => mapping(uint256 => uint256)) addrToTypeToCreditHistoryIndex;
        /**
         * @notice Mapping from an address to totalCredit, categorized by type of credit
         */
        mapping(address => mapping(uint256 => uint256)) addrToTypeToTotalCredit;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeecredithistory.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeCreditHistoryStorageV0Location =
        0x30bf6f679829f8f2f9755a593c694551b0ec31f7962855eb55f725e310bdff00;

    function _getArianeeCreditHistoryStorageV0() internal pure returns (ArianeeCreditHistoryStorageV0 storage $) {
        assembly {
            $.slot := ArianeeCreditHistoryStorageV0Location
        }
    }

    /**
     * @notice Ensures that the _msgSender() is the ArianeeStore contract
     */
    modifier onlyStore() {
        require(
            msg.sender == address(_getArianeeCreditHistoryStorageV0().store),
            "ArianeeCreditHistory: This function can only be called by the ArianeeStore contract"
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
        ArianeeCreditHistoryStorageV0 storage $ = _getArianeeCreditHistoryStorageV0();
        $.store = IArianeeStore(_storeAddress);
    }

    /**
     * @notice Add a credit history for a given spender, price, quantity and type
     * @param _spender Address of the buyer
     * @param _price Credit price at the time of the buy
     * @param _quantity Quantity of credit buyed
     * @param _type Type of credit
     */
    function addCreditHistory(address _spender, uint256 _price, uint256 _quantity, uint256 _type) external onlyStore {
        ArianeeCreditHistoryStorageV0 storage $ = _getArianeeCreditHistoryStorageV0();
        $.addrToTypeToCreditHistory[_spender][_type].push(CreditBuy({ price: _price, quantity: _quantity }));
        $.addrToTypeToTotalCredit[_spender][_type] = $.addrToTypeToTotalCredit[_spender][_type] + _quantity;
    }

    /**
     * @notice Consume a given quantity of credit and return the price of the oldest non spent credit
     * @param _spender Address of the buyer
     * @param _type Type of credit
     * @param _quantity Quantity of credit buyed
     */
    function consumeCredits(address _spender, uint256 _type, uint256 _quantity) external onlyStore returns (uint256) {
        ArianeeCreditHistoryStorageV0 storage $ = _getArianeeCreditHistoryStorageV0();
        require($.addrToTypeToTotalCredit[_spender][_type] > 0, "ArianeeCreditHistory: Unknow credit type");

        uint256 _index = $.addrToTypeToCreditHistoryIndex[_spender][_type];
        require(
            $.addrToTypeToCreditHistory[_spender][_type][_index].quantity >= _quantity,
            "ArianeeCreditHistory: Not enough credit"
        );

        uint256 price = $.addrToTypeToCreditHistory[_spender][_type][_index].price;
        $.addrToTypeToCreditHistory[_spender][_type][_index].quantity =
            $.addrToTypeToCreditHistory[_spender][_type][_index].quantity - _quantity;
        $.addrToTypeToTotalCredit[_spender][_type] = $.addrToTypeToTotalCredit[_spender][_type] - 1;

        if ($.addrToTypeToCreditHistory[_spender][_type][_index].quantity == 0) {
            $.addrToTypeToCreditHistoryIndex[_spender][_type] = $.addrToTypeToCreditHistoryIndex[_spender][_type] + 1;
        }

        return price;
    }

    /**
     * @notice Get the credit history for a given spender and credit type
     * @param _spender Address for which we want the credit history
     * @param _type Type of the credit for which we want the history
     * @param _index Index of the credit history
     * @return _price Price of the credit
     * @return _quantity Quantity of the credit
     */
    function userCreditHistory(
        address _spender,
        uint256 _type,
        uint256 _index
    ) external view returns (uint256 _price, uint256 _quantity) {
        ArianeeCreditHistoryStorageV0 storage $ = _getArianeeCreditHistoryStorageV0();
        _price = $.addrToTypeToCreditHistory[_spender][_type][_index].price;
        _quantity = $.addrToTypeToCreditHistory[_spender][_type][_index].quantity;
    }

    /**
     * @notice Get the index of the credit history for a given spender and credit type
     * @param _spender Address for which we want the credit history
     * @param _type Type of the credit for which we want the history
     * @return _historyIndex Index of the credit history
     */
    function userIndex(address _spender, uint256 _type) external view returns (uint256 _historyIndex) {
        _historyIndex = _getArianeeCreditHistoryStorageV0().addrToTypeToCreditHistoryIndex[_spender][_type];
    }

    /**
     * @notice Get the total balance of credit for a given spender
     * @param _spender for which we want the credit history.
     * @param _type of the credit for which we want the history.
     * @return _totalCredits Balance of the spender.
     */
    function balanceOf(address _spender, uint256 _type) external view returns (uint256 _totalCredits) {
        _totalCredits = _getArianeeCreditHistoryStorageV0().addrToTypeToTotalCredit[_spender][_type];
    }
}
