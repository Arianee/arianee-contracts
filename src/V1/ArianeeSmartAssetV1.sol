// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Stateless
import { ROLE_ADMIN, ROLE_ARIANEE_STORE } from "../V0/Constants.sol";

// ArianeeSmartAsset
import { ArianeeSmartAsset } from "../V0/ArianeeSmartAsset.sol";
// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title ArianeeSmartAssetV1
 * @notice This contract is the ERC721 implementation of the Arianee Protocol. An ERC721 token inside the Arianee ecosystem is called a SmartAsset.
 * @dev https://docs.arianee.org
 * @author Arianee — The Most Widely Used Protocol for Tokenized Digital Product Passports: Open & Interoperable. Working with over 50+ global brands!
 */
/// @custom:oz-upgrades-from ArianeeSmartAsset
contract ArianeeSmartAssetV1 is ArianeeSmartAsset {
    /// @custom:storage-location erc7201:arianeesmartasset.storage.v1
    struct ArianeeSmartAssetStorageV1 {
        string _string;
        uint256 _uint256;
        mapping(uint256 => bytes) _mapping_uint256_bytes;
    }

    // keccak256(abi.encode(uint256(keccak256("arianeesmartasset.storage.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant ArianeeSmartAssetStorageV1Location =
        0x0302a220fb0640bde2dd6c45397105a6bc2610d5275e8c6ef2ab5c2e3381ab00;

    function _getArianeeSmartAssetStorageV1() internal pure returns (ArianeeSmartAssetStorageV1 storage $) {
        assembly {
            $.slot := ArianeeSmartAssetStorageV1Location
        }
    }

    /**
     * @dev You can change the trusted forwarder after initial deployment by overriding the `ERC2771ContextUpgradeable.trustedForwarder()` function
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(
        address _trustedForwarder
    ) ArianeeSmartAsset(_trustedForwarder) {
        _disableInitializers();
    }

    function initializeV1(
        address _additionalAdmin,
        string calldata _newBaseURI,
        string calldata _stringValue
    ) public reinitializer(2) {
        _grantRole(ROLE_ADMIN, _additionalAdmin);

        ArianeeSmartAssetStorageV0 storage $v0 = _getArianeeSmartAssetStorageV0();
        $v0.baseURI = _newBaseURI;

        ArianeeSmartAssetStorageV1 storage $v1 = _getArianeeSmartAssetStorageV1();
        $v1._string = _stringValue;
        $v1._mapping_uint256_bytes[123] = abi.encode(456);
    }

    function getString() public view returns (string memory) {
        return _getArianeeSmartAssetStorageV1()._string;
    }

    function setUint256(
        uint256 _value
    ) public onlyRole(ROLE_ARIANEE_STORE) {
        _getArianeeSmartAssetStorageV1()._uint256 = _value;
    }

    function getUint256() public view returns (uint256) {
        return _getArianeeSmartAssetStorageV1()._uint256;
    }

    function getMapping(
        uint256 _key
    ) public view returns (bytes memory) {
        return _getArianeeSmartAssetStorageV1()._mapping_uint256_bytes[_key];
    }
}
