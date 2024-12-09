// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Proxy Utils
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

abstract contract UnorderedNonceUpgradeable is Initializable {
    /// @custom:storage-location erc7201:unorderednonce.storage.v0
    struct UnorderedNonceStorage {
        /// @notice A map from commitmentHash and a caller specified word index to a bitmap. Used to set bits in the bitmap to prevent against signature replay attacks
        /// @dev Uses unordered nonces so that permit messages do not need to be spent in a certain order
        /// @dev The mapping is indexed first by the commitmentHash, then by an index specified in the nonce
        /// @dev It returns a uint256 bitmap
        /// @dev The index, or wordPosition is capped at type(uint248).max
        mapping(uint256 => mapping(uint256 => uint256)) nonceBitmap;
    }

    // keccak256(abi.encode(uint256(keccak256("unorderednonce.storage.v0")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant UnorderedNonceStorageLocation =
        0xff29894d3e1897d0481106c97b1260b7947eec5ac744355a6aeb472862a7ad00;

    function _getUnorderedNonceStorage() private pure returns (UnorderedNonceStorage storage $) {
        assembly {
            $.slot := UnorderedNonceStorageLocation
        }
    }

    function __UnorderedNonce_init() internal onlyInitializing { }

    function __UnorderedNonce_init_unchained() internal onlyInitializing { }

    /// @notice Invalidates the bits specified in mask for the bitmap at the word position
    /// @dev The wordPos is maxed at type(uint248).max
    /// @param wordPos A number to index the nonceBitmap at
    /// @param mask A bitmap masked against commitmentHash's current bitmap at the word position
    function invalidateUnorderedNonces(uint256 commitmentHash, uint256 wordPos, uint256 mask) internal {
        require(wordPos <= type(uint248).max, "UnorderedNonce: `wordPos` too large");
        _getUnorderedNonceStorage().nonceBitmap[commitmentHash][wordPos] |= mask;

        emit UnorderedNonceInvalidation(commitmentHash, wordPos, mask);
    }

    /// @notice Returns the index of the bitmap and the bit position within the bitmap. Used for unordered nonces
    /// @param nonce The nonce to get the associated word and bit positions
    /// @return wordPos The word position or index into the nonceBitmap
    /// @return bitPos The bit position
    /// @dev The first 248 bits of the nonce value is the index of the desired bitmap
    /// @dev The last 8 bits of the nonce value is the position of the bit in the bitmap
    function bitmapPositions(
        uint256 nonce
    ) private pure returns (uint256 wordPos, uint256 bitPos) {
        wordPos = uint248(nonce >> 8);
        bitPos = uint8(nonce);
    }

    /// @notice Checks whether a nonce is taken and sets the bit at the bit position in the bitmap at the word position
    /// @param commitmentHash The commitmentHash to use the nonce at
    /// @param nonce The nonce to spend
    /// @return used A boolean indicating whether the nonce was successfully used
    function _useUnorderedNonce(uint256 commitmentHash, uint256 nonce) internal returns (bool) {
        (uint256 wordPos, uint256 bitPos) = bitmapPositions(nonce);
        uint256 bit = 1 << bitPos;
        uint256 flipped = _getUnorderedNonceStorage().nonceBitmap[commitmentHash][wordPos] ^= bit;

        return !(flipped & bit == 0);
    }
}

event UnorderedNonceInvalidation(uint256 indexed _commitmentHash, uint256 _word, uint256 _mask);
