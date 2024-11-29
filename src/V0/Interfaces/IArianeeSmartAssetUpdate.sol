// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeSmartAssetUpdate {
    function updateSmartAsset(uint256 _tokenId, bytes32 _imprint, address _issuer, uint256 _rewards) external;

    function readUpdateSmartAsset(uint256 _tokenId, address _from) external returns (uint256);
}
