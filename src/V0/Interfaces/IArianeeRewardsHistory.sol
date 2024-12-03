// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeRewardsHistory {
    function setTokenReward(uint256 _tokenId, uint256 _rewards) external;

    function getTokenReward(
        uint256 _tokenId
    ) external view returns (uint256);

    function resetTokenReward(
        uint256 _tokenId
    ) external;

    function setTokenNmpProvider(uint256 _tokenId, address _nmpProvider) external;

    function getTokenNmpProvider(
        uint256 _tokenId
    ) external view returns (address);

    function setTokenWalletProvider(uint256 _tokenId, address _walletProvider) external;

    function getTokenWalletProvider(
        uint256 _tokenId
    ) external view returns (address);
}
