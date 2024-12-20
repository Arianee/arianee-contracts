// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeWhitelist {
    function addWhitelistedAddress(uint256 _tokenId, address _address) external;

    function isAuthorized(uint256 _tokenId, address _sender, address _tokenOwner) external view returns (bool);
}
