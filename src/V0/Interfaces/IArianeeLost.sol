// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeLost {
    function setMissingStatus(
        uint256 _tokenId
    ) external;

    function unsetMissingStatus(
        uint256 _tokenId
    ) external;

    function setStolenStatus(
        uint256 _tokenId
    ) external;

    function unsetStolenStatus(
        uint256 _tokenId
    ) external;

    function isMissing(
        uint256 _tokenId
    ) external view returns (bool _isMissing);
}
