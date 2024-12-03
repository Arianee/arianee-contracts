// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IArianeeIdentity {
    function updateInformations(string calldata _uri, bytes32 _imprint) external;
    function validateInformation(
        address _identity,
        string calldata _uriToValidate,
        bytes32 _imprintToValidate
    ) external;

    function addressIsApproved(
        address _identity
    ) external view returns (bool _isApproved);
    function addressURI(
        address _identity
    ) external view returns (string memory _uri);
    function addressImprint(
        address _identity
    ) external view returns (bytes32 _imprint);
    function waitingURI(
        address _identity
    ) external view returns (string memory _waitingUri);
    function waitingImprint(
        address _identity
    ) external view returns (bytes32 _waitingImprint);
}
