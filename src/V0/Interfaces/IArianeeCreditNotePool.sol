// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/**
 * @notice The CreditNoteProof must be the second argument if used in a function
 * This is allowing us to remove the CreditNoteProof from `_msgData()` easily
 */
struct CreditNoteProof {
    uint256[2] _pA; // 64 bytes
    uint256[2][2] _pB; // 128 bytes
    uint256[2] _pC; // 64 bytes
    uint256[4] _pubSignals; // 128 bytes
} // Total: 384 bytes

interface IArianeeCreditNotePool {
    function spend(
        CreditNoteProof calldata _creditNoteProof,
        bytes calldata _intentMsgData,
        uint256 _creditType
    ) external;
}
