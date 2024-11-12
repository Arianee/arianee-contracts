// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Roles
bytes32 constant ROLE_ADMIN = 0x00; // Same as `DEFAULT_ADMIN_ROLE` in `AccessControlUpgradeable`
bytes32 constant ROLE_ARIANEE_STORE = keccak256("ROLE_ARIANEE_STORE");

// ArianeeSmartAsset
string constant ERC721_NAME = "Arianee";
string constant ERC721_SYMBOL = "Arianee";

string constant URI_BASE = "https://cert.arianee.org/";

uint256 constant ACCESS_TYPE_VIEW = 0;
uint256 constant ACCESS_TYPE_TRANSFER = 1;

// ArianeeEvent
uint256 constant EVENT_DESTROY_DELAY = 31_536_000; // 1 year in seconds
