// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

string constant ERC721_NAME = "Arianee";
string constant ERC721_SYMBOL = "Arianee";

string constant URI_BASE = "https://cert.arianee.org/";

uint256 constant ACCESS_TYPE_VIEW = 0;
uint256 constant ACCESS_TYPE_TRANSFER = 1;

// Roles
bytes32 constant ROLE_SMART_ASSET_MANAGER = keccak256("ROLE_SMART_ASSET_MANAGER");
