// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Roles
bytes32 constant ROLE_ADMIN = 0x00; // 0x1effbbff9c66c5e59634f24fe842750c60d18891155c32dd155fc2d661a4c86d (Same as `DEFAULT_ADMIN_ROLE` in `AccessControlUpgradeable`)
bytes32 constant ROLE_ARIANEE_STORE = keccak256("ROLE_ARIANEE_STORE"); // 0x7c58c52c6ee36b58d66053b60f9071543575bb40c49fb6188a64738ae98ca57b
bytes32 constant ROLE_WHITELIST_MANAGER = keccak256("ROLE_WHITELIST_MANAGER"); // 0x53d446f05f3fa43bc6251ec5193ea1862b593fbfadb02d741a7a09c4776da75a

// ArianeeSmartAsset
string constant ERC721_NAME = "Arianee";
string constant ERC721_SYMBOL = "Arianee";

string constant URI_BASE = "https://cert.arianee.org/";

uint256 constant ACCESS_TYPE_VIEW = 0;
uint256 constant ACCESS_TYPE_TRANSFER = 1;

// ArianeeEvent
uint256 constant EVENT_DESTROY_DELAY = 31_536_000; // 1 year in seconds

// ArianeeStore
uint256 constant CREDIT_TYPE_CERTIFICATE = 0;
uint256 constant CREDIT_TYPE_MESSAGE = 1;
uint256 constant CREDIT_TYPE_EVENT = 2;
uint256 constant CREDIT_TYPE_UPDATE = 3;

// ArianeeIssuerProxy
uint256 constant SELECTOR_SIZE = 4;
uint256 constant OWNERSHIP_PROOF_SIZE = 352;
uint256 constant CREDIT_NOTE_PROOF_SIZE = 384;
