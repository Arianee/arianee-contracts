# AGENTS.md

<!--
  This file is the AI entry point for this repository.
  Keep it up to date — agents rely on it to understand the project.
  See: https://github.com/Arianee/arianee-knowledge-base/blob/main/templates/AGENTS-GUIDELINES.md
-->

## Overview

The core smart contracts powering the Arianee Protocol — a decentralized solution for tokenized digital product passports. Built with Foundry on a multi-EVM foundation. Features include events timestamping, decentralized messaging, privacy via zk-proofs, and transfer permits (Smart Asset Sharing Tokens).

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Solidity |
| Framework | Foundry (forge, cast, anvil) |
| Runtime | EVM-compatible chains |
| Package manager | npm (for ABI generation) |

## Architecture

```
src/
├── V0/                # Legacy contract versions
├── V1/                # Current contract versions
├── ByteUtils.sol      # Utility library
└── UnorderedNonceUpgradeable.sol
```

### Key features
- **Events Timestamping** — NFT metadata enrichment through lifecycle
- **Decentralized Messaging** — On-chain brand-to-consumer communication
- **Privacy** — Zero-knowledge proofs for on/off-chain data protection
- **Transfer Permit (Permit721)** — Delegated marketplace rights for DPP transfers

## Dependencies

### Depends on
- OpenZeppelin contracts (upgradeable)
- Foundry toolchain

### Depended on by
- `@arianee/arianee-protocol-client` (in arianee-sdk)
- `@arianee/arianee-abi` — Generated ABI definitions
- All services interacting with Arianee on-chain

## Deployment

Smart contracts deployed on multiple EVM chains.

| Network | Deploy method |
|---------|---------------|
| <!-- TODO: list networks --> | Foundry scripts |

### CI/CD
- **CircleCI** — tests

## Configuration

Foundry config in `foundry.toml`.

## Development

### Setup
```bash
git clone https://github.com/Arianee/arianee-contracts.git
cd arianee-contracts
# Install Foundry: https://book.getfoundry.sh/getting-started/installation
forge install
```

### Common commands
```bash
forge test            # Run tests
forge build           # Compile contracts
npm run gen:abi       # Generate ABI files
forge script <path>   # Run deployment scripts
```

## Conventions

- Solidity style per Foundry defaults
- Upgradeable contract pattern (UUPS or Transparent proxy)

## Ownership

| Role | Team / Person |
|------|--------------|
| Squad | <!-- TODO: needs human input --> |
| Main contributors | <!-- TODO: needs human input --> |
