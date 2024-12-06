#!/bin/bash

# We init the Prover here so its shared between all tests, note that all tests using this Prover must use the same context as defined here (in the `initArgs` variable)
# You can also directly init the Prover from a test `setUp()` with `proverFfi("init", vm.toString(abi.encode(...)));

# Variables: signerPk, protocolVersion, chainId, aria, creditHistory, arianeeEvent, identity, smartAsset, store, lost, whitelist, arianeeMessage, smartAssetUpdate, issuerProxy
# Types: ["uint256","string","uint256","address","address","address","address","address","address","address","address","address","address","address"]
# Values: [123, "1.0", 1337, address(1), address(2), address(3), address(4), address(5), address(6), address(7), address(8), address(9), address(10), address(11)]
initArgs="0x6e877e433c86230899021755ec4267cbaea840c0d88b58e1f24ff9d667d4448d00000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000539000000000000000000000000c9fbe33b21c5874a132304e255be3f42c0ad6f410000000000000000000000007200973328f4622fb78687792e9aa2886e7eadbd000000000000000000000000bcb35b776ab08faea9dbd5213b1a544b7230cf9c0000000000000000000000006cb6ae7d9f9656e94bc6086bc6a753e59481e4e300000000000000000000000031830d9d870025300e0cf759397b5d94ea564fcc000000000000000000000000dc95a0cd2f1ba4522a7d8252ef3448cfc18032ce000000000000000000000000cd16801e775cdc4f1df78eace8c60ce8a6ee4da9000000000000000000000000663be2ca36656125747c77c78a610f8b539607bd000000000000000000000000f679af232cba80de6f796abfbb108dc9e557aaf1000000000000000000000000d842742ca7b92a4ca25b70e23b05326858da5ceb0000000000000000000000000d59ac73ffad1ffab2f9cd48fc7f3e54a693fb2a0000000000000000000000000000000000000000000000000000000000000003312e300000000000000000000000000000000000000000000000000000000000"
npm run --silent prover init "$initArgs" -- --no-stdout-write

forge test --force --match-path "./test/**/*.t.p.sol" "$@"
npm run --silent prover stop
