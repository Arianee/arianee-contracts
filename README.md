## Arianee Contracts

<p align="center">
    <b>The @arianee/contracts repository houses the smart contracts that drive the Arianee Protocol—a decentralized, open-source solution for creating tokenized digital product passports. While these contracts are central to the protocol, they represent only part of its broader infrastructure. Built on a multi-EVM foundation, the protocol empowers brands to manage product identities, track lifecycle events, and directly engage with product owners.</b>
    <img src="https://cdn.prod.website-files.com/63dd075a9e277ca2c4b0244c/662b5abddfe83c59ee4135bb_USER%20OWNED%20DATA-p-800.png" width="600" />
</p>

## Key Features

- **Events Timestamping**: Enriching NFT metadata throughout its lifecycle allows the NFT to evolve alongside the customer journey, ideal for applications like e-maintenance booklets.
- **Decentralized Messaging**: Enabling secure, zero-party data exchanges between brands and consumers through on-chain mechanisms.
- **Privacy**: Protecting brands off and on-chain data through zero-knowledge proofs and other privacy-enhancing technologies.
- **Transfer Permit**: A Smart Asset Sharing Token that delegates marketplace rights for seamless digital product passport transfers post-sale, enhancing transaction fluidity for sellers, buyers, and marketplaces alike.

## Useful Links

- **Arianee Website**: https://arianee.com
- **Arianee Protocol**: https://arianee.org
- **Arianee Documentation**: https://docs.arianee.org
- **Foundry**: https://book.getfoundry.sh

## Security & Audits

In July 2024, a comprehensive audit of the circuits was conducted by [Veridise](https://veridise.com) to ensure the security and integrity of our privacy protocol. The full audit report is available in the repository for detailed insights and findings.

You can access the reports by following the links below:

- [VAR_Arianee_Circuits-Final](https://github.com/Arianee/arianee-sdk/blob/main/packages/privacy-circuits/VAR_Arianee_Circuits-Final.pdf)
- [VAR_Arianee_Contracts-Final](https://github.com/Arianee/ArianeeMaster/blob/1.5/VAR_Arianee_Contracts-Final.pdf)

## Repository Usage

### Build
To build the project, run the following command:
```shell
$ forge build
```

### Test
To run the tests, use the following command:
```shell
$ forge test
```

### Format
To format the code, run the following command:
```shell
$ forge fmt
```

### Anvil
To run an anvil node (local testnet shipped with Foundry), use the following command:
```shell
$ anvil
```
More information on Anvil can be found [here](https://book.getfoundry.sh/anvil/#overview-of-anvil).

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```
More information about Solidity Scripting can be found [here](https://book.getfoundry.sh/tutorials/solidity-scripting#solidity-scripting).

### Cast

```shell
$ cast <subcommand>
```
More information about Cast can be found [here](https://book.getfoundry.sh/cast/#overview-of-cast).

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```
