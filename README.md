# Ambire contest details
- $32,000 USDC main award pot
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code423n4.com/2023-05-Ambire-contest/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts May 22, 2023 20:00 UTC
- Ends May 25, 2023 20:0 UTC
- The Ambire Wallet [contracts to be audited](https://github.com/AmbireTech/ambire-common/tree/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts)

# 🔥 Ambire Wallet 🔥

_The Web3 wallet that makes crypto self-custody easy and secure for everyone, built via account abstraction._

![Ambire Wallet](/marketing-assets/ambire.png)

# Useful links

* [ambire.com](https://www.ambire.com)
* [Twitter](https://twitter.com/AmbireWallet)
* [GitHub](https://github.com/AmbireTech/) 
* [Discord](https://discord.gg/nMBGJsb)

# Hello Wardens 👋

**We are looking forward to you diving into our code!**

Feel free to ask us anything you want, no matter if it's a minor nitpick or a severe issue. We remain available around the clock in the Code4rena Discord, and don't hestitate to tag @Ivo#8114

Good luck and enjoy hunting! 🐛🚫

We hope you're excited about finally seeing a usable and powerful smart contract wallet on Ethereum!

## Contest scope

All the contracts in `contracts/`, namely `AmbireAccount.sol`, `libs/SignatureValidator.sol`, `libs/Bytes.sol`, `AmbireAccountFactory.sol`, a total of 476 LoC.

## Architecture

Ambire is a smart contract wallet a.k.a account abstraction wallet. Each user is represented by a smart contract, which is a minimal proxy (EIP 1167) for `AmbireAccount.sol` ([example](https://polygonscan.com/address/0x7ce38c302924f4b84a2c3a158df7ca9a5b7d1e1e#code)) - we call "account". Many addresses can control each account - we call this "privileges" in the contract and "keys" in the UI.

The main contract everything is centered around is `AmbireAccount.sol`, which is the actual smart wallet.

Accounts can execute multiple calls in the same on-chain transaction. We call the array of user transactions a "user bundle" - the user signs the hash of this array along with anti-replay data such as nonce, chainID and others. Once it's signed, anyone can execute it by calling `AmbireAccount(account).execute`

The addresses that control an account (privileges) can be EOAs but they can also be smart contracts themselves, thanks to the `SmartWallet` signature mode in `SignatureValidator` which enables EIP-1271 signatures to be used.

To allow more sophisticated authentication schemes without upgradability, we use a very simple relationship: a periphery contract that only deals with the specific authentication scheme can be added to `privileges`. For example, if a user wants to convert their account to a multisig, they can remove all other privileges and only authorize a single one: a multisig manager contract, that will verify N/M signatures and call `AmbireAccount(account).executeBySender` upon successful verification. This also works for EIP 1271 signatures since `AmbireAccount.isValidSignature` uses `SignatureValidator`, which supports EIP 1271 itself, so it will propagate the call down to the multisig manager contract.

There are a few ways for a user bundle to get executed:
* Directly, when a user's EOA pays for gas
* Through a Relayer that takes the signed message that authorizes a user bundle, and broadcasts it itself, paying for gas. The user bundle will have to contain an ERC-20 transaction that pays the Relayer to reimburse it for gas. Currently we have a proprietary relayer that does all of this.
* Through ERC-4337

The actual proxy for each account is deployed counterfactually, when the first user bundle is executed.

Because user bundles are authorized as signed messages, there's no need for hardware wallets to support EIP-1559 directly.

Similar products include Argent, Safe and Sequence. The most notable differences is that the Ambire contracts are designed to be as simple as possible.

### Testing and JS libs

The contracts in scope can also be found in this repo: https://github.com/AmbireTech/ambire-common/tree/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts.

The code is frozen for review on commit ad7d99b2b30b6d79959b6767da933bf01c58ade7 in the repo [ambire-common](https://github.com/AmbireTech/ambire-common/tree/ad7d99b2b30b6d79959b6767da933bf01c58ade7/contracts).

There are tests that you can run via `npm test` in the `ambire-common` repo. You can find them in `contracts/tests/`.

There's one additional part that is not yet added to the repo, and this is the **deploy mechanism implemented [here in IdentityProxyDeploy](https://github.com/AmbireTech/adex-protocol-eth/blob/master/js/IdentityProxyDeploy.js)**. Instead of deploying the whole `AmbireAccount` contract every time, we use minimal proxies. This is pretty standard, but most smart contract wallets use an `initialize()` function that can only be called once to set the privileges of the contract, because minimal proxies normally don't have constructors. Instead of this approach, which is quite unsafe, we use `IdentityProxyDeploy`, which generates deploy bytecode which directly does SSTORE in the correct storage slots to set the privileges for the relevant keys.

You can test Ambire itself at [wallet.ambire.com](https://www.ambire.com), where it uses an older version of the contracts - one that was audited before through a [Code4rena contest](https://code4rena.com/reports/2021-10-ambire).

### Design decisions
The contracts are free of inheritance and external dependencies.

There is no code upgradability and no ownership (`onlyOwner`) or pausability, to ensure immutability. For easier readability, there are no modifiers, while keeping the code DRY.

Storage usage is cut down to the minimum: when bigger data structures need to be saved, we take advantage of the cheap calldata and always pass them in, verifying the hash against a storage slot in the process, for example `QuickAccManager` uses this for quick accounts.

## Smart contract summary

### AmbireAccount.sol
The core of the Ambire smart wallet. Each user is a minimal proxy with this contract as a base. It contains very few methods, with the most notable being:
* `execute`: executes a signed user bundle
* `executeBySender`: executes a bundle as long as `msg.sender` is authorized

There's a few methods that can only be called by the AmbireAccount itself, which means the only way to call them is through a call through `execute`/`executeBySender`, ensuring it's authorized. Those methods are `setAddrPrivilege`, `tipMiner` and `tryCatch`.

It's only dependency is an internal one, `SignatureValidator`.

### SignatureValidator.sol
Validates signatures in a few modes: EIP-712, EthSign, SmartWallet and Spoof. The first two verify signed messages using `ecrecover`, the only difference being that EthSign expects the "Ethereum signed message:" prefix. SmartWallet is for ERC-1271 signatures (smart contract signatures), and Spoof is for spoofed signatures that only work when `tx.origin == address(1)`.

### AmbireAccountFactory.sol
A simple CREATE2 factory contract designed to deploy minimal proxies for users. The most notable point here is `deploySafe`, which is a method that protects us from griefing conditions: `CREATE2` will fail if a contract has already been deployed, and this method essentially ensures a contract is deployed without failing if it already is.

The use case of this is counterfactual deployment: the proxy of each account will be deployed when the first user bundle is executed, but we don't want to fail the whole bundle in case the contract has already been deployed.

There is a method to drain the contract of ERC-20 tokens.


## Known tradeoffs

**NOTE**: "bundle"/"user bundle" in this context means array of AmbireAccount-level transactions (`AmbireAccount.Transaction[]`)

* **Account recovery security model**: Recovery signatures allow users to recover access to their accounts if they lose their keys. Timelocked transactions can be sent or cancelled by any recovery key. This means that if the recovery key is compromised AND the user key is lost, the attacker can cause grief by cancelling every attempt of the user to recover their funds. We consider this possibility to be extremely rare (both events to happen at once).
* **Storing additional data in `privileges`:** instead of boolean values, we use `bytes32` for the `privileges` mapping and treat any nonzero value as `true`.  Utilizing a storage slot has the same gas costs no matter if `true` or hash is stored. This is used for recovery signatures, which allow timelocked account recovery procedures to be performed.
* **ERC-4337 support left for a later stage:** while we do have ERC-4337 support [implemented](https://github.com/AmbireTech/wallet/blob/v2-improvements/contracts/ERC4337Manager.sol), we are choosing not to include it in the scope so as to keep things simple for the intial launch, which will use our own relayer instead of ERC-4337 anyway
* **ERC-20 fees taken through the transaction batch:** there's no special mechanism for reimbursing the relayer for the gas fee. Instead, the relayer looks at the bundle (`Transactions[]`) and sees if one or more of those transactions are ERC-20 `transfer`s that send tokens to it. The relayer is responsible for checking whether the fee token and amount is acceptable for it, as well as checking it the transaction will execute before broadcasting it to the mempool. This is also a tradeoff cause the internal transactions may fail, in which case the whole bundle reverts and the fee is not paid, but the relayer will pay for gas. This is worked around on the Relayer end by utilizing Flashbots and Eden to avoid mining failing transactions, and by simulating the transactions right before trying to mine them. The reason we don't try/catch the errors int he `AmbireAccount` is because we want user bundles to succeed/fail as a whole (atomically), and the transaction to show as failing on Etherscan.
* **Signature spoof mode:** the `SignatureValidator.sol` contract has a mode which allows signatures to be spoofed. The purpose of this is to allow easier simulation through `eth_call` and `eth_estimateGas` before having a signature from the user, since without this we would have a cyclical dependency that takes two steps to resolve (fee is unknown, user signs once to estimate the fee, then user signs a second time cause the bundle changed). This spoofing should not be allowed when calling through anywhere else other than `AmbireAccount(account).execute`, and it only works if `tx.origin == address(1)`.
* **Signature validation before deployment:** due to the nature of EIP 1271, signatures cannot be validated before the user account is deployed. In Ambire, the user account (proxy) is deployed when the user performs their first transaction.
* **no nonce in executeBySender:** the purpose of a nonce is to prevent replay attacks for transactions. `executeBySender` is called directly by an EOA or another contract who is authorized, and doesn't rely on a user signature, and the replay protection of `execute` doesn't apply to it. The concern arrises that a user might sign a SCW transaction bundle meant to be executed via `execute`, broadcast it, and then for whatever reason call `executeBySender` themselves to execute it (eg relayer goes down), allowing the original signed bundle to still be executed. This must be solved in the front-end: once a transaction bundle is signed, if the user wants to apply it with their EOA rather, we should call `execute` with that original signature rather than `executeBySender`.

## Networks

The contracts will be deployed on Ethereum, Polygon, Fantom, Binance Smart Chain, Avalanche, Arbitrum and other popular EVM chains.

# Final notes

if you're excited about building an easy to use, but powerful account abstraction, feel free to reach out at contactus@ambire.com 🔥 
