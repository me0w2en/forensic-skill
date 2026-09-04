---
name: blockchain-forensics
description: |
  Crypto-asset tracing for CTF/DFIR: recover wallets from seed phrases, pull desktop-wallet artifacts and
  passwords, trace funds across explorers/RPC, and analyse smart-contract incidents (proxy rug pulls, TRON
  multisig/permission abuse) and mining IOCs. Enter when the artifact is a wallet app, a mnemonic, an
  address or tx hash, a smart-contract/DeFi incident, or a mining-pool indicator.
  Trigger keywords: blockchain, 블록체인, bitcoin, btc, ethereum, eth, sepolia, tron, trx, nile, usdt,
  erc-20, trc-20, wallet, seed phrase, mnemonic, bip39, bip44, derivation path, exodus, metamask, keepass,
  wallet.dat, etherscan, tronscan, blockscout, json-rpc, eth_call, debug_traceTransaction, selector, solc,
  bytecode, proxy, upgradeTo, delegatecall, rug pull, honeypot, multisig, monero, xmr, xmrig, stratum.
---

# Blockchain / Crypto-Asset Forensics

Two modes: (1) get the wallet/keys/password from host artifacts (cross-links memory & mobile), and
(2) trace/analyse on-chain — funds, contracts, attribution — with integer-exact, evidence-graded rigor.

## ACTION REQUIRED (do now, do not stop to confirm)
1. `NOW`  Confirm router entry + `work/<case>/` (hashes verified, timezone/format recorded).
2. `NOW`  Read `../../tool-index.md`: `python3` ✅ (`bip_utils`/`base58`/`web3` via `uv pip`), `jq` ✅,
   `curl` ✅. `scope.md → network_profile` must allow public explorer/RPC lookups (it usually does).
3. `NEXT` Decide: wallet recovery, host-artifact extraction, fund tracing, or contract analysis.
4. `NEXT` Pin an evidence block/timestamp for any on-chain claim so results are reproducible.
5. `ACT`  Reconcile values in integer base units (wei/sun); grade each wallet `direct|correlation|withheld`; log to `timeline.md`.

## When to use / hand off
| If it's really… | Go to |
|---|---|
| A wallet password / seed that lives in a memory dump | `skills/memory-forensics/` (extract), then trace here |
| Install/encryption times & `.seco`/`.kdbx` files on disk | `skills/disk-image/` + `skills/windows-artifacts/` |
| A mobile wallet app DB | `skills/mobile-artifacts/` |
| XMRig config / mining traffic on a host or in a container | `skills/linux-container-cloud/` / `skills/memory-forensics/` |

## Tools (install-name → what it's for)
- `python3` + `bip_utils`, `base58`, `hashlib` — derive addresses from a mnemonic; hex↔Base58Check.
- `python3` + `web3`/`eth-abi` or `curl`+`jq` — JSON-RPC (`eth_call`, `eth_getCode`, `debug_traceTransaction`).
- `jq` ✅ — slice explorer/RPC JSON, aggregate signers, reconcile amounts.
- `solc` / `solc-js` (npm `solc`) — recompile contract source for byte-exact bytecode comparison.
- Explorers (browser/API): Etherscan, TronScan/Nile TronScan, Blockscout.
- Cross-links: `aeskeyfind` (memory) for wallet keys in RAM; Prefetch/`.seco` mtime (disk) for times.

## Workflow

### Phase 1 — Recover a wallet from a seed / mnemonic
```bash
uv pip install bip_utils base58 2>/dev/null
python3 - <<'PY'
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
m="move pretty trouble photo window february giant bar prison under ancient spread"
seed=Bip39SeedGenerator(m).Generate()
for coin,path in [(Bip44Coins.TRON,"m/44'/195'"),(Bip44Coins.ETHEREUM,"m/44'/60'"),(Bip44Coins.BITCOIN,"m/44'/0'")]:
    acct=Bip44.FromSeed(seed,coin).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
    print(coin, acct.PublicKey().ToAddress())
PY
```
Check the derived address on the right network (KDFC #152: a Nile *testnet* honeypot is empty on mainnet).

### Phase 2 — Desktop-wallet host artifacts
- **Exodus** (KDFC #306): install time from Prefetch; encryption time from `exodus.wallet\seed.seco` /
  `twofactor-secret.seco` mtime; password in **process memory** near the string
  `.../app-<ver>/resources/app.asar/src/static/wallet.html#` → hand extraction to `memory-forensics`.
  Reconstitute by copying the 5 `exodus.wallet` files into a matching-version install.
- **KeePass** `.kdbx` (KDFC #252): master key partially leaks from RAM via CVE-2023-32784 (first char and
  some of the second are missing) — combine with a wordlist to brute the missing leading char.
- `wallet.dat` (Bitcoin Core) → `bitcoin2john` → john/hashcat.

### Phase 3 — Trace funds
```bash
# Etherscan/Blockscout API (or the web UI) hop by hop:
curl -s "https://api.etherscan.io/api?module=account&action=txlist&address=0x...&sort=asc&apikey=$KEY" | jq '.result[] | {hash,from,to,value}'
# TRON (Nile) signer aggregation for a sweep cluster:
curl -s "https://nile.trongrid.io/wallet/gettransactioninfobyid" -d '{"value":"<txhash>"}' | jq '.signature_addresses'
```
Reconcile in integer base units (wei/sun): deposit ledger total == pre-drain contract balance ==
sum of sink transfers, at a pinned block. Never trust the UI's TVL / `totalSupply()`.

### Phase 4 — Smart-contract incident (proxy rug pull / permission abuse)
```bash
RPC=https://sepolia.publicnode.com
# implementation slot before vs after the suspected upgrade block:
curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":["0xPROXY","0x<implSlot>","0x<blkBefore>"]}'
curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"eth_getStorageAt","params":["0xPROXY","0x<implSlot>","0x<blkAfter>"]}'
# fetch runtime bytecode of each impl and diff the 4-byte selectors:
curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0xIMPL","latest"]}' | jq -r .result
```
Malicious impl typically preserves every legit selector and adds ONE hidden drain selector gated to a
hardcoded caller, sending `SELFBALANCE` (the proxy's pooled ETH, under DELEGATECALL) to a hardcoded sink
(KDFC #251). Prove authorship byte-exactly by recompiling the source with the exact `solc` version and
options, excluding the trailing CBOR metadata, and matching bytecode. Confirm with archive
`debug_traceTransaction` (callTracer/prestateTracer diffMode).
TRON permission abuse (KDFC #152): look for `AccountPermissionUpdateContract` making the victim key
weight < threshold; attribute attackers by aggregating `signature_addresses` of the sweep txs and proving
hex→Base58Check identity of the sink.

### Phase 5 — Mining IOCs
XMRig config (`stratum+tcp://`, pool `mine.c3pool.com`/`supportxmr`), version strings, RandomX — cross-link
to `linux-container-cloud`/`memory-forensics` where the miner was found; base64 `userData` often fetches `xmrig.sh`.

## Flag-hiding checklist
- A "leaked" mnemonic that shows a balance but can't withdraw → permission/multisig trap or missing gas (KDFC #152).
- Wallet password only in process memory, anchored on the app's asar/resource path (KDFC #306).
- Testnet vs mainnet — the funds may live on Sepolia/Nile, not mainnet.
- A hidden contract selector added by a malicious proxy implementation (KDFC #251).
- Keys split across channels (Meet invite + email) for an off-chain decryptor (KDFC #303).
- The terminal address that receives all hops and never sends onward = final destination.

## Pitfalls
- Never assert same-natural-person control of multiple wallets — on-chain evidence can't prove it.
- Use integer base units; floating ETH/USDT reconciliation drifts.
- Pin a block for every balance/`eth_call`; "latest" changes under you.
- Exclude infra/false positives: permissionless CREATE2 factory, faucet funders, registered-but-never-signing keys.
- Recompiled bytecode differs in the CBOR metadata tail — exclude it before comparing.

## Worked precedents
- **KDFC2026 #251 Carpet Pull** — upgradeable-proxy rug: impl-slot before/after, selector diff, byte-exact solc recompile, integer-wei three-way reconciliation.
- **KDFC2026 #152 Mnemonic Yum** — TRON Nile honeypot, BIP44 derivation, `AccountPermissionUpdateContract` multisig, signer aggregation.
- **KDFC2023 #306 Coin Chaser** — Exodus install/encrypt times, password in memory, Etherscan hop tracing.
- **KDFC2023 #252 Password Stealer** — KeePass CVE-2023-32784 partial master-key + brute.

## References
- `../../references/timestamps.md`
- Etherscan/TronScan/Blockscout docs; Sepolia public RPC (publicnode/dRPC)
- bip_utils: https://github.com/ebellocchia/bip_utils
-. (blockchain sections) and.
