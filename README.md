# mf-announcement-registry

Monad Foundation node-ops announcements ([mf-nodeops-comms](https://github.com/monad-crypto/mf-nodeops-comms)), with
their GPG signatures verified on-chain.

The Foundation signs each announcement with GPG, and two of its pinned keys must sign. This registry checks that on
Monad and stores the verified text, so a validator can read it from their own node. There is nothing to download,
no gpg to run, and no fingerprints to compare by hand.

```sh
cast call $REGISTRY "latest()(uint64)" --rpc-url http://localhost:8080
cast call $REGISTRY "announcement(uint64)(string,bytes20[])" 6 --rpc-url http://localhost:8080
```

`ui/index.html` is a single static page that lists them, with light formatting (bold, code, links). It reads
the testnet deployment through the public RPC by default; Settings at the bottom points it at any other RPC, such
as your own node.

## How it works

The proof does the checking; the contract only feeds it and stores the result.

| Part | Role |
|---|---|
| `circuit/` | A Noir circuit. Given the text and the pinned keys as public inputs, and two signature packets as witnesses (inputs the contract does not pass), it parses the signed part of each packet, computes its digest (SHA-256 or SHA-512) over the text, verifies the Ed25519 signature with [noir-ed25519](https://github.com/willemolding/noir-ed25519) (a submodule pinned to a commit), and checks that the two signers are distinct pinned keys. It outputs the announcement number, the two signers, and the earliest signature expiration. |
| `contracts/` | `AnnouncementRegistry` passes the text and the pinned keys to the verifier, checks that no signature has expired at the current block, and stores the text. It has no owner and no upgrades. |
| `cli/` | `mfreg`: prints the key set, picks two signatures by distinct pinned keys, and produces the proof with `nargo` and `bb`. It verifies nothing itself; the circuit does. |
| `ui/` | Read-only page. |

The signature file never goes on-chain: whoever submits only needs the text, the proof and the circuit's outputs.

Limits, fixed by the circuit: text up to 4096 bytes; SHA-256 or SHA-512 signatures (SHA-384 is not counted); up to
8 pinned keys; up to 256 bytes and 16 hashed subpackets per signature.

What is trusted: the Foundation's keys (pinned at deployment), this code and its libraries (none is audited),
Barretenberg, and your node. Not trusted: whoever submits, whoever hosts
the UI, and where the files came from.

A new key set means a new registry.

## Deployments

Monad testnet (chain 10143), with the Foundation's keys and mf-0 to mf-6 submitted:

| Contract | Address |
|---|---|
| `AnnouncementRegistry` | `0x8F759C1c40322f49881053c95b1DE5C2035863D1` |
| `HonkVerifier` | `0x8B2ea61247eCdb30EC388BeDe2C59d58B33a8C92` |
| `RelationsLib` (linked by the verifier) | `0xdadf06027Ee1AC32D08e3ac31ae86D72E8C54f35` |

The addresses come from CREATE2, so a mainnet deployment of the same code and keys gets the same ones.

## Checking a deployed registry

Run these once against your own node.

```sh
cast call $REGISTRY "keySet()(bytes20[])"   # must equal https://docs.monad.xyz/node-ops/gpg-keys.json
```

The verifier and the registry are deployed with CREATE2, so their addresses follow from the compiled code and the
key packets alone. To check that the deployed code is this repository's, rebuild and compare the addresses:

```sh
cd contracts
KEYS=$(../target/release/mfreg keys <keys-dir>) forge script script/Deploy.s.sol --rpc-url $RPC   # no --broadcast
```

`contracts/src/HonkVerifier.sol` regenerates byte-identically from the circuit:

```sh
cd circuit && nargo compile && bb write_vk -b target/mf_signatures.json -o target -t evm-no-zk \
  && bb write_solidity_verifier -k target/vk -o /tmp/HonkVerifier.sol -t evm-no-zk \
  && cmp /tmp/HonkVerifier.sol ../contracts/src/HonkVerifier.sol
```

## Usage

Requirements:
- Rust
- [Foundry](https://getfoundry.sh) 1.8+
- `nargo` 1.0.0-beta.22 and `bb` 5.0.0-nightly.20260522 on `PATH` (the pair `bbup` maps to that nargo release)

A proof takes about 30 seconds and 5.6 GB of memory on an M4.

```sh
git submodule update --init
cargo build --release
alias mfreg=target/release/mfreg

# Prove an announcement: a directory with announcement.txt and announcement.sig, as in mf-nodeops-comms.
mfreg prove testdata/mf-6 testdata/keys            # writes testdata/mf-6/proof.json

# Submit it (about 5-5.5M gas)
P=testdata/mf-6/proof.json
cast send $REGISTRY "submit(bytes,uint64,bytes20[2],uint64,bytes)" \
  $(jq -r .text $P) $(jq -r .number $P) "[$(jq -r '.signers | join(",")' $P)]" $(jq -r .expiresAt $P) $(jq -r .proof $P) \
  --rpc-url $RPC --private-key $KEY

# Deploy (the verifier and the registry, through the CREATE2 deployer)
cd contracts
KEYS=$(../target/release/mfreg keys ../testdata/keys) \
  forge script script/Deploy.s.sol --rpc-url $RPC --private-key $KEY --broadcast
```

To try it locally, run `anvil --fork-url https://rpc.monad.xyz`, which is a local Monad mainnet fork, and use its
first test account.

After deploying to mainnet, set `DEFAULT_RPC` to `https://rpc.monad.xyz` and `NETWORK` to `""` in `ui/index.html`.

## Tests

```sh
cargo test                  # signature selection; the circuit on mf-6, and on changes it must reject:
                            # changed text, unpinned or repeated signer, SHA-384 (~1 min; runs nargo)
cd contracts && forge test  # all published announcements with real proofs, public inputs match the prover,
                            # and failure cases
```

`testdata/` holds the announcements and keys from mf-nodeops-comms at commit 6c94e756cf64, their
proofs, and gpg-generated vectors in `testdata/generated/` (see `make.sh` there).

When the circuit changes, regenerate `HonkVerifier.sol` (see above) and every `proof.json` with `mfreg prove`.
