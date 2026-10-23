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

`ui/public/index.html` is a single static page that lists them, with light formatting (bold, code, links). It
reads the testnet deployment through the public RPC by default; Settings at the bottom points it at any other RPC,
such as your own node. It has no dependencies and loads nothing else.

`ui/prove.html` submits an announcement: it fetches the text and signatures from mf-nodeops-comms, proves each
signature in the browser (about 20 seconds and up to 3 GB of memory each, on a desktop browser) and sends them with
the connected wallet. Only this page loads the prover, about 90 MB on first use.

### Hosting the page yourself

Don't rely on someone else's copy of the page: whoever serves it could change what it shows. Serve your own, from
this repository:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/node101-io/mf-announcement-registry)

The button copies the repository to your GitHub account, builds `ui/` and serves it from your Cloudflare account
(`wrangler.jsonc`). Alternatively, connect the repository in Cloudflare Pages with `npm ci --prefix ui && npm run
build --prefix ui` as the build command and `ui/dist` as the output directory, or open `ui/public/index.html` from
disk to read announcements.

## How it works

The proofs do the checking; the contract feeds them, counts signers and stores the result.

| Part | Role |
|---|---|
| `circuit/` | A Noir circuit for one signature. Given the text and the pinned keys as public inputs, and a signature packet as a witness (an input the contract does not pass), it parses the signed part of the packet, computes its digest (SHA-256 or SHA-512) over the text, verifies the Ed25519 signature with [noir-ed25519](https://github.com/willemolding/noir-ed25519) (a submodule pinned to a commit), and checks that the signer is a pinned key. It outputs the announcement number, the signer, and the signature expiration. |
| `contracts/` | `AnnouncementRegistry` takes one proof per signature. It passes the text and the pinned keys to the verifier, checks that the signature has not expired at the current block, and collects the signers of each text; once two distinct keys have signed, it stores the text. It has no owner and no upgrades. |
| `cli/` | `mfreg`: prints the key set, picks two signatures by distinct pinned keys, and proves each with `nargo` and `bb`. It verifies nothing itself; the circuit does. |
| `ui/` | The read-only page, and the page that proves and submits in the browser. |

One proof per signature keeps the circuit small enough to prove in a browser, at about twice the gas of a single
proof for both. The signature file never goes on-chain: whoever submits only needs the text, the proofs and the
circuit's outputs. Signatures can be submitted by different people, at different times.

Limits, fixed by the circuit: text up to 4096 bytes; SHA-256 or SHA-512 signatures (SHA-384 is not counted); up to
8 pinned keys; up to 256 bytes and 16 hashed subpackets per signature.

What is trusted: the Foundation's keys (pinned at deployment), this code and its libraries (none is audited),
Barretenberg, and your node. Not trusted: whoever submits or proves, and where the files came from. The page that
shows announcements is trusted to show what the registry holds, so serve your own copy (below).

A new key set means a new registry.

## Deployments

Monad testnet (chain 10143), with the Foundation's keys and mf-6 submitted:

| Contract | Address |
|---|---|
| `AnnouncementRegistry` | `0x3BA0034A2d8b39144b4d653791D96e087B903F90` |
| `HonkVerifier` | `0xCF0B07fa964DBC53AE254462B722D11BAaFedeEA` |
| `RelationsLib` (linked by the verifier) | `0x1767a88043E60370f697908615dEbA95E77aB47F` |

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

A proof takes about 15 seconds on an M4; `mfreg prove` makes one for each of two signatures.

```sh
git submodule update --init
cargo build --release
alias mfreg=target/release/mfreg

# Prove an announcement: a directory with announcement.txt and announcement.sig, as in mf-nodeops-comms.
mfreg prove testdata/mf-6 testdata/keys            # writes testdata/mf-6/proof.json

# Submit both signatures (about 5M gas each)
P=testdata/mf-6/proof.json
for i in 0 1; do
  cast send $REGISTRY "submit(bytes,uint64,bytes20,uint64,bytes)" $(jq -r .text $P) $(jq -r .number $P) \
    $(jq -r ".proofs[$i].signer" $P) $(jq -r ".proofs[$i].expiresAt" $P) $(jq -r ".proofs[$i].proof" $P) \
    --rpc-url $RPC --private-key $KEY
done

# Deploy (the verifier and the registry, through the CREATE2 deployer)
cd contracts
KEYS=$(../target/release/mfreg keys ../testdata/keys) \
  forge script script/Deploy.s.sol --rpc-url $RPC --private-key $KEY --broadcast
```

To try it locally, run `anvil --fork-url https://rpc.monad.xyz`, which is a local Monad mainnet fork, and use its
first test account.

After deploying to mainnet, set `DEFAULT_RPC` to `https://rpc.monad.xyz` and `NETWORK` to `""` in
`ui/public/index.html`, and `DEFAULT_RPC` and `CHAIN_ID` (143) in `ui/src/prove.ts`.

To work on the pages, run `npm install --prefix ui && npm run dev --prefix ui`.

## Tests

```sh
cargo test                  # signature selection; the circuit on mf-6, and on changes it must reject:
                            # changed text, unpinned signer, SHA-384; ui/public/circuit.json is current
                            # (~30 s; runs nargo)
cd contracts && forge test  # all published announcements with real proofs, public inputs match the prover,
                            # signers are counted per text, and failure cases
```

`testdata/` holds the announcements and keys from mf-nodeops-comms at commit 6c94e756cf64, their
proofs, and gpg-generated vectors in `testdata/generated/` (see `make.sh` there).

When the circuit changes, regenerate `HonkVerifier.sol` (see above), every `proof.json` with `mfreg prove`, and
`ui/public/circuit.json` with `npm run circuit --prefix ui`.
