// Proves an announcement's signatures in the browser and, as a separate step,
// submits them with the connected wallet. Nothing here needs to be trusted: the
// registry verifies every proof on-chain. Proving loads about 90 MB (the circuit, Barretenberg and its CRS)
// and needs up to 3 GB of memory.

import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Noir, type CompiledCircuit, type InputMap } from "@noir-lang/noir_js";
import { hex, select, signatures, type Signature } from "./openpgp";

// Must match public/index.html.
const DEFAULT_REGISTRY = "0x3BA0034A2d8b39144b4d653791D96e087B903F90";
const DEFAULT_RPC = "https://testnet-rpc.monad.xyz";
const CHAIN_ID = 10143;
const COMMS = "https://raw.githubusercontent.com/monad-crypto/mf-nodeops-comms/main/announcements";

// Must match the circuit and the registry.
const MAX_TEXT = 4096;
const MAX_KEYS = 8;
const HASHED_BUF = 256 + 32;
const THRESHOLD = 2;
const SEL = { submit: "3dc527e3", pending: "d9a9d060", publicKeys: "e96d6e4f", keySet: "788499c0", announcement: "91b5aa36", verifier: "2b7ac3f3", verify: "ea50d0e4" };

const rpc = localStorage.getItem("rpc") || DEFAULT_RPC;
const registry = localStorage.getItem("registry") || DEFAULT_REGISTRY;

declare global {
  interface Window {
    ethereum?: { request(args: { method: string; params?: unknown[] }): Promise<any> };
  }
}

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

function log(message: string, className = "") {
  $("log").append(Object.assign(document.createElement("div"), { textContent: message, className }));
}

// Minimal JSON-RPC and ABI coding over hex strings without 0x.
async function request(method: string, params: unknown[]): Promise<any> {
  const res = await fetch(rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message);
  return json.result;
}
const call = async (data: string, to = registry) => ((await request("eth_call", [{ to, data: "0x" + data }, "latest"])) as string).slice(2);
const word = (v: bigint | number) => BigInt(v).toString(16).padStart(64, "0");
const padded = (bytes: Uint8Array) => word(bytes.length) + hex(bytes).padEnd(Math.ceil(bytes.length / 32) * 64, "0");
const words = (data: string) => data.match(/.{64}/g) ?? [];
const array = (data: string) => words(data).slice(2, 2 + Number(BigInt("0x" + words(data)[1])));

async function announced(number: bigint): Promise<boolean> {
  return call(SEL.announcement + word(number)).then(() => true, () => false);
}

/** Fingerprints of the keys that have signed `text` so far, while it is not registered. */
async function pendingSigners(text: Uint8Array): Promise<string[]> {
  return array(await call(SEL.pending + word(32) + padded(text))).map((w) => w.slice(0, 40).toUpperCase());
}

/** Whether the registry's verifier accepts the proof, asked with eth_call: nothing is sent. */
async function verifies(proof: Uint8Array, publicInputs: string[]): Promise<boolean> {
  const verifier = (await call(SEL.verifier)).slice(24);
  const tail = padded(proof);
  const data = SEL.verify + word(64) + word(64 + tail.length / 2) + tail
    + word(publicInputs.length) + publicInputs.map((v) => word(BigInt(v))).join("");
  return call(data, "0x" + verifier).then((r) => BigInt("0x" + r) === 1n, () => false);
}

/** The circuit's inputs, as `mfreg` writes them to Prover.toml. */
function inputs(text: Uint8Array, fingerprints: string[], publicKeys: string[], s: Signature): InputMap {
  const chunks = new Uint8Array(Math.ceil(MAX_TEXT / 31) * 31);
  chunks.set(text);
  const hashed = new Uint8Array(HASHED_BUF);
  hashed.set(s.hashed);
  return {
    text: Array.from({ length: chunks.length / 31 }, (_, i) => "0x" + hex(chunks.subarray(31 * i, 31 * i + 31))),
    text_len: text.length,
    fingerprints: Array.from({ length: MAX_KEYS }, (_, i) => (fingerprints[i] ? "0x" + fingerprints[i] : "0")),
    public_keys: Array.from({ length: MAX_KEYS }, (_, i) =>
      publicKeys[i] ? ["0x" + publicKeys[i].slice(0, 32), "0x" + publicKeys[i].slice(32)] : ["0", "0"]),
    hashed: Array.from(hashed),
    hashed_len: s.hashed.length,
    r: Array.from(s.r),
    s: Array.from(s.s),
  };
}

function submitData(text: Uint8Array, number: bigint, signer: string, expiresAt: bigint, proof: Uint8Array): string {
  const textTail = padded(text);
  return "0x" + SEL.submit + word(5 * 32) + word(number) + signer.padEnd(64, "0") + word(expiresAt)
    + word(5 * 32 + textTail.length / 2) + textTail + padded(proof);
}

async function wallet(): Promise<string> {
  const eth = window.ethereum;
  if (!eth) throw new Error("No wallet found. Install one, such as MetaMask, to submit.");
  const [account] = await eth.request({ method: "eth_requestAccounts" });
  const chainId = "0x" + CHAIN_ID.toString(16);
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId }] });
  } catch {
    await eth.request({
      method: "wallet_addEthereumChain",
      params: [{ chainId, chainName: "Monad", rpcUrls: [rpc], nativeCurrency: { name: "MON", symbol: "MON", decimals: 18 } }],
    });
  }
  return account;
}

async function receipt(hash: string) {
  for (;;) {
    const r = await request("eth_getTransactionReceipt", [hash]);
    if (r) return r;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
}

async function load(): Promise<[Uint8Array, string]> {
  const n = $<HTMLInputElement>("number").value.trim();
  const [txt, sig] = [$<HTMLInputElement>("txt").files?.[0], $<HTMLInputElement>("sig").files?.[0]];
  if (txt && sig) return [new Uint8Array(await txt.arrayBuffer()), await sig.text()];
  if (!/^\d+$/.test(n)) throw new Error("Enter an announcement number, or choose both files.");
  const get = async (file: string) => {
    const res = await fetch(`${COMMS}/mf-${n}/${file}`);
    if (!res.ok) throw new Error(`mf-${n}/${file}: HTTP ${res.status}`);
    return res;
  };
  return [new Uint8Array(await (await get("announcement.txt")).arrayBuffer()), await (await get("announcement.sig")).text()];
}

/** Proofs made by Prove, which Submit sends. */
let proved: { text: Uint8Array; number: bigint; proofs: { issuer: string; data: string }[] } | undefined;

function forget() {
  proved = undefined;
  $("submit").hidden = true;
}

async function prove() {
  $("log").replaceChildren();
  forget();
  const [text, armored] = await load();
  const number = /^(?:MF )?Announcement #(\d+)\n/.exec(new TextDecoder().decode(text))?.[1];
  const registered = number !== undefined && (await announced(BigInt(number)));

  const fingerprints = array(await call(SEL.keySet)).map((w) => w.slice(0, 40).toUpperCase());
  const publicKeys = array(await call(SEL.publicKeys));
  const pending = await pendingSigners(text);
  // A registered announcement needs no more signatures: prove one anyway, as a test.
  const needed = registered ? 1 : THRESHOLD - pending.length;
  const chosen = registered
    ? select(signatures(armored), fingerprints, [], 0, 1)
    : select(signatures(armored), fingerprints, pending, Date.now() / 1000, needed);
  if (registered) log(`Announcement #${number} is already registered, so this proof is only a test: it can't be submitted.`);
  else if (pending.length) log(`Already submitted: ${pending.join(", ")}`);
  if (chosen.length < needed) throw new Error("Not enough valid signatures by pinned keys to complete this announcement.");

  log("Loading the circuit and Barretenberg…");
  const circuit: CompiledCircuit = await (await fetch("circuit.json")).json();
  const noir = new Noir(circuit);
  const api = await Barretenberg.new({ threads: navigator.hardwareConcurrency, srsSize: 2 ** 21 });
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  const proofs = [];
  let n = 0n;
  try {
    for (const s of chosen) {
      log(`Proving the signature by ${s.issuer}…`);
      const started = Date.now();
      const { witness } = await noir.execute(inputs(text, fingerprints, publicKeys, s));
      const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: "evm-no-zk" });
      log(`Proved in ${Math.round((Date.now() - started) / 1000)} s.`);
      if (!(await verifies(proof, publicInputs))) throw new Error("The registry's verifier rejects this proof.");
      log("The registry's verifier accepts it (checked with eth_call, nothing sent).", "ok");

      const [out, signer, expiresAt] = publicInputs.slice(-3).map((v) => BigInt(v));
      n = out;
      proofs.push({ issuer: s.issuer, data: submitData(text, out, signer.toString(16).padStart(40, "0"), expiresAt, proof) });
    }
  } finally {
    await api.destroy();
  }
  if (registered) return;
  proved = { text, number: n, proofs };
  $("submit").hidden = false;
  log("Submit sends one transaction per signature from your wallet. The registry takes each signature once: if "
    + "someone submits it before you, your proof can't be submitted any more.");
}

async function submit() {
  const { text, number, proofs } = proved!;
  const account = await wallet();
  for (const p of proofs) {
    // Someone may have submitted the same signature since it was proved here.
    if (await announced(number)) break;
    if ((await pendingSigners(text)).includes(p.issuer)) {
      log(`The signature by ${p.issuer} has already been submitted by someone else: skipping it.`);
      continue;
    }
    log(`Confirm the transaction for ${p.issuer} in your wallet.`);
    const hash = await window.ethereum!.request({ method: "eth_sendTransaction", params: [{ from: account, to: registry, data: p.data }] });
    log(`Submitted ${hash}, waiting for it…`);
    const r = await receipt(hash);
    if (r.status !== "0x1") throw new Error(`Transaction ${hash} failed.`);
  }
  forget();
  if (await announced(number)) log(`Done: announcement #${number} is registered.`, "ok");
  else log(`Announcement #${number} still needs ${THRESHOLD - (await pendingSigners(text)).length} more signature(s).`);
}

/** Runs `f` from a button, with both buttons disabled meanwhile. */
function action(f: () => Promise<void>) {
  return (e: Event) => {
    e.preventDefault();
    const buttons = [$<HTMLButtonElement>("run"), $<HTMLButtonElement>("submit")];
    buttons.forEach((b) => (b.disabled = true));
    f()
      .catch((err) => log(err instanceof Error ? err.message : String(err), "error"))
      .finally(() => buttons.forEach((b) => (b.disabled = false)));
  };
}

$("registry").textContent = registry;
if (!crossOriginIsolated) log("This page is not cross-origin isolated, so proving runs on one thread and is slower.");
$("form").addEventListener("submit", action(prove));
$("form").addEventListener("input", forget);
$("submit").addEventListener("click", action(submit));
