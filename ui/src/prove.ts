// Proves an announcement's signatures in the browser and submits them with the
// connected wallet. Nothing here needs to be trusted: the registry verifies every
// proof on-chain. Proving loads about 90 MB (the circuit, Barretenberg and its CRS)
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
const SEL = { submit: "3dc527e3", pending: "d9a9d060", publicKeys: "e96d6e4f", keySet: "788499c0", announcement: "91b5aa36" };

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
const call = async (data: string) => ((await request("eth_call", [{ to: registry, data: "0x" + data }, "latest"])) as string).slice(2);
const word = (v: bigint | number) => BigInt(v).toString(16).padStart(64, "0");
const padded = (bytes: Uint8Array) => word(bytes.length) + hex(bytes).padEnd(Math.ceil(bytes.length / 32) * 64, "0");
const words = (data: string) => data.match(/.{64}/g) ?? [];
const array = (data: string) => words(data).slice(2, 2 + Number(BigInt("0x" + words(data)[1])));

async function announced(number: bigint): Promise<boolean> {
  return call(SEL.announcement + word(number)).then(() => true, () => false);
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

async function run() {
  $("log").replaceChildren();
  const [text, armored] = await load();
  const number = /^(?:MF )?Announcement #(\d+)\n/.exec(new TextDecoder().decode(text))?.[1];
  if (number && (await announced(BigInt(number)))) return log(`Announcement #${number} is already registered.`, "ok");

  const fingerprints = array(await call(SEL.keySet)).map((w) => w.slice(0, 40).toUpperCase());
  const publicKeys = array(await call(SEL.publicKeys));
  const pending = array(await call(SEL.pending + word(32) + padded(text))).map((w) => w.slice(0, 40).toUpperCase());
  const needed = THRESHOLD - pending.length;
  const chosen = select(signatures(armored), fingerprints, pending, Date.now() / 1000, needed);
  if (pending.length) log(`Already submitted: ${pending.join(", ")}`);
  if (chosen.length < needed) throw new Error("Not enough valid signatures by pinned keys to complete this announcement.");

  const account = await wallet();
  log("Loading the circuit and Barretenberg…");
  const circuit: CompiledCircuit = await (await fetch("circuit.json")).json();
  const noir = new Noir(circuit);
  const api = await Barretenberg.new({ threads: navigator.hardwareConcurrency, srsSize: 2 ** 21 });
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  try {
    for (const s of chosen) {
      log(`Proving the signature by ${s.issuer}…`);
      const started = Date.now();
      const { witness } = await noir.execute(inputs(text, fingerprints, publicKeys, s));
      const { proof, publicInputs } = await backend.generateProof(witness, { verifierTarget: "evm-no-zk" });
      log(`Proved in ${Math.round((Date.now() - started) / 1000)} s. Confirm the transaction in your wallet.`);

      const [n, signer, expiresAt] = publicInputs.slice(-3).map((v) => BigInt(v));
      const data = submitData(text, n, signer.toString(16).padStart(40, "0"), expiresAt, proof);
      const hash = await window.ethereum!.request({ method: "eth_sendTransaction", params: [{ from: account, to: registry, data }] });
      log(`Submitted ${hash}, waiting for it…`);
      const r = await receipt(hash);
      if (r.status !== "0x1") throw new Error(`Transaction ${hash} failed.`);
    }
    log(`Done: announcement #${number ?? "?"} has ${THRESHOLD} signatures and is registered.`, "ok");
  } finally {
    await api.destroy();
  }
}

$("registry").textContent = registry;
if (!crossOriginIsolated) log("This page is not cross-origin isolated, so proving runs on one thread and is slower.");
$("form").addEventListener("submit", (e) => {
  e.preventDefault();
  const button = $<HTMLButtonElement>("run");
  button.disabled = true;
  run()
    .catch((err) => log(err instanceof Error ? err.message : String(err), "error"))
    .finally(() => (button.disabled = false));
});
