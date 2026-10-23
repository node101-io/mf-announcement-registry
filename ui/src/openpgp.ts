// Just enough OpenPGP to pick the signatures to prove, as in cli/src/openpgp.rs.
// Nothing here is trusted: the circuit checks the packets and verifies the signatures.

const HASH_SHA256 = 8;
const HASH_SHA512 = 10;

export type Signature = {
  /** Upper-case hex fingerprint of the signing key. */
  issuer: string;
  hash: number;
  /** Unix time, or 0 if the signature never expires. */
  expiresAt: number;
  /** The signed part of the packet: version through the hashed subpackets. */
  hashed: Uint8Array;
  r: Uint8Array;
  s: Uint8Array;
};

/** The signature packets of an armored detached signature. */
export function signatures(armored: string): Signature[] {
  return packets(dearmor(armored)).map(([tag, body]) => {
    if (tag !== 2) throw new Error("not a signature packet");
    return signature(body);
  });
}

/** Up to `count` signatures by distinct `pinned` keys not in `skip`, that the circuit
 *  supports (SHA-256 or SHA-512) and that are unexpired at `now`. */
export function select(all: Signature[], pinned: string[], skip: string[], now: number, count: number): Signature[] {
  const chosen: Signature[] = [];
  for (const s of all) {
    const usable = (s.hash === HASH_SHA256 || s.hash === HASH_SHA512)
      && (s.expiresAt === 0 || now < s.expiresAt)
      && pinned.includes(s.issuer)
      && !skip.includes(s.issuer)
      && !chosen.some((c) => c.issuer === s.issuer);
    if (usable && chosen.length < count) chosen.push(s);
  }
  return chosen;
}

function dearmor(armored: string): Uint8Array {
  const lines = armored.split(/\r?\n/);
  const begin = lines.findIndex((l) => l.startsWith("-----BEGIN PGP "));
  if (begin < 0) throw new Error("invalid armor");
  let i = begin + 1;
  while (i < lines.length && lines[i].trim() !== "") i++;
  const body: string[] = [];
  for (i++; i < lines.length && !lines[i].startsWith("=") && !lines[i].startsWith("-----END"); i++) body.push(lines[i].trim());
  return Uint8Array.from(atob(body.join("")), (c) => c.charCodeAt(0));
}

function signature(body: Uint8Array): Signature {
  const hashedEnd = 6 + be(slice(body, 4, 6));
  const hashed = slice(body, 0, hashedEnd);
  const { issuer, expiresAt } = subpackets(hashed.subarray(6));
  const unhashedEnd = hashedEnd + 2 + be(slice(body, hashedEnd, hashedEnd + 2));
  // Skips the unhashed subpackets and the two-byte digest prefix.
  const [r, rest] = mpi(body.subarray(unhashedEnd + 2));
  const [s] = mpi(rest);
  if (!issuer) throw new Error("missing issuer fingerprint");
  return { issuer, hash: body[3], expiresAt, hashed, r, s };
}

/** The issuer fingerprint and the expiration time (0 if none) from the hashed subpackets. */
function subpackets(area: Uint8Array): { issuer?: string; expiresAt: number } {
  let issuer: string | undefined;
  let created = 0;
  let expiresIn = 0;
  while (area.length > 0) {
    const [len, header] = length(area);
    const sub = slice(area, header, header + len);
    if (sub.length === 0) throw new Error("malformed subpacket");
    const kind = sub[0] & 0x7f;
    if (kind === 33 && sub.length === 22) issuer = hex(sub.subarray(2)).toUpperCase();
    if (kind === 2 && sub.length === 5) created = be(sub.subarray(1));
    if (kind === 3 && sub.length === 5) expiresIn = be(sub.subarray(1));
    area = area.subarray(header + len);
  }
  return { issuer, expiresAt: expiresIn === 0 ? 0 : created + expiresIn };
}

/** Splits data into [tag, body] packets. */
function packets(data: Uint8Array): [number, Uint8Array][] {
  const out: [number, Uint8Array][] = [];
  while (data.length > 0) {
    const ctb = data[0];
    let tag: number, len: number, header: number;
    if ((ctb & 0xc0) === 0x80) {
      const n = [1, 2, 4][ctb & 3];
      if (!n) throw new Error("indeterminate packet length");
      [tag, len, header] = [(ctb >> 2) & 0x0f, be(slice(data, 1, 1 + n)), 1 + n];
    } else if ((ctb & 0xc0) === 0xc0) {
      const [l, n] = length(data.subarray(1));
      [tag, len, header] = [ctb & 0x3f, l, 1 + n];
    } else {
      throw new Error("invalid packet header");
    }
    out.push([tag, slice(data, header, header + len)]);
    data = data.subarray(header + len);
  }
  return out;
}

/** Decodes a one-, two- or five-octet length, returning [length, header size]. */
function length(data: Uint8Array): [number, number] {
  const o = data[0];
  if (o < 192) return [o, 1];
  if (o < 224 && data.length >= 2) return [((o - 192) << 8) + data[1] + 192, 2];
  if (o === 255 && data.length >= 5) return [be(data.subarray(1, 5)), 5];
  throw new Error("unsupported or truncated length");
}

/** Reads an MPI of at most 32 bytes, left-padded to 32 bytes. */
function mpi(data: Uint8Array): [Uint8Array, Uint8Array] {
  const n = Math.ceil(be(slice(data, 0, 2)) / 8);
  if (n > 32) throw new Error("invalid MPI");
  const out = new Uint8Array(32);
  out.set(slice(data, 2, 2 + n), 32 - n);
  return [out, data.subarray(2 + n)];
}

/** data[start..end], which must be in bounds. */
function slice(data: Uint8Array, start: number, end: number): Uint8Array {
  if (end > data.length) throw new Error("truncated packet");
  return data.subarray(start, end);
}

function be(bytes: Uint8Array): number {
  return bytes.reduce((acc, b) => acc * 256 + b, 0);
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
