//! Verification of Monad Foundation node-ops announcements.
//!
//! An announcement is a text file plus an ASCII-armored OpenPGP detached
//! signature file holding one signature packet per signer. Only the format the
//! Foundation uses is parsed: v4 binary-document signatures by Ed25519 primary
//! keys, hashed with SHA-256, SHA-384 or SHA-512 (SHA-384 is parsed but not
//! counted). Anything else is rejected rather than interpreted.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

pub type Fingerprint = [u8; 20];

#[derive(Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

const TAG_SIGNATURE: u8 = 2;
const TAG_PUBLIC_KEY: u8 = 6;
const ALGO_EDDSA: u8 = 22;
const HASH_SHA256: u8 = 8;
const HASH_SHA384: u8 = 9;
const HASH_SHA512: u8 = 10;
const SIG_BINARY: u8 = 0x00;
const ED25519_OID: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

/// Number of distinct pinned keys that must sign an announcement.
pub const THRESHOLD: usize = 2;

/// A pinned primary key.
#[derive(Clone, Debug)]
pub struct Key {
    pub fingerprint: Fingerprint,
    /// RFC 8032 encoding of the Ed25519 public key.
    pub public_key: [u8; 32],
}

/// A valid signature by a pinned key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    pub fingerprint: Fingerprint,
    /// The signed part of the packet: version through the hashed subpackets.
    pub hashed: Vec<u8>,
    pub public_key: [u8; 32],
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// The OpenPGP digest the Ed25519 signature is over (32, 48 or 64 bytes).
    pub digest: Vec<u8>,
    /// Signature expiration as a Unix time, or 0 if it never expires.
    pub expires_at: u64,
}

/// Parses the dearmored detached signature packets in `sig` over `text`, and
/// verifies those made by `keys`, in packet order. Signatures by other keys, and
/// SHA-384 signatures (which the circuit does not support), are skipped; an
/// invalid signature by a pinned key fails the whole announcement.
pub fn signatures(text: &[u8], sig: &[u8], keys: &[Key]) -> Result<Vec<Signed>, Error> {
    let mut out = Vec::new();
    for (tag, body) in packets(sig)? {
        if tag != TAG_SIGNATURE {
            return Err(Error("signature file contains a non-signature packet"));
        }
        let s = parse_signature(body)?;
        let Some(key) = keys.iter().find(|k| k.fingerprint == s.issuer) else {
            continue;
        };
        if s.hash == HASH_SHA384 {
            continue;
        }

        let trailer = [&[0x04, 0xff][..], &(s.hashed.len() as u32).to_be_bytes()];
        let digest = match s.hash {
            HASH_SHA256 => hash::<Sha256>(&[text, s.hashed, trailer[0], trailer[1]]),
            _ => hash::<Sha512>(&[text, s.hashed, trailer[0], trailer[1]]),
        };
        if digest[..2] != s.digest_prefix {
            return Err(Error("signature digest prefix mismatch"));
        }
        let verifying = VerifyingKey::from_bytes(&key.public_key).map_err(|_| Error("invalid Ed25519 public key"))?;
        verifying
            .verify_strict(&digest, &Signature::from_components(s.r, s.s))
            .map_err(|_| Error("invalid signature"))?;

        out.push(Signed { fingerprint: s.issuer, hashed: s.hashed.to_vec(), public_key: key.public_key, r: s.r, s: s.s, digest, expires_at: s.expires_at });
    }
    Ok(out)
}

/// The signatures to prove: the first THRESHOLD signatures, in packet order, by
/// distinct keys and unexpired at `now`.
pub fn select(signed: &[Signed], now: u64) -> Option<Vec<Signed>> {
    let mut chosen: Vec<Signed> = Vec::new();
    for s in signed {
        let expired = s.expires_at != 0 && now >= s.expires_at;
        if !expired && !chosen.iter().any(|c| c.fingerprint == s.fingerprint) {
            chosen.push(s.clone());
        }
        if chosen.len() == THRESHOLD {
            return Some(chosen);
        }
    }
    None
}

fn hash<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = D::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().to_vec()
}

/// Reads the number from the first line, which must be exactly
/// `MF Announcement #N` or `Announcement #N`.
pub fn announcement_number(text: &str) -> Result<u64, Error> {
    let line = text.split('\n').next().unwrap_or_default();
    let digits = line
        .strip_prefix("MF Announcement #")
        .or_else(|| line.strip_prefix("Announcement #"))
        .ok_or(Error("unrecognized announcement header"))?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return Err(Error("invalid announcement number"));
    }
    digits.parse().map_err(|_| Error("invalid announcement number"))
}

/// Parses a v4 Ed25519 primary public key packet body and computes its fingerprint.
pub fn parse_public_key(body: &[u8]) -> Result<Key, Error> {
    // version(1) created(4) algo(1) oid_len(1) oid(9) mpi_bits(2) 0x40 point(32)
    let supported = body.len() == 51
        && body[0] == 4
        && body[5] == ALGO_EDDSA
        && body[6] as usize == ED25519_OID.len()
        && body[7..16] == ED25519_OID
        && body[16..18] == [0x01, 0x07]
        && body[18] == 0x40;
    if !supported {
        return Err(Error("unsupported public key"));
    }
    let public_key: [u8; 32] = body[19..].try_into().unwrap();
    VerifyingKey::from_bytes(&public_key).map_err(|_| Error("invalid Ed25519 public key"))?;

    let mut h = Sha1::new();
    h.update([0x99]);
    h.update((body.len() as u16).to_be_bytes());
    h.update(body);
    Ok(Key { fingerprint: h.finalize().into(), public_key })
}

/// Returns the primary public key packet body of a binary certificate.
pub fn primary_key_packet(cert: &[u8]) -> Result<&[u8], Error> {
    match packets(cert)?.first() {
        Some(&(TAG_PUBLIC_KEY, body)) => Ok(body),
        _ => Err(Error("certificate does not start with a public key packet")),
    }
}

/// Decodes an ASCII-armored OpenPGP block. The CRC line is not checked; the
/// decoded data is authenticated by its fingerprint, not by the armor.
pub fn dearmor(armored: &str) -> Result<Vec<u8>, Error> {
    let body: String = armored
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN PGP "))
        .skip(1)
        .skip_while(|l| !l.trim().is_empty())
        .take_while(|l| !l.starts_with('=') && !l.starts_with("-----END"))
        .map(str::trim)
        .collect();
    STANDARD.decode(body).map_err(|_| Error("invalid armor"))
}

struct SignaturePacket<'a> {
    /// Version through the end of the hashed subpackets: the signed trailer.
    hashed: &'a [u8],
    hash: u8,
    issuer: Fingerprint,
    /// Unix time, or 0 if the signature never expires.
    expires_at: u64,
    digest_prefix: [u8; 2],
    r: [u8; 32],
    s: [u8; 32],
}

fn parse_signature(body: &[u8]) -> Result<SignaturePacket<'_>, Error> {
    let truncated = Error("truncated signature packet");
    let &[version, sig_type, algo, hash, ..] = body else {
        return Err(truncated);
    };
    let supported_hash = matches!(hash, HASH_SHA256 | HASH_SHA384 | HASH_SHA512);
    if version != 4 || sig_type != SIG_BINARY || algo != ALGO_EDDSA || !supported_hash {
        return Err(Error("unsupported signature"));
    }

    let hashed_end = 6 + be(body.get(4..6).ok_or(truncated)?);
    let hashed = body.get(..hashed_end).ok_or(Error("truncated signature packet"))?;
    let (issuer, expires_at) = hashed_subpackets(&hashed[6..])?;

    // Unhashed subpackets are not covered by the signature and are skipped.
    let unhashed_len = be(body.get(hashed_end..hashed_end + 2).ok_or(Error("truncated signature packet"))?);
    let rest = body
        .get(hashed_end + 2 + unhashed_len..)
        .ok_or(Error("truncated signature packet"))?;
    let digest_prefix = rest.get(..2).ok_or(Error("truncated signature packet"))?;
    let (r, rest) = mpi32(&rest[2..])?;
    let (s, rest) = mpi32(rest)?;
    if !rest.is_empty() {
        return Err(Error("trailing data in signature packet"));
    }

    Ok(SignaturePacket { hashed, hash, issuer, expires_at, digest_prefix: [digest_prefix[0], digest_prefix[1]], r, s })
}

/// Reads the hashed subpackets: the single issuer fingerprint, and the
/// signature expiration as a Unix time (0 if none). Signatures with unknown
/// critical subpackets are rejected, as RFC 4880 requires.
fn hashed_subpackets(mut area: &[u8]) -> Result<(Fingerprint, u64), Error> {
    let (mut issuer, mut created, mut expires_in) = (None, None, None);
    while !area.is_empty() {
        let (len, header) = subpacket_length(area)?;
        let sub = area
            .get(header..header + len)
            .filter(|s| !s.is_empty())
            .ok_or(Error("malformed subpacket"))?;
        let (kind, critical, data) = (sub[0] & 0x7f, sub[0] & 0x80 != 0, &sub[1..]);
        match kind {
            33 => {
                if issuer.is_some() || data.len() != 21 || data[0] != 4 {
                    return Err(Error("unsupported issuer fingerprint subpacket"));
                }
                issuer = Some(data[1..].try_into().unwrap());
            }
            2 | 3 => {
                let value: [u8; 4] = data.try_into().map_err(|_| Error("malformed time subpacket"))?;
                let slot = if kind == 2 { &mut created } else { &mut expires_in };
                if slot.replace(u32::from_be_bytes(value)).is_some() {
                    return Err(Error("duplicate time subpacket"));
                }
            }
            _ if critical => return Err(Error("unknown critical subpacket")),
            _ => {}
        }
        area = &area[header + len..];
    }
    let issuer = issuer.ok_or(Error("missing issuer fingerprint"))?;
    let expires_at = match (created, expires_in) {
        (_, None | Some(0)) => 0,
        (Some(created), Some(secs)) => created as u64 + secs as u64,
        (None, Some(_)) => return Err(Error("signature expiration without creation time")),
    };
    Ok((issuer, expires_at))
}

/// Splits data into (tag, body) packets. Partial and indeterminate lengths are rejected.
fn packets(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut out = Vec::new();
    while let Some(&ctb) = data.first() {
        if ctb & 0x80 == 0 {
            return Err(Error("invalid packet header"));
        }
        let (tag, len, header) = if ctb & 0x40 == 0 {
            let n = match ctb & 0x03 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => return Err(Error("indeterminate packet length")),
            };
            let len = be(data.get(1..1 + n).ok_or(Error("truncated packet header"))?);
            ((ctb >> 2) & 0x0f, len, 1 + n)
        } else {
            let (len, n) = match data.get(1) {
                Some(&o) if o < 224 || o == 255 => subpacket_length(&data[1..])?,
                Some(_) => return Err(Error("partial packet length")),
                None => return Err(Error("truncated packet header")),
            };
            (ctb & 0x3f, len, 1 + n)
        };
        let body = data.get(header..header + len).ok_or(Error("truncated packet"))?;
        out.push((tag, body));
        data = &data[header + len..];
    }
    Ok(out)
}

/// Decodes a one-, two- or five-octet length, returning (length, header size).
fn subpacket_length(data: &[u8]) -> Result<(usize, usize), Error> {
    let truncated = Error("truncated length");
    match *data.first().ok_or(Error("truncated length"))? {
        o @ 0..=191 => Ok((o as usize, 1)),
        o @ 192..=254 => {
            let o2 = *data.get(1).ok_or(truncated)?;
            Ok((((o as usize - 192) << 8) + o2 as usize + 192, 2))
        }
        255 => Ok((be(data.get(1..5).ok_or(truncated)?), 5)),
    }
}

/// Reads a canonical MPI of at most 32 bytes, left-padded to 32 bytes.
fn mpi32(data: &[u8]) -> Result<([u8; 32], &[u8]), Error> {
    let bits = be(data.get(..2).ok_or(Error("truncated MPI"))?);
    let n = bits.div_ceil(8);
    let value = data.get(2..2 + n).ok_or(Error("truncated MPI"))?;
    if n > 32 || value.first().is_some_and(|&b| 8 * n - b.leading_zeros() as usize != bits) {
        return Err(Error("invalid MPI"));
    }
    let mut out = [0u8; 32];
    out[32 - n..].copy_from_slice(value);
    Ok((out, &data[2 + n..]))
}

fn be(bytes: &[u8]) -> usize {
    bytes.iter().fold(0, |acc, &b| (acc << 8) | b as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata");

    fn keys(dir: &str, skip: &str) -> Vec<Key> {
        let mut paths: Vec<_> = fs::read_dir(format!("{DATA}/{dir}"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "asc") && !p.to_string_lossy().contains(skip))
            .collect();
        paths.sort();
        paths
            .iter()
            .map(|p| {
                let cert = dearmor(&fs::read_to_string(p).unwrap()).unwrap();
                parse_public_key(primary_key_packet(&cert).unwrap()).unwrap()
            })
            .collect()
    }

    fn announcement(n: u64) -> (Vec<u8>, Vec<u8>) {
        let dir = format!("{DATA}/mf-{n}");
        (
            fs::read(format!("{dir}/announcement.txt")).unwrap(),
            dearmor(&fs::read_to_string(format!("{dir}/announcement.sig")).unwrap()).unwrap(),
        )
    }

    /// A gpg-generated vector from testdata/generated, with the test keys.
    fn generated(name: &str) -> Result<Vec<Signed>, Error> {
        let dir = format!("{DATA}/generated/{name}");
        let text = fs::read(format!("{dir}/announcement.txt")).unwrap();
        let sig = dearmor(&fs::read_to_string(format!("{dir}/announcement.sig")).unwrap()).unwrap();
        signatures(&text, &sig, &keys("generated/keys", "none"))
    }

    fn hex(f: &Fingerprint) -> String {
        f.iter().map(|b| format!("{b:02X}")).collect()
    }

    #[test]
    fn keys_match_published_fingerprints() {
        let mut got: Vec<String> = keys("keys", "none").iter().map(|k| hex(&k.fingerprint)).collect();
        let mut published = vec![
            "B26F10A7157EA66528FD21381CD1328B3352B251",
            "EE7A445EC4643BCEC07E76982E22B777D5136DBD",
            "53E38FB05A545B69C2C284EA27C4446634EC4967",
            "A74F880CF4910EC8A54AADDADFCF19E737660B35",
            "C63CAE08321029D52ACCD85CF8AEB590EB6069FB",
        ];
        got.sort();
        published.sort();
        assert_eq!(got, published);
    }

    #[test]
    fn all_published_announcements_have_two_valid_signers() {
        for n in 0..=6 {
            let (text, sig) = announcement(n);
            let signed = signatures(&text, &sig, &keys("keys", "none")).unwrap_or_else(|e| panic!("mf-{n}: {e}"));
            let chosen = select(&signed, 0).unwrap_or_else(|| panic!("mf-{n}: below threshold"));
            assert_ne!(chosen[0].fingerprint, chosen[1].fingerprint);
            assert!(chosen.iter().all(|s| s.expires_at == 0 && s.digest.len() == 32));
            assert_eq!(announcement_number(std::str::from_utf8(&text).unwrap()), Ok(n));
        }
    }

    #[test]
    fn tampered_text_is_rejected() {
        let (mut text, sig) = announcement(6);
        text.push(b'\n');
        assert_eq!(signatures(&text, &sig, &keys("keys", "none")).unwrap_err(), Error("signature digest prefix mismatch"));
        let (mut text, sig) = announcement(6);
        text[20] ^= 1;
        assert!(signatures(&text, &sig, &keys("keys", "none")).is_err());
    }

    #[test]
    fn signature_by_unpinned_key_is_skipped() {
        // mf-6 is signed by signer_1 and signer_2; drop signer_2 from the key set.
        let (text, sig) = announcement(6);
        let signed = signatures(&text, &sig, &keys("keys", "signer_2")).unwrap();
        assert_eq!(signed.len(), 1);
        assert_eq!(select(&signed, 0), None);
    }

    #[test]
    fn corrupted_signature_is_rejected() {
        let (text, mut sig) = announcement(6);
        let last = sig.len() - 1;
        sig[last] ^= 1;
        assert_eq!(signatures(&text, &sig, &keys("keys", "none")).unwrap_err(), Error("invalid signature"));
    }

    #[test]
    fn sha256_and_sha512_signatures_verify() {
        let signed = generated("sha").unwrap();
        assert_eq!(signed.iter().map(|s| s.digest.len()).collect::<Vec<_>>(), [64, 32]);
        assert!(select(&signed, 0).is_some());
    }

    #[test]
    fn sha384_signatures_are_not_counted() {
        let signed = generated("sha384").unwrap();
        assert_eq!(signed.len(), 1);
        assert_eq!(select(&signed, 0), None);
    }

    #[test]
    fn expired_signatures_are_not_selected() {
        let signed = generated("expiring").unwrap();
        let expires_at = 1_790_000_000 + 10 * 365 * 86_400;
        assert_eq!(signed[0].expires_at, expires_at);
        assert!(select(&signed, expires_at - 1).is_some());
        assert_eq!(select(&signed, expires_at), None);
    }

    #[test]
    fn a_key_counts_once() {
        let signed = generated("same-key").unwrap();
        assert_eq!(signed.len(), 2);
        assert_eq!(select(&signed, 0), None);
    }

    #[test]
    fn header_formats() {
        assert_eq!(announcement_number("MF Announcement #12\nbody"), Ok(12));
        assert_eq!(announcement_number("Announcement #3\n"), Ok(3));
        assert_eq!(announcement_number("MF Announcement #0"), Ok(0));
        for bad in ["MF Announcement #", "MF Announcement #07", "MF Announcement #1 ", " MF Announcement #1", "Announcement 1", "MF Announcement #1\r\n"] {
            assert!(announcement_number(bad).is_err(), "{bad:?}");
        }
    }
}
