//! Just enough OpenPGP to pick the signatures to prove. Nothing here is trusted:
//! the circuit checks the packets and verifies the signatures.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha1::{Digest, Sha1};

type Result<T> = std::result::Result<T, &'static str>;

const HASH_SHA256: u8 = 8;
const HASH_SHA512: u8 = 10;

/// Number of distinct pinned keys that must sign an announcement.
pub const THRESHOLD: usize = 2;

/// A pinned primary key.
#[derive(Clone)]
pub struct Key {
    pub fingerprint: [u8; 20],
    /// RFC 8032 encoding of the Ed25519 public key.
    pub public_key: [u8; 32],
}

#[derive(Clone)]
pub struct Signature {
    pub issuer: [u8; 20],
    hash: u8,
    /// Unix time, or 0 if the signature never expires.
    expires_at: u64,
    /// The signed part of the packet: version through the hashed subpackets.
    pub hashed: Vec<u8>,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// The primary public key packet body of an armored certificate.
pub fn key_packet(armored: &str) -> Result<Vec<u8>> {
    match packets(&dearmor(armored)?)?.first() {
        Some(&(6, body)) => Ok(body.to_vec()),
        _ => Err("certificate does not start with a public key packet"),
    }
}

/// A v4 Ed25519 primary key packet body and its fingerprint.
pub fn key(packet: &[u8]) -> Result<Key> {
    // version(1) created(4) algo(1) oid_len(1) oid(9) mpi_bits(2) 0x40 point(32)
    if packet.len() != 51 || packet[0] != 4 || packet[5] != 22 || packet[18] != 0x40 {
        return Err("not a v4 Ed25519 key");
    }
    let fingerprint = Sha1::new().chain_update([0x99, 0, 51]).chain_update(packet).finalize().into();
    Ok(Key { fingerprint, public_key: packet[19..].try_into().unwrap() })
}

/// The signature packets of an armored detached signature.
pub fn signatures(armored: &str) -> Result<Vec<Signature>> {
    packets(&dearmor(armored)?)?.into_iter().map(|(tag, body)| if tag == 2 { signature(body) } else { Err("not a signature packet") }).collect()
}

/// The first THRESHOLD signatures by distinct pinned keys that the circuit
/// supports (SHA-256 or SHA-512) and that are unexpired at `now`.
pub fn select(signatures: &[Signature], keys: &[Key], now: u64) -> Option<Vec<Signature>> {
    let mut chosen: Vec<Signature> = Vec::new();
    for s in signatures {
        let usable = matches!(s.hash, HASH_SHA256 | HASH_SHA512)
            && (s.expires_at == 0 || now < s.expires_at)
            && keys.iter().any(|k| k.fingerprint == s.issuer)
            && !chosen.iter().any(|c| c.issuer == s.issuer);
        if usable {
            chosen.push(s.clone());
        }
        if chosen.len() == THRESHOLD {
            return Some(chosen);
        }
    }
    None
}

fn dearmor(armored: &str) -> Result<Vec<u8>> {
    let body: String = armored
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN PGP "))
        .skip(1)
        .skip_while(|l| !l.trim().is_empty())
        .take_while(|l| !l.starts_with('=') && !l.starts_with("-----END"))
        .map(str::trim)
        .collect();
    STANDARD.decode(body).map_err(|_| "invalid armor")
}

fn signature(body: &[u8]) -> Result<Signature> {
    let truncated = "truncated signature packet";
    let hashed_end = 6 + be(body.get(4..6).ok_or(truncated)?);
    let hashed = body.get(..hashed_end).ok_or(truncated)?;
    let (issuer, expires_at) = subpackets(&hashed[6..])?;
    let unhashed_end = hashed_end + 2 + be(body.get(hashed_end..hashed_end + 2).ok_or(truncated)?);
    // Skips the unhashed subpackets and the two-byte digest prefix.
    let (r, rest) = mpi(body.get(unhashed_end + 2..).ok_or(truncated)?)?;
    let (s, _) = mpi(rest)?;
    Ok(Signature { issuer: issuer.ok_or("missing issuer fingerprint")?, hash: body[3], expires_at, hashed: hashed.to_vec(), r, s })
}

/// The issuer fingerprint and the expiration time (0 if none) from the hashed subpackets.
fn subpackets(mut area: &[u8]) -> Result<(Option<[u8; 20]>, u64)> {
    let (mut issuer, mut created, mut expires_in) = (None, 0, 0);
    while !area.is_empty() {
        let (len, header) = length(area)?;
        let sub = area.get(header..header + len).filter(|s| !s.is_empty()).ok_or("malformed subpacket")?;
        match (sub[0] & 0x7f, sub.len()) {
            (33, 22) => issuer = sub[2..].try_into().ok(),
            (2, 5) => created = be(&sub[1..]) as u64,
            (3, 5) => expires_in = be(&sub[1..]) as u64,
            _ => {}
        }
        area = &area[header + len..];
    }
    Ok((issuer, if expires_in == 0 { 0 } else { created + expires_in }))
}

/// Splits data into (tag, body) packets.
fn packets(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    while let Some(&ctb) = data.first() {
        let (tag, len, header) = match ctb {
            0x80..=0xbf => {
                let n = [1, 2, 4].get(ctb as usize & 3).ok_or("indeterminate packet length")?;
                ((ctb >> 2) & 0x0f, be(data.get(1..1 + n).ok_or("truncated packet")?), 1 + n)
            }
            0xc0.. => {
                let (len, n) = length(&data[1..])?;
                (ctb & 0x3f, len, 1 + n)
            }
            _ => return Err("invalid packet header"),
        };
        out.push((tag, data.get(header..header + len).ok_or("truncated packet")?));
        data = &data[header + len..];
    }
    Ok(out)
}

/// Decodes a one-, two- or five-octet length, returning (length, header size).
fn length(data: &[u8]) -> Result<(usize, usize)> {
    match *data {
        [o @ 0..=191, ..] => Ok((o as usize, 1)),
        [o @ 192..=223, o2, ..] => Ok((((o as usize - 192) << 8) + o2 as usize + 192, 2)),
        [255, ref rest @ ..] if rest.len() >= 4 => Ok((be(&rest[..4]), 5)),
        _ => Err("unsupported or truncated length"),
    }
}

/// Reads an MPI of at most 32 bytes, left-padded to 32 bytes.
fn mpi(data: &[u8]) -> Result<([u8; 32], &[u8])> {
    let n = be(data.get(..2).ok_or("truncated MPI")?).div_ceil(8);
    let value = data.get(2..2 + n).filter(|_| n <= 32).ok_or("invalid MPI")?;
    let mut out = [0; 32];
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

    fn keys(dir: &str) -> Vec<Key> {
        crate::key_packets(format!("{DATA}/{dir}").as_ref()).unwrap().iter().map(|p| key(p).unwrap()).collect()
    }

    fn signed(dir: &str) -> Vec<Signature> {
        signatures(&fs::read_to_string(format!("{DATA}/{dir}/announcement.sig")).unwrap()).unwrap()
    }

    fn hex(f: &[u8; 20]) -> String {
        f.iter().map(|b| format!("{b:02X}")).collect()
    }

    #[test]
    fn keys_match_published_fingerprints() {
        let got: Vec<String> = keys("keys").iter().map(|k| hex(&k.fingerprint)).collect();
        assert_eq!(got, [
            "B26F10A7157EA66528FD21381CD1328B3352B251", // signer_1
            "EE7A445EC4643BCEC07E76982E22B777D5136DBD", // signer_2
            "53E38FB05A545B69C2C284EA27C4446634EC4967", // signer_3
            "A74F880CF4910EC8A54AADDADFCF19E737660B35", // signer_4
            "C63CAE08321029D52ACCD85CF8AEB590EB6069FB", // signer_6
        ]);
    }

    #[test]
    fn selects_two_signers_for_every_published_announcement() {
        for n in 0..=6 {
            let chosen = select(&signed(&format!("mf-{n}")), &keys("keys"), 0).unwrap_or_else(|| panic!("mf-{n}"));
            assert_ne!(chosen[0].issuer, chosen[1].issuer);
        }
    }

    #[test]
    fn skips_unpinned_keys() {
        // mf-6 is signed by signer_1 and signer_2.
        let without_signer_2: Vec<Key> = keys("keys").into_iter().filter(|k| hex(&k.fingerprint) != "EE7A445EC4643BCEC07E76982E22B777D5136DBD").collect();
        assert!(select(&signed("mf-6"), &without_signer_2, 0).is_none());
    }

    #[test]
    fn a_key_counts_once() {
        assert!(select(&signed("generated/same-key"), &keys("generated/keys"), 0).is_none());
    }

    #[test]
    fn skips_sha384() {
        assert!(select(&signed("generated/sha384"), &keys("generated/keys"), 0).is_none());
    }

    #[test]
    fn skips_expired_signatures() {
        let expires_at = 1_790_000_000 + 10 * 365 * 86_400;
        let signed = signed("generated/expiring");
        assert!(select(&signed, &keys("generated/keys"), expires_at - 1).is_some());
        assert!(select(&signed, &keys("generated/keys"), expires_at).is_none());
    }
}
