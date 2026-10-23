//! The signed part of an OpenPGP v4 signature packet: version, type, algorithms
//! and hashed subpackets. Only what the Foundation uses is accepted: binary-document
//! signatures by EdDSA keys with SHA-256 or SHA-512.

pub global MAX_HASHED: u32 = 256;
/// The hashed area with 32 bytes of padding, so reads at fixed offsets past a
/// subpacket header stay in bounds.
pub global HASHED_BUF: u32 = MAX_HASHED + 32;
global MAX_SUBPACKETS: u32 = 16;

pub global HASH_SHA256: u8 = 8;
pub global HASH_SHA512: u8 = 10;

pub struct Hashed {
    pub hash: u8,
    /// v4 fingerprint of the signing key, as a big-endian integer.
    pub issuer: Field,
    /// Signature expiration as a Unix time, 0 if it never expires.
    pub expires_at: u64,
}

/// Checks `hashed[..len]` and reads the single issuer fingerprint and the expiration.
/// Unknown critical subpackets are rejected, as RFC 4880 requires.
pub fn parse(hashed: [u8; HASHED_BUF], len: u32) -> Hashed {
    assert(len <= MAX_HASHED);
    assert(hashed[0] == 4); // version
    assert(hashed[1] == 0); // binary document
    assert(hashed[2] == 22); // EdDSA
    let hash = hashed[3];
    assert((hash == HASH_SHA256) | (hash == HASH_SHA512));
    assert(len == 6 + be16(hashed, 4));

    let mut pos: u32 = 6;
    let mut issuer: Field = 0;
    let mut has_issuer = false;
    let mut created: u64 = 0;
    let mut has_created = false;
    let mut expires_in: u64 = 0;
    let mut has_expires_in = false;
    for _ in 0..MAX_SUBPACKETS {
        if pos < len {
            // One-, two- or five-octet length, counting the type byte.
            let first = hashed[pos] as u32;
            let (sub_len, header) = if first < 192 {
                (first, 1)
            } else if first < 255 {
                (((first - 192) << 8) + (hashed[pos + 1] as u32) + 192, 2)
            } else {
                (be32(hashed, pos + 1), 5)
            };
            assert(sub_len >= 1);
            assert(sub_len <= MAX_HASHED);
            let start = pos + header;
            let end = start + sub_len;
            assert(end <= len);

            let kind = hashed[start] & 0x7f;
            let critical = (hashed[start] & 0x80) != 0;
            if kind == 33 {
                assert(!has_issuer);
                assert(sub_len == 22);
                assert(hashed[start + 1] == 4); // v4 fingerprint
                for k in 0..20 {
                    issuer = issuer * 256 + hashed[start + 2 + k] as Field;
                }
                has_issuer = true;
            } else if kind == 2 {
                assert(!has_created);
                assert(sub_len == 5);
                created = be32(hashed, start + 1) as u64;
                has_created = true;
            } else if kind == 3 {
                assert(!has_expires_in);
                assert(sub_len == 5);
                expires_in = be32(hashed, start + 1) as u64;
                has_expires_in = true;
            } else {
                assert(!critical);
            }
            pos = end;
        }
    }
    // Every subpacket was read: at most MAX_SUBPACKETS are supported.
    assert(pos == len);
    assert(has_issuer);

    let mut expires_at: u64 = 0;
    if has_expires_in & (expires_in != 0) {
        assert(has_created);
        expires_at = created + expires_in;
    }
    Hashed { hash, issuer, expires_at }
}

fn be16(bytes: [u8; HASHED_BUF], at: u32) -> u32 {
    ((bytes[at] as u32) << 8) + (bytes[at + 1] as u32)
}

fn be32(bytes: [u8; HASHED_BUF], at: u32) -> u32 {
    ((bytes[at] as u32) << 24)
        + ((bytes[at + 1] as u32) << 16)
        + ((bytes[at + 2] as u32) << 8)
        + (bytes[at + 3] as u32)
}
