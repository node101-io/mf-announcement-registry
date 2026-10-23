//! Proves that an announcement text carries valid OpenPGP signatures by two
//! distinct pinned keys.
//!
//! Public inputs: the text (31 bytes per field), its length, and the pinned keys,
//! all supplied by the registry contract. Public outputs: the announcement
//! number, the two signers' fingerprints, and the earliest signature expiration
//! (0 = never), which the contract compares with the block time.
//!
//! The signatures themselves are private: the prover picks two valid ones.

use bignum::{BigNum, ED25519_Fq as Fq, ED25519_Fr as Fr};
use ed25519::ed25519_verify;
use edwards_bignum::{CurveTrait, ed25519::Ed25519, ScalarField};
use openpgp::{HASH_SHA256, HASHED_BUF, MAX_HASHED};

mod header;
mod openpgp;

global MAX_TEXT: u32 = 4096;
global TEXT_FIELDS: u32 = 133; // ceil(4096 / 31)
global MAX_KEYS: u32 = 8;
global SIGNATURES: u32 = 2;
global PREIMAGE: u32 = MAX_TEXT + MAX_HASHED + 6;

fn main(
    text: pub [Field; TEXT_FIELDS],
    text_len: pub u32,
    // v4 fingerprints of the pinned keys (0 for unused slots), and their RFC 8032
    // encodings as big-endian 16-byte halves.
    fingerprints: pub [Field; MAX_KEYS],
    public_keys: pub [[Field; 2]; MAX_KEYS],
    // Per signature: the signed part of the packet (version through hashed
    // subpackets), R and S, and the x-coordinates of the public key and R.
    hashed: [[u8; HASHED_BUF]; SIGNATURES],
    hashed_lens: [u32; SIGNATURES],
    rs: [[u8; 32]; SIGNATURES],
    ss: [[u8; 32]; SIGNATURES],
    public_key_xs: [[u128; 3]; SIGNATURES],
    r_xs: [[u128; 3]; SIGNATURES],
) -> pub (u64, [Field; SIGNATURES], u64) {
    let text = unpack_text(text, text_len);
    let number = header::number(text, text_len);

    let mut signers = [0; SIGNATURES];
    let mut expires_at: u64 = 0;
    for i in 0..SIGNATURES {
        let packet = openpgp::parse(hashed[i], hashed_lens[i]);
        let public_key = pinned_key(fingerprints, public_keys, packet.issuer);
        let (digest, digest_len) = digest(text, text_len, hashed[i], hashed_lens[i], packet.hash);

        let a = decompress(public_key, public_key_xs[i]);
        let r = decompress(rs[i], r_xs[i]);
        let s = scalar(ss[i]);
        assert(ed25519_verify(a, s, r, BoundedVec::from_parts(digest, digest_len)));

        signers[i] = packet.issuer;
        let earlier = (expires_at == 0) | (packet.expires_at < expires_at);
        if (packet.expires_at != 0) & earlier {
            expires_at = packet.expires_at;
        }
    }
    assert(signers[0] != signers[1]);

    (number, signers, expires_at)
}

/// Unpacks 31-byte big-endian chunks, requiring zeros past `len`.
fn unpack_text(fields: [Field; TEXT_FIELDS], len: u32) -> [u8; MAX_TEXT] {
    assert(len <= MAX_TEXT);
    let mut text = [0; MAX_TEXT];
    for f in 0..TEXT_FIELDS {
        let chunk: [u8; 31] = fields[f].to_be_bytes();
        for k in 0..31 {
            let i = f * 31 + k;
            if i < MAX_TEXT {
                text[i] = chunk[k];
            } else {
                assert(chunk[k] == 0);
            }
        }
    }
    for i in 0..MAX_TEXT {
        if i >= len {
            assert(text[i] == 0);
        }
    }
    text
}

/// The public key whose fingerprint is `issuer`, which must be pinned exactly once.
fn pinned_key(fingerprints: [Field; MAX_KEYS], public_keys: [[Field; 2]; MAX_KEYS], issuer: Field) -> [u8; 32] {
    assert(issuer != 0);
    let mut found: Field = 0;
    let mut halves: [Field; 2] = [0, 0];
    for k in 0..MAX_KEYS {
        let m = (fingerprints[k] == issuer) as Field;
        found += m;
        halves[0] += m * public_keys[k][0];
        halves[1] += m * public_keys[k][1];
    }
    assert(found == 1);
    let hi: [u8; 16] = halves[0].to_be_bytes();
    let lo: [u8; 16] = halves[1].to_be_bytes();
    let mut out = [0; 32];
    for i in 0..16 {
        out[i] = hi[i];
        out[16 + i] = lo[i];
    }
    out
}

/// The OpenPGP v4 digest: hash(text || hashed || 0x04 0xff || be32(hashed length)),
/// zero-padded to 64 bytes, and its length.
fn digest(text: [u8; MAX_TEXT], text_len: u32, hashed: [u8; HASHED_BUF], hashed_len: u32, hash: u8) -> ([u8; 64], u32) {
    let mut storage = [0; PREIMAGE];
    for i in 0..MAX_TEXT {
        storage[i] = text[i];
    }
    let mut preimage: BoundedVec<u8, PREIMAGE> = BoundedVec::from_parts(storage, text_len);
    preimage.extend_from_bounded_vec(BoundedVec::<u8, HASHED_BUF>::from_parts(hashed, hashed_len));
    let n: [u8; 4] = (hashed_len as Field).to_be_bytes();
    preimage.extend_from_array([0x04, 0xff, n[0], n[1], n[2], n[3]]);

    let sha256: [u8; 32] = sha256::sha256_var(preimage.storage(), preimage.len());
    let sha512: [u8; 64] = sha512::sha512::sha512_var(preimage);
    if hash == HASH_SHA256 {
        let mut out = [0; 64];
        for i in 0..32 {
            out[i] = sha256[i];
        }
        (out, 32)
    } else {
        (sha512, 64)
    }
}

/// Decodes an RFC 8032 point encoding, given its x-coordinate as a witness.
/// Non-canonical encodings (y >= p, or x == 0 with the sign bit set) are rejected.
fn decompress(encoded: [u8; 32], x_limbs: [u128; 3]) -> Ed25519 {
    let sign = encoded[31] >> 7;
    let mut y_bytes = encoded;
    y_bytes[31] = y_bytes[31] & 0x7f;
    let y = Fq::from_le_bytes(y_bytes);
    let x = Fq::from_limbs(x_limbs);
    assert_canonical(y);
    assert_canonical(x);

    let point = Ed25519::from((x, y));
    point.assert_is_on_curve();
    assert((x.to_le_bytes()[0] & 1) == sign);
    point
}

/// Decodes S, rejecting S >= L as RFC 8032 requires.
fn scalar(encoded: [u8; 32]) -> ScalarField<64> {
    let s = Fr::from_le_bytes(encoded);
    let limbs = s.get_limbs();
    s.validate_in_field();
    assert(limbs != Fr::params().modulus);

    let two_120: Field = 0x1000000000000000000000000000000;
    ScalarField::<64>::from(limbs[0] as Field + (limbs[1] as Field) * two_120 + (limbs[2] as Field) * two_120 * two_120)
}

/// Constrains `v` to 120-bit limbs and `v < p`. `validate_in_field` alone admits `v == p`.
fn assert_canonical(v: Fq) {
    v.validate_in_range();
    v.validate_in_field();
    assert(v.get_limbs() != Fq::params().modulus);
}
