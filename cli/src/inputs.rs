//! The circuit's inputs, written as a Prover.toml.

use mf_verify::{Key, Signed};
use num_bigint::BigUint;

/// Must match the circuit's globals.
const MAX_TEXT: usize = 4096;
const MAX_KEYS: usize = 8;
const MAX_HASHED: usize = 256;
const HASHED_BUF: usize = MAX_HASHED + 32;

#[derive(Clone)]
pub struct Signature {
    /// The signed part of the packet: version through the hashed subpackets.
    pub hashed: Vec<u8>,
    /// RFC 8032 encodings of R and S. The public key comes from the pinned keys.
    pub r: [u8; 32],
    pub s: [u8; 32],
    /// x-coordinates of the public key and R, which the circuit takes as witnesses.
    pub public_key_x: BigUint,
    pub r_x: BigUint,
}

pub struct Inputs {
    pub text: Vec<u8>,
    pub keys: Vec<Key>,
    pub signatures: Vec<Signature>,
}

impl Inputs {
    pub fn new(text: &[u8], keys: &[Key], chosen: &[Signed]) -> Self {
        let signatures = chosen
            .iter()
            .map(|s| Signature {
                hashed: s.hashed.clone(),
                r: s.r,
                s: s.s,
                public_key_x: x_coordinate(&s.public_key),
                r_x: x_coordinate(&s.r),
            })
            .collect();
        Inputs { text: text.to_vec(), keys: keys.to_vec(), signatures }
    }

    /// Text as 31-byte big-endian chunks, keys as 16-byte halves, x-coordinates as
    /// 120-bit limbs, packet bytes as byte arrays.
    pub fn to_toml(&self) -> Result<String, String> {
        if self.text.len() > MAX_TEXT {
            return Err(format!("text is {} bytes; the circuit takes at most {MAX_TEXT}", self.text.len()));
        }
        if self.keys.len() > MAX_KEYS {
            return Err(format!("at most {MAX_KEYS} keys are supported"));
        }
        if self.signatures.iter().any(|s| s.hashed.len() > MAX_HASHED) {
            return Err("signature packet has too many hashed subpackets for the circuit".into());
        }
        let field = |b: &[u8]| format!("\"0x{}\"", hex::encode(b));
        let list = |items: Vec<String>| format!("[{}]", items.join(", "));
        let halves = |b: &[u8]| list(b.chunks(16).map(field).collect());
        let bytes = |b: &[u8]| list(b.iter().map(u8::to_string).collect());
        let limbs = |x: &BigUint| {
            let mask = (BigUint::from(1u8) << 120u32) - 1u8;
            list((0..3).map(|i| format!("\"0x{:x}\"", (x >> (120 * i)) & &mask)).collect())
        };
        let each = |f: &dyn Fn(&Signature) -> String| list(self.signatures.iter().map(f).collect());

        let mut text = self.text.clone();
        text.resize(MAX_TEXT.div_ceil(31) * 31, 0);
        let mut fingerprints: Vec<String> = self.keys.iter().map(|k| field(&k.fingerprint)).collect();
        let mut public_keys: Vec<String> = self.keys.iter().map(|k| halves(&k.public_key)).collect();
        fingerprints.resize(MAX_KEYS, "0".into());
        public_keys.resize(MAX_KEYS, "[0, 0]".into());

        Ok([
            format!("text = {}", list(text.chunks(31).map(field).collect())),
            format!("text_len = {}", self.text.len()),
            format!("fingerprints = {}", list(fingerprints)),
            format!("public_keys = {}", list(public_keys)),
            format!("hashed = {}", each(&|s| {
                let mut h = s.hashed.clone();
                h.resize(HASHED_BUF, 0);
                bytes(&h)
            })),
            format!("hashed_lens = {}", each(&|s| s.hashed.len().to_string())),
            format!("rs = {}", each(&|s| bytes(&s.r))),
            format!("ss = {}", each(&|s| bytes(&s.s))),
            format!("public_key_xs = {}", each(&|s| limbs(&s.public_key_x))),
            format!("r_xs = {}", each(&|s| limbs(&s.r_x))),
        ]
        .join("\n"))
    }
}

fn p() -> BigUint {
    (BigUint::from(1u8) << 255u32) - 19u8
}

/// Recovers x from an RFC 8032 point encoding (section 5.1.3).
fn x_coordinate(encoded: &[u8; 32]) -> BigUint {
    let p = p();
    let one = BigUint::from(1u8);
    let mut y_bytes = *encoded;
    y_bytes[31] &= 0x7f;
    let y = BigUint::from_bytes_le(&y_bytes);
    let sign = encoded[31] >> 7;

    // d = -121665 / 121666
    let inv = |v: &BigUint| v.modpow(&(&p - 2u8), &p);
    let d = (&p - BigUint::from(121665u32)) * inv(&BigUint::from(121666u32)) % &p;
    let yy = &y * &y % &p;
    let u = (&yy + &p - &one) % &p;
    let v = (&d * &yy + &one) % &p;
    let x2 = u * inv(&v) % &p;
    let mut x = x2.modpow(&((&p + 3u8) >> 3u32), &p);
    if (&x * &x) % &p != x2 {
        x = x * BigUint::from(2u8).modpow(&((&p - 1u8) >> 2u32), &p) % &p;
    }
    if x.bit(0) != (sign == 1) {
        x = (&p - x) % &p;
    }
    x
}

/// Runs the circuit on mf-6 and on changes it must reject, with `nargo execute`
/// (which needs `nargo` on PATH). Each run takes about 15 seconds.
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path, process::Command, sync::Mutex};

    const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    /// nargo writes to the circuit's target directory, so runs must not overlap.
    static NARGO: Mutex<()> = Mutex::new(());

    fn mf6() -> Inputs {
        let keys: Vec<Key> = crate::key_packets(Path::new(&format!("{ROOT}/testdata/keys")))
            .unwrap()
            .iter()
            .map(|body| mf_verify::parse_public_key(body).unwrap())
            .collect();
        let text = fs::read(format!("{ROOT}/testdata/mf-6/announcement.txt")).unwrap();
        let sig = mf_verify::dearmor(&fs::read_to_string(format!("{ROOT}/testdata/mf-6/announcement.sig")).unwrap()).unwrap();
        let chosen = mf_verify::select(&mf_verify::signatures(&text, &sig, &keys).unwrap(), 0).unwrap();
        Inputs::new(&text, &keys, &chosen)
    }

    /// Whether the circuit's constraints hold for `inputs`.
    fn solves(inputs: &Inputs) -> bool {
        let _guard = NARGO.lock().unwrap_or_else(|e| e.into_inner());
        let circuit = format!("{ROOT}/circuit");
        fs::write(format!("{circuit}/Test.toml"), inputs.to_toml().unwrap()).unwrap();
        let out = Command::new("nargo")
            .args(["execute", "--prover-name", "Test"])
            .current_dir(&circuit)
            .output()
            .expect("nargo must be on PATH");
        fs::remove_file(format!("{circuit}/Test.toml")).unwrap();
        out.status.success()
    }

    #[test]
    fn accepts_mf6() {
        assert!(solves(&mf6()));
    }

    #[test]
    fn rejects_changed_text() {
        let mut i = mf6();
        i.text[20] ^= 1;
        assert!(!solves(&i));
    }

    #[test]
    fn rejects_same_signature_twice() {
        let mut i = mf6();
        i.signatures[1] = i.signatures[0].clone();
        assert!(!solves(&i));
    }

    #[test]
    fn rejects_unpinned_signer() {
        let mut i = mf6(); // signed by signer_1 and signer_2
        i.keys.retain(|k| hex::encode_upper(k.fingerprint) != "EE7A445EC4643BCEC07E76982E22B777D5136DBD");
        assert!(!solves(&i));
    }

    #[test]
    fn rejects_s_plus_l() {
        let mut i = mf6();
        let l = (BigUint::from(1u8) << 252u32) + BigUint::parse_bytes(b"27742317777372353535851937790883648493", 10).unwrap();
        let mut s = (BigUint::from_bytes_le(&i.signatures[0].s) + l).to_bytes_le();
        s.resize(32, 0);
        i.signatures[0].s = s.try_into().unwrap();
        assert!(!solves(&i));
    }

    #[test]
    fn rejects_r_with_flipped_sign_bit() {
        let mut i = mf6();
        i.signatures[0].r[31] ^= 0x80;
        assert!(!solves(&i));
    }

    #[test]
    fn rejects_public_key_with_other_root() {
        let mut i = mf6();
        i.signatures[0].public_key_x = p() - &i.signatures[0].public_key_x;
        assert!(!solves(&i));
    }

    #[test]
    fn rejects_sha384() {
        let mut i = mf6();
        i.signatures[0].hashed[3] = 9;
        assert!(!solves(&i));
    }
}
