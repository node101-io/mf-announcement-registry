//! The circuit's inputs, written as a Prover.toml.

use crate::openpgp::{Key, Signature};

/// Must match the circuit's globals.
const MAX_TEXT: usize = 4096;
const MAX_KEYS: usize = 8;
const MAX_HASHED: usize = 256;
const HASHED_BUF: usize = MAX_HASHED + 32;

pub struct Inputs {
    pub text: Vec<u8>,
    pub keys: Vec<Key>,
    pub signatures: Vec<Signature>,
}

impl Inputs {
    /// Text as 31-byte big-endian chunks, keys as 16-byte halves, packet bytes as byte arrays.
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
        ]
        .join("\n"))
    }
}

/// Runs the circuit on mf-6 and on changes it must reject, with `nargo execute`
/// (which needs `nargo` on PATH). Each run takes about 15 seconds.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::openpgp;
    use std::{fs, path::Path, process::Command, sync::Mutex};

    const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    /// nargo writes to the circuit's target directory, so runs must not overlap.
    static NARGO: Mutex<()> = Mutex::new(());

    fn mf6() -> Inputs {
        let keys: Vec<Key> = crate::key_packets(Path::new(&format!("{ROOT}/testdata/keys")))
            .unwrap()
            .iter()
            .map(|p| openpgp::key(p).unwrap())
            .collect();
        let text = fs::read(format!("{ROOT}/testdata/mf-6/announcement.txt")).unwrap();
        let signatures = openpgp::signatures(&fs::read_to_string(format!("{ROOT}/testdata/mf-6/announcement.sig")).unwrap()).unwrap();
        Inputs { text, signatures: openpgp::select(&signatures, &keys, 0).unwrap(), keys }
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
    fn rejects_sha384() {
        let mut i = mf6();
        i.signatures[0].hashed[3] = 9;
        assert!(!solves(&i));
    }
}
