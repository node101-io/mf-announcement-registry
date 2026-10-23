//! Command-line tool for the announcement registry.

mod inputs;
mod openpgp;

use clap::Parser;
use inputs::Inputs;
use std::{fs, path::Path, path::PathBuf, process::Command, time::SystemTime};

#[derive(Parser)]
#[command(about = "Prove Monad Foundation announcements for the on-chain registry")]
enum Cmd {
    /// Print the primary key packets of <KEYS> (*.asc), comma-separated: the registry constructor argument.
    Keys { keys: PathBuf },
    /// Prove <ANNOUNCEMENT>/announcement.{txt,sig} and write <ANNOUNCEMENT>/proof.json.
    Prove {
        announcement: PathBuf,
        keys: PathBuf,
        /// The Noir circuit directory.
        #[arg(long, default_value = concat!(env!("CARGO_MANIFEST_DIR"), "/../circuit"))]
        circuit: PathBuf,
    },
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    match Cmd::parse() {
        Cmd::Keys { keys } => {
            let packets = key_packets(&keys)?;
            for packet in &packets {
                eprintln!("{}", hex::encode_upper(openpgp::key(packet)?.fingerprint));
            }
            let hex: Vec<String> = packets.iter().map(|p| format!("0x{}", hex::encode(p))).collect();
            println!("{}", hex.join(","));
        }
        Cmd::Prove { announcement, keys, circuit } => {
            let text = fs::read(announcement.join("announcement.txt"))?;
            let signatures = openpgp::signatures(&fs::read_to_string(announcement.join("announcement.sig"))?)?;
            let keys = key_packets(&keys)?.iter().map(|p| openpgp::key(p)).collect::<std::result::Result<Vec<_>, _>>()?;
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            let chosen = openpgp::select(&signatures, &keys, now).ok_or("fewer than two pinned keys signed")?;

            fs::write(circuit.join("Prover.toml"), Inputs { text: text.clone(), keys, signatures: chosen }.to_toml()?)?;
            run(Command::new("nargo").arg("execute").current_dir(&circuit))?;
            run(Command::new("bb")
                .args(["prove", "--write_vk", "-t", "evm-no-zk", "-o", "target"])
                .args(["-b", "target/mf_signatures.json", "-w", "target/mf_signatures.gz"])
                .current_dir(&circuit))?;

            // The last four public inputs are the circuit's outputs, which `submit` takes alongside the proof.
            let inputs: Vec<[u8; 32]> = fs::read(circuit.join("target/public_inputs"))?.chunks(32).map(|w| w.try_into().unwrap()).collect();
            let [number, signer_0, signer_1, expires_at] = inputs[inputs.len() - 4..] else { unreachable!() };
            let uint = |w: [u8; 32]| u64::from_be_bytes(w[24..].try_into().unwrap());
            println!("announcement #{} signed by {} and {}", uint(number), hex::encode_upper(&signer_0[12..]), hex::encode_upper(&signer_1[12..]));

            let out = announcement.join("proof.json");
            let json = serde_json::json!({
                "text": format!("0x{}", hex::encode(&text)),
                "number": uint(number),
                "signers": [format!("0x{}", hex::encode(&signer_0[12..])), format!("0x{}", hex::encode(&signer_1[12..]))],
                "expiresAt": uint(expires_at),
                "proof": format!("0x{}", hex::encode(fs::read(circuit.join("target/proof"))?)),
                "publicInputs": inputs.iter().map(|w| format!("0x{}", hex::encode(w))).collect::<Vec<_>>(),
            });
            fs::write(&out, serde_json::to_string_pretty(&json)?)?;
            println!("wrote {}", out.display());
        }
    }
    Ok(())
}

/// Reads the primary public key packet of every *.asc certificate in `dir`, sorted by file name.
fn key_packets(dir: &Path) -> Result<Vec<Vec<u8>>> {
    let mut paths: Vec<_> = fs::read_dir(dir)?.map(|entry| entry.map(|e| e.path())).collect::<std::result::Result<_, _>>()?;
    paths.retain(|p| p.extension().is_some_and(|ext| ext == "asc"));
    paths.sort();
    paths
        .iter()
        .map(|p| Ok(openpgp::key_packet(&fs::read_to_string(p)?)?))
        .collect()
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().map_err(|e| format!("{:?}: {e}", cmd.get_program()))?;
    if !status.success() {
        return Err(format!("{:?} failed: {status}", cmd.get_program()).into());
    }
    Ok(())
}
