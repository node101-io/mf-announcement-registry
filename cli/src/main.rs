//! Command-line tool for the announcement registry.

mod inputs;

use clap::Parser;
use inputs::Inputs;
use mf_verify::Key;
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
            for body in &packets {
                eprintln!("{}", hex::encode_upper(mf_verify::parse_public_key(body)?.fingerprint));
            }
            let hex: Vec<String> = packets.iter().map(|p| format!("0x{}", hex::encode(p))).collect();
            println!("{}", hex.join(","));
        }
        Cmd::Prove { announcement, keys, circuit } => {
            let text = fs::read(announcement.join("announcement.txt"))?;
            let sig = mf_verify::dearmor(&fs::read_to_string(announcement.join("announcement.sig"))?)?;
            let keys: Vec<Key> = key_packets(&keys)?
                .iter()
                .map(|body| mf_verify::parse_public_key(body))
                .collect::<std::result::Result<_, _>>()?;

            let number = mf_verify::announcement_number(std::str::from_utf8(&text)?)?;
            let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs();
            let signed = mf_verify::signatures(&text, &sig, &keys)?;
            let chosen = mf_verify::select(&signed, now).ok_or("fewer than two pinned keys signed")?;
            println!("announcement #{number} signed by:");
            for s in &chosen {
                println!("  {}", hex::encode_upper(s.fingerprint));
            }

            fs::write(circuit.join("Prover.toml"), Inputs::new(&text, &keys, &chosen).to_toml()?)?;
            run(Command::new("nargo").arg("execute").current_dir(&circuit))?;
            run(Command::new("bb")
                .args(["prove", "--write_vk", "-t", "evm-no-zk", "-o", "target"])
                .args(["-b", "target/mf_signatures.json", "-w", "target/mf_signatures.gz"])
                .current_dir(&circuit))?;

            // The circuit's public outputs, passed to `submit` alongside the proof.
            let expires_at = chosen.iter().map(|s| s.expires_at).filter(|&t| t != 0).min().unwrap_or(0);
            let out = announcement.join("proof.json");
            let json = serde_json::json!({
                "text": format!("0x{}", hex::encode(&text)),
                "number": number,
                "signers": chosen.iter().map(|s| format!("0x{}", hex::encode(s.fingerprint))).collect::<Vec<_>>(),
                "expiresAt": expires_at,
                "proof": format!("0x{}", hex::encode(fs::read(circuit.join("target/proof"))?)),
                "publicInputs": fs::read(circuit.join("target/public_inputs"))?
                    .chunks(32)
                    .map(|w| format!("0x{}", hex::encode(w)))
                    .collect::<Vec<_>>(),
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
        .map(|p| {
            let cert = mf_verify::dearmor(&fs::read_to_string(p)?)?;
            Ok(mf_verify::primary_key_packet(&cert)?.to_vec())
        })
        .collect()
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().map_err(|e| format!("{:?}: {e}", cmd.get_program()))?;
    if !status.success() {
        return Err(format!("{:?} failed: {status}", cmd.get_program()).into());
    }
    Ok(())
}
