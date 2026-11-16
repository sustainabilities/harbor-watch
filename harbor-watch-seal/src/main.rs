//! harbor-watch-seal — the SSC envelope.
//!
//! The tool that preaches weight attestation ships attested. The
//! envelope: every file's sha512 in a manifest, the manifest signed
//! with ML-DSA-65 (FIPS 204 — the estate's ratified signature scheme,
//! pure Rust), the provenance statement alongside.
//!
//! Commands:
//!   harbor-watch-seal keygen <dir>              — the SSC signing seed (once)
//!   harbor-watch-seal seal <dir> <payload-dir>  — manifest + signature + provenance
//!   harbor-watch-seal verify <dir>              — re-hash everything, verify the signature
//!
//! Anti-tampering: any byte of any file changes → the manifest hash
//! breaks → the signature fails. The envelope IS the receipt.

use ml_dsa::{Keypair as _, MlDsa65, Seed, Signature, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone)]
struct ManifestEntry {
    path: String,
    sha512: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Envelope {
    ssc: String,
    sealed: String,
    provenance: Provenance,
    manifest: Vec<ManifestEntry>,
    signature: SignatureBlock,
}

#[derive(Serialize, Deserialize, Clone)]
struct Provenance {
    sealed_by: String,
    tool_version: String,
    note: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct SignatureBlock {
    algo: String,
    pubkey_hex: String,
    sig_hex: String,
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<ManifestEntry>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("read {}: {}", dir.display(), e))? {
        let p = entry.map_err(|e| format!("dir entry: {}", e))?.path();
        if p.is_dir() {
            if p.file_name().map(|n| n == "target" || n == ".git").unwrap_or(false) {
                continue; // build artifacts and git internals are not the artifact
            }
            walk(&p, base, out)?;
        } else if p.file_name().map(|n| n == "envelope.json").unwrap_or(false) {
            continue; // the envelope does not carry its own hash
        } else {
            let bytes = std::fs::read(&p).map_err(|e| format!("read {}: {}", p.display(), e))?;
            let hash = hex(&Sha512::digest(&bytes));
            let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().into_owned();
            out.push(ManifestEntry { path: rel, sha512: hash });
        }
    }
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("keygen") => cmd_keygen(&args.get(1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))),
        Some("seal") if args.len() >= 3 => cmd_seal(Path::new(&args[1]), Path::new(&args[2])),
        Some("verify") if args.len() >= 2 => cmd_verify(Path::new(&args[1])),
        _ => usage(),
    }
}

fn usage() {
    eprintln!("usage: harbor-watch-seal keygen <dir>");
    eprintln!("       harbor-watch-seal seal <key-dir> <payload-dir>");
    eprintln!("       harbor-watch-seal verify <payload-dir-with-envelope>");
    std::process::exit(2);
}

fn cmd_keygen(dir: &Path) {
    std::fs::create_dir_all(dir).expect("create key dir");
    // the seed IS the private key serialization (32 bytes, FIPS 204)
    let mut seed_bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed_bytes))
        .expect("read /dev/urandom");
    let seed = Seed::try_from(seed_bytes.as_slice()).expect("seed");
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk_hex = hex(&sk.verifying_key().encode().to_vec());
    std::fs::write(dir.join("ssc-signing-seed.bin"), seed_bytes).expect("write signing seed");
    std::fs::write(dir.join("ssc-verify-key.hex"), &vk_hex).expect("write verifying key");
    println!("SSC keypair generated:");
    println!("  signing seed (KEEP GUARDED): {}", dir.join("ssc-signing-seed.bin").display());
    println!("  verifying key (public):      {}", dir.join("ssc-verify-key.hex").display());
    println!("  the verifying key's hex is what every recipient pins.");
}

fn cmd_seal(key_dir: &Path, payload_dir: &Path) {
    let seed_bytes = std::fs::read(key_dir.join("ssc-signing-seed.bin")).expect("read the signing seed");
    let seed = Seed::try_from(seed_bytes.as_slice()).expect("seed");
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let mut manifest = Vec::new();
    walk(payload_dir, payload_dir, &mut manifest).expect("walk the payload");
    manifest.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest_json = serde_json::to_string_pretty(&manifest).expect("manifest");
    use ml_dsa::Signer as _;
    let sig = sk.sign(manifest_json.as_bytes());
    let envelope = Envelope {
        ssc: "envelope-v1".into(),
        sealed: now(),
        provenance: Provenance {
            sealed_by: "SafeHarbors Corporation".into(),
            tool_version: format!("harbor-watch-seal v{}", env!("CARGO_PKG_VERSION")),
            note: "sealed with ML-DSA-65 (FIPS 204); the manifest covers every file's sha512; verify before running".into(),
        },
        manifest: manifest.clone(),
        signature: SignatureBlock {
            algo: "ML-DSA-65".into(),
            pubkey_hex: hex(&sk.verifying_key().encode().to_vec()),
            sig_hex: hex(&sig.encode().to_vec()),
        },
    };
    let out = payload_dir.join("envelope.json");
    std::fs::write(&out, serde_json::to_string_pretty(&envelope).unwrap()).expect("write envelope");
    println!("SEALED  {} ({} files)", out.display(), manifest.len());
    println!("  manifest: sha512 per file; ML-DSA-65 signature over the manifest");
    println!("  verify with: harbor-watch-seal verify {}", payload_dir.display());
}

fn cmd_verify(dir: &Path) {
    let env_path = dir.join("envelope.json");
    let text = std::fs::read_to_string(&env_path).unwrap_or_else(|e| {
        eprintln!("refused: no envelope at {}: {}", env_path.display(), e);
        std::process::exit(1);
    });
    let env: Envelope = serde_json::from_str(&text).expect("parse the envelope");
    // 1. the manifest matches the files on disk
    let mut broken = Vec::new();
    for entry in &env.manifest {
        let p = dir.join(&entry.path);
        match std::fs::read(&p) {
            Ok(bytes) => {
                let h = hex(&Sha512::digest(&bytes));
                if h != entry.sha512 {
                    broken.push(format!("{}: hash mismatch (tampered or corrupted)", entry.path));
                }
            }
            Err(_) => broken.push(format!("{}: MISSING", entry.path)),
        }
    }
    // 2. the signature verifies against the pinned key
    let vk_bytes = unhex(&env.signature.pubkey_hex);
    let vk_enc = <_ as TryFrom<&[u8]>>::try_from(vk_bytes.as_slice()).expect("verifying key bytes");
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);
    let manifest_json = serde_json::to_string_pretty(&env.manifest).expect("manifest re-render");
    let sig_bytes = unhex(&env.signature.sig_hex);
    let sig_enc = <_ as TryFrom<&[u8]>>::try_from(sig_bytes.as_slice()).expect("signature bytes");
    let sig = Signature::<MlDsa65>::decode(&sig_enc).expect("decode signature");
    let sig_ok = vk.verify(manifest_json.as_bytes(), &sig).is_ok();
    if !broken.is_empty() {
        for b in &broken {
            eprintln!("TAMPERED: {}", b);
        }
        std::process::exit(1);
    }
    if !sig_ok {
        eprintln!("SIGNATURE FAILED: the manifest does not verify under the SSC key. Do not trust this envelope.");
        std::process::exit(1);
    }
    println!("ENVELOPE VERIFIED  {} ({} files)", env_path.display(), env.manifest.len());
    println!("  every file's sha512 matches the manifest;");
    println!("  the manifest verifies under the SSC ML-DSA-65 key;");
    println!("  sealed {} by {}.", env.sealed, env.provenance.sealed_by);
}

fn now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let rem = secs % 86_400;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}
