use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use bn254_decision_plonk_direct_guest::{
    CanonicalPlonkSourceInput, PLONK_SOURCE_IDS, export_canonical_plonk_rows, input_keyset_digest,
    plonk_reseal_report, registry_keyset_digest,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

fn create_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| panic!("create-new {}: {error}", path.display()));
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let mut source_root = None;
    let mut output = None;
    let mut reseal = false;
    while let Some(flag) = arguments.next() {
        match flag.to_str() {
            Some("--fixtures-root") => source_root = arguments.next().map(PathBuf::from),
            Some("--output") => output = arguments.next().map(PathBuf::from),
            Some("--reseal") => reseal = true,
            _ => panic!("usage: export_rows --fixtures-root ABS [--output ABS | --reseal]"),
        }
    }
    let source_root = source_root.expect("--fixtures-root ABS is required");
    assert!(
        source_root.is_absolute(),
        "--fixtures-root must be absolute"
    );

    let loaded = PLONK_SOURCE_IDS.map(|name| {
        (
            name,
            std::fs::read(source_root.join(name).join("verification_key.json")).unwrap(),
            std::fs::read(source_root.join(name).join("proof.json")).unwrap(),
            std::fs::read(source_root.join(name).join("public.json")).unwrap(),
        )
    });
    let sources = loaded
        .iter()
        .map(|(name, vk, proof, public)| CanonicalPlonkSourceInput {
            source_id: name,
            verification_key_json: vk,
            proof_json: proof,
            public_json: public,
        })
        .collect::<Vec<_>>();
    if reseal {
        print!("{}", plonk_reseal_report(&sources).expect("reseal"));
        return;
    }
    let output = output.expect("--output ABS is required");
    assert!(output.is_absolute(), "--output must be absolute");
    if output.exists() {
        assert!(
            output.read_dir().unwrap().next().is_none(),
            "output directory must be empty"
        );
    } else {
        std::fs::create_dir_all(&output).unwrap();
    }
    let export = export_canonical_plonk_rows(&sources).expect("canonical committed test fixtures");
    let n2 = export.n2_combined_account;
    let n3 = export.n3_combined_account;
    let row = |name: &str, data: &[u8]| {
        json!({
            "path": name,
            "length": data.len(),
            "sha256": sha256(data),
            "input_digest": hex(input_keyset_digest(data).expect("allowlisted input digest")),
            "registry_keyset_digest_v3": hex(
                registry_keyset_digest(data).expect("v3 registry digest")
            ),
            "registry_len": solana_bn254_batch_syscall::registry_account_len(2, 0),
        })
    };
    let manifest = json!({
        "schema": "helius.bn254-decision.plonk-direct-test-exceptions.v1",
        "semantics": "committed snarkjs PLONK fixtures shaped like zolana transact: one public signal, Poseidon chain over (nIn, nOut) at 1_1, 2_2, 2_3, distinct keys over one SRS; not production proofs",
        "source_set_sha256": export.source_set_sha256,
        "rows": {
            "n2": row("n2.bin", &n2),
            "n3": row("n3.bin", &n3),
        }
    });
    create_new(&output.join("n2.bin"), &n2);
    create_new(&output.join("n3.bin"), &n3);
    create_new(
        &output.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest).unwrap(),
    );
}
