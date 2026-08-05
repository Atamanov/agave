use std::{env, path::PathBuf};

use groth16_solana::vk::gnark::generate_bsb22_vk_file;
use sha2::{Digest, Sha256};

struct Fixture {
    directory: &'static str,
    symbol: &'static str,
    digest_environment: &'static str,
    expected_generation_sha256: &'static str,
    expected_payload_sha256: &'static str,
    expected_vk_sha256: &'static str,
    expected_n: usize,
    expected_public_variables_including_one: usize,
    expected_payload_bytes: usize,
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    println!("cargo:rerun-if-env-changed=HELIUS_PLONK_RECURSION_FIXTURE_ROOT");
    let fixtures = env::var_os("HELIUS_PLONK_RECURSION_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("fixtures/fixed-statement-v3"));
    let output = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    for fixture in [
        Fixture {
            directory: "n2-secure",
            symbol: "VK_N2_SECURE",
            digest_environment: "HELIUS_PLONK_N2_OUTER_VK_SHA256",
            expected_generation_sha256: "4594d021e9d9d8a138dc445b3561a304ec5f99e5c571940b262fa2a5f52db581",
            expected_payload_sha256: "5a381a6ae9c930e49b0a758324331c87594abefbb496fe159f1a176f3327f4f3",
            expected_vk_sha256: "0ab7160a5df8ac73ee8e0bdfb4e30867ff5219e1de484d41f78a89c10b311ed7",
            expected_n: 2,
            expected_public_variables_including_one: 5,
            expected_payload_bytes: 512,
        },
        Fixture {
            directory: "n3-secure",
            symbol: "VK_N3_SECURE",
            digest_environment: "HELIUS_PLONK_N3_OUTER_VK_SHA256",
            expected_generation_sha256: "b36fa21be193f3eaa382d8cdb968aad6f332d96a6ecb7c49e0cd2454447f65b8",
            expected_payload_sha256: "58e22abcfc95483ae180e081f44d32cd5b6b898d092571b14a1c5f5caa9cf4ca",
            expected_vk_sha256: "32cf5f71d4d462e930745414a7fea30cb19cd0a42a3242225b3aba8e6bf70d81",
            expected_n: 3,
            expected_public_variables_including_one: 8,
            expected_payload_bytes: 608,
        },
    ] {
        let directory = fixtures.join(fixture.directory);
        let generation_path = directory.join("generation.json");
        let payload_path = directory.join("payload_unnegated_a.bin");
        let vk_path = directory.join("vk.bin");
        for path in [&generation_path, &payload_path, &vk_path] {
            println!("cargo:rerun-if-changed={}", path.display());
        }

        let generation_bytes = std::fs::read(&generation_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", generation_path.display()));
        assert_eq!(
            format!("{:x}", Sha256::digest(&generation_bytes)),
            fixture.expected_generation_sha256,
            "{} does not match the freshly generated sealed metadata",
            generation_path.display()
        );
        let generation = std::str::from_utf8(&generation_bytes)
            .unwrap_or_else(|error| panic!("decode {}: {error}", generation_path.display()));
        assert!(
            generation.contains(
                "\"schema\": \"helios.genuine-snarkjs-plonk-recursion.secure-os-random.fixed-statement.v3\""
            ),
            "{} is not the fixed-statement-v3 PLONK recursion export",
            generation_path.display()
        );
        assert!(
            generation.contains(&format!("\"n_proofs\": {}", fixture.expected_n)),
            "{} has the wrong proof count",
            generation_path.display()
        );
        assert!(
            generation.contains(&format!(
                "\"outer_public_variables_including_one_wire\": {}",
                fixture.expected_public_variables_including_one
            )),
            "{} has the wrong public-variable count",
            generation_path.display()
        );
        assert!(
            generation.contains("\"outer_bsb22_commitments\": 1")
                && generation.contains("\"measurement_ready\": true")
                && generation.contains("\"deterministic_public_toxic_waste\": false"),
            "{} is not a measurement-ready secure one-commitment export",
            generation_path.display()
        );

        let payload = std::fs::read(&payload_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", payload_path.display()));
        assert_eq!(
            payload.len(),
            fixture.expected_payload_bytes,
            "{} has the wrong exact payload length",
            payload_path.display()
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&payload)),
            fixture.expected_payload_sha256,
            "{} does not match the freshly generated sealed payload",
            payload_path.display()
        );

        let vk_bytes = std::fs::read(&vk_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", vk_path.display()));
        let vk_sha256 = format!("{:x}", Sha256::digest(&vk_bytes));
        assert_eq!(
            vk_sha256,
            fixture.expected_vk_sha256,
            "{} does not match the freshly generated sealed outer VK",
            vk_path.display()
        );
        println!("cargo:rustc-env={}={vk_sha256}", fixture.digest_environment);

        generate_bsb22_vk_file(
            &vk_path,
            &output,
            &format!("{}.rs", fixture.directory.replace('-', "_")),
            fixture.symbol,
        )
        .unwrap_or_else(|error| {
            panic!(
                "generate {} from {}: {error:?}",
                fixture.symbol,
                vk_path.display()
            )
        });
    }
}
