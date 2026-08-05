//! B5 verification of genuine recursive outer proofs over authenticated real
//! Zolana Groth16 statements.
//!
//! The three OS-random gnark Groth16/BSB22 outer VKs are generated into this
//! guest from digest-sealed compact artifacts. Each payload ends in exactly
//! one six-pair B5 check: one final exponentiation and six G2 subgroup checks.

#![cfg_attr(target_os = "solana", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use groth16_solana::groth16::Groth16Verifyingkey;
use solana_bn254_batch_syscall::{PodG1Point, PodG2Point, PodScalar};
use solana_bn254_groth16_batch::{
    PedersenKey, Proof, ProofCommitment, RandomizerMode, ValidatedVerifyingKey, VerifyingKey,
    Version, groth16_batch_verify,
};

mod hash_to_field;
use hash_to_field::hash_to_field_bn254_fr;

mod vk_g2 {
    include!(concat!(env!("OUT_DIR"), "/n2_distinct.rs"));
}
mod vk_g3 {
    include!(concat!(env!("OUT_DIR"), "/n3_distinct.rs"));
}
mod vk_g5 {
    include!(concat!(env!("OUT_DIR"), "/n5_same.rs"));
}

pub use {vk_g2::VK_G2, vk_g3::VK_G3, vk_g5::VK_G5};

pub mod tag {
    pub const VERIFY: u8 = 0;
}

pub mod layout {
    pub const PROOF_BYTES: usize = 64 + 128 + 64;
    pub const COMMITMENT_BYTES: usize = 64 + 64;
    pub const HEADER_BYTES: usize = PROOF_BYTES + COMMITMENT_BYTES;
    pub const G2_PUBLIC_INPUTS: usize = 3;
    pub const G3_PUBLIC_INPUTS: usize = 4;
    pub const G5_PUBLIC_INPUTS: usize = 6;
    pub const G2_PAYLOAD_BYTES: usize = HEADER_BYTES + G2_PUBLIC_INPUTS * 32;
    pub const G3_PAYLOAD_BYTES: usize = HEADER_BYTES + G3_PUBLIC_INPUTS * 32;
    pub const G5_PAYLOAD_BYTES: usize = HEADER_BYTES + G5_PUBLIC_INPUTS * 32;
}

fn read<const N: usize>(data: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let value = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(value)
}

const FQ_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

fn fq_neg_be(a: &[u8; 32]) -> [u8; 32] {
    if a == &[0u8; 32] {
        return [0u8; 32];
    }
    let mut out = [0u8; 32];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let lhs = u16::from(FQ_MODULUS_BE[i]);
        let rhs = u16::from(a[i]) + borrow;
        let (value, next_borrow) = if lhs >= rhs {
            (lhs - rhs, 0)
        } else {
            (lhs + 0x100 - rhs, 1)
        };
        out[i] = value as u8;
        borrow = next_borrow;
    }
    out
}

fn negate_g2_be(g2: &[u8; 128]) -> [u8; 128] {
    let mut out = *g2;
    for offset in [64usize, 96] {
        let limb: &[u8; 32] = g2[offset..offset + 32].try_into().expect("fixed limb");
        out[offset..offset + 32].copy_from_slice(&fq_neg_be(limb));
    }
    out
}

fn vk_from_gnark(vk: &Groth16Verifyingkey<'_>) -> Option<ValidatedVerifyingKey> {
    let pedersen = vk.vk_commitment.as_ref().map(|commitment| PedersenKey {
        // gnark's key is `(g2, -[sigma]g2)`. The B5 fold uses
        // `([sigma]g2, g2)` with the PoK point negated in its MSM.
        g2: PodG2Point(negate_g2_be(&commitment.g_sigma_neg_g2)),
        sigma_g2: PodG2Point(commitment.g2),
    });
    VerifyingKey {
        alpha_g1: PodG1Point(vk.vk_alpha_g1),
        beta_g2: PodG2Point(vk.vk_beta_g2),
        gamma_g2: PodG2Point(vk.vk_gamma_g2),
        delta_g2: PodG2Point(vk.vk_delta_g2),
        ic: vk.vk_ic.iter().copied().map(PodG1Point).collect(),
        pedersen,
    }
    .trust()
    .ok()
}

/// Exact payload: `A | B | C | commitment | PoK | explicit publics`.
/// `A` is the unnegated outer Groth16 point. The BSB22 commitment-derived
/// hash wire is recomputed and appended inside the verifier.
pub fn verify_payload<const N: usize>(data: &[u8], vk: &Groth16Verifyingkey<'_>) -> Option<bool> {
    if data.len() != layout::HEADER_BYTES + N * 32
        || vk.nr_pubinputs != N
        || vk.vk_commitment.is_none()
        || vk.vk_ic.len() != N + 2
    {
        return None;
    }
    let mut offset = 0usize;
    let a = read::<64>(data, &mut offset)?;
    let b = read::<128>(data, &mut offset)?;
    let c = read::<64>(data, &mut offset)?;
    let commitment = read::<64>(data, &mut offset)?;
    let pok = read::<64>(data, &mut offset)?;
    let mut public_inputs = Vec::with_capacity(N + 1);
    for _ in 0..N {
        public_inputs.push(PodScalar(read::<32>(data, &mut offset)?));
    }
    if offset != data.len() {
        return None;
    }
    public_inputs.push(PodScalar(hash_to_field_bn254_fr(
        &commitment,
        b"bsb22-commitment",
    )?));

    let key = vk_from_gnark(vk)?;
    let proof = Proof {
        vk_index: 0,
        a: PodG1Point(a),
        b: PodG2Point(b),
        c: PodG1Point(c),
        commitment: Some(ProofCommitment {
            com: PodG1Point(commitment),
            pok: PodG1Point(pok),
        }),
        public_inputs,
    };
    groth16_batch_verify(Version::V0, &[key], &[proof], RandomizerMode::Independent).ok()
}

pub fn verify_scenario(selector: u8, data: &[u8]) -> Option<bool> {
    match selector {
        2 => verify_payload::<{ layout::G2_PUBLIC_INPUTS }>(data, &VK_G2),
        3 => verify_payload::<{ layout::G3_PUBLIC_INPUTS }>(data, &VK_G3),
        5 => verify_payload::<{ layout::G5_PUBLIC_INPUTS }>(data, &VK_G5),
        _ => None,
    }
}

pub fn verify_account_payload(data: &[u8]) -> Option<bool> {
    match data.len() {
        layout::G2_PAYLOAD_BYTES => verify_payload::<{ layout::G2_PUBLIC_INPUTS }>(data, &VK_G2),
        layout::G3_PAYLOAD_BYTES => verify_payload::<{ layout::G3_PUBLIC_INPUTS }>(data, &VK_G3),
        layout::G5_PAYLOAD_BYTES => verify_payload::<{ layout::G5_PUBLIC_INPUTS }>(data, &VK_G5),
        _ => None,
    }
}

pub fn compiled_outer_vk_sha256(selector: u8) -> Option<&'static str> {
    match selector {
        2 => Some(env!("HELIUS_GROTH_G2_OUTER_VK_SHA256")),
        3 => Some(env!("HELIUS_GROTH_G3_OUTER_VK_SHA256")),
        5 => Some(env!("HELIUS_GROTH_G5_OUTER_VK_SHA256")),
        _ => None,
    }
}

pub fn compiled_payload_sha256(selector: u8) -> Option<&'static str> {
    match selector {
        2 => Some(env!("HELIUS_GROTH_G2_PAYLOAD_SHA256")),
        3 => Some(env!("HELIUS_GROTH_G3_PAYLOAD_SHA256")),
        5 => Some(env!("HELIUS_GROTH_G5_PAYLOAD_SHA256")),
        _ => None,
    }
}

pub const COMPILED_COMPACT_MANIFEST_SHA256: &str = env!("HELIUS_GROTH_RECURSION_MANIFEST_SHA256");

#[cfg(all(target_os = "solana", feature = "bpf-entrypoint"))]
mod entrypoint {
    use pinocchio::{AccountView, Address, ProgramResult, entrypoint, error::ProgramError};

    entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if instruction_data != [super::tag::VERIFY] {
            return Err(ProgramError::InvalidInstructionData);
        }
        let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        let data = account
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        match super::verify_account_payload(&data) {
            Some(true) => Ok(()),
            Some(false) => Err(ProgramError::Custom(1)),
            None => Err(ProgramError::InvalidAccountData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        path::{Path, PathBuf},
        sync::Mutex,
    };

    static VERIFICATION_LOCK: Mutex<()> = Mutex::new(());

    fn fixture_root() -> PathBuf {
        std::env::var_os("HELIUS_GROTH_RECURSION_FIXTURE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../research/bn254-decision-table-v2-20260804/recursion-v2")
            })
    }

    fn scenario_directory(selector: u8) -> &'static str {
        match selector {
            2 => "n2-distinct",
            3 => "n3-distinct",
            5 => "n5-same",
            _ => panic!("unknown selector"),
        }
    }

    fn fixture_file(selector: u8, name: &str) -> Vec<u8> {
        std::fs::read(fixture_root().join(scenario_directory(selector)).join(name))
            .unwrap_or_else(|error| panic!("read selector={selector} {name}: {error}"))
    }

    fn public_count(selector: u8) -> usize {
        match selector {
            2 => layout::G2_PUBLIC_INPUTS,
            3 => layout::G3_PUBLIC_INPUTS,
            5 => layout::G5_PUBLIC_INPUTS,
            _ => panic!("unknown selector"),
        }
    }

    #[test]
    fn exact_real_zolana_payloads_and_mutations() {
        let _guard = VERIFICATION_LOCK.lock().expect("verification test lock");
        for selector in [2u8, 3, 5] {
            let generation = fixture_file(selector, "generation.json");
            let generation = std::str::from_utf8(&generation).expect("generation UTF-8");
            assert!(generation.contains(
                "\"schema\": \"helios.gnark-bn254-recursion.secure-os-random.imported-zolana-statement.v4\""
            ));
            assert!(generation.contains("\"exact_inner_proof_equality_constrained\": true"));
            assert!(generation.contains("\"all_inner_proofs_host_verified\": true"));
            assert!(generation.contains("\"outer_proof_host_verified\": true"));

            let data = fixture_file(selector, "payload_unnegated_a.bin");
            assert_eq!(verify_scenario(selector, &data), Some(true));
            assert_eq!(verify_account_payload(&data), Some(true));

            // Proof A/B/C and the two BSB22 proof components.
            for offset in [0usize, 64, 192, 256, 320] {
                let mut changed = data.clone();
                changed[offset] ^= 1;
                assert_ne!(
                    verify_scenario(selector, &changed),
                    Some(true),
                    "selector={selector}, proof offset={offset}"
                );
            }

            // Application public and fixed statement public are distinct
            // negative categories. The checked-in statement file must equal
            // the final payload scalar before the mutation is attempted.
            let mut changed_public = data.clone();
            changed_public[layout::HEADER_BYTES] ^= 1;
            assert_ne!(verify_scenario(selector, &changed_public), Some(true));

            let statement = fixture_file(selector, "statement_commitment_fr.bin");
            assert_eq!(&data[data.len() - 32..], statement.as_slice());
            let mut changed_statement = data.clone();
            let last = changed_statement.len() - 32;
            changed_statement[last] ^= 1;
            assert_ne!(verify_scenario(selector, &changed_statement), Some(true));

            for public_index in 0..public_count(selector) {
                let mut changed = data.clone();
                changed[layout::HEADER_BYTES + 32 * public_index] ^= 1;
                assert_ne!(
                    verify_scenario(selector, &changed),
                    Some(true),
                    "selector={selector}, public={public_index}"
                );
            }
            assert_eq!(verify_scenario(0, &data), None);
            assert_eq!(verify_account_payload(&data[..data.len() - 1]), None);
            let mut trailing = data;
            trailing.push(0);
            assert_eq!(verify_account_payload(&trailing), None);
        }
    }

    #[cfg(feature = "research-observer")]
    #[test]
    fn exact_outer_operation_shapes_are_one_six_pair_check() {
        use solana_bn254_batch_syscall::research_observer;

        let _guard = VERIFICATION_LOCK.lock().expect("verification test lock");
        #[cfg(feature = "backend-b5-helius-ifma")]
        assert!(solana_bn254_batch_syscall::selected_backend_compiled_with_avx512_ifma());
        for (selector, expected_gamma_msm) in [(2u8, 6u64), (3, 7), (5, 9)] {
            research_observer::reset();
            let data = fixture_file(selector, "payload_unnegated_a.bin");
            assert_eq!(verify_scenario(selector, &data), Some(true));
            assert_eq!(
                research_observer::observed_pairing_check_shapes(),
                vec![(6, 6)]
            );
            assert_eq!(
                research_observer::observed_g1_msm_point_count_list(),
                vec![1, 1, expected_gamma_msm, 1, 1, 1]
            );
            assert!(research_observer::observed_pairing_map_shapes().is_empty());
            assert!(research_observer::observed_registered_pairing_shapes().is_empty());
        }
    }

    /// The BSB22 wire is a challenge, so a reduction that differs from the
    /// arkworks original on any real commitment binds the proof to another
    /// statement while still verifying.
    #[test]
    fn bsb22_reduction_is_byte_identical_on_every_real_commitment() {
        use ark_ff::PrimeField;

        for selector in [2u8, 3, 5] {
            let data = fixture_file(selector, "payload_unnegated_a.bin");
            let commitment: [u8; 64] = data[layout::PROOF_BYTES..layout::PROOF_BYTES + 64]
                .try_into()
                .expect("commitment slice");
            let digest =
                hash_to_field::expand_message_xmd_sha256_l48(&commitment, b"bsb22-commitment");
            let mut le = digest;
            le.reverse();
            let limbs = ark_bn254::Fr::from_le_bytes_mod_order(&le).into_bigint().0;
            let mut expected = [0u8; 32];
            for (chunk, limb) in expected.chunks_exact_mut(8).zip(limbs.iter().rev()) {
                chunk.copy_from_slice(&limb.to_be_bytes());
            }
            assert_eq!(
                hash_to_field::reduce_be_384(&digest),
                Some(expected),
                "selector={selector}"
            );
        }
    }

    #[test]
    fn compiled_seals_match_compact_manifest_and_files() {
        assert_eq!(
            COMPILED_COMPACT_MANIFEST_SHA256,
            "4d2d2e40408e481c543ace25276e42a34b6980d3de4fd622277ca0b0459f5cdd"
        );
        for selector in [2u8, 3, 5] {
            let payload = fixture_file(selector, "payload_unnegated_a.bin");
            assert_eq!(
                compiled_payload_sha256(selector),
                Some(format!("{:x}", Sha256::digest(payload)).as_str())
            );
        }
        assert_eq!(
            compiled_outer_vk_sha256(2),
            Some("2a6fda1a4be28af88044e181e59c4ea0cc23ba5f1e35c0958baaa504174ee416")
        );
        assert_eq!(
            compiled_outer_vk_sha256(3),
            Some("ef5786d016d67e10bc5290ff62de65a18b67ca3a1627022a11a4eed557f8cc8a")
        );
        assert_eq!(
            compiled_outer_vk_sha256(5),
            Some("a265ecefc4f5da6c9b9c433b4ab083462908749784692cd74b807fd59621f9f4")
        );
    }
}
