//! On-chain verification of the fixed-statement-v3 PLONK recursive outer
//! proofs generated from the campaign's canonical snarkjs test exceptions.
//!
//! The outer proofs are genuine OS-random gnark Groth16/BSB22 proofs. Each
//! selected VK is compiled into the guest. Verification converts the one
//! committed proof into the Agave batch representation and ends in exactly
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

mod vk_n2 {
    include!(concat!(env!("OUT_DIR"), "/n2_secure.rs"));
}
mod vk_n3 {
    include!(concat!(env!("OUT_DIR"), "/n3_secure.rs"));
}

pub use {vk_n2::VK_N2_SECURE, vk_n3::VK_N3_SECURE};

pub mod tag {
    /// Verify the exact payload held by account 0. Its exact length selects
    /// the sealed n=2 or n=3 outer VK; callers cannot supply a VK.
    pub const VERIFY: u8 = 0;
}

pub mod layout {
    pub const PROOF_BYTES: usize = 64 + 128 + 64;
    pub const COMMITMENT_BYTES: usize = 64 + 64;
    pub const HEADER_BYTES: usize = PROOF_BYTES + COMMITMENT_BYTES;
    pub const N2_PUBLIC_INPUTS: usize = 4;
    pub const N3_PUBLIC_INPUTS: usize = 7;
    pub const N2_PAYLOAD_BYTES: usize = HEADER_BYTES + N2_PUBLIC_INPUTS * 32;
    pub const N3_PAYLOAD_BYTES: usize = HEADER_BYTES + N3_PUBLIC_INPUTS * 32;
}

fn read<const N: usize>(data: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    let value = data.get(*offset..end)?.try_into().ok()?;
    *offset = end;
    Some(value)
}

// BN254 base-field modulus, big-endian.
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

/// Negate a G2 point encoded as `x1 | x0 | y1 | y0`.
fn negate_g2_be(g2: &[u8; 128]) -> [u8; 128] {
    let mut out = *g2;
    for offset in [64usize, 96] {
        let limb: &[u8; 32] = g2[offset..offset + 32].try_into().expect("fixed limb");
        out[offset..offset + 32].copy_from_slice(&fq_neg_be(limb));
    }
    out
}

/// Convert gnark's commitment-key convention to the B5 verifier convention.
/// gnark stores `(g2, -[sigma]g2)`; the folded PoK equation uses
/// `([sigma]g2, g2)` beside `(com, -pok)`.
fn vk_from_gnark(vk: &Groth16Verifyingkey<'_>) -> Option<ValidatedVerifyingKey> {
    let pedersen = vk.vk_commitment.as_ref().map(|commitment| PedersenKey {
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

/// Verify one exact uncompressed recursive payload.
///
/// Layout: `A(64) | B(128) | C(64) | commitment(64) | PoK(64) |
/// explicit_public_inputs(N*32)`. The commitment-derived BSB22 hash scalar is
/// recomputed inside the guest and appended as gnark's trailing K-column wire.
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
    )));

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
        2 => verify_payload::<4>(data, &VK_N2_SECURE),
        3 => verify_payload::<7>(data, &VK_N3_SECURE),
        _ => None,
    }
}

/// Entrypoint-facing dispatch. The instruction tag is strategy-only; the
/// exact payload length selects one of the two compiled, digest-sealed VKs.
pub fn verify_account_payload(data: &[u8]) -> Option<bool> {
    match data.len() {
        layout::N2_PAYLOAD_BYTES => {
            verify_payload::<{ layout::N2_PUBLIC_INPUTS }>(data, &VK_N2_SECURE)
        }
        layout::N3_PAYLOAD_BYTES => {
            verify_payload::<{ layout::N3_PUBLIC_INPUTS }>(data, &VK_N3_SECURE)
        }
        _ => None,
    }
}

pub fn compiled_outer_vk_sha256(selector: u8) -> Option<&'static str> {
    match selector {
        2 => Some(env!("HELIOS_PLONK_N2_OUTER_VK_SHA256")),
        3 => Some(env!("HELIOS_PLONK_N3_OUTER_VK_SHA256")),
        _ => None,
    }
}

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
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    // The research observer is process-global. Serialize verification tests
    // so the mutation suite cannot interleave syscall events with the exact
    // shape assertion when Rust's test harness uses multiple threads.
    static VERIFICATION_LOCK: Mutex<()> = Mutex::new(());

    fn fixture_root() -> PathBuf {
        std::env::var_os("HELIOS_PLONK_RECURSION_FIXTURE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fixed-statement-v3")
            })
    }

    fn scenario_directory(selector: u8) -> &'static str {
        match selector {
            2 => "n2-secure",
            3 => "n3-secure",
            _ => panic!("unknown selector"),
        }
    }

    fn fixture_file(selector: u8, name: &str) -> Vec<u8> {
        std::fs::read(fixture_root().join(scenario_directory(selector)).join(name))
            .unwrap_or_else(|error| panic!("read selector={selector} {name}: {error}"))
    }

    #[test]
    fn exact_v3_payloads_verify_and_mutations_fail() {
        let _guard = VERIFICATION_LOCK.lock().expect("verification test lock");
        for selector in [2u8, 3] {
            let generation = fixture_file(selector, "generation.json");
            let generation = std::str::from_utf8(&generation).expect("generation JSON UTF-8");
            assert!(generation.contains(
                "\"schema\": \"helios.genuine-snarkjs-plonk-recursion.secure-os-random.fixed-statement.v3\""
            ));
            assert!(generation.contains("\"measurement_ready\": true"));

            let data = fixture_file(selector, "payload_unnegated_a.bin");
            assert_eq!(verify_scenario(selector, &data), Some(true));
            assert_eq!(verify_account_payload(&data), Some(true));

            // Every proof/BSB22 component is covered, followed by every
            // explicit public input (including the fixed statement scalar).
            for offset in [0usize, 64, 192, 256, 320] {
                let mut corrupted = data.clone();
                corrupted[offset] ^= 1;
                assert_ne!(
                    verify_scenario(selector, &corrupted),
                    Some(true),
                    "selector={selector}, mutated offset={offset}"
                );
            }
            let explicit_publics = if selector == 2 { 4 } else { 7 };
            for public_index in 0..explicit_publics {
                let mut corrupted = data.clone();
                corrupted[384 + 32 * public_index] ^= 1;
                assert_ne!(
                    verify_scenario(selector, &corrupted),
                    Some(true),
                    "selector={selector}, public={public_index}"
                );
            }
            assert_eq!(verify_scenario(0, &data), None);
            assert_eq!(verify_scenario(selector, &data[..data.len() - 1]), None);
            assert_eq!(verify_account_payload(&data[..data.len() - 1]), None);
            let mut trailing = data;
            trailing.push(0);
            assert_eq!(verify_scenario(selector, &trailing), None);
        }
    }

    #[cfg(feature = "research-observer")]
    #[test]
    fn exact_outer_operation_shapes_are_one_six_pair_check() {
        use solana_bn254_batch_syscall::research_observer;

        let _guard = VERIFICATION_LOCK.lock().expect("verification test lock");
        #[cfg(feature = "backend-b5-helios-ifma")]
        assert!(solana_bn254_batch_syscall::selected_backend_compiled_with_avx512_ifma());
        for (selector, expected_gamma_msm) in [(2u8, 7u64), (3, 10)] {
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
            assert_eq!(research_observer::observed_standalone_probe_calls(), (0, 0));
        }
    }

    #[test]
    fn compiled_vk_seals_match_fresh_v3_generation() {
        assert_eq!(
            compiled_outer_vk_sha256(2),
            Some("0ab7160a5df8ac73ee8e0bdfb4e30867ff5219e1de484d41f78a89c10b311ed7")
        );
        assert_eq!(
            compiled_outer_vk_sha256(3),
            Some("32cf5f71d4d462e930745414a7fea30cb19cd0a42a3242225b3aba8e6bf70d81")
        );
    }
}
