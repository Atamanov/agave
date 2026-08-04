//! Fixed-vector checks for all BN254 batch syscalls.

use {
    solana_bn254::prelude::{alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be},
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodG2Point, PodPlonkReductionContext, PodPlonkReductionInput,
        PodScalar, PodSnarkjsPlonkMultiVkContext, PodSnarkjsPlonkMultiVkInput,
        PodSnarkjsPlonkReductionContext, PodSnarkjsPlonkReductionInput, Version,
        alt_bn128_fr_batch_invert, alt_bn128_fr_lincomb, alt_bn128_g1_msm, alt_bn128_pairing_check,
        alt_bn128_pairing_map, alt_bn128_plonk_batch_reduce, alt_bn128_snarkjs_plonk_batch_reduce,
        alt_bn128_snarkjs_plonk_multi_vk_batch_reduce, plonk_reduction_output_count,
        snarkjs_plonk_multi_vk_output_count,
    },
    solana_msg::msg,
    solana_program_entrypoint::{custom_heap_default, custom_panic_default},
    solana_sha256_hasher::hash,
};

fn g1_points(bytes: &[u8]) -> Vec<PodG1Point> {
    bytes
        .chunks_exact(64)
        .map(|c| PodG1Point(c.try_into().unwrap()))
        .collect()
}

fn scalars(bytes: &[u8]) -> Vec<PodScalar> {
    bytes
        .chunks_exact(32)
        .map(|c| PodScalar(c.try_into().unwrap()))
        .collect()
}

fn pairs(bytes: &[u8]) -> Vec<PodG1G2Pair> {
    bytes
        .chunks_exact(192)
        .map(|c| PodG1G2Pair {
            g1: PodG1Point(c[..64].try_into().unwrap()),
            g2: solana_bn254_batch_syscall::PodG2Point(c[64..].try_into().unwrap()),
        })
        .collect()
}

const G1_GENERATOR_BE: &str = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
// r - 1 for the BN254 scalar field, big-endian
const FR_MAX_BE: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
const PLONK_OMEGA_8_BE: &str = "2b337de1c8c14f22ec9b9e2f96afef3652627366f8170a0a948dad4ac1bd5e80";
const PLONK_OUTPUT_DIGESTS: [&str; 3] = [
    "d0df536b1747dbd7aa51cf5bea0b8f0c414d4370b5fd2a8e705dd238cdfdaacf",
    "f025a54f60400c89b216520464a878d6152b4581ccad15c383223cfc9191d584",
    "0ab3a0a371075d6e0c5b132379e6ff67be62094ffc4df59dc98b5d74378fe561",
];
// on the twist curve, not in the r-order subgroup (x = (1, 0), greatest y)
const NON_SUBGROUP_G2_BE: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012351dcdda257b62181cbd745dfee16d5fdf4eb185bbcf33c20a0fe6eaa9cb4a307fb3d558dafafb6bf6dd326a5fefe0beca3f9ac3bd999a390d504fad34b0b8c";
// the "jeff1" test vector (two pairs, product == 1)
const TRUE_PAIRS: &str = "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn g1_msm_matches_composed_group_ops() {
    // [2]G + [3]G via the MSM must equal mul+mul+add via the group op
    let generator = hex(G1_GENERATOR_BE);
    let points = [generator.clone(), generator.clone()].concat();
    let mut scalar_bytes = vec![0u8; 64];
    scalar_bytes[31] = 2;
    scalar_bytes[63] = 3;

    let mul = |scalar_byte: u8| {
        let mut input = generator.clone();
        let mut scalar = [0u8; 32];
        scalar[31] = scalar_byte;
        input.extend_from_slice(&scalar);
        alt_bn128_g1_multiplication_be(&input).unwrap()
    };
    let expected = alt_bn128_g1_addition_be(&[mul(2), mul(3)].concat()).unwrap();

    let result =
        alt_bn128_g1_msm(Version::V0, &g1_points(&points), &scalars(&scalar_bytes)).unwrap();
    assert_eq!(result.0.as_slice(), expected.as_slice());
}

fn g1_msm_rejects_empty_input() {
    assert!(alt_bn128_g1_msm(Version::V0, &[], &[]).is_err());
}

fn pairing_check_verdicts() {
    let true_pairs = hex(TRUE_PAIRS);
    let mut gt_identity = [0u8; 384];
    gt_identity[31] = 1;
    assert!(
        alt_bn128_pairing_check(Version::V0, &pairs(&true_pairs)).unwrap(),
        "known-good vector must verify"
    );
    assert_eq!(
        alt_bn128_pairing_map(Version::V0, &pairs(&true_pairs))
            .unwrap()
            .0,
        gt_identity,
        "known-good product must return canonical GT identity"
    );

    // negate the first G1 point (multiply by r - 1): the verdict flips to false,
    // which is a value and NOT an error
    let mut mul_input = true_pairs[..64].to_vec();
    mul_input.extend_from_slice(&hex(FR_MAX_BE));
    let negated = alt_bn128_g1_multiplication_be(&mul_input).unwrap();
    let mut false_pairs = true_pairs;
    false_pairs[..64].copy_from_slice(&negated);
    assert!(!alt_bn128_pairing_check(Version::V0, &pairs(&false_pairs)).unwrap());
    assert_ne!(
        alt_bn128_pairing_map(Version::V0, &pairs(&false_pairs))
            .unwrap()
            .0,
        gt_identity,
        "nonidentity product must remain distinguishable in canonical GT"
    );
}

fn pairing_check_rejects_non_subgroup_g2() {
    let pair = [hex(G1_GENERATOR_BE), hex(NON_SUBGROUP_G2_BE)].concat();
    assert!(alt_bn128_pairing_check(Version::V0, &pairs(&pair)).is_err());
}

fn pairing_check_rejects_zero_pairs() {
    assert!(alt_bn128_pairing_check(Version::V0, &[]).is_err());
}

fn fr_lincomb_inner_product() {
    // <[2, 3], [5, 7]> = 10 + 21 = 31
    let mut a = [0u8; 64];
    a[31] = 2;
    a[63] = 3;
    let mut b = [0u8; 64];
    b[31] = 5;
    b[63] = 7;
    let result = alt_bn128_fr_lincomb(Version::V0, &scalars(&a), &scalars(&b)).unwrap();
    let mut expected = [0u8; 32];
    expected[31] = 31;
    assert_eq!(result.0, expected);

    // empty is a domain error, not a vacuous zero
    assert!(alt_bn128_fr_lincomb(Version::V0, &[], &[]).is_err());
}

fn fr_batch_invert_roundtrip() {
    // invert [1, 2] then invert the result: back to [1, 2]
    let mut a = [0u8; 64];
    a[31] = 1;
    a[63] = 2;
    let inv = alt_bn128_fr_batch_invert(Version::V0, &scalars(&a)).unwrap();
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(inv[0].0, one, "1^-1 == 1");
    let back = alt_bn128_fr_batch_invert(Version::V0, &inv).unwrap();
    assert_eq!(back, scalars(&a), "inverting twice is the identity");

    // a zero element is a domain error
    assert!(alt_bn128_fr_batch_invert(Version::V0, &scalars(&[0u8; 64])).is_err());
}

fn scalar(value: u8) -> PodScalar {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    PodScalar(bytes)
}

fn plonk_context() -> PodPlonkReductionContext {
    PodPlonkReductionContext {
        domain_size_be: 8u64.to_be_bytes(),
        num_public_inputs_be: 1u32.to_be_bytes(),
        reserved: [0u8; 4],
        omega: PodScalar(hex(PLONK_OMEGA_8_BE).try_into().unwrap()),
        k1: scalar(2),
        k2: scalar(3),
    }
}

fn plonk_input(seed: u8) -> PodPlonkReductionInput {
    PodPlonkReductionInput {
        challenge_digests: core::array::from_fn(|index| {
            scalar(seed.saturating_add(u8::try_from(index).unwrap_or(u8::MAX))).0
        }),
        evaluations: core::array::from_fn(|index| {
            scalar(
                seed.saturating_add(11)
                    .saturating_add(u8::try_from(index).unwrap_or(u8::MAX)),
            )
        }),
        rho: scalar(seed.saturating_add(1)),
    }
}

fn snarkjs_context(seed: u8) -> PodSnarkjsPlonkReductionContext {
    PodSnarkjsPlonkReductionContext {
        domain_size_be: 8u64.to_be_bytes(),
        num_public_inputs_be: 1u32.to_be_bytes(),
        reserved: [0u8; 4],
        omega: PodScalar(hex(PLONK_OMEGA_8_BE).try_into().unwrap()),
        k1: scalar(2),
        k2: scalar(3),
        transcript_vk_points: core::array::from_fn(|index| {
            let mut bytes = [0u8; 64];
            bytes[31] = seed;
            bytes[63] = u8::try_from(index).unwrap_or(u8::MAX).saturating_add(1);
            PodG1Point(bytes)
        }),
        x_2: {
            let mut bytes = [0u8; 128];
            bytes[31] = seed;
            bytes[127] = 42;
            PodG2Point(bytes)
        },
    }
}

fn snarkjs_input(seed: u8) -> PodSnarkjsPlonkReductionInput {
    PodSnarkjsPlonkReductionInput {
        transcript_points: core::array::from_fn(|index| {
            let mut bytes = [0u8; 64];
            bytes[31] = seed;
            bytes[63] = u8::try_from(index).unwrap_or(u8::MAX).saturating_add(1);
            PodG1Point(bytes)
        }),
        evaluations: core::array::from_fn(|index| {
            scalar(
                seed.saturating_add(11)
                    .saturating_add(u8::try_from(index).unwrap_or(u8::MAX)),
            )
        }),
    }
}

fn plonk_reducer_outputs() -> [Vec<PodScalar>; 3] {
    let public_inputs = [scalar(101)];
    let synthetic = alt_bn128_plonk_batch_reduce(
        Version::V0,
        &plonk_context(),
        &[plonk_input(7)],
        &public_inputs,
    )
    .unwrap();
    let canonical = alt_bn128_snarkjs_plonk_batch_reduce(
        Version::V0,
        &snarkjs_context(7),
        &[snarkjs_input(11)],
        &public_inputs,
    )
    .unwrap();
    let contexts = [PodSnarkjsPlonkMultiVkContext {
        context_index_be: 0u32.to_be_bytes(),
        reserved: [0u8; 4],
        application_context: [9u8; 32],
        reduction: snarkjs_context(9),
        g2_gen: {
            let mut bytes = [0u8; 128];
            bytes[0] = 9;
            bytes[127] = 1;
            PodG2Point(bytes)
        },
    }];
    let inputs = [PodSnarkjsPlonkMultiVkInput {
        proof_index_be: 0u32.to_be_bytes(),
        context_index_be: 0u32.to_be_bytes(),
        proof: snarkjs_input(13),
    }];
    let multi = alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
        Version::V0,
        &contexts,
        &inputs,
        &public_inputs,
    )
    .unwrap();
    [synthetic, canonical, multi]
}

fn scalar_digest(values: &[PodScalar]) -> [u8; 32] {
    let bytes: Vec<u8> = values.iter().flat_map(|value| value.0).collect();
    hash(&bytes).to_bytes()
}

fn plonk_reducers_match_fixed_outputs() {
    let [synthetic, canonical, multi] = plonk_reducer_outputs();
    assert_eq!(synthetic.len(), plonk_reduction_output_count(1).unwrap());
    assert_eq!(canonical.len(), plonk_reduction_output_count(1).unwrap());
    assert_eq!(
        multi.len(),
        snarkjs_plonk_multi_vk_output_count(1, 1).unwrap()
    );
    for (values, expected) in [
        (synthetic.as_slice(), PLONK_OUTPUT_DIGESTS[0]),
        (canonical.as_slice(), PLONK_OUTPUT_DIGESTS[1]),
        (multi.as_slice(), PLONK_OUTPUT_DIGESTS[2]),
    ] {
        assert_eq!(scalar_digest(values).as_slice(), hex(expected));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn plonk_outputs_match() {
        super::plonk_reducers_match_fixed_outputs();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn entrypoint(_input: *mut u8) -> u64 {
    msg!("alt_bn128_batch");

    g1_msm_matches_composed_group_ops();
    g1_msm_rejects_empty_input();
    pairing_check_verdicts();
    pairing_check_rejects_non_subgroup_g2();
    pairing_check_rejects_zero_pairs();
    fr_lincomb_inner_product();
    fr_batch_invert_roundtrip();
    plonk_reducers_match_fixed_outputs();

    0
}

custom_heap_default!();
custom_panic_default!();
