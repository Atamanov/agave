//! Alt_bn128 batch syscalls tests: `sol_alt_bn128_g1_msm`,
//! `sol_alt_bn128_pairing_check`, `sol_alt_bn128_fr_lincomb`, and
//! `sol_alt_bn128_fr_batch_invert`.

use {
    solana_bn254::prelude::{alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be},
    solana_define_syscall::define_syscall,
    solana_msg::msg,
    solana_program_entrypoint::{custom_heap_default, custom_panic_default},
};

// declared locally until the published solana-define-syscall ships them
define_syscall!(fn sol_alt_bn128_g1_msm(num_points: u64, points_addr: *const u8, scalars_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_pairing_check(num_pairs: u64, pairs_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_fr_lincomb(num_elems: u64, a_addr: *const u8, b_addr: *const u8, result_addr: *mut u8) -> u64);
define_syscall!(fn sol_alt_bn128_fr_batch_invert(num_elems: u64, a_addr: *const u8, result_addr: *mut u8) -> u64);

// the syscall results as their own types, mirroring the host-side pods; the
// arkworks-backed batch crate cannot come to the solana target, so the byte
// newtypes are declared locally alongside the syscall stubs
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodG1Point([u8; 64]);
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodPairingResult([u8; 32]);

impl PodPairingResult {
    fn verdict(&self) -> bool {
        self.0[31] == 1
    }
}

const G1_GENERATOR_BE: &str = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";
// r - 1 for the BN254 scalar field, big-endian
const FR_MAX_BE: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
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

fn g1_msm(num_points: u64, points: &[u8], scalars: &[u8]) -> (u64, PodG1Point) {
    let mut result = PodG1Point([0u8; 64]);
    let code = unsafe {
        sol_alt_bn128_g1_msm(
            num_points,
            points.as_ptr(),
            scalars.as_ptr(),
            result.0.as_mut_ptr(),
        )
    };
    (code, result)
}

fn pairing_check(num_pairs: u64, pairs: &[u8]) -> (u64, PodPairingResult) {
    let mut result = PodPairingResult([0u8; 32]);
    let code =
        unsafe { sol_alt_bn128_pairing_check(num_pairs, pairs.as_ptr(), result.0.as_mut_ptr()) };
    (code, result)
}

fn fr_lincomb(num_elems: u64, a: &[u8], b: &[u8]) -> (u64, [u8; 32]) {
    let mut result = [0u8; 32];
    let code = unsafe {
        sol_alt_bn128_fr_lincomb(num_elems, a.as_ptr(), b.as_ptr(), result.as_mut_ptr())
    };
    (code, result)
}

fn fr_batch_invert(num_elems: u64, a: &[u8], out: &mut [u8]) -> u64 {
    unsafe { sol_alt_bn128_fr_batch_invert(num_elems, a.as_ptr(), out.as_mut_ptr()) }
}

fn g1_msm_matches_composed_group_ops() {
    // [2]G + [3]G via the MSM must equal mul+mul+add via the group op
    let generator = hex(G1_GENERATOR_BE);
    let points = [generator.clone(), generator.clone()].concat();
    let mut scalars = vec![0u8; 64];
    scalars[31] = 2;
    scalars[63] = 3;

    let mul = |scalar_byte: u8| {
        let mut input = generator.clone();
        let mut scalar = [0u8; 32];
        scalar[31] = scalar_byte;
        input.extend_from_slice(&scalar);
        alt_bn128_g1_multiplication_be(&input).unwrap()
    };
    let expected =
        alt_bn128_g1_addition_be(&[mul(2), mul(3)].concat()).unwrap();

    let (code, result) = g1_msm(2, &points, &scalars);
    assert_eq!(code, 0);
    assert_eq!(result.0.as_slice(), expected.as_slice());
}

fn g1_msm_rejects_empty_input() {
    let (code, _) = g1_msm(0, &[], &[]);
    assert_eq!(code, 1);
}

fn pairing_check_verdicts() {
    let pairs = hex(TRUE_PAIRS);
    let (code, word) = pairing_check(2, &pairs);
    assert_eq!(code, 0);
    assert!(word.verdict(), "known-good vector must verify");
    assert_eq!(&word.0[..31], &[0u8; 31]);

    // negate the first G1 point (multiply by r - 1): verdict flips to false,
    // which is a zero word and NOT an error
    let mut mul_input = pairs[..64].to_vec();
    mul_input.extend_from_slice(&hex(FR_MAX_BE));
    let negated = alt_bn128_g1_multiplication_be(&mul_input).unwrap();
    let mut false_pairs = pairs;
    false_pairs[..64].copy_from_slice(&negated);
    let (code, word) = pairing_check(2, &false_pairs);
    assert_eq!(code, 0);
    assert!(!word.verdict());
    assert_eq!(word.0, [0u8; 32]);
}

fn pairing_check_rejects_non_subgroup_g2() {
    let pair = [hex(G1_GENERATOR_BE), hex(NON_SUBGROUP_G2_BE)].concat();
    let (code, word) = pairing_check(1, &pair);
    assert_eq!(code, 1);
    assert_eq!(word.0, [0u8; 32], "result must be untouched on error");
}

fn pairing_check_rejects_zero_pairs() {
    let (code, _) = pairing_check(0, &[]);
    assert_eq!(code, 1);
}

fn fr_lincomb_inner_product() {
    // <[2, 3], [5, 7]> = 10 + 21 = 31
    let mut a = [0u8; 64];
    a[31] = 2;
    a[63] = 3;
    let mut b = [0u8; 64];
    b[31] = 5;
    b[63] = 7;
    let (code, result) = fr_lincomb(2, &a, &b);
    assert_eq!(code, 0);
    let mut expected = [0u8; 32];
    expected[31] = 31;
    assert_eq!(result, expected);

    // empty is a domain error, not a vacuous zero
    let (code, _) = fr_lincomb(0, &[], &[]);
    assert_eq!(code, 1);
}

fn fr_batch_invert_roundtrip() {
    // invert [1, 2] then invert the result: back to [1, 2]
    let mut a = [0u8; 64];
    a[31] = 1;
    a[63] = 2;
    let mut inv = [0u8; 64];
    assert_eq!(fr_batch_invert(2, &a, &mut inv), 0);
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(&inv[..32], &one, "1^-1 == 1");
    let mut back = [0u8; 64];
    assert_eq!(fr_batch_invert(2, &inv, &mut back), 0);
    assert_eq!(back, a, "inverting twice is the identity");

    // a zero element is a domain error and leaves the output untouched
    let zeros = [0u8; 64];
    let mut out = [0xabu8; 64];
    assert_eq!(fr_batch_invert(2, &zeros, &mut out), 1);
    assert_eq!(out, [0xabu8; 64]);
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

    0
}

custom_heap_default!();
custom_panic_default!();
