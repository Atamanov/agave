//! Campaign program for the batch-verification case grid. Account 0 holds
//! authenticated real Zolana confidential-transfer Groth16 fixtures in a fixed layout; the instruction tag selects
//! the verification strategy. Every case reads the same fixture, so charged
//! CU differences come from the strategy alone. Points are uncompressed:
//! wire decompression costs the same in every case and stays out of the grid.
//!
//! Account layout: tag-independent.
//! `[n:1][k:1][vk_index:n][k x vk(576)][n x proof(320)][n x pubinput(32)]`
//! vk record: alpha(64) beta(128) gamma(128) delta(128) ic0(64) ic1(64).
//! proof record: neg_a(64) a(64) b(128) c(64).
//!
//! Tags used by the decision bench: 0 = current independent verification;
//! 2 = B5 batch; 3 = B5 batch with the fixed-G2 suffix resolved by the v3
//! registry; 4 = corrected B5+Fp12; 5 = excluded registry initialization;
//! 9 = current+Fp12 as n independent maps. The old shared-gamma residual is
//! deliberately not a decision-table case.

#![cfg_attr(target_os = "solana", no_std)]

extern crate alloc;

use alloc::{vec, vec::Vec};

use ark_bn254::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use core::ops::{AddAssign, Mul, Neg};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_bn254::prelude::{
    alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
};
use solana_bn254_batch_syscall::{
    PodG1G2Pair, PodG1Point, PodG1RegisteredG2Pair, PodG2Point, PodGtElement, PodScalar,
    PodTrustedGtExponent, Version, alt_bn128_g1_msm,
};
use solana_bn254_groth16_batch::{
    CurrentFp12Target, Proof, RandomizerMode, SameVkTarget, ValidatedVerifyingKey, VerifyingKey,
    Version as FoldVersion, derive_randomizers, derive_seed, fold_pairs_for_verification,
    groth16_batch_verify, groth16_current_fp12_verify, groth16_same_vk_fp12_verify,
    validate_batch_shape,
};
use solana_sha256_hasher::{hash as sha256_hash, hashv as sha256_hashv};

#[cfg(target_os = "solana")]
use solana_bn254_batch_syscall::{
    alt_bn128_pairing_check_registered, alt_bn128_pairing_map, alt_bn128_trusted_gt_multiexp,
    alt_bn128_vk_registry_init,
};

pub mod tag {
    pub const SOLO: u8 = 0;
    pub const RLC_PRECOMPILES: u8 = 1;
    pub const BATCH_SYSCALL: u8 = 2;
    pub const REGISTRY: u8 = 3;
    pub const BATCH_FP12: u8 = 4;
    pub const REGISTRY_INIT: u8 = 5;
    pub const CURRENT_FP12: u8 = 9;
}

const REGISTRY_V3_MAGIC: &[u8; 8] = b"B254VK3\0";
const REGISTRY_V3_VERSION: u8 = 3;
const REGISTRY_V3_FROZEN: u8 = 1;
const REGISTRY_V3_CURVE: u8 = 1;
const REGISTRY_V3_BACKEND_B5: u8 = 5;
const REGISTRY_V3_HEADER_BYTES: usize = 80;
const REGISTRY_V3_G2_ENTRY_BYTES: usize = 37_744;
const REGISTRY_V3_GT_ENTRY_BYTES: usize = 608;
const REGISTRY_V3_PDA_SEED: &[u8] = b"bn254-b5-vk-registry-v3";
const REGISTRY_V3_KEYSET_DOMAIN: &[u8] = b"agave:bn254:b5:keyset:v3";
const FP12_APPLICATION_CONTEXT: [u8; 32] = *b"bn254-decision-bench-fp12-v3!!!!";

/// Consumer the pinned registry addresses below are derived under. A guest
/// loaded at any other program id must reject: the pinned address would not be
/// a program-derived address of the running program.
#[cfg(any(target_os = "solana", test))]
const REGISTRY_V3_CONSUMER: [u8; 32] = [41u8; 32];

/// `(keyset digest, registry PDA)` for every keyset the grid runs, standing in
/// for what a real consumer emits at codegen time. The address is
/// `find_program_address([REGISTRY_V3_PDA_SEED, digest], REGISTRY_V3_CONSUMER)`
/// and `pinned_registry_addresses_derive` re-runs that derivation. Lookup is
/// keyed by the digest the guest recomputes from the fixture, so a fixture
/// cannot present another keyset's registry account.
#[cfg(any(target_os = "solana", test))]
const REGISTRY_V3_PINNED: [([u8; 32], [u8; 32]); 3] = [
    // n=5 k=1
    (
        [
            0x1f, 0xd5, 0xbf, 0x4d, 0x5d, 0x7b, 0x82, 0xe1, 0x81, 0xc2, 0xa0, 0xcb, 0x2e, 0x87,
            0x2b, 0x8e, 0x1f, 0xcd, 0x8b, 0x4a, 0x30, 0xfc, 0xcc, 0x78, 0xeb, 0xca, 0xa2, 0xbd,
            0x6c, 0xa3, 0x47, 0x14,
        ],
        [
            0xc6, 0x0e, 0x1d, 0x88, 0x05, 0x3b, 0x4f, 0x42, 0x97, 0x65, 0xa9, 0xe6, 0xb2, 0x67,
            0x6e, 0x7f, 0xe1, 0x20, 0x13, 0x59, 0x5f, 0x62, 0xf7, 0x9d, 0xf2, 0x89, 0xb4, 0x42,
            0x7c, 0x38, 0x47, 0xbd,
        ],
    ),
    // n=2 k=2
    (
        [
            0x33, 0x3b, 0x0e, 0x26, 0x32, 0x8a, 0x95, 0x9b, 0x2f, 0x41, 0x64, 0x0c, 0xed, 0x8f,
            0x0a, 0x7b, 0xfe, 0x2b, 0x31, 0x20, 0xd7, 0xd1, 0x53, 0xd7, 0x58, 0xd3, 0x8d, 0x27,
            0x34, 0xcb, 0xf6, 0x57,
        ],
        [
            0x9b, 0x27, 0xd4, 0xcf, 0xe7, 0xb8, 0xe3, 0x29, 0xfb, 0x5f, 0x13, 0x84, 0xdd, 0x31,
            0xdf, 0x09, 0xff, 0x46, 0x20, 0x23, 0x50, 0x92, 0xed, 0xcf, 0x16, 0x8b, 0x05, 0xcd,
            0xd4, 0xfe, 0x0a, 0x45,
        ],
    ),
    // n=3 k=3
    (
        [
            0xc5, 0xab, 0xf0, 0x55, 0xd1, 0x98, 0x8e, 0x11, 0x3b, 0xbd, 0x06, 0x33, 0xb4, 0xa5,
            0x4b, 0x22, 0x20, 0x2a, 0xe7, 0x10, 0xe2, 0xe7, 0x85, 0x20, 0x2a, 0x48, 0x49, 0xa3,
            0xab, 0x5a, 0x74, 0x45,
        ],
        [
            0x20, 0xdc, 0xf1, 0x92, 0xd9, 0x17, 0xd0, 0xd2, 0x54, 0xdf, 0xfa, 0xc5, 0x02, 0x8e,
            0xcc, 0x87, 0xbd, 0x53, 0xcf, 0x3a, 0xff, 0x61, 0x4e, 0x11, 0x74, 0x27, 0x29, 0x9c,
            0x04, 0xb6, 0x17, 0x96,
        ],
    ),
];

const VK_BYTES: usize = 64 + 128 + 128 + 128 + 64 + 64;
const PROOF_BYTES: usize = 64 + 64 + 128 + 64;
struct VkView<'a> {
    alpha: &'a [u8; 64],
    beta: &'a [u8; 128],
    gamma: &'a [u8; 128],
    delta: &'a [u8; 128],
    ic0: &'a [u8; 64],
    ic1: &'a [u8; 64],
}

struct ProofView<'a> {
    neg_a: &'a [u8; 64],
    a: &'a [u8; 64],
    b: &'a [u8; 128],
    c: &'a [u8; 64],
}

struct Fixture<'a> {
    n: usize,
    k: usize,
    vk_index: &'a [u8],
    vks: Vec<VkView<'a>>,
    proofs: Vec<ProofView<'a>>,
    inputs: Vec<&'a [u8; 32]>,
}

fn slice<'a, const N: usize>(data: &'a [u8], offset: &mut usize) -> Option<&'a [u8; N]> {
    let out = data.get(*offset..*offset + N)?.try_into().ok()?;
    *offset += N;
    Some(out)
}

#[inline(never)]
fn parse(data: &[u8]) -> Option<Fixture<'_>> {
    let n = usize::from(*data.first()?);
    let k = usize::from(*data.get(1)?);
    let mut offset = 2usize;
    if n == 0 || k == 0 || k > n {
        return None;
    }
    let vk_index = data.get(offset..offset + n)?;
    offset += n;
    let mut vks = Vec::with_capacity(k);
    for _ in 0..k {
        vks.push(VkView {
            alpha: slice::<64>(data, &mut offset)?,
            beta: slice::<128>(data, &mut offset)?,
            gamma: slice::<128>(data, &mut offset)?,
            delta: slice::<128>(data, &mut offset)?,
            ic0: slice::<64>(data, &mut offset)?,
            ic1: slice::<64>(data, &mut offset)?,
        });
    }
    let mut proofs = Vec::with_capacity(n);
    for _ in 0..n {
        proofs.push(ProofView {
            neg_a: slice::<64>(data, &mut offset)?,
            a: slice::<64>(data, &mut offset)?,
            b: slice::<128>(data, &mut offset)?,
            c: slice::<64>(data, &mut offset)?,
        });
    }
    let mut inputs = Vec::with_capacity(n);
    for _ in 0..n {
        inputs.push(slice::<32>(data, &mut offset)?);
    }
    if vk_index.iter().any(|&i| usize::from(i) >= k) {
        return None;
    }
    Some(Fixture {
        n,
        k,
        vk_index,
        vks,
        proofs,
        inputs,
    })
}

/// Case 0: n independent verifies, each a 4-pair standard pairing call.
#[inline(never)]
fn verify_solo(f: &Fixture<'_>) -> Option<bool> {
    for i in 0..f.n {
        let vk = &f.vks[usize::from(f.vk_index[i])];
        let ic = [*vk.ic0, *vk.ic1];
        let key = Groth16Verifyingkey {
            nr_pubinputs: 1,
            vk_alpha_g1: *vk.alpha,
            vk_beta_g2: *vk.beta,
            vk_gamma_g2: *vk.gamma,
            vk_delta_g2: *vk.delta,
            vk_ic: &ic,
            vk_commitment: None,
        };
        let p = &f.proofs[i];
        let public_inputs = [*f.inputs[i]];
        let mut verifier = Groth16Verifier::new(p.neg_a, p.b, p.c, &public_inputs, &key).ok()?;
        if verifier.verify().is_err() {
            return Some(false);
        }
    }
    Some(true)
}

/// 128-bit Fiat-Shamir scalars over the whole fixture; r_0 = 1.
#[inline(never)]
fn randomizers(data: &[u8], n: usize) -> Option<Vec<[u8; 32]>> {
    let seed = sha256_hash(data).to_bytes();
    let mut out = Vec::with_capacity(n);
    let mut one = [0u8; 32];
    one[31] = 1;
    out.push(one);
    for i in 1..n {
        let h = sha256_hashv(&[&seed, &[i as u8]]).to_bytes();
        let mut r = [0u8; 32];
        r[16..].copy_from_slice(&h[..16]);
        out.push(r);
    }
    Some(out)
}

fn mul(point: &[u8; 64], scalar: &[u8; 32]) -> Option<[u8; 64]> {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(scalar);
    alt_bn128_g1_multiplication_be(&input).ok()?.try_into().ok()
}

fn add(a: &[u8; 64], b: &[u8; 64]) -> Option<[u8; 64]> {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(a);
    input[64..].copy_from_slice(b);
    alt_bn128_g1_addition_be(&input).ok()?.try_into().ok()
}

/// Sum of 128-bit randomizers. The sum stays far below the field modulus, so
/// plain big-endian integer addition needs no reduction.
fn scalar_sum(rs: &[&[u8; 32]]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for r in rs {
        let mut carry = 0u16;
        for byte in (0..32).rev() {
            let v = u16::from(acc[byte]) + u16::from(r[byte]) + carry;
            acc[byte] = v as u8;
            carry = v >> 8;
        }
    }
    acc
}

/// Case 1 pair list: n + 3k pairs, 192 bytes each, in the standard
/// precompile encoding. The verifier and [`pair_counts`] share this builder,
/// so a reported count is the count the syscall receives.
#[inline(never)]
fn build_rlc_pairs(f: &Fixture<'_>, data: &[u8]) -> Option<Vec<u8>> {
    let rs = randomizers(data, f.n)?;
    let mut pairs: Vec<u8> = Vec::with_capacity((f.n + 3 * f.k) * 192);

    // Proof side: e(r_i * negA_i, B_i).
    let mut vkx = Vec::with_capacity(f.n);
    for (i, randomizer) in rs.iter().enumerate().take(f.n) {
        let p = &f.proofs[i];
        let ra = mul(p.neg_a, randomizer)?;
        pairs.extend_from_slice(&ra);
        pairs.extend_from_slice(p.b);
        let vk = &f.vks[usize::from(f.vk_index[i])];
        vkx.push(add(vk.ic0, &mul(vk.ic1, f.inputs[i])?)?);
    }
    // Key side per vk: gamma, delta, alpha-beta.
    for key in 0..f.k {
        let members: Vec<usize> = (0..f.n)
            .filter(|&i| usize::from(f.vk_index[i]) == key)
            .collect();
        let vk = &f.vks[key];
        let mut vkx_sum: Option<[u8; 64]> = None;
        let mut c_sum: Option<[u8; 64]> = None;
        for &i in &members {
            let wx = mul(&vkx[i], &rs[i])?;
            let wc = mul(f.proofs[i].c, &rs[i])?;
            vkx_sum = Some(match vkx_sum {
                Some(acc) => add(&acc, &wx)?,
                None => wx,
            });
            c_sum = Some(match c_sum {
                Some(acc) => add(&acc, &wc)?,
                None => wc,
            });
        }
        let r_sum = scalar_sum(&members.iter().map(|&i| &rs[i]).collect::<Vec<_>>());
        let alpha_sum = mul(vk.alpha, &r_sum)?;
        pairs.extend_from_slice(&vkx_sum?);
        pairs.extend_from_slice(vk.gamma);
        pairs.extend_from_slice(&c_sum?);
        pairs.extend_from_slice(vk.delta);
        pairs.extend_from_slice(&alpha_sum);
        pairs.extend_from_slice(vk.beta);
    }
    Some(pairs)
}

/// Case 1: one RLC over the standard precompiles, verified in a single
/// standard pairing call.
#[inline(never)]
fn verify_rlc_precompiles(f: &Fixture<'_>, data: &[u8]) -> Option<bool> {
    let pairs = build_rlc_pairs(f, data)?;
    let out = alt_bn128_pairing_be(&pairs).ok()?;
    Some(out.last() == Some(&1))
}

/// Case 2: the shipped fold through the batch syscalls.
#[inline(never)]
fn batch_inputs(f: &Fixture<'_>) -> Option<(Vec<ValidatedVerifyingKey>, Vec<Proof>)> {
    let mut keys = Vec::with_capacity(f.k);
    for vk in &f.vks {
        let key = VerifyingKey {
            alpha_g1: PodG1Point(*vk.alpha),
            beta_g2: PodG2Point(*vk.beta),
            gamma_g2: PodG2Point(*vk.gamma),
            delta_g2: PodG2Point(*vk.delta),
            ic: vec![PodG1Point(*vk.ic0), PodG1Point(*vk.ic1)],
            pedersen: None,
        };
        keys.push(key.trust().ok()?);
    }
    let mut proofs = Vec::with_capacity(f.n);
    for i in 0..f.n {
        let p = &f.proofs[i];
        proofs.push(Proof {
            vk_index: u16::from(f.vk_index[i]),
            a: PodG1Point(*p.a),
            b: PodG2Point(*p.b),
            c: PodG1Point(*p.c),
            commitment: None,
            public_inputs: vec![PodScalar(*f.inputs[i])],
        });
    }
    Some((keys, proofs))
}

/// Case 2: the shipped fold through the batch syscalls.
#[inline(never)]
fn verify_batch_syscall(f: &Fixture<'_>) -> Option<bool> {
    let (keys, proofs) = batch_inputs(f)?;
    groth16_batch_verify(FoldVersion::V0, &keys, &proofs, RandomizerMode::Independent).ok()
}

fn msm(points: &[[u8; 64]], scalars: &[[u8; 32]]) -> Option<[u8; 64]> {
    let pods: Vec<PodG1Point> = points.iter().map(|p| PodG1Point(*p)).collect();
    let pod_scalars: Vec<PodScalar> = scalars.iter().map(|s| PodScalar(*s)).collect();
    let out = alt_bn128_g1_msm(Version::V0, &pods, &pod_scalars).ok()?;
    Some(out.0)
}

fn fr_from_pod(value: &[u8; 32]) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(value.rchunks_exact(8)) {
        *limb = u64::from_be_bytes(bytes.try_into().ok()?);
    }
    Fr::from_bigint(<Fr as PrimeField>::BigInt::new(limbs))
}

fn fr_to_pod(value: &Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn registry_sources(f: &Fixture<'_>) -> (Vec<PodG2Point>, Vec<PodG1G2Pair>) {
    let mut g2 = Vec::with_capacity(3 * f.k);
    let mut gt = Vec::with_capacity(f.k);
    for vk in &f.vks {
        g2.extend([
            PodG2Point(*vk.beta),
            PodG2Point(*vk.gamma),
            PodG2Point(*vk.delta),
        ]);
        gt.push(PodG1G2Pair {
            g1: PodG1Point(*vk.alpha),
            g2: PodG2Point(*vk.beta),
        });
    }
    (g2, gt)
}

fn registry_keyset_digest_v3(f: &Fixture<'_>) -> [u8; 32] {
    let (g2, gt) = registry_sources(f);
    let mut sources = Vec::with_capacity(g2.len() * 128 + gt.len() * 192);
    for source in &g2 {
        sources.extend_from_slice(&source.0);
    }
    for source in &gt {
        sources.extend_from_slice(&source.g1.0);
        sources.extend_from_slice(&source.g2.0);
    }
    solana_keccak_hasher::hashv(&[
        REGISTRY_V3_KEYSET_DOMAIN,
        &[REGISTRY_V3_VERSION],
        &(g2.len() as u16).to_le_bytes(),
        &(gt.len() as u16).to_le_bytes(),
        &sources,
    ])
    .to_bytes()
}

/// Pinned registry address for a recomputed keyset digest. An unknown digest
/// has no pinned address and the caller must reject; deriving one here would
/// re-introduce the per-bump hashing this guest exists to keep out of the
/// measurement.
#[cfg(any(target_os = "solana", test))]
fn pinned_registry_address(digest: &[u8; 32]) -> Option<&'static [u8; 32]> {
    REGISTRY_V3_PINNED
        .iter()
        .find_map(|(pinned, address)| (pinned == digest).then_some(address))
}

fn registry_header_matches(
    data: &[u8],
    f: &Fixture<'_>,
    consumer: &[u8; 32],
    expected_digest: &[u8; 32],
) -> bool {
    data.get(..8) == Some(REGISTRY_V3_MAGIC.as_slice())
        && data.get(8).copied() == Some(REGISTRY_V3_VERSION)
        && data.get(9).copied() == Some(REGISTRY_V3_FROZEN)
        && data.get(10).copied() == Some(REGISTRY_V3_CURVE)
        && data.get(11).copied() == Some(REGISTRY_V3_BACKEND_B5)
        && data.get(12..14) == Some(&(3 * f.k as u16).to_le_bytes())
        && data.get(14..16) == Some(&(f.k as u16).to_le_bytes())
        && data.get(16..48) == Some(consumer.as_slice())
        && data.get(48..80) == Some(expected_digest.as_slice())
        && data.len()
            == REGISTRY_V3_HEADER_BYTES
                + 3 * f.k * REGISTRY_V3_G2_ENTRY_BYTES
                + f.k * REGISTRY_V3_GT_ENTRY_BYTES
}

fn registry_g2_id(data: &[u8], index: usize, f: &Fixture<'_>) -> Option<[u8; 32]> {
    if index >= 3 * f.k {
        return None;
    }
    let start = REGISTRY_V3_HEADER_BYTES + index * REGISTRY_V3_G2_ENTRY_BYTES;
    data.get(start..start + 32)?.try_into().ok()
}

fn registry_gt_record(
    data: &[u8],
    index: usize,
    f: &Fixture<'_>,
) -> Option<([u8; 32], PodGtElement)> {
    if index >= f.k {
        return None;
    }
    let start = REGISTRY_V3_HEADER_BYTES
        + 3 * f.k * REGISTRY_V3_G2_ENTRY_BYTES
        + index * REGISTRY_V3_GT_ENTRY_BYTES;
    let id = data.get(start..start + 32)?.try_into().ok()?;
    let target = data.get(start + 224..start + 608)?.try_into().ok()?;
    Some((id, PodGtElement(target)))
}

#[cfg(target_os = "solana")]
fn initialize_registry_v3(f: &Fixture<'_>, registry_data: &mut [u8]) -> Option<()> {
    let (g2, gt) = registry_sources(f);
    alt_bn128_vk_registry_init(
        Version::V0,
        0,
        &g2,
        &gt,
        &registry_keyset_digest_v3(f),
        registry_data,
    )
    .ok()
}

/// Registry B5 is exactly the ordinary B5 fold up to the pairing boundary.
/// Only the fixed-G2 suffix is replaced with authenticated registry IDs.
#[cfg(target_os = "solana")]
#[inline(never)]
fn verify_registry_v3(f: &Fixture<'_>, registry_data: &[u8]) -> Option<bool> {
    let (keys, proofs) = batch_inputs(f)?;
    let pairs = fold_pairs_for_verification(&keys, &proofs, RandomizerMode::Independent).ok()?;
    let full = pairs.get(..f.n)?;
    let mut registered = Vec::with_capacity(3 * f.k);
    let mut cursor = f.n;
    for key in 0..f.k {
        if !f.vk_index.iter().any(|index| usize::from(*index) == key) {
            continue;
        }
        for fixed in 0..3 {
            let pair = *pairs.get(cursor)?;
            cursor += 1;
            registered.push(PodG1RegisteredG2Pair {
                g1: pair.g1,
                g2_id: registry_g2_id(registry_data, 3 * key + fixed, f)?,
            });
        }
    }
    if cursor != pairs.len() {
        return None;
    }
    alt_bn128_pairing_check_registered(Version::V0, 0, full, &registered).ok()
}

#[cfg(target_os = "solana")]
#[inline(never)]
fn verify_current_fp12(f: &Fixture<'_>, registry_data: &[u8]) -> Option<bool> {
    let (keys, proofs) = batch_inputs(f)?;
    for proof in &proofs {
        let key_index = usize::from(proof.vk_index);
        let (_, target) = registry_gt_record(registry_data, key_index, f)?;
        let mut local = proof.clone();
        local.vk_index = 0;
        if !groth16_current_fp12_verify(
            keys.get(key_index)?,
            &local,
            &CurrentFp12Target::new(*keys.get(key_index)?.digest(), target),
        )
        .ok()?
        {
            return Some(false);
        }
    }
    Some(true)
}

#[cfg(target_os = "solana")]
#[inline(never)]
fn verify_batch_fp12(f: &Fixture<'_>, registry_data: &[u8]) -> Option<bool> {
    let (keys, proofs) = batch_inputs(f)?;
    if f.k == 1 {
        let (_, target) = registry_gt_record(registry_data, 0, f)?;
        return groth16_same_vk_fp12_verify(
            keys.first()?,
            &proofs,
            &FP12_APPLICATION_CONTEXT,
            &SameVkTarget::new(*keys.first()?.digest(), target),
        )
        .ok();
    }

    validate_batch_shape(&keys, &proofs).ok()?;
    let seed = derive_seed(RandomizerMode::Independent, &keys, &proofs);
    let mut randomizers =
        derive_randomizers(&seed, proofs.len() as u64, RandomizerMode::Independent);
    *randomizers.first_mut()? = Fr::one();

    let mut pairs = Vec::with_capacity(f.n + 2 * f.k);
    for (index, (proof, randomizer)) in proofs.iter().zip(&randomizers).enumerate() {
        let a = if index == 0 {
            proof.a.0
        } else {
            msm(&[proof.a.0], &[fr_to_pod(randomizer)])?
        };
        pairs.push(PodG1G2Pair {
            g1: PodG1Point(a),
            g2: proof.b,
        });
    }

    let mut operands = Vec::with_capacity(f.k);
    for key_index in 0..f.k {
        let members: Vec<usize> = proofs
            .iter()
            .enumerate()
            .filter(|(_, proof)| usize::from(proof.vk_index) == key_index)
            .map(|(index, _)| index)
            .collect();
        if members.is_empty() {
            continue;
        }
        let key = keys.get(key_index)?.key();
        let mut r_sum = Fr::zero();
        let mut input_coefficients = vec![Fr::zero(); key.num_public_inputs()];
        for &index in &members {
            let r = randomizers[index];
            r_sum.add_assign(r);
            for (coefficient, input) in input_coefficients
                .iter_mut()
                .zip(&proofs[index].public_inputs)
            {
                coefficient.add_assign(r.mul(fr_from_pod(&input.0)?));
            }
        }

        let mut gamma_points = Vec::with_capacity(key.ic.len());
        let mut gamma_scalars = Vec::with_capacity(key.ic.len());
        gamma_points.push(key.ic[0].0);
        gamma_scalars.push(fr_to_pod(&r_sum.neg()));
        for (point, coefficient) in key.ic.iter().skip(1).zip(&input_coefficients) {
            gamma_points.push(point.0);
            gamma_scalars.push(fr_to_pod(&coefficient.neg()));
        }
        pairs.push(PodG1G2Pair {
            g1: PodG1Point(msm(&gamma_points, &gamma_scalars)?),
            g2: key.gamma_g2,
        });

        let delta_points: Vec<[u8; 64]> = members.iter().map(|&index| proofs[index].c.0).collect();
        let delta_scalars: Vec<[u8; 32]> = members
            .iter()
            .map(|&index| fr_to_pod(&randomizers[index].neg()))
            .collect();
        pairs.push(PodG1G2Pair {
            g1: PodG1Point(msm(&delta_points, &delta_scalars)?),
            g2: key.delta_g2,
        });

        let (target_id, _) = registry_gt_record(registry_data, key_index, f)?;
        operands.push(PodTrustedGtExponent {
            target_id,
            exponent: PodScalar(fr_to_pod(&r_sum)),
        });
    }
    if pairs.len() != f.n + 2 * f.k || operands.len() != f.k {
        return None;
    }
    let mapped = alt_bn128_pairing_map(Version::V0, &pairs).ok()?;
    let target = alt_bn128_trusted_gt_multiexp(Version::V0, 0, &operands).ok()?;
    Some(mapped == target)
}

/// Pairs a case submits to a pairing check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairCounts {
    /// Pairs charged at the full per-pair price.
    pub full: usize,
    /// Pairs charged at the registry-validated price.
    pub prepped: usize,
    /// True when the numbers come from the pair list this program builds.
    /// False when the fold builds the list inside the library, where the
    /// layout is the documented n + 3k and not observable here.
    pub observed: bool,
}

/// Pair counts per case, for cross-checking documented pairing arithmetic
/// against the code that calls the syscalls.
pub fn pair_counts(ix_tag: u8, data: &[u8]) -> Option<PairCounts> {
    let f = parse(data)?;
    let counts = match ix_tag {
        // groth16-solana builds each 4-pair list internally, one call per proof.
        tag::SOLO => PairCounts {
            full: 4 * f.n,
            prepped: 0,
            observed: false,
        },
        tag::RLC_PRECOMPILES => PairCounts {
            full: build_rlc_pairs(&f, data)?.len() / 192,
            prepped: 0,
            observed: true,
        },
        // The fold assembles its own pair list inside zolana-groth16-batch.
        tag::BATCH_SYSCALL => PairCounts {
            full: f.n + 3 * f.k,
            prepped: 0,
            observed: false,
        },
        tag::REGISTRY => PairCounts {
            full: f.n,
            prepped: 3 * f.k,
            observed: false,
        },
        tag::BATCH_FP12 => PairCounts {
            full: f.n + 2 * f.k,
            prepped: 0,
            observed: false,
        },
        tag::CURRENT_FP12 => PairCounts {
            full: 3 * f.n,
            prepped: 0,
            observed: false,
        },
        _ => return None,
    };
    Some(counts)
}

/// Run the case selected by `ix_tag` over the fixture account bytes.
pub fn run_case(ix_tag: u8, data: &[u8]) -> Option<bool> {
    let fixture = parse(data)?;
    match ix_tag {
        tag::SOLO => verify_solo(&fixture),
        tag::RLC_PRECOMPILES => verify_rlc_precompiles(&fixture, data),
        tag::BATCH_SYSCALL => verify_batch_syscall(&fixture),
        tag::BATCH_FP12 | tag::CURRENT_FP12 | tag::REGISTRY => None,
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
        let ix_tag = *instruction_data
            .first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        if matches!(
            ix_tag,
            super::tag::REGISTRY
                | super::tag::BATCH_FP12
                | super::tag::CURRENT_FP12
                | super::tag::REGISTRY_INIT
        ) {
            let (registry_slice, rest) = accounts.split_at_mut(1);
            let registry = registry_slice
                .first_mut()
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            let fixture = rest.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
            let fixture_data = fixture
                .try_borrow()
                .map_err(|_| ProgramError::AccountBorrowFailed)?;
            let parsed = super::parse(&fixture_data).ok_or(ProgramError::InvalidAccountData)?;
            let digest = super::registry_keyset_digest_v3(&parsed);
            if _program_id.as_array() != &super::REGISTRY_V3_CONSUMER {
                return Err(ProgramError::IncorrectProgramId);
            }
            let expected =
                super::pinned_registry_address(&digest).ok_or(ProgramError::InvalidSeeds)?;
            if registry.address().as_array() != expected || !registry.owned_by(_program_id) {
                return Err(ProgramError::InvalidAccountOwner);
            }
            let expected_len =
                solana_bn254_batch_syscall::registry_account_len(3 * parsed.k, parsed.k);
            if registry.data_len() != expected_len {
                return Err(ProgramError::InvalidAccountData);
            }

            if ix_tag == super::tag::REGISTRY_INIT {
                if !registry.is_writable() {
                    return Err(ProgramError::InvalidAccountData);
                }
                let mut registry_data = registry
                    .try_borrow_mut()
                    .map_err(|_| ProgramError::AccountBorrowFailed)?;
                return super::initialize_registry_v3(&parsed, &mut registry_data)
                    .ok_or(ProgramError::InvalidAccountData);
            }
            if registry.is_writable() {
                return Err(ProgramError::InvalidAccountData);
            }
            let registry_data = registry
                .try_borrow()
                .map_err(|_| ProgramError::AccountBorrowFailed)?;
            // The registered-pairing syscall authenticates the immutable
            // program-owned PDA, complete v3 header and every opaque ID.  Do
            // not repeat that work in the guest's measured Registry path.
            // The Fp12 paths read registry bytes directly, so they retain the
            // guest-side header check.
            if ix_tag != super::tag::REGISTRY
                && !super::registry_header_matches(
                    &registry_data,
                    &parsed,
                    _program_id.as_array(),
                    &digest,
                )
            {
                return Err(ProgramError::InvalidAccountData);
            }
            let verdict = match ix_tag {
                super::tag::REGISTRY => super::verify_registry_v3(&parsed, &registry_data),
                super::tag::BATCH_FP12 => super::verify_batch_fp12(&parsed, &registry_data),
                super::tag::CURRENT_FP12 => super::verify_current_fp12(&parsed, &registry_data),
                _ => None,
            };
            return match verdict {
                Some(true) => Ok(()),
                Some(false) => Err(ProgramError::Custom(1)),
                None => Err(ProgramError::InvalidAccountData),
            };
        }
        let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
        let data = account
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        match super::run_case(ix_tag, &data) {
            Some(true) => Ok(()),
            Some(false) => Err(ProgramError::Custom(1)),
            None => Err(ProgramError::InvalidAccountData),
        }
    }
}

#[cfg(all(test, not(target_os = "solana")))]
mod registry_pin_tests {
    use super::*;
    use solana_address::Address;

    #[test]
    fn pinned_registry_addresses_derive() {
        for (digest, address) in REGISTRY_V3_PINNED {
            let (derived, _) = Address::find_program_address(
                &[REGISTRY_V3_PDA_SEED, &digest],
                &Address::new_from_array(REGISTRY_V3_CONSUMER),
            );
            assert_eq!(
                derived.to_bytes(),
                address,
                "pinned address is not the PDA of its digest"
            );
        }
    }

    #[test]
    fn pinned_digests_are_distinct() {
        for (index, (digest, _)) in REGISTRY_V3_PINNED.iter().enumerate() {
            assert!(
                pinned_registry_address(digest).is_some(),
                "entry {index} is not reachable by lookup"
            );
            assert_eq!(
                REGISTRY_V3_PINNED
                    .iter()
                    .filter(|(other, _)| other == digest)
                    .count(),
                1,
                "entry {index} shares its digest with another row"
            );
        }
    }

    #[test]
    fn unpinned_digest_has_no_address() {
        assert!(pinned_registry_address(&[0u8; 32]).is_none());
    }
}

/// Fixture record sizes for the host-side builder.
pub mod layout {
    pub const VK_BYTES: usize = super::VK_BYTES;
    pub const PROOF_BYTES: usize = super::PROOF_BYTES;
    pub const REGISTRY_PDA_SEED: &[u8] = super::REGISTRY_V3_PDA_SEED;
}
