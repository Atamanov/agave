//! Campaign program for the batch-verification case grid. Account 0 holds
//! authenticated real Zolana confidential-transfer Groth16 fixtures in a fixed layout; the instruction tag selects
//! the verification strategy. Every case reads the same fixture, so charged
//! CU differences come from the strategy alone. A deployment of any strategy
//! receives a compressed proof and pays to decompress it, so every case
//! restores the compressed wire form of the uncompressed fixture points before
//! it verifies.
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

#[cfg(test)]
use ark_bn254::Fr;
#[cfg(test)]
use ark_ff::{BigInteger, One, PrimeField};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_bn254::compression::prelude::{
    alt_bn128_g1_compress_be, alt_bn128_g1_decompress_be, alt_bn128_g2_compress_be,
    alt_bn128_g2_decompress_be,
};
use solana_bn254::prelude::{
    alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
};
use solana_bn254_batch_syscall::{
    PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS, PodG1G2Pair, PodG1Point, PodG1RegisteredG2Pair,
    PodG2Point, PodGtElement, PodScalar, PodTrustedGtExponent, REGISTRY_MAX_REGISTERED_PAIRS,
    Version, alt_bn128_fr_lincomb, alt_bn128_g1_msm,
};
use solana_bn254_groth16_batch::{
    CurrentFp12Target, Proof, RandomizerMode, SameVkTarget, ValidatedVerifyingKey, VerifyingKey,
    Version as FoldVersion, derive_randomizer_scalars, derive_seed, fold_pairs_for_verification,
    groth16_batch_verify, groth16_current_fp12_verify, groth16_same_vk_fp12_verify,
    lane_padding_pairs, validate_batch_shape,
};
#[cfg(test)]
use solana_bn254_groth16_batch::derive_randomizers;
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
/// keyed by the account address, which admits only a registry of this
/// consumer; binding that account to the fixture is the source comparison in
/// [`verify_registry_v3`], not a table lookup.
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

/// The record's `a` is deliberately absent: only the batch marshalling reads
/// it, and it does so straight out of the record.
struct ProofView<'a> {
    neg_a: &'a [u8; 64],
    b: &'a [u8; 128],
    c: &'a [u8; 64],
}

/// The three fixed-stride record regions, bounded once. A record is cut out
/// where it is read; parsing never materializes a view per record.
struct Fixture<'a> {
    n: usize,
    k: usize,
    vk_index: &'a [u8],
    vks: &'a [u8],
    proofs: &'a [u8],
    inputs: &'a [u8],
}

impl<'a> Fixture<'a> {
    fn vk(&self, index: usize) -> Option<VkView<'a>> {
        let record = record(self.vks, index, VK_BYTES)?;
        Some(VkView {
            alpha: record.get(..64)?.try_into().ok()?,
            beta: record.get(64..192)?.try_into().ok()?,
            gamma: record.get(192..320)?.try_into().ok()?,
            delta: record.get(320..448)?.try_into().ok()?,
            ic0: record.get(448..512)?.try_into().ok()?,
            ic1: record.get(512..)?.try_into().ok()?,
        })
    }

    fn key_of(&self, index: usize) -> Option<usize> {
        self.vk_index.get(index).copied().map(usize::from)
    }

    fn proof(&self, index: usize) -> Option<ProofView<'a>> {
        let record = record(self.proofs, index, PROOF_BYTES)?;
        Some(ProofView {
            neg_a: record.get(..64)?.try_into().ok()?,
            b: record.get(128..256)?.try_into().ok()?,
            c: record.get(256..)?.try_into().ok()?,
        })
    }

    fn input(&self, index: usize) -> Option<&'a [u8; 32]> {
        record(self.inputs, index, 32)?.try_into().ok()
    }
}

fn record(region: &[u8], index: usize, stride: usize) -> Option<&[u8]> {
    let start = index.checked_mul(stride)?;
    region.get(start..start.checked_add(stride)?)
}

fn region<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]> {
    let out = data.get(*offset..offset.checked_add(len)?)?;
    *offset += len;
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
    let vk_index = region(data, &mut offset, n)?;
    let vks = region(data, &mut offset, k.checked_mul(VK_BYTES)?)?;
    let proofs = region(data, &mut offset, n.checked_mul(PROOF_BYTES)?)?;
    let inputs = region(data, &mut offset, n.checked_mul(32)?)?;
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

/// Charge the compressed wire form of one G1 proof point.
///
/// Zolana carries `a` and `c` in 32 bytes each, so a deployment decompresses
/// before it can pair. The fixture is sealed uncompressed, so the guest
/// re-creates the encoding the sender transmitted and decompresses that. The
/// round trip must return the same point, which is what binds the metered
/// decompression to the point the verifier then consumes.
fn wire_g1(point: &[u8; 64]) -> Option<()> {
    (alt_bn128_g1_decompress_be(&alt_bn128_g1_compress_be(point).ok()?).ok()? == *point)
        .then_some(())
}

/// The same for `b`, which zolana carries in 64 bytes.
fn wire_g2(point: &[u8; 128]) -> Option<()> {
    (alt_bn128_g2_decompress_be(&alt_bn128_g2_compress_be(point).ok()?).ok()? == *point)
        .then_some(())
}

/// Case 0: n independent verifies, each a 4-pair standard pairing call.
#[inline(never)]
fn verify_solo(f: &Fixture<'_>) -> Option<bool> {
    for i in 0..f.n {
        let vk = f.vk(f.key_of(i)?)?;
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
        let p = f.proof(i)?;
        wire_g1(p.neg_a)?;
        wire_g2(p.b)?;
        wire_g1(p.c)?;
        let public_inputs = [*f.input(i)?];
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
        let p = f.proof(i)?;
        let ra = mul(p.neg_a, randomizer)?;
        pairs.extend_from_slice(&ra);
        pairs.extend_from_slice(p.b);
        let vk = f.vk(f.key_of(i)?)?;
        vkx.push(add(vk.ic0, &mul(vk.ic1, f.input(i)?)?)?);
    }
    // Key side per vk: gamma, delta, alpha-beta.
    for key in 0..f.k {
        let members: Vec<usize> = (0..f.n)
            .filter(|&i| usize::from(f.vk_index[i]) == key)
            .collect();
        let vk = f.vk(key)?;
        let mut vkx_sum: Option<[u8; 64]> = None;
        let mut c_sum: Option<[u8; 64]> = None;
        for &i in &members {
            let wx = mul(&vkx[i], &rs[i])?;
            let wc = mul(f.proof(i)?.c, &rs[i])?;
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
    let mut keys: Vec<ValidatedVerifyingKey> = Vec::with_capacity(f.k);
    let key_slots = keys.spare_capacity_mut();
    for index in 0..f.k {
        let vk = f.vk(index)?;
        let key = VerifyingKey {
            alpha_g1: PodG1Point(*vk.alpha),
            beta_g2: PodG2Point(*vk.beta),
            gamma_g2: PodG2Point(*vk.gamma),
            delta_g2: PodG2Point(*vk.delta),
            ic: vec![PodG1Point(*vk.ic0), PodG1Point(*vk.ic1)],
            pedersen: None,
        };
        key_slots.get_mut(index)?.write(key.trust().ok()?);
    }
    // SAFETY: the loop wrote slots 0..f.k of the capacity reserved above. An
    // early return leaves the length at zero and leaks the IC allocations of
    // the slots already written; it frees nothing that is still owned.
    unsafe { keys.set_len(f.k) };
    // A `Proof` is 416 bytes, so pushing one costs a build and a move. Writing
    // it into the reserved slot costs the build alone.
    let mut proofs: Vec<Proof> = Vec::with_capacity(f.n);
    let spare = proofs.spare_capacity_mut();
    for index in 0..f.n {
        let p = record(f.proofs, index, PROOF_BYTES)?;
        let a: [u8; 64] = p.get(64..128)?.try_into().ok()?;
        let b: [u8; 128] = p.get(128..256)?.try_into().ok()?;
        let c: [u8; 64] = p.get(256..)?.try_into().ok()?;
        wire_g1(&a)?;
        wire_g2(&b)?;
        wire_g1(&c)?;
        spare.get_mut(index)?.write(Proof {
            vk_index: u16::try_from(f.key_of(index)?).ok()?,
            a: PodG1Point(a),
            b: PodG2Point(b),
            c: PodG1Point(c),
            commitment: None,
            public_inputs: vec![PodScalar(*f.input(index)?)],
        });
    }
    // SAFETY: the loop wrote slots 0..f.n, and `with_capacity(f.n)` reserved
    // them. Any early return above leaves the length at zero, which leaks the
    // public-input allocations of the slots already written and frees nothing
    // that is still owned.
    unsafe { proofs.set_len(f.n) };
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

#[cfg(test)]
fn fr_from_pod(value: &[u8; 32]) -> Option<Fr> {
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(value.rchunks_exact(8)) {
        *limb = u64::from_be_bytes(bytes.try_into().ok()?);
    }
    Fr::from_bigint(<Fr as PrimeField>::BigInt::new(limbs))
}

#[cfg(test)]
fn fr_to_pod(value: &Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// `r - 1`, the field's `-1`, big-endian.
const MINUS_ONE_BE: PodScalar = PodScalar([
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
]);

const ONE_BE: PodScalar = PodScalar([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

/// `sum_i a[i] * b[i] mod r`. The scalar-field call is target-transparent and
/// rejects a non-canonical operand rather than reducing it.
fn fr_inner_product(a: &[PodScalar], b: &[PodScalar]) -> Option<PodScalar> {
    alt_bn128_fr_lincomb(Version::V0, a, b).ok()
}

/// `-x mod r`, which maps zero to zero where `r - x` would not.
fn fr_negate(scalar: &PodScalar) -> Option<PodScalar> {
    fr_inner_product(core::slice::from_ref(scalar), &[MINUS_ONE_BE])
}

/// `sum_i values[i] mod r`, reducing once.
fn fr_sum(values: &[PodScalar]) -> Option<PodScalar> {
    match values {
        [] => None,
        [single] => Some(*single),
        _ => fr_inner_product(values, &vec![ONE_BE; values.len()]),
    }
}

/// Independent transcript randomizers with `r_0` pinned to one, so the first
/// proof's A needs no scalar multiplication.
///
/// The draw never leaves the byte domain. `byte_randomizers_are_the_field_path`
/// pins the vector against the field derivation this replaced, element by
/// element.
fn batch_fp12_randomizers(seed: &[u8; 32], count: usize) -> Vec<PodScalar> {
    let mut randomizers =
        derive_randomizer_scalars(seed, count as u64, RandomizerMode::Independent);
    if let Some(first) = randomizers.first_mut() {
        *first = ONE_BE;
    }
    randomizers
}

/// [`batch_fp12_randomizers`] as it stood while it built field elements, kept
/// as the bit-exactness reference.
#[cfg(test)]
fn reference_batch_fp12_randomizers(seed: &[u8; 32], count: usize) -> Vec<Fr> {
    let mut randomizers = derive_randomizers(seed, count as u64, RandomizerMode::Independent);
    if let Some(first) = randomizers.first_mut() {
        *first = Fr::one();
    }
    randomizers
}

/// The multi-key Fp12 fold: one pair per proof, then a gamma and a delta pair
/// per key, plus the exponent that key's cached `e(alpha, beta)` is raised to.
///
/// Nothing here builds a field element. Each IC column is the inner product
/// `<-r, x_j>`, one scalar-field call over the wire bytes the proof carries.
/// `proofs` must already have passed `validate_batch_shape`, which is where a
/// non-canonical public input is rejected.
fn batch_fp12_fold(
    keys: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    randomizers: &[PodScalar],
) -> Option<(Vec<PodG1G2Pair>, Vec<(usize, PodScalar)>)> {
    if randomizers.len() != proofs.len() {
        return None;
    }
    // every key-side term of a randomizer enters the fold negated, so -r_i is
    // derived once and serves both the gamma columns and the delta MSM
    let neg_r = randomizers
        .iter()
        .map(fr_negate)
        .collect::<Option<Vec<PodScalar>>>()?;

    let mut pairs = Vec::with_capacity(proofs.len() + 2 * keys.len());
    for (index, (proof, randomizer)) in proofs.iter().zip(randomizers).enumerate() {
        let a = if index == 0 {
            proof.a.0
        } else {
            msm(&[proof.a.0], &[randomizer.0])?
        };
        pairs.push(PodG1G2Pair {
            g1: PodG1Point(a),
            g2: proof.b,
        });
    }

    let mut exponents = Vec::with_capacity(keys.len());
    for (key_index, validated) in keys.iter().enumerate() {
        let members: Vec<usize> = proofs
            .iter()
            .enumerate()
            .filter(|(_, proof)| usize::from(proof.vk_index) == key_index)
            .map(|(index, _)| index)
            .collect();
        if members.is_empty() {
            continue;
        }
        let key = validated.key();
        let member_neg_r: Vec<PodScalar> = members.iter().map(|&index| neg_r[index]).collect();
        let neg_r_sum = fr_sum(&member_neg_r)?;

        let mut gamma_points = Vec::with_capacity(key.ic.len());
        let mut gamma_scalars = Vec::with_capacity(key.ic.len());
        gamma_points.push(key.ic[0].0);
        gamma_scalars.push(neg_r_sum.0);
        let mut column = Vec::with_capacity(members.len());
        for (position, point) in key.ic.iter().enumerate().skip(1) {
            let input_index = position.checked_sub(1)?;
            column.clear();
            for &index in &members {
                column.push(*proofs.get(index)?.public_inputs.get(input_index)?);
            }
            gamma_points.push(point.0);
            gamma_scalars.push(fr_inner_product(&member_neg_r, &column)?.0);
        }
        pairs.push(PodG1G2Pair {
            g1: PodG1Point(msm(&gamma_points, &gamma_scalars)?),
            g2: key.gamma_g2,
        });

        let delta_points: Vec<[u8; 64]> = members.iter().map(|&index| proofs[index].c.0).collect();
        let delta_scalars: Vec<[u8; 32]> = member_neg_r.iter().map(|scalar| scalar.0).collect();
        pairs.push(PodG1G2Pair {
            g1: PodG1Point(msm(&delta_points, &delta_scalars)?),
            g2: key.delta_g2,
        });

        exponents.push((key_index, fr_negate(&neg_r_sum)?));
    }
    Some((pairs, exponents))
}

fn registry_sources(f: &Fixture<'_>) -> (Vec<PodG2Point>, Vec<PodG1G2Pair>) {
    let mut g2 = Vec::with_capacity(3 * f.k);
    let mut gt = Vec::with_capacity(f.k);
    for vk in (0..f.k).filter_map(|index| f.vk(index)) {
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

/// Keyset digest pinned to a registry address. An address outside the table is
/// not one of this consumer's registries and the caller must reject. Deriving
/// the address here instead would re-introduce the per-bump hashing this guest
/// exists to keep out of the measurement.
#[cfg(any(target_os = "solana", test))]
fn pinned_registry_digest(address: &[u8; 32]) -> Option<&'static [u8; 32]> {
    REGISTRY_V3_PINNED
        .iter()
        .find_map(|(digest, pinned)| {
            (pinned.first() == address.first() && pinned == address).then_some(digest)
        })
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

/// `(opaque id, canonical source)` of one G2 entry.
fn registry_g2_entry(data: &[u8], index: usize) -> Option<(&[u8], &[u8])> {
    let start = REGISTRY_V3_HEADER_BYTES + index * REGISTRY_V3_G2_ENTRY_BYTES;
    let head = data.get(start..start + 160)?;
    Some((head.get(..32)?, head.get(32..)?))
}

/// Replace the fold's fixed-G2 suffix with registry IDs.
///
/// Substituting entry `3 * key + fixed` for the fold's own G2 is sound only if
/// that entry stands for the same point, so every substitution compares the
/// entry's canonical source against the G2 it replaces. That is what stops a
/// fixture from pairing its own G1 terms against another keyset's registry;
/// the address check upstream only proves the account is a registry of this
/// consumer, not that it is this fixture's registry.
fn registered_suffix(
    f: &Fixture<'_>,
    pairs: &[PodG1G2Pair],
    registry_data: &[u8],
) -> Option<Vec<PodG1RegisteredG2Pair>> {
    let mut registered = Vec::with_capacity(3 * f.k);
    let mut cursor = f.n;
    for key in 0..f.k {
        if !f.vk_index.iter().any(|index| usize::from(*index) == key) {
            continue;
        }
        for fixed in 0..3 {
            let pair = pairs.get(cursor)?;
            cursor += 1;
            let (id, source) = registry_g2_entry(registry_data, 3 * key + fixed)?;
            if source != pair.g2.0.as_slice() {
                return None;
            }
            registered.push(PodG1RegisteredG2Pair {
                g1: pair.g1,
                g2_id: id.try_into().ok()?,
            });
        }
    }
    (cursor == pairs.len()).then_some(registered)
}

/// `(opaque id, target)` of the GT entry that stands for `e(alpha, beta)` of
/// key `index`.
///
/// The entry carries its own canonical source, and taking the entry is sound
/// only if that source is the key the fixture declares, so the two are
/// compared byte for byte. That comparison, not a keyset digest recomputed
/// over the whole registry, is what stops a fixture from taking another
/// keyset's target: the pinned address only proves the account is a registry
/// of this consumer.
fn registry_gt_record(
    data: &[u8],
    index: usize,
    f: &Fixture<'_>,
) -> Option<([u8; 32], PodGtElement)> {
    let vk = f.vk(index)?;
    let start = REGISTRY_V3_HEADER_BYTES
        + 3 * f.k * REGISTRY_V3_G2_ENTRY_BYTES
        + index * REGISTRY_V3_GT_ENTRY_BYTES;
    let entry = data.get(start..start + REGISTRY_V3_GT_ENTRY_BYTES)?;
    if entry.get(32..96)? != vk.alpha.as_slice() || entry.get(96..224)? != vk.beta.as_slice() {
        return None;
    }
    let id = entry.get(..32)?.try_into().ok()?;
    let target = entry.get(224..)?.try_into().ok()?;
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
    let mut pairs = fold_pairs_for_verification(&keys, &proofs, RandomizerMode::Independent).ok()?;
    let registered = registered_suffix(f, &pairs, registry_data)?;
    // The suffix now owns the fixed-G2 terms, so the fold's tail is free for
    // the pad. A registered pair occupies a lane like any other, so the lane
    // decision is over the total.
    pairs.truncate(f.n);
    let pad = lane_padding_pairs(f.n, registered.len(), REGISTRY_MAX_REGISTERED_PAIRS);
    if !pad.is_empty() {
        pairs.extend_from_slice(pad);
    }
    alt_bn128_pairing_check_registered(Version::V0, 0, &pairs, &registered).ok()
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
    let randomizers = batch_fp12_randomizers(&seed, proofs.len());
    let (mut pairs, exponents) = batch_fp12_fold(&keys, &proofs, &randomizers)?;

    let mut operands = Vec::with_capacity(f.k);
    for (key_index, exponent) in exponents {
        let (target_id, _) = registry_gt_record(registry_data, key_index, f)?;
        operands.push(PodTrustedGtExponent {
            target_id,
            exponent,
        });
    }
    if pairs.len() != f.n + 2 * f.k || operands.len() != f.k {
        return None;
    }
    // Inert pairs leave the mapped product, and so the comparison against the
    // registry target, exactly as it was.
    let pad = lane_padding_pairs(pairs.len(), 0, PAIRING_MAP_MAX_PAIRS);
    if !pad.is_empty() {
        pairs.extend_from_slice(pad);
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
    fn padded(full: usize, registered: usize, cap: usize) -> usize {
        full + lane_padding_pairs(full, registered, cap).len()
    }
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
            full: padded(f.n + 3 * f.k, 0, PAIRING_MAX_PAIRS),
            prepped: 0,
            observed: false,
        },
        // A registered pair occupies a lane too, so the lane decision is over
        // the total and the pad lands in the full list.
        tag::REGISTRY => PairCounts {
            full: padded(f.n, 3 * f.k, REGISTRY_MAX_REGISTERED_PAIRS),
            prepped: 3 * f.k,
            observed: false,
        },
        tag::BATCH_FP12 => PairCounts {
            full: padded(f.n + 2 * f.k, 0, PAIRING_MAP_MAX_PAIRS),
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
            if _program_id.as_array() != &super::REGISTRY_V3_CONSUMER {
                return Err(ProgramError::IncorrectProgramId);
            }
            // Address in, digest out. The hot Registry path never recomputes
            // the keyset digest: it binds the account by comparing each
            // registry source against the G2 that source replaces.
            let pinned_digest = super::pinned_registry_digest(registry.address().as_array())
                .ok_or(ProgramError::InvalidSeeds)?;
            if !registry.owned_by(_program_id) {
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
                if &super::registry_keyset_digest_v3(&parsed) != pinned_digest {
                    return Err(ProgramError::InvalidSeeds);
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
            // The Fp12 paths read registry bytes directly, so they keep a
            // guest-side header check. The digest they check it against is the
            // one the pinned address encodes; binding the entries to this
            // fixture is the source comparison in `registry_gt_record`.
            if ix_tag != super::tag::REGISTRY
                && !super::registry_header_matches(
                    &registry_data,
                    &parsed,
                    _program_id.as_array(),
                    pinned_digest,
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
    fn pinned_addresses_are_distinct() {
        for (index, (digest, address)) in REGISTRY_V3_PINNED.iter().enumerate() {
            assert_eq!(
                pinned_registry_digest(address),
                Some(digest),
                "entry {index} is not reachable by lookup"
            );
            assert_eq!(
                REGISTRY_V3_PINNED
                    .iter()
                    .filter(|(_, other)| other == address)
                    .count(),
                1,
                "entry {index} shares its address with another row"
            );
        }
    }

    #[test]
    fn unpinned_address_has_no_digest() {
        assert!(pinned_registry_digest(&[0u8; 32]).is_none());
    }
}

/// The GT-entry binding that replaced the hot-path keyset digest on the Fp12
/// rails. Point encodings are arbitrary here: the record reader compares bytes
/// and never interprets them.
#[cfg(all(test, not(target_os = "solana")))]
mod registry_gt_record_tests {
    use super::*;

    const N: usize = 3;
    const K: usize = 3;

    fn fixture_bytes() -> Vec<u8> {
        let mut data = vec![N as u8, K as u8, 0, 1, 2];
        data.extend((0..K * VK_BYTES + N * PROOF_BYTES + N * 32).map(|index| (index % 251) as u8));
        data
    }

    /// A registry image whose GT entries carry each key's own `alpha || beta`.
    fn registry_image(f: &Fixture<'_>) -> Vec<u8> {
        let mut data = vec![
            0u8;
            REGISTRY_V3_HEADER_BYTES
                + 3 * K * REGISTRY_V3_G2_ENTRY_BYTES
                + K * REGISTRY_V3_GT_ENTRY_BYTES
        ];
        for key in 0..K {
            let start = REGISTRY_V3_HEADER_BYTES
                + 3 * K * REGISTRY_V3_G2_ENTRY_BYTES
                + key * REGISTRY_V3_GT_ENTRY_BYTES;
            let vk = f.vk(key).expect("synthetic key");
            data[start..start + 32].copy_from_slice(&[0x40 | key as u8; 32]);
            data[start + 32..start + 96].copy_from_slice(vk.alpha);
            data[start + 96..start + 224].copy_from_slice(vk.beta);
            data[start + 224..start + 608].copy_from_slice(&[0x90 | key as u8; 384]);
        }
        data
    }

    #[test]
    fn a_matching_source_carries_the_entry_id_and_target() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        let image = registry_image(&fixture);
        for key in 0..K {
            let (id, target) =
                registry_gt_record(&image, key, &fixture).expect("entry binds to its key");
            assert_eq!(id, [0x40 | key as u8; 32], "key {key} took the wrong id");
            assert_eq!(
                target.0,
                [0x90 | key as u8; 384],
                "key {key} took the wrong target"
            );
        }
    }

    /// One byte of the stored source is enough. Another keyset's registry
    /// differs in every source, so its target cannot reach the comparison.
    #[test]
    fn a_substituted_source_is_rejected() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        for key in 0..K {
            for offset in [32usize, 95, 96, 223] {
                let mut image = registry_image(&fixture);
                let start = REGISTRY_V3_HEADER_BYTES
                    + 3 * K * REGISTRY_V3_G2_ENTRY_BYTES
                    + key * REGISTRY_V3_GT_ENTRY_BYTES;
                image[start + offset] ^= 1;
                assert!(
                    registry_gt_record(&image, key, &fixture).is_none(),
                    "key {key} accepted a source it does not stand for at byte {offset}"
                );
            }
        }
    }

    /// A key's entry must be the entry at its own index, so two keys cannot
    /// swap targets.
    #[test]
    fn another_keys_entry_is_rejected() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        let image = registry_image(&fixture);
        // two entries swapped: each now stands for the other key
        let mut swapped = image.clone();
        let base = REGISTRY_V3_HEADER_BYTES + 3 * K * REGISTRY_V3_G2_ENTRY_BYTES;
        let first = base..base + REGISTRY_V3_GT_ENTRY_BYTES;
        let second = base + REGISTRY_V3_GT_ENTRY_BYTES..base + 2 * REGISTRY_V3_GT_ENTRY_BYTES;
        let head = image[first.clone()].to_vec();
        let next = image[second.clone()].to_vec();
        swapped[first].copy_from_slice(&next);
        swapped[second].copy_from_slice(&head);
        assert!(registry_gt_record(&swapped, 0, &fixture).is_none());
        assert!(registry_gt_record(&swapped, 1, &fixture).is_none());
    }

    #[test]
    fn an_out_of_range_key_and_a_truncated_registry_are_rejected() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        let image = registry_image(&fixture);
        assert!(registry_gt_record(&image, K, &fixture).is_none());
        let mut short = image.clone();
        short.truncate(short.len() - 1);
        assert!(registry_gt_record(&short, K - 1, &fixture).is_none());
    }

    /// The header check no longer recomputes the keyset digest, so it must
    /// still refuse a header that does not carry the digest its address
    /// encodes.
    #[test]
    fn the_header_check_binds_the_pinned_digest() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        let consumer = [7u8; 32];
        let digest = [9u8; 32];
        let mut header = vec![0u8; REGISTRY_V3_HEADER_BYTES];
        header[..8].copy_from_slice(REGISTRY_V3_MAGIC);
        header[8] = REGISTRY_V3_VERSION;
        header[9] = REGISTRY_V3_FROZEN;
        header[10] = REGISTRY_V3_CURVE;
        header[11] = REGISTRY_V3_BACKEND_B5;
        header[12..14].copy_from_slice(&(3 * K as u16).to_le_bytes());
        header[14..16].copy_from_slice(&(K as u16).to_le_bytes());
        header[16..48].copy_from_slice(&consumer);
        header[48..80].copy_from_slice(&digest);
        let mut image = header.clone();
        image.resize(
            REGISTRY_V3_HEADER_BYTES
                + 3 * K * REGISTRY_V3_G2_ENTRY_BYTES
                + K * REGISTRY_V3_GT_ENTRY_BYTES,
            0,
        );
        assert!(registry_header_matches(&image, &fixture, &consumer, &digest));
        for byte in 0..REGISTRY_V3_HEADER_BYTES {
            let mut mutated = image.clone();
            mutated[byte] ^= 1;
            assert!(
                !registry_header_matches(&mutated, &fixture, &consumer, &digest),
                "header byte {byte} is unchecked"
            );
        }
        let mut short = image.clone();
        short.truncate(short.len() - 1);
        assert!(!registry_header_matches(&short, &fixture, &consumer, &digest));
    }
}

/// The fixture-to-registry binding that replaced the hot-path keyset digest.
/// Point encodings are arbitrary here: the suffix builder compares bytes and
/// never interprets them.
#[cfg(all(test, not(target_os = "solana")))]
mod registered_suffix_tests {
    use super::*;

    const N: usize = 2;
    const K: usize = 2;

    /// `[n][k][vk_index][k x vk][n x proof][n x pubinput]` filled with a
    /// position-dependent pattern, so every G2 in the fold is distinct.
    fn fixture_bytes() -> Vec<u8> {
        let mut data = vec![N as u8, K as u8, 0, 1];
        data.extend((0..K * VK_BYTES + N * PROOF_BYTES + N * 32).map(|index| (index % 251) as u8));
        data
    }

    /// A registry image whose G2 sources are the fold's own fixed-G2 suffix.
    fn registry_image(pairs: &[PodG1G2Pair]) -> Vec<u8> {
        let mut data = vec![0u8; REGISTRY_V3_HEADER_BYTES + 3 * K * REGISTRY_V3_G2_ENTRY_BYTES];
        for slot in 0..3 * K {
            let start = REGISTRY_V3_HEADER_BYTES + slot * REGISTRY_V3_G2_ENTRY_BYTES;
            data[start..start + 32].copy_from_slice(&[slot as u8; 32]);
            data[start + 32..start + 160].copy_from_slice(&pairs[N + slot].g2.0);
        }
        data
    }

    /// `n + 3k` pairs with a distinct G2 per position.
    fn fold_pairs() -> Vec<PodG1G2Pair> {
        (0..N + 3 * K)
            .map(|index| PodG1G2Pair {
                g1: PodG1Point([index as u8; 64]),
                g2: PodG2Point([0x80 | index as u8; 128]),
            })
            .collect()
    }

    #[test]
    fn matching_sources_carry_the_entry_ids() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        let pairs = fold_pairs();
        let registered =
            registered_suffix(&fixture, &pairs, &registry_image(&pairs)).expect("suffix binds");
        assert_eq!(registered.len(), 3 * K);
        for (slot, pair) in registered.iter().enumerate() {
            assert_eq!(pair.g2_id, [slot as u8; 32], "slot {slot} took the wrong id");
            assert_eq!(pair.g1, pairs[N + slot].g1, "slot {slot} took the wrong G1");
        }
    }

    /// One byte of one source is enough: another keyset's registry differs in
    /// every source, so it cannot reach the pairing.
    #[test]
    fn a_substituted_source_is_rejected() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        let pairs = fold_pairs();
        for slot in 0..3 * K {
            let mut image = registry_image(&pairs);
            let source = REGISTRY_V3_HEADER_BYTES + slot * REGISTRY_V3_G2_ENTRY_BYTES + 32;
            image[source] ^= 1;
            assert!(
                registered_suffix(&fixture, &pairs, &image).is_none(),
                "slot {slot} accepted a source it does not pair against"
            );
        }
    }

    /// The suffix must consume the fold to its end, so a registry that is short
    /// of entries cannot silently drop a key's pairs.
    #[test]
    fn a_truncated_registry_is_rejected() {
        let bytes = fixture_bytes();
        let fixture = parse(&bytes).expect("synthetic fixture parses");
        let pairs = fold_pairs();
        let mut image = registry_image(&pairs);
        image.truncate(REGISTRY_V3_HEADER_BYTES + (3 * K - 1) * REGISTRY_V3_G2_ENTRY_BYTES);
        assert!(registered_suffix(&fixture, &pairs, &image).is_none());
    }
}

/// The multi-key Fp12 fold as it stood before the coefficients moved into the
/// scalar-field syscall, kept as the bit-exactness reference for
/// [`batch_fp12_identity_tests`].
#[cfg(test)]
fn reference_batch_fp12_fold(
    keys: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    randomizers: &[Fr],
) -> Option<(Vec<PodG1G2Pair>, Vec<(usize, PodScalar)>)> {
    use ark_ff::Zero;
    use core::ops::{AddAssign, Mul, Neg};

    if randomizers.len() != proofs.len() {
        return None;
    }
    let mut pairs = Vec::with_capacity(proofs.len() + 2 * keys.len());
    for (index, (proof, randomizer)) in proofs.iter().zip(randomizers).enumerate() {
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

    let mut exponents = Vec::with_capacity(keys.len());
    for key_index in 0..keys.len() {
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

        exponents.push((key_index, PodScalar(fr_to_pod(&r_sum))));
    }
    Some((pairs, exponents))
}

#[cfg(all(test, not(target_os = "solana")))]
mod batch_fp12_identity_tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::rngs::StdRng;
    use solana_bn254_groth16_batch::test_utils::{fr_bytes, make_proof, make_vk, rng};

    const R_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    /// `(label, keys, proofs)` over every multi-key shape the fold
    /// distinguishes: one proof per key, several proofs sharing a key, a
    /// zero-input circuit, several IC columns, and a committed key, which the
    /// grid never runs but the fold must not diverge on.
    fn batches() -> Vec<(&'static str, Vec<ValidatedVerifyingKey>, Vec<Proof>)> {
        let mut rng = rng();
        let mut out = Vec::new();

        // the grid's own shapes: k distinct keys, one proof each
        for (label, k) in [("k1_n1", 1usize), ("k2_n2", 2), ("k3_n3", 3), ("k5_n5", 5)] {
            let mut keys = Vec::new();
            let mut proofs = Vec::new();
            for index in 0..k {
                let (trapdoor, vk) = make_vk(&mut rng, 1, false);
                let input = Fr::rand(&mut rng);
                proofs.push(make_proof(&mut rng, &trapdoor, index as u16, &[input]));
                keys.push(vk);
            }
            out.push((label, keys, proofs));
        }

        for (label, inputs, committed) in [
            ("k2_shared_zero_inputs", 0usize, false),
            ("k2_shared_four_inputs", 4, false),
            ("k2_shared_committed", 1, true),
        ] {
            let mut keys = Vec::new();
            let mut proofs = Vec::new();
            for key_index in 0..2u16 {
                let (trapdoor, vk) = make_vk(&mut rng, inputs, committed);
                // two proofs under the first key, one under the second, so a
                // column with more than one term is covered
                for _ in 0..(2 - usize::from(key_index)) {
                    let values: Vec<Fr> = (0..inputs).map(|_| Fr::rand(&mut rng)).collect();
                    proofs.push(make_proof(&mut rng, &trapdoor, key_index, &values));
                }
                keys.push(vk);
            }
            out.push((label, keys, proofs));
        }
        out
    }

    fn assert_same_fold(
        label: &str,
        keys: &[ValidatedVerifyingKey],
        proofs: &[Proof],
        randomizers: &[Fr],
    ) {
        let scalars: Vec<PodScalar> = randomizers
            .iter()
            .map(|randomizer| PodScalar(fr_to_pod(randomizer)))
            .collect();
        let expected = reference_batch_fp12_fold(keys, proofs, randomizers);
        let folded = batch_fp12_fold(keys, proofs, &scalars);
        match (&expected, &folded) {
            (Some((expected_pairs, expected_exponents)), Some((pairs, exponents))) => {
                assert_eq!(expected_pairs.len(), pairs.len(), "{label}: pair count");
                for (index, (expected, folded)) in expected_pairs.iter().zip(pairs).enumerate() {
                    assert_eq!(expected, folded, "{label}: pair {index}");
                }
                assert_eq!(expected_exponents, exponents, "{label}: target exponents");
            }
            _ => assert!(
                expected.is_none() && folded.is_none(),
                "{label}: one fold produced a result and the other did not"
            ),
        }
    }

    fn transcript_randomizers(keys: &[ValidatedVerifyingKey], proofs: &[Proof]) -> Vec<Fr> {
        let seed = derive_seed(RandomizerMode::Independent, keys, proofs);
        reference_batch_fp12_randomizers(&seed, proofs.len())
    }

    /// The byte draw must reproduce the field draw exactly. It feeds the MSM
    /// scalars, so a divergence changes the statement the map proves while
    /// still verifying.
    #[test]
    fn byte_randomizers_are_the_field_path() {
        for (label, keys, proofs) in batches() {
            let seed = derive_seed(RandomizerMode::Independent, &keys, &proofs);
            for count in [1usize, proofs.len(), 7, 16] {
                let expected: Vec<PodScalar> = reference_batch_fp12_randomizers(&seed, count)
                    .iter()
                    .map(|randomizer| PodScalar(fr_to_pod(randomizer)))
                    .collect();
                let scalars = batch_fp12_randomizers(&seed, count);
                assert_eq!(scalars.len(), count, "{label}: count {count}");
                for (index, (scalar, expected)) in scalars.iter().zip(&expected).enumerate() {
                    assert_eq!(scalar, expected, "{label}: count {count} index {index}");
                }
            }
        }
    }

    /// Bit-identical to the field-arithmetic reference over the randomizers the
    /// guest actually derives.
    #[test]
    fn derived_randomizers_fold_identically() {
        for (label, keys, proofs) in batches() {
            validate_batch_shape(&keys, &proofs).expect("fixture must be a valid batch shape");
            let randomizers = transcript_randomizers(&keys, &proofs);
            assert_eq!(randomizers.first(), Some(&Fr::one()));
            assert_same_fold(label, &keys, &proofs, &randomizers);
        }
    }

    /// Randomizer values at the edges of the field, including the zero the
    /// derivation cannot produce, plus a distinct value per proof.
    #[test]
    fn edge_randomizers_fold_identically() {
        use core::ops::Sub;

        let mut rng = rng();
        let edges = [
            Fr::one(),
            Fr::from(0u64),
            Fr::from(0u64).sub(Fr::one()),
            Fr::from(2u64),
            Fr::from(1u128 << 127),
            Fr::from(u128::MAX) + Fr::one(),
        ];
        for (label, keys, proofs) in batches() {
            for (index, edge) in edges.iter().enumerate() {
                let randomizers = vec![*edge; proofs.len()];
                assert_same_fold(
                    &format!("{label}/uniform{index}"),
                    &keys,
                    &proofs,
                    &randomizers,
                );
            }
            let mixed: Vec<Fr> = (0..proofs.len()).map(|_| Fr::rand(&mut rng)).collect();
            assert_same_fold(&format!("{label}/random"), &keys, &proofs, &mixed);
        }
    }

    /// Public inputs at the ends of the canonical range, where a byte path that
    /// skipped the field would be most likely to diverge.
    #[test]
    fn edge_public_inputs_fold_identically() {
        let mut r_minus_one = R_BE;
        r_minus_one[31] = 0x00;
        let mut two_pow_128 = [0u8; 32];
        two_pow_128[15] = 1;
        let edges = [
            PodScalar([0u8; 32]),
            fr_bytes(&Fr::one()),
            PodScalar(r_minus_one),
            PodScalar(two_pow_128),
        ];

        for (label, keys, proofs) in batches() {
            let randomizers = transcript_randomizers(&keys, &proofs);
            for (index, edge) in edges.iter().enumerate() {
                let mut mutated = proofs.clone();
                for proof in &mut mutated {
                    for input in &mut proof.public_inputs {
                        *input = *edge;
                    }
                }
                assert_same_fold(
                    &format!("{label}/all-inputs-{index}"),
                    &keys,
                    &mutated,
                    &randomizers,
                );

                let mut single = proofs.clone();
                if let Some(input) = single
                    .first_mut()
                    .and_then(|proof| proof.public_inputs.first_mut())
                {
                    *input = *edge;
                    assert_same_fold(
                        &format!("{label}/first-input-{index}"),
                        &keys,
                        &single,
                        &randomizers,
                    );
                }
            }
        }
    }

    /// A public input at or above r never reaches the fold, and the fold itself
    /// still refuses one: the scalar-field call rejects rather than reduces.
    #[test]
    fn non_canonical_public_input_is_still_rejected() {
        let mut r_plus_one = R_BE;
        r_plus_one[31] = 0x02;
        for bad in [R_BE, r_plus_one, [0xffu8; 32]] {
            for (label, keys, proofs) in batches() {
                if proofs.iter().all(|proof| proof.public_inputs.is_empty()) {
                    continue;
                }
                let randomizers: Vec<PodScalar> = transcript_randomizers(&keys, &proofs)
                    .iter()
                    .map(|randomizer| PodScalar(fr_to_pod(randomizer)))
                    .collect();
                for position in 0..proofs.len() {
                    let mut mutated = proofs.clone();
                    if mutated[position].public_inputs.is_empty() {
                        continue;
                    }
                    mutated[position].public_inputs[0] = PodScalar(bad);
                    assert!(
                        validate_batch_shape(&keys, &mutated).is_err(),
                        "{label}: shape check accepted a non-canonical input at {position}"
                    );
                    assert!(
                        batch_fp12_fold(&keys, &mutated, &randomizers).is_none(),
                        "{label}: fold accepted a non-canonical input at {position}"
                    );
                }
            }
        }
    }

    /// The scalar helpers against arkworks, with the folded constants derived
    /// here rather than trusted.
    #[test]
    fn scalar_helpers_match_field_arithmetic() {
        use core::ops::{Neg, Sub};

        assert_eq!(MINUS_ONE_BE.0, fr_to_pod(&Fr::one().neg()));
        assert_eq!(ONE_BE.0, fr_to_pod(&Fr::one()));

        let mut rng: StdRng = rng();
        let mut values = vec![
            Fr::from(0u64),
            Fr::one(),
            Fr::from(0u64).sub(Fr::one()),
            Fr::from(u128::MAX) + Fr::one(),
        ];
        values.extend((0..8).map(|_| Fr::rand(&mut rng)));

        for value in &values {
            assert_eq!(
                fr_negate(&PodScalar(fr_to_pod(value))),
                Some(PodScalar(fr_to_pod(&value.neg())))
            );
        }
        for width in 1..=values.len() {
            let window = &values[..width];
            let pods: Vec<PodScalar> = window
                .iter()
                .map(|value| PodScalar(fr_to_pod(value)))
                .collect();
            let sum: Fr = window.iter().copied().sum();
            assert_eq!(
                fr_sum(&pods),
                Some(PodScalar(fr_to_pod(&sum))),
                "sum {width}"
            );

            let other: Vec<Fr> = (0..width).map(|_| Fr::rand(&mut rng)).collect();
            let other_pods: Vec<PodScalar> = other
                .iter()
                .map(|value| PodScalar(fr_to_pod(value)))
                .collect();
            let inner: Fr = window.iter().zip(&other).map(|(x, y)| *x * y).sum();
            assert_eq!(
                fr_inner_product(&pods, &other_pods),
                Some(PodScalar(fr_to_pod(&inner))),
                "inner product {width}"
            );
        }
        assert_eq!(fr_sum(&[]), None);
    }
}

/// Fixture record sizes for the host-side builder.
pub mod layout {
    pub const VK_BYTES: usize = super::VK_BYTES;
    pub const PROOF_BYTES: usize = super::PROOF_BYTES;
    pub const REGISTRY_PDA_SEED: &[u8] = super::REGISTRY_V3_PDA_SEED;
}
