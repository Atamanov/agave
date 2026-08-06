//! Direct PLONK fixture program for the BN254 decision grid.
//!
//! Only the three byte-exact committed snarkjs fixtures are admitted. They are
//! shaped like zolana transact, one public signal over a Poseidon chain at
//! (nIn, nOut) of 1_1, 2_2 and 2_3, and they are test fixtures, not production
//! proofs. They carry distinct keys over one authenticated SRS. The optimized
//! paths preserve the audited `023-neg-scalars` transcript/scalar kernel and
//! concatenate exactly `2n` and `18n` G1 terms into two MSMs. Tags mirror the
//! Groth16 guest: 0 current, 2 B5, 3 B5 registry, 4 B5+Fp12, 5 registry init,
//! and 9 current+Fp12.

#![cfg_attr(target_os = "solana", no_std)]

extern crate alloc;

use {
    alloc::{vec, vec::Vec},
    plonk_solana::{
        Fr as OptimizedFr, G1 as OptimizedG1, G2 as OptimizedG2, Proof as OptimizedProof,
        VerificationKey as OptimizedVerifyingKey,
    },
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodG1RegisteredG2Pair, PodG2Point, PodScalar,
        PodSnarkjsPlonkMultiVkContext, PodSnarkjsPlonkMultiVkInput,
        PodSnarkjsPlonkReductionContext, PodSnarkjsPlonkReductionInput,
    },
    solana_keccak_hasher::hashv,
};

#[allow(dead_code)]
mod optimized_023;

use optimized_023::{
    BatchScalar, G2_GENERATOR_BE, P_CONTRIBUTIONS, PairingContributionSink, Q_CONTRIBUTIONS,
    prepare_pairing_contributions, verify as verify_023,
};

#[cfg(all(feature = "registry-syscall", target_os = "solana"))]
use solana_bn254_batch_syscall::{
    Version as SyscallVersion, alt_bn128_pairing_check_registered, alt_bn128_vk_registry_init,
    registry_account_len,
};

use optimized_023::prepare_pairing_operands;

pub mod tag {
    pub const CURRENT: u8 = 0;
    pub const BATCH_B5: u8 = 2;
    pub const REGISTRY_B5: u8 = 3;
    pub const BATCH_FP12_B5: u8 = 4;
    pub const REGISTRY_INIT: u8 = 5;
    pub const CURRENT_FP12: u8 = 9;
}

/// Exact transaction account count for each measured tag. Fp12 changes only
/// the final pairing handler; it does not introduce registry state.
pub const fn expected_account_count(tag: u8) -> Option<usize> {
    match tag {
        tag::CURRENT | tag::BATCH_B5 | tag::BATCH_FP12_B5 | tag::CURRENT_FP12 => Some(1),
        tag::REGISTRY_B5 | tag::REGISTRY_INIT => Some(2),
        _ => None,
    }
}

pub mod layout {
    pub const MAGIC: &[u8; 8] = b"PLKFP12\0";
    pub const VERSION: u8 = 1;
    pub const HEADER_BYTES: usize = 12;
    pub const GROUP_HEADER_BYTES: usize = 4;
    pub const VK_BYTES: usize = 8 + 4 + 5 * 64 + 3 * 64 + 2 * 32 + 2 * 128;
    pub const PROOF_BASE_BYTES: usize = 9 * 64 + 6 * 32;
    pub const FQ12_BYTES: usize = 384;
    pub const MAX_GROUPS: usize = 16;
    pub const MAX_TOTAL_PROOFS: usize = 32;
    pub const REGISTRY_PDA_SEED: &[u8] = b"bn254-b5-vk-registry-v3";
    pub const INPUT_PDA_SEED: &[u8] = b"plonk-input-v1";
    pub const REGISTRY_MAGIC: &[u8; 8] = b"B254VK3\0";
    pub const REGISTRY_VERSION: u8 = 3;
    pub const REGISTRY_FROZEN: u8 = 1;
    pub const REGISTRY_CURVE_BN254: u8 = 1;
    pub const REGISTRY_HEADER_BYTES: usize = 80;
    pub const REGISTRY_KEYSET_DIGEST_BYTES: usize = 32;
    pub const REGISTRY_SOURCE_COUNT: usize = 2;
    pub const REGISTRY_BACKEND_B5: u8 = 5;
    pub const REGISTRY_SOURCE_BYTES: usize = 128;
    pub const OPAQUE_G2_ID_BYTES: usize = 32;
    pub const REGISTRY_HOT_INSTRUCTION_BYTES: usize = 1 + 2 * OPAQUE_G2_ID_BYTES;
    pub const REGISTERED_PAIR_BYTES: usize = 64 + OPAQUE_G2_ID_BYTES;
    /// This branch's prepared-G2 wire size. It is not the format the stateless
    /// prepare syscalls emit, which `bn254-batch-syscall::prepared_abi` pins at
    /// `PREPARED_G2_WIRE_BYTES = 16_712` on `local/bn254-prepared-stateless`.
    /// Two formats exist because the two branches grew apart; converging them
    /// changes every sealed registry digest, so it is a deliberate change and
    /// not a constant to quietly retune. `registry_account_size_is_pinned`
    /// fails if this moves untracked.
    pub const G2_PREPARED_BYTES: usize = 37_584;
    pub const REGISTRY_ENTRY_BYTES: usize =
        OPAQUE_G2_ID_BYTES + REGISTRY_SOURCE_BYTES + G2_PREPARED_BYTES;
    pub const REGISTRY_BYTES: usize =
        REGISTRY_HEADER_BYTES + REGISTRY_SOURCE_COUNT * REGISTRY_ENTRY_BYTES;
}

const KEYSET_DIGEST_DOMAIN: &[u8] = b"zolana:bn254:plonk:g2-registry-keyset:v1";
const REGISTRY_V3_KEYSET_DOMAIN: &[u8] = b"agave:bn254:b5:keyset:v3";
// Code-derived from the exact allowlisted shared `[1]_2`, `[tau]_2` sources.
// Registry initialization independently recomputes and checks this value.
#[cfg(any(target_os = "solana", test))]
const AUTHENTICATED_REGISTRY_KEYSET_DIGEST_V3: [u8; 32] = [
    0xfc, 0xd7, 0x36, 0xe3, 0x1b, 0x14, 0x8a, 0xaf, 0xd7, 0x34, 0xbf, 0x34, 0x17, 0xb5, 0xc8, 0xdb,
    0xfc, 0x97, 0x77, 0x92, 0xf6, 0xa6, 0x90, 0x01, 0x99, 0x55, 0x24, 0x1f, 0xac, 0x84, 0x43, 0x05,
];
/// Consumer both pinned address tables are derived under. A guest loaded at
/// any other program id must reject: the pinned addresses would not be
/// program-derived addresses of the running program.
#[cfg(any(target_os = "solana", test))]
const REGISTRY_V3_CONSUMER: [u8; 32] = [42u8; 32];

/// `(keyset digest, registry PDA)` for every keyset the grid runs, standing in
/// for what a real consumer emits at codegen time. The address is
/// `find_program_address([REGISTRY_PDA_SEED, digest], REGISTRY_V3_CONSUMER)`
/// and `pinned_registry_addresses_derive` re-runs that derivation. Lookup is
/// keyed by the digest the guest recomputes from the account, so a fixture
/// cannot present another keyset's registry account.
#[cfg(any(target_os = "solana", test))]
const REGISTRY_V3_PINNED: [([u8; 32], [u8; 32]); 1] = [(
    AUTHENTICATED_REGISTRY_KEYSET_DIGEST_V3,
    [
        0x89, 0xcd, 0x12, 0x7c, 0x74, 0xb2, 0x75, 0x6a, 0xb1, 0x78, 0xc4, 0x2a, 0x84, 0x77, 0x22,
        0x20, 0x9a, 0x90, 0x57, 0x29, 0x5c, 0x89, 0x8f, 0xb3, 0xcb, 0x13, 0x48, 0x55, 0x08, 0xa8,
        0xaa, 0xbe,
    ],
)];

#[cfg(not(target_os = "solana"))]
const OPAQUE_G2_ID_DOMAIN: &[u8] = b"agave:bn254:b5:g2-registry:v3";
const KEYSET_DIGEST_VERSION: u8 = 1;
const POLICY_KEYSET_DIGESTS: [[u8; 32]; 5] = [
    // transact_1_1 alone
    [
        0x20, 0x0f, 0x96, 0xba, 0xbc, 0x80, 0x40, 0x91, 0x1e, 0xa3, 0x9f, 0xdd, 0xc4, 0xe6, 0x31,
        0x66, 0x1a, 0x59, 0xec, 0x86, 0x4a, 0x5b, 0xd8, 0x60, 0x72, 0x71, 0x27, 0xa7, 0xfb, 0x92,
        0x9d, 0x4d,
    ],
    // transact_2_2 alone
    [
        0x31, 0x30, 0x3f, 0x56, 0xd8, 0x63, 0x9a, 0x1e, 0xea, 0xb2, 0x1c, 0x6d, 0xc9, 0xbc, 0x4a,
        0xbe, 0x23, 0x76, 0x01, 0x0c, 0x8f, 0x9d, 0xdc, 0xef, 0x16, 0x91, 0x1d, 0xe1, 0x46, 0x2d,
        0x3f, 0x31,
    ],
    // transact_2_3 alone
    [
        0xf9, 0x8c, 0x1f, 0x36, 0xeb, 0x5a, 0xc1, 0x56, 0x75, 0xae, 0x69, 0xd8, 0x82, 0xc7, 0xde,
        0xc1, 0x11, 0x6e, 0x73, 0x1a, 0xab, 0x88, 0x23, 0x5c, 0xfb, 0x70, 0x92, 0x75, 0x13, 0x9c,
        0x83, 0xe2,
    ],
    // row n2
    [
        0x8b, 0x96, 0x5f, 0x9a, 0x42, 0x16, 0x05, 0xe6, 0xc6, 0x6e, 0x43, 0x5f, 0x4a, 0xaa, 0x7d,
        0x04, 0x43, 0x45, 0x72, 0x33, 0x50, 0x84, 0xb2, 0x74, 0xae, 0xaf, 0xd4, 0x53, 0x00, 0x5b,
        0xaf, 0x4b,
    ],
    // row n3
    [
        0x4c, 0x9d, 0xa2, 0x24, 0x2e, 0x41, 0x6b, 0x52, 0x8b, 0x92, 0x3e, 0x76, 0x32, 0x6b, 0x1b,
        0xc5, 0xd3, 0xe0, 0xe6, 0x14, 0xd6, 0x24, 0x38, 0x4a, 0xfe, 0xe6, 0x30, 0xf7, 0x34, 0x6a,
        0x6b, 0xb1,
    ],
];

/// Input-account PDA of each allowlisted keyset, index-aligned with
/// [`POLICY_KEYSET_DIGESTS`], standing in for what a real consumer emits at
/// codegen time. Each entry is
/// `find_program_address([INPUT_PDA_SEED, digest], REGISTRY_V3_CONSUMER)` and
/// `pinned_input_addresses_derive` re-runs that derivation. Membership in this
/// table is the keyset allowlist, so a keyset outside the policy has no
/// address and cannot reach a verifier.
#[cfg(any(target_os = "solana", test))]
const POLICY_INPUT_ADDRESSES: [[u8; 32]; POLICY_KEYSET_DIGESTS.len()] = [
    // transact_1_1 alone
    [
        0x4f, 0xe3, 0x1f, 0x3c, 0xd0, 0xe0, 0x82, 0x87, 0x0f, 0xa1, 0xfb, 0x63, 0x1c, 0x41, 0xbe,
        0xdc, 0xfb, 0x52, 0xc5, 0x2d, 0x08, 0x31, 0x7e, 0x6c, 0x78, 0x96, 0x11, 0xf2, 0x2a, 0xe1,
        0x0b, 0xfc,
    ],
    // transact_2_2 alone
    [
        0x9e, 0x46, 0xf4, 0x4b, 0x62, 0x62, 0xe1, 0x2d, 0x05, 0xed, 0x37, 0x13, 0xa4, 0xd2, 0xa7,
        0x41, 0x59, 0x05, 0x2b, 0xd0, 0x26, 0x78, 0x10, 0x0a, 0x45, 0xfd, 0x6f, 0x84, 0xdb, 0x44,
        0xe5, 0x61,
    ],
    // transact_2_3 alone
    [
        0x1f, 0xe4, 0xb9, 0xd8, 0xa1, 0x0d, 0x9c, 0xff, 0xde, 0xed, 0x92, 0x9b, 0x69, 0x81, 0x02,
        0xc9, 0x28, 0x2b, 0x4b, 0x0c, 0x66, 0x4e, 0x04, 0xd3, 0xee, 0xbd, 0xda, 0x05, 0x97, 0x64,
        0xc0, 0x0c,
    ],
    // row n2
    [
        0x07, 0x2c, 0x47, 0x46, 0xe2, 0xa0, 0xb6, 0x4e, 0xa8, 0xc3, 0x0d, 0xc8, 0x4a, 0x31, 0xc1,
        0x1c, 0x85, 0x99, 0x28, 0x4b, 0x2e, 0x99, 0xb8, 0xae, 0x6e, 0xf7, 0x3f, 0x63, 0x62, 0x5b,
        0x91, 0xb6,
    ],
    // row n3
    [
        0x90, 0xfa, 0xfc, 0x74, 0xa7, 0xbb, 0xe0, 0x21, 0xec, 0xdf, 0x3e, 0x26, 0x70, 0x53, 0x8e,
        0x6f, 0x7c, 0x83, 0x70, 0x0b, 0x2e, 0x2a, 0x07, 0x80, 0xa4, 0x53, 0x90, 0xa0, 0x56, 0x5a,
        0xe6, 0xd8,
    ],
];

const TRANSACT_1_1_KEY_DIGEST: [u8; 32] = [
    0x1e, 0xc1, 0xa5, 0x4b, 0x3a, 0xad, 0xea, 0x2a, 0x30, 0x8e, 0xf1, 0x77, 0xcd, 0xec, 0x6a, 0x89,
    0x8c, 0xd0, 0xab, 0x21, 0x53, 0xb5, 0x21, 0x70, 0x66, 0x7d, 0x94, 0x81, 0x36, 0x38, 0x15, 0x16,
];

const TRANSACT_2_2_KEY_DIGEST: [u8; 32] = [
    0x67, 0x6b, 0x3a, 0xdd, 0xca, 0xe8, 0x3d, 0x1d, 0xcd, 0x70, 0x2d, 0x5a, 0xa6, 0x37, 0xcf, 0x2e,
    0xd4, 0x1f, 0xd0, 0x8f, 0x36, 0x87, 0x61, 0x23, 0x18, 0xdb, 0xa0, 0xfb, 0xae, 0x90, 0xbf, 0xf2,
];

const TRANSACT_2_3_KEY_DIGEST: [u8; 32] = [
    0x8d, 0x59, 0x14, 0xd5, 0x88, 0xd0, 0x82, 0xeb, 0x87, 0xb7, 0x1d, 0xbb, 0x7a, 0x17, 0x71, 0x9e,
    0xe7, 0xc4, 0xd6, 0x87, 0x5a, 0xed, 0x7d, 0x2c, 0x49, 0xe0, 0xfa, 0x28, 0xeb, 0x56, 0x09, 0xff,
];

/// Canonical snarkjs roots of unity, by domain power. A verifying key does not
/// carry omega on the wire, so it is derived from the domain size the key does
/// carry, and a wrong entry would evaluate the vanishing polynomial on the wrong
/// domain. `authenticated_omega_matches_every_fixture` checks the table against
/// the `w` each fixture key declares.
const AUTHENTICATED_OMEGA_BY_POWER: [(u32, [u8; 32]); 2] = [
    (
        13,
        [
            0x00, 0x6f, 0xab, 0x49, 0xb8, 0x69, 0xae, 0x62, 0x00, 0x1d, 0xea, 0xc8, 0x78, 0xb2,
            0x66, 0x7b, 0xd3, 0x1b, 0xf3, 0xe2, 0x8e, 0x3a, 0x2d, 0x76, 0x4a, 0xa4, 0x9b, 0x8d,
            0x9b, 0xbd, 0xd3, 0x10,
        ],
    ),
    (
        14,
        [
            0x2d, 0x96, 0x56, 0x51, 0xcd, 0xd9, 0xe4, 0x81, 0x1f, 0x4e, 0x51, 0xb8, 0x0d, 0xdc,
            0xa8, 0xa8, 0xb4, 0xa9, 0x3e, 0xe1, 0x74, 0x20, 0xaa, 0xe6, 0xad, 0xaa, 0x01, 0xc2,
            0x61, 0x7c, 0x6e, 0x85,
        ],
    ),
];

fn authenticated_omega(domain_size: u64) -> Option<[u8; 32]> {
    if !domain_size.is_power_of_two() {
        return None;
    }
    let power = domain_size.trailing_zeros();
    AUTHENTICATED_OMEGA_BY_POWER
        .iter()
        .find_map(|(candidate, omega)| (*candidate == power).then_some(*omega))
}

/// Invariant, established by [`parse_vk`] and relied on by [`validate_group`]
/// and [`keyset_digest`]: `vk_digest` is `authenticated_vk_digest` over this
/// key's canonical account bytes and `application_context` is
/// `registry_context(&vk_digest)`. A key outside the fixture allowlist has no
/// context and never becomes a `Group`.
/// `parse_account_binds_every_group_to_its_key` pins this.
struct Group<'a> {
    vk: VerifyingKey<'a>,
    vk_digest: [u8; 32],
    application_context: [u8; 32],
    proofs: Vec<Proof<'a>>,
}

/// Every field is a view into the transaction's account mapping. The account
/// is readonly and outlives the instruction, and no handler mutates a key or a
/// proof, so a group costs pointers instead of a kilobyte of copies.
struct VerifyingKey<'a> {
    domain_size: u64,
    num_public_inputs: u32,
    q_m: &'a PodG1Point,
    q_l: &'a PodG1Point,
    q_r: &'a PodG1Point,
    q_o: &'a PodG1Point,
    q_c: &'a PodG1Point,
    s_sigma: [&'a PodG1Point; 3],
    k1: &'a PodScalar,
    k2: &'a PodScalar,
    g2_gen: &'a PodG2Point,
    g2_tau: &'a PodG2Point,
}

struct Evaluations<'a> {
    a: &'a PodScalar,
    b: &'a PodScalar,
    c: &'a PodScalar,
    s_sigma1: &'a PodScalar,
    s_sigma2: &'a PodScalar,
    z_omega: &'a PodScalar,
}

struct Proof<'a> {
    wire_commitments: [&'a PodG1Point; 3],
    grand_product: &'a PodG1Point,
    quotient: [&'a PodG1Point; 3],
    opening: &'a PodG1Point,
    shifted_opening: &'a PodG1Point,
    evaluations: Evaluations<'a>,
    public_inputs: &'a [PodScalar],
}

/// Borrowing an account field is only sound while these carry no alignment
/// requirement: the account layout packs them at arbitrary byte offsets.
const _: () = assert!(
    core::mem::align_of::<PodG1Point>() == 1
        && core::mem::align_of::<PodG2Point>() == 1
        && core::mem::align_of::<PodScalar>() == 1
);

fn read<const N: usize>(data: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let bytes = data.get(*offset..offset.checked_add(N)?)?;
    *offset += N;
    let mut output = [0u8; N];
    output.copy_from_slice(bytes);
    Some(output)
}

/// Advance past one packed field and return a view of it.
fn view<'a, T: bytemuck::Pod>(data: &'a [u8], offset: &mut usize) -> Option<&'a T> {
    let bytes = data.get(*offset..offset.checked_add(core::mem::size_of::<T>())?)?;
    *offset += core::mem::size_of::<T>();
    bytemuck::try_from_bytes(bytes).ok()
}

fn registry_context(digest: &[u8; 32]) -> Option<[u8; 32]> {
    let ordinal = match *digest {
        TRANSACT_1_1_KEY_DIGEST => 0usize,
        TRANSACT_2_2_KEY_DIGEST => 1usize,
        TRANSACT_2_3_KEY_DIGEST => 2usize,
        _ => return None,
    };
    // The custom-recursion circuit commits to these zero-based fixture
    // contexts. Every PLONK batching column uses the same transcript bytes.
    Some(application_context(ordinal))
}

/// Keccak over the exact canonical VK block. The account stores those fields
/// contiguously and in this order with no padding, so hashing the block is the
/// same statement as hashing the fields one by one, which is what the pinned
/// `TRANSACT_*_KEY_DIGEST` constants were sealed against.
/// `vk_digest_is_the_canonical_vk_block` pins the two spellings together.
fn authenticated_vk_digest(vk_bytes: &[u8]) -> [u8; 32] {
    hashv(&[vk_bytes]).to_bytes()
}

#[inline(never)]
fn parse_vk<'a>(
    data: &'a [u8],
    offset: &mut usize,
) -> Option<(VerifyingKey<'a>, [u8; 32], [u8; 32])> {
    let vk_bytes = data.get(*offset..offset.checked_add(layout::VK_BYTES)?)?;
    let key = VerifyingKey {
        domain_size: u64::from_be_bytes(read::<8>(data, offset)?),
        num_public_inputs: u32::from_be_bytes(read::<4>(data, offset)?),
        q_m: view(data, offset)?,
        q_l: view(data, offset)?,
        q_r: view(data, offset)?,
        q_o: view(data, offset)?,
        q_c: view(data, offset)?,
        s_sigma: [
            view(data, offset)?,
            view(data, offset)?,
            view(data, offset)?,
        ],
        k1: view(data, offset)?,
        k2: view(data, offset)?,
        g2_gen: view(data, offset)?,
        g2_tau: view(data, offset)?,
    };
    if key.g2_gen.0 == [0u8; 128] || key.g2_tau.0 == [0u8; 128] {
        return None;
    }
    // Qr and Qc are canonical projective infinity only when the circuit never
    // uses those selectors. Both spellings are admitted; a finite one is
    // validated like every other commitment, and every other commitment plus
    // both SRS points must stay finite either way. The decompression this
    // needs has no sBPF form, so the target enforces it through the validating
    // MSM and pairing syscalls that consume every admitted point instead.
    #[cfg(not(target_os = "solana"))]
    {
        use ark_ec::AffineRepr;
        let mut finite_g1_points = Vec::with_capacity(8);
        finite_g1_points.extend_from_slice(&[
            &key.q_m,
            &key.q_l,
            &key.q_o,
            &key.s_sigma[0],
            &key.s_sigma[1],
            &key.s_sigma[2],
        ]);
        if key.q_r.0 != [0u8; 64] {
            finite_g1_points.push(&key.q_r);
        }
        if key.q_c.0 != [0u8; 64] {
            finite_g1_points.push(&key.q_c);
        }
        for point in &finite_g1_points {
            if point.to_affine().ok()?.is_zero() {
                return None;
            }
        }
        if key.g2_gen.to_affine().ok()?.is_zero() || key.g2_tau.to_affine().ok()?.is_zero() {
            return None;
        }
    }
    // The complete canonical key bytes are authenticated against the static
    // fixture allowlist. Re-running `ValidatedVerifyingKey::trust` here would
    // redo three large coset exponentiations for every already trusted key on
    // every transaction. All admitted points are subsequently consumed by a
    // validating G1/MSM or pairing syscall.
    let digest = authenticated_vk_digest(vk_bytes);
    let context = registry_context(&digest)?;
    Some((key, digest, context))
}

#[inline(never)]
fn parse_proof<'a>(data: &'a [u8], offset: &mut usize, inputs: usize) -> Option<Proof<'a>> {
    let wire_commitments = [
        view(data, offset)?,
        view(data, offset)?,
        view(data, offset)?,
    ];
    let grand_product = view(data, offset)?;
    let quotient = [
        view(data, offset)?,
        view(data, offset)?,
        view(data, offset)?,
    ];
    let opening = view(data, offset)?;
    let shifted_opening = view(data, offset)?;
    let evaluations = Evaluations {
        a: view(data, offset)?,
        b: view(data, offset)?,
        c: view(data, offset)?,
        s_sigma1: view(data, offset)?,
        s_sigma2: view(data, offset)?,
        z_omega: view(data, offset)?,
    };
    let public_bytes = data.get(*offset..offset.checked_add(inputs.checked_mul(32)?)?)?;
    *offset += public_bytes.len();
    let public_inputs = bytemuck::try_cast_slice(public_bytes).ok()?;
    Some(Proof {
        wire_commitments,
        grand_product,
        quotient,
        opening,
        shifted_opening,
        evaluations,
        public_inputs,
    })
}

#[inline(never)]
fn parse_account(data: &[u8]) -> Option<Vec<Group<'_>>> {
    let mut offset = 0usize;
    if &read::<8>(data, &mut offset)? != layout::MAGIC {
        return None;
    }
    if read::<1>(data, &mut offset)?[0] != layout::VERSION {
        return None;
    }
    let group_count = usize::from(read::<1>(data, &mut offset)?[0]);
    if group_count == 0 || group_count > layout::MAX_GROUPS {
        return None;
    }
    if read::<2>(data, &mut offset)? != [0u8; 2] {
        return None;
    }

    let mut groups = Vec::with_capacity(group_count);
    let mut total = 0usize;
    for _ in 0..group_count {
        let proof_count = usize::from(u16::from_be_bytes(read::<2>(data, &mut offset)?));
        if proof_count == 0 || read::<2>(data, &mut offset)? != [0u8; 2] {
            return None;
        }
        total = total.checked_add(proof_count)?;
        if total > layout::MAX_TOTAL_PROOFS {
            return None;
        }
        let (vk, vk_digest, application_context) = parse_vk(data, &mut offset)?;
        let inputs = vk.num_public_inputs as usize;
        let mut proofs = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            proofs.push(parse_proof(data, &mut offset, inputs)?);
        }
        groups.push(Group {
            vk,
            vk_digest,
            application_context,
            proofs,
        });
    }
    (offset == data.len()).then_some(groups)
}

#[cfg(any(feature = "registry-syscall", not(target_os = "solana")))]
struct RegistryEntry<'a> {
    id: &'a [u8; layout::OPAQUE_G2_ID_BYTES],
    source: &'a [u8; layout::REGISTRY_SOURCE_BYTES],
}

#[cfg(any(feature = "registry-syscall", not(target_os = "solana")))]
struct RegistryState<'a> {
    keyset_digest: &'a [u8; layout::REGISTRY_KEYSET_DIGEST_BYTES],
    entries: [RegistryEntry<'a>; layout::REGISTRY_SOURCE_COUNT],
}

fn keyset_digest(groups: &[Group]) -> Option<[u8; 32]> {
    let version = [KEYSET_DIGEST_VERSION];
    let count = (groups.len() as u64).to_be_bytes();
    let mut parts = Vec::with_capacity(3 + groups.len());
    parts.push(KEYSET_DIGEST_DOMAIN);
    parts.push(&version);
    parts.push(&count);
    for group in groups {
        parts.push(&group.vk_digest);
    }
    Some(hashv(&parts).to_bytes())
}

fn policy_allows_keyset(digest: &[u8; 32]) -> bool {
    POLICY_KEYSET_DIGESTS
        .iter()
        .any(|allowed| allowed == digest)
}

/// Pinned input-account address of an allowlisted keyset. A keyset outside the
/// policy has no address and the caller must reject. One scan answers both
/// questions; deriving the address here instead would charge
/// `create_program_address` per bump attempt on every measured column.
#[cfg(any(target_os = "solana", test))]
fn pinned_input_address(digest: &[u8; 32]) -> Option<&'static [u8; 32]> {
    let index = POLICY_KEYSET_DIGESTS
        .iter()
        .position(|allowed| allowed == digest)?;
    POLICY_INPUT_ADDRESSES.get(index)
}

/// Common identity policy for every measured PLONK column. Account metadata
/// is enforced by the SBF entrypoint; this helper authenticates the exact
/// ordered full-VK set admitted at that address.
fn authenticated_input_digest(groups: &[Group]) -> Option<[u8; 32]> {
    let digest = keyset_digest(groups)?;
    policy_allows_keyset(&digest).then_some(digest)
}

fn shared_srs<'a>(groups: &[Group<'a>]) -> Option<[&'a PodG2Point; layout::REGISTRY_SOURCE_COUNT]> {
    let first = &groups.first()?.vk;
    groups
        .iter()
        .all(|group| {
            let key = &group.vk;
            key.g2_gen == first.g2_gen && key.g2_tau == first.g2_tau
        })
        .then_some([first.g2_gen, first.g2_tau])
}

/// Agave v3 registry digest for the exact ordered `[1]_2`, `[tau]_2` SRS.
/// This is separate from the legacy fixture-set allowlist digest above.
fn registry_keyset_digest_v3(groups: &[Group]) -> Option<[u8; 32]> {
    let sources = shared_srs(groups)?;
    Some(
        hashv(&[
            REGISTRY_V3_KEYSET_DOMAIN,
            &[layout::REGISTRY_VERSION],
            &(sources.len() as u16).to_le_bytes(),
            &0u16.to_le_bytes(),
            &sources[0].0,
            &sources[1].0,
        ])
        .to_bytes(),
    )
}

/// Hot-path digest after `parse_account` authenticated every complete VK.
/// All admitted fixture keys carry this byte-exact SRS; the shared-SRS and
/// generator checks prevent a future allowlist addition from silently using
/// the sealed digest for a different SRS.
#[cfg(any(target_os = "solana", test))]
fn sealed_registry_keyset_digest_v3(groups: &[Group]) -> Option<[u8; 32]> {
    let sources = shared_srs(groups)?;
    if sources[0].0 != G2_GENERATOR_BE {
        return None;
    }
    Some(AUTHENTICATED_REGISTRY_KEYSET_DIGEST_V3)
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

/// One-pass frozen-header authentication and ordered opaque-ID extraction.
/// The entrypoint first checks owner, readonly state, exact PDA and length.
/// The registered syscall then revalidates the canonical body and every ID
/// against this same registry account at index zero.
#[cfg(test)]
fn authenticated_registry_ids(
    data: &[u8],
    consumer: &[u8; 32],
    expected_digest: &[u8; 32],
) -> Option<[[u8; 32]; layout::REGISTRY_SOURCE_COUNT]> {
    if data.get(..8)? != layout::REGISTRY_MAGIC
        || *data.get(8)? != layout::REGISTRY_VERSION
        || *data.get(9)? != layout::REGISTRY_FROZEN
        || *data.get(10)? != layout::REGISTRY_CURVE_BN254
        || *data.get(11)? != layout::REGISTRY_BACKEND_B5
        || u16::from_le_bytes(data.get(12..14)?.try_into().ok()?) as usize
            != layout::REGISTRY_SOURCE_COUNT
        || u16::from_le_bytes(data.get(14..16)?.try_into().ok()?) != 0
        || data.get(16..48)? != consumer
        || data.get(48..80)? != expected_digest
        || data.len() != layout::REGISTRY_BYTES
    {
        return None;
    }
    let mut ids = [[0u8; 32]; layout::REGISTRY_SOURCE_COUNT];
    for (index, id) in ids.iter_mut().enumerate() {
        let start = layout::REGISTRY_HEADER_BYTES + index * layout::REGISTRY_ENTRY_BYTES;
        *id = data
            .get(start..start + layout::OPAQUE_G2_ID_BYTES)?
            .try_into()
            .ok()?;
        // v3 IDs encode their slot in the first two bytes. Swaps fail here;
        // the runtime authenticates every remaining byte.
        if id[..2] != (index as u16).to_le_bytes() {
            return None;
        }
    }
    Some(ids)
}

/// Parse the only caller-supplied values used by the RegistryB5 hot path.
/// IDs are in the fixed pairing order `(tau slot 1, generator slot 0)`.
/// The runtime registered-pairing syscall authenticates every remaining ID
/// byte against the exact registry account selected by the entrypoint.
#[cfg(any(target_os = "solana", test))]
fn registered_ids_from_instruction(
    instruction_data: &[u8],
) -> Option<[[u8; 32]; layout::REGISTRY_SOURCE_COUNT]> {
    if instruction_data.len() != layout::REGISTRY_HOT_INSTRUCTION_BYTES
        || instruction_data[0] != tag::REGISTRY_B5
    {
        return None;
    }
    let tau: [u8; 32] = instruction_data.get(1..33)?.try_into().ok()?;
    let generator: [u8; 32] = instruction_data.get(33..65)?.try_into().ok()?;
    if tau[..2] != 1u16.to_le_bytes() || generator[..2] != 0u16.to_le_bytes() {
        return None;
    }
    Some([tau, generator])
}

#[cfg(not(target_os = "solana"))]
fn opaque_g2_id(
    registry_address: &[u8; 32],
    index: usize,
    source: &[u8; layout::REGISTRY_SOURCE_BYTES],
    prepared: &[u8; layout::G2_PREPARED_BYTES],
) -> [u8; layout::OPAQUE_G2_ID_BYTES] {
    let mut id = hashv(&[
        OPAQUE_G2_ID_DOMAIN,
        registry_address,
        &[layout::REGISTRY_VERSION],
        &(index as u32).to_le_bytes(),
        source,
        prepared,
    ])
    .to_bytes();
    id[..2].copy_from_slice(&(index as u16).to_le_bytes());
    id
}

#[cfg(any(feature = "registry-syscall", not(target_os = "solana")))]
fn parse_registry<'a>(
    data: &'a [u8],
    program_id: &[u8; 32],
    registry_address: &[u8; 32],
) -> Option<RegistryState<'a>> {
    if data.get(..8)? != layout::REGISTRY_MAGIC
        || *data.get(8)? != layout::REGISTRY_VERSION
        || *data.get(9)? != layout::REGISTRY_FROZEN
        || *data.get(10)? != layout::REGISTRY_CURVE_BN254
        || *data.get(11)? != layout::REGISTRY_BACKEND_B5
        || u16::from_le_bytes(data.get(12..14)?.try_into().ok()?) as usize
            != layout::REGISTRY_SOURCE_COUNT
        || u16::from_le_bytes(data.get(14..16)?.try_into().ok()?) != 0
        || data.get(16..48)? != program_id
        || data.len() != layout::REGISTRY_BYTES
    {
        return None;
    }
    let keyset_digest = data.get(48..80)?.try_into().ok()?;
    let parse_entry = |index: usize| -> Option<RegistryEntry<'a>> {
        let offset = layout::REGISTRY_HEADER_BYTES + index * layout::REGISTRY_ENTRY_BYTES;
        let id = data
            .get(offset..offset + layout::OPAQUE_G2_ID_BYTES)?
            .try_into()
            .ok()?;
        let source_offset = offset + layout::OPAQUE_G2_ID_BYTES;
        let source = data
            .get(source_offset..source_offset + layout::REGISTRY_SOURCE_BYTES)?
            .try_into()
            .ok()?;
        #[cfg(not(target_os = "solana"))]
        {
            let prepared_offset = source_offset + layout::REGISTRY_SOURCE_BYTES;
            let prepared = data
                .get(prepared_offset..prepared_offset + layout::G2_PREPARED_BYTES)?
                .try_into()
                .ok()?;
            if id != &opaque_g2_id(registry_address, index, source, prepared) {
                return None;
            }
        }
        #[cfg(target_os = "solana")]
        let _ = (registry_address, index);
        Some(RegistryEntry { id, source })
    };
    let entries = [parse_entry(0)?, parse_entry(1)?];
    Some(RegistryState {
        keyset_digest,
        entries,
    })
}

/// Install the exact shared `[1]_2` and `[tau]_2` sources. The runtime validates
/// both sources and writes the complete canonical prepared payload atomically
/// through the transaction account mapping.
#[cfg(all(feature = "registry-syscall", target_os = "solana"))]
fn initialize_g2_registry_groups(
    groups: &[Group],
    digest: &[u8; 32],
    output: &mut [u8],
) -> Option<()> {
    authenticated_input_digest(groups)?;
    if digest != &registry_keyset_digest_v3(groups)?
        || output.len() != registry_account_len(layout::REGISTRY_SOURCE_COUNT, 0)
        || output.iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let sources = shared_srs(groups)?.map(|source| *source);
    alt_bn128_vk_registry_init(SyscallVersion::V0, 0, &sources, &[], digest, output).ok()
}

#[cfg(all(feature = "registry-syscall", target_os = "solana"))]
pub fn initialize_g2_registry(data: &[u8], output: &mut [u8]) -> Option<()> {
    let groups = parse_account(data)?;
    let digest = registry_keyset_digest_v3(&groups)?;
    initialize_g2_registry_groups(&groups, &digest, output)
}

#[cfg(target_os = "solana")]
unsafe extern "C" {
    fn sol_alt_bn128_pairing_map(
        num_pairs: u64,
        pairs_addr: *const u8,
        result_addr: *mut u8,
    ) -> u64;
}

fn pairing_map(pairs: &[PodG1G2Pair]) -> Option<[u8; layout::FQ12_BYTES]> {
    #[cfg(target_os = "solana")]
    {
        let mut output = [0u8; layout::FQ12_BYTES];
        let code = unsafe {
            sol_alt_bn128_pairing_map(
                pairs.len() as u64,
                pairs.as_ptr().cast(),
                output.as_mut_ptr(),
            )
        };
        (code == 0).then_some(output)
    }
    #[cfg(not(target_os = "solana"))]
    {
        use solana_bn254_batch_syscall::{Version, alt_bn128_pairing_map};
        Some(alt_bn128_pairing_map(Version::V0, pairs).ok()?.0)
    }
}

fn identity_bytes() -> [u8; layout::FQ12_BYTES] {
    let mut output = [0u8; layout::FQ12_BYTES];
    output[31] = 1;
    output
}

fn application_context(index: usize) -> [u8; 32] {
    let mut output = [0u8; 32];
    output[24..].copy_from_slice(&(index as u64).to_be_bytes());
    output
}

fn optimized_fr(value: &PodScalar) -> Option<OptimizedFr> {
    OptimizedFr::from_be_bytes(&value.0)
}

fn optimized_vk(group: &Group) -> Option<OptimizedVerifyingKey> {
    let key = &group.vk;
    let omega = authenticated_omega(key.domain_size)?;
    Some(OptimizedVerifyingKey {
        n_public: key.num_public_inputs,
        power: key.domain_size.trailing_zeros(),
        k1: optimized_fr(key.k1)?,
        k2: optimized_fr(key.k2)?,
        w: OptimizedFr::from_be_bytes(&omega)?,
        qm: OptimizedG1(key.q_m.0),
        ql: OptimizedG1(key.q_l.0),
        qr: OptimizedG1(key.q_r.0),
        qo: OptimizedG1(key.q_o.0),
        qc: OptimizedG1(key.q_c.0),
        s1: OptimizedG1(key.s_sigma[0].0),
        s2: OptimizedG1(key.s_sigma[1].0),
        s3: OptimizedG1(key.s_sigma[2].0),
        x_2: OptimizedG2(key.g2_tau.0),
    })
}

fn optimized_proof(proof: &Proof) -> Option<OptimizedProof> {
    Some(OptimizedProof {
        a: OptimizedG1(proof.wire_commitments[0].0),
        b: OptimizedG1(proof.wire_commitments[1].0),
        c: OptimizedG1(proof.wire_commitments[2].0),
        z: OptimizedG1(proof.grand_product.0),
        t1: OptimizedG1(proof.quotient[0].0),
        t2: OptimizedG1(proof.quotient[1].0),
        t3: OptimizedG1(proof.quotient[2].0),
        wxi: OptimizedG1(proof.opening.0),
        wxiw: OptimizedG1(proof.shifted_opening.0),
        eval_a: optimized_fr(proof.evaluations.a)?,
        eval_b: optimized_fr(proof.evaluations.b)?,
        eval_c: optimized_fr(proof.evaluations.c)?,
        eval_s1: optimized_fr(proof.evaluations.s_sigma1)?,
        eval_s2: optimized_fr(proof.evaluations.s_sigma2)?,
        eval_zw: optimized_fr(proof.evaluations.z_omega)?,
    })
}

/// Structural checks only. Scalar canonicality is deliberately NOT repeated
/// here: every evaluation is converted by `optimized_fr` in `optimized_proof`
/// and every public input by `Raw::from_be_bytes` in `prepare`, both of which
/// reject a value at or above the modulus and fail the whole verification. All
/// three callers reach both. Repeating it cost 31,207 CU of the n=2 cell, a
/// tenth of the transaction, for no security property.
///
/// Key authentication is not repeated either. [`parse_account`] is the only
/// constructor of a [`Group`], and it sets `vk_digest` from the key bytes and
/// `application_context` from that digest, so comparing them here can only
/// ever hash the same key a second time and find the same answer.
fn validate_group(group: &Group) -> Option<()> {
    if group.proofs.is_empty()
        || !group.vk.domain_size.is_power_of_two()
        || !(4..=(1 << 28)).contains(&group.vk.domain_size)
        || u64::from(group.vk.num_public_inputs) >= group.vk.domain_size
    {
        return None;
    }
    for proof in &group.proofs {
        if proof.public_inputs.len() != group.vk.num_public_inputs as usize
            || [
                &proof.wire_commitments[0],
                &proof.wire_commitments[1],
                &proof.wire_commitments[2],
                &proof.grand_product,
                &proof.quotient[0],
                &proof.quotient[1],
                &proof.quotient[2],
                &proof.opening,
                &proof.shifted_opening,
            ]
            .iter()
            .any(|point| point.0 == [0u8; 64])
        {
            return None;
        }
    }
    Some(())
}

/// Everything a batch must satisfy before any handler may reduce it, and the
/// total proof count it commits to. This is the whole admission decision that
/// [`atomic_batch_digest`] used to carry: strict context ordering, per-group
/// structure, an authenticated omega for every declared domain, and a bounded
/// nonzero proof count. Rejecting exactly here keeps the batch handlers from
/// paying for a transcript none of them reads.
/// `validate_batch_rejects_what_the_transcript_rejected` pins the two against
/// each other.
#[inline(never)]
fn validate_batch(groups: &[Group]) -> Option<usize> {
    if groups.is_empty()
        || groups
            .windows(2)
            .any(|pair| pair[0].application_context >= pair[1].application_context)
    {
        return None;
    }
    let total = groups.iter().try_fold(0usize, |count, group| {
        validate_group(group)?;
        authenticated_omega(group.vk.domain_size)?;
        count.checked_add(group.proofs.len())
    })?;
    (total != 0 && total <= layout::MAX_TOTAL_PROOFS).then_some(total)
}

struct DigestContext {
    index: [u8; 4],
    domain_size: [u8; 8],
    public_count: [u8; 4],
    omega: [u8; 32],
}

struct DigestProof {
    proof_index: [u8; 4],
    context_index: [u8; 4],
}

/// Canonical atomic transcript shared by all PLONK final handlers. Its byte
/// order matches the prior multi-VK transcript contract, but coefficient
/// derivation and proof reduction now stay in the consumer so the generic
/// native reducer cannot become an accidental comparison variable.
#[inline(never)]
fn atomic_batch_digest(groups: &[Group]) -> Option<[u8; 32]> {
    const DOMAIN: &[u8] = b"solana-snarkjs-plonk-multi-vk-batch:v1:independent";
    let total = validate_batch(groups)?;

    let context_frames: Vec<DigestContext> = groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let key = &group.vk;
            Some(DigestContext {
                index: u32::try_from(index).ok()?.to_be_bytes(),
                domain_size: key.domain_size.to_be_bytes(),
                public_count: key.num_public_inputs.to_be_bytes(),
                omega: authenticated_omega(key.domain_size)?,
            })
        })
        .collect::<Option<_>>()?;
    let mut proof_frames = Vec::with_capacity(total);
    for (context_index, group) in groups.iter().enumerate() {
        for _ in &group.proofs {
            proof_frames.push(DigestProof {
                proof_index: u32::try_from(proof_frames.len()).ok()?.to_be_bytes(),
                context_index: u32::try_from(context_index).ok()?.to_be_bytes(),
            });
        }
    }

    let context_count = (groups.len() as u64).to_be_bytes();
    let proof_count = (total as u64).to_be_bytes();
    let public_count = groups
        .iter()
        .map(|group| group.proofs.len() * group.vk.num_public_inputs as usize)
        .sum::<usize>();
    let public_count = (public_count as u64).to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(4 + groups.len() * 17 + total * 18);
    parts.extend_from_slice(&[DOMAIN, &context_count, &proof_count, &public_count]);
    for ((group, frame), context_index) in groups.iter().zip(&context_frames).zip(0usize..) {
        let key = &group.vk;
        debug_assert_eq!(frame.index, (context_index as u32).to_be_bytes());
        parts.push(&frame.index);
        parts.push(&group.application_context);
        parts.push(&frame.domain_size);
        parts.push(&frame.public_count);
        parts.push(&frame.omega);
        parts.push(&key.k1.0);
        parts.push(&key.k2.0);
        for point in [
            &key.q_m,
            &key.q_l,
            &key.q_r,
            &key.q_o,
            &key.q_c,
            &key.s_sigma[0],
            &key.s_sigma[1],
            &key.s_sigma[2],
        ] {
            parts.push(&point.0);
        }
        parts.push(&key.g2_tau.0);
        parts.push(&key.g2_gen.0);
    }
    let mut proof_index = 0usize;
    for group in groups {
        for proof in &group.proofs {
            let frame = proof_frames.get(proof_index)?;
            parts.push(&frame.proof_index);
            parts.push(&frame.context_index);
            for public in proof.public_inputs {
                parts.push(&public.0);
            }
            for point in [
                &proof.wire_commitments[0],
                &proof.wire_commitments[1],
                &proof.wire_commitments[2],
                &proof.grand_product,
                &proof.quotient[0],
                &proof.quotient[1],
                &proof.quotient[2],
                &proof.opening,
                &proof.shifted_opening,
            ] {
                parts.push(&point.0);
            }
            for scalar in [
                &proof.evaluations.a,
                &proof.evaluations.b,
                &proof.evaluations.c,
                &proof.evaluations.s_sigma1,
                &proof.evaluations.s_sigma2,
                &proof.evaluations.z_omega,
            ] {
                parts.push(&scalar.0);
            }
            proof_index += 1;
        }
    }
    (proof_index == total).then(|| hashv(&parts).to_bytes())
}

fn outer_batch_scalar_bytes(seed: &[u8; 32], proof_index: usize) -> [u8; 32] {
    let digest = hashv(&[seed, b"rho", &(proof_index as u64).to_be_bytes()]).to_bytes();
    let mut rho = [0u8; 32];
    rho[16..].copy_from_slice(&digest[16..]);
    for index in (0..32).rev() {
        let (value, carry) = rho[index].overflowing_add(1);
        rho[index] = value;
        if !carry {
            break;
        }
    }
    rho
}

fn outer_batch_scalar(seed: &[u8; 32], proof_index: usize) -> Option<BatchScalar> {
    BatchScalar::from_be_bytes(&outer_batch_scalar_bytes(seed, proof_index))
}

struct ContributionVectors<'a> {
    p_points: &'a mut Vec<PodG1Point>,
    p_scalars: &'a mut Vec<PodScalar>,
    q_points: &'a mut Vec<PodG1Point>,
    q_scalars: &'a mut Vec<PodScalar>,
}

impl PairingContributionSink for ContributionVectors<'_> {
    #[inline(always)]
    fn push_p(&mut self, point: OptimizedG1, scalar: [u8; 32]) {
        self.p_points.push(PodG1Point(point.0));
        self.p_scalars.push(PodScalar(scalar));
    }

    #[inline(always)]
    fn push_q(&mut self, point: OptimizedG1, scalar: [u8; 32]) {
        self.q_points.push(PodG1Point(point.0));
        self.q_scalars.push(PodScalar(scalar));
    }
}

/// Recompute all proof equations through `023-neg-scalars`, absorb the
/// independently derived rho into K, and concatenate their fully expanded
/// source terms into exactly two MSM calls. No proof-local G1 operation is
/// performed. All final handlers consume these same two pairs.
/// Retained as the independent host oracle for [`campaign_replay_witness`].
/// The measured batch columns reduce through [`reduced_pairs_multi_vk`].
#[cfg(not(target_os = "solana"))]
#[inline(never)]
fn optimized_reduced_pairs(groups: &[Group]) -> Option<Vec<PodG1G2Pair>> {
    use solana_bn254_batch_syscall::{Version, alt_bn128_g1_msm};

    let srs = shared_srs(groups)?;
    if srs[0].0 != G2_GENERATOR_BE {
        return None;
    }
    let seed = atomic_batch_digest(groups)?;
    let total: usize = groups.iter().map(|group| group.proofs.len()).sum();
    let mut p_points = Vec::with_capacity(total * P_CONTRIBUTIONS);
    let mut p_scalars = Vec::with_capacity(total * P_CONTRIBUTIONS);
    let mut q_points = Vec::with_capacity(total * Q_CONTRIBUTIONS);
    let mut q_scalars = Vec::with_capacity(total * Q_CONTRIBUTIONS);
    let mut contributions = ContributionVectors {
        p_points: &mut p_points,
        p_scalars: &mut p_scalars,
        q_points: &mut q_points,
        q_scalars: &mut q_scalars,
    };
    let mut proof_index = 0usize;
    for group in groups {
        let vk = optimized_vk(group)?;
        for source_proof in &group.proofs {
            let proof = optimized_proof(source_proof)?;
            let rho = outer_batch_scalar(&seed, proof_index)?;
            let publics: Vec<[u8; 32]> = source_proof
                .public_inputs
                .iter()
                .map(|scalar| scalar.0)
                .collect();
            prepare_pairing_contributions(&vk, &proof, &publics, rho, &mut contributions).ok()?;
            proof_index += 1;
        }
    }
    if proof_index != total
        || contributions.p_points.len() != total * P_CONTRIBUTIONS
        || contributions.p_scalars.len() != total * P_CONTRIBUTIONS
        || contributions.q_points.len() != total * Q_CONTRIBUTIONS
        || contributions.q_scalars.len() != total * Q_CONTRIBUTIONS
    {
        return None;
    }
    drop(contributions);
    let p = alt_bn128_g1_msm(Version::V0, &p_points, &p_scalars).ok()?;
    let q = alt_bn128_g1_msm(Version::V0, &q_points, &q_scalars).ok()?;
    Some(vec![
        PodG1G2Pair { g1: p, g2: *srs[1] },
        PodG1G2Pair { g1: q, g2: *srs[0] },
    ])
}

/// Coefficients the runtime multi-VK reducer returns per context, and per
/// proof of which the first two are the P stream.
///
/// The reducer folds the eight verifying-key coefficients and the context
/// generator once per context, so its Q stream is `9*contexts + 9*proofs`
/// where the in-guest kernel emits `18*proofs`. Those agree only while every
/// context carries exactly one proof, which is true of every measured row.
/// Point a batch with several proofs per key at this path and the MSM shape
/// changes even though the verdict does not.
const REDUCER_CONTEXT_TERMS: usize = 9;
const REDUCER_ROW_TERMS: usize = 11;
const REDUCER_ROW_P_TERMS: usize = 2;

/// Both reducer records are close to a kilobyte, so every one of these
/// helpers writes through a reference into heap storage. Returning one by
/// value, or building the point arrays as literals, materializes it in the
/// caller's frame and overflows the 4 KiB SBF stack.
#[inline(never)]
fn zeroed_contexts(count: usize) -> Vec<PodSnarkjsPlonkMultiVkContext> {
    vec![
        PodSnarkjsPlonkMultiVkContext {
            context_index_be: [0u8; 4],
            reserved: [0u8; 4],
            application_context: [0u8; 32],
            reduction: PodSnarkjsPlonkReductionContext {
                domain_size_be: [0u8; 8],
                num_public_inputs_be: [0u8; 4],
                reserved: [0u8; 4],
                omega: PodScalar([0u8; 32]),
                k1: PodScalar([0u8; 32]),
                k2: PodScalar([0u8; 32]),
                transcript_vk_points: [PodG1Point([0u8; 64]); 8],
                x_2: PodG2Point([0u8; 128]),
            },
            g2_gen: PodG2Point([0u8; 128]),
        };
        count
    ]
}

#[inline(never)]
fn zeroed_inputs(count: usize) -> Vec<PodSnarkjsPlonkMultiVkInput> {
    vec![
        PodSnarkjsPlonkMultiVkInput {
            proof_index_be: [0u8; 4],
            context_index_be: [0u8; 4],
            proof: PodSnarkjsPlonkReductionInput {
                transcript_points: [PodG1Point([0u8; 64]); 9],
                evaluations: [PodScalar([0u8; 32]); 6],
            },
        };
        count
    ]
}

#[inline(never)]
fn fill_multi_vk_context(
    slot: &mut PodSnarkjsPlonkMultiVkContext,
    index: usize,
    group: &Group,
) -> Option<()> {
    let key = &group.vk;
    slot.context_index_be = u32::try_from(index).ok()?.to_be_bytes();
    slot.application_context = group.application_context;
    slot.reduction.domain_size_be = key.domain_size.to_be_bytes();
    slot.reduction.num_public_inputs_be = key.num_public_inputs.to_be_bytes();
    slot.reduction.omega = PodScalar(authenticated_omega(key.domain_size)?);
    slot.reduction.k1 = *key.k1;
    slot.reduction.k2 = *key.k2;
    // Canonical snarkjs transcript order (Qm,Ql,Qr,Qo,Qc,S1,S2,S3); the
    // returned shared coefficients arrive in this same order.
    let points = &mut slot.reduction.transcript_vk_points;
    points[0] = *key.q_m;
    points[1] = *key.q_l;
    points[2] = *key.q_r;
    points[3] = *key.q_o;
    points[4] = *key.q_c;
    points[5] = *key.s_sigma[0];
    points[6] = *key.s_sigma[1];
    points[7] = *key.s_sigma[2];
    slot.reduction.x_2 = *key.g2_tau;
    slot.g2_gen = *key.g2_gen;
    Some(())
}

#[inline(never)]
fn fill_multi_vk_input(
    slot: &mut PodSnarkjsPlonkMultiVkInput,
    proof_index: usize,
    context_index: usize,
    proof: &Proof,
) -> Option<()> {
    slot.proof_index_be = u32::try_from(proof_index).ok()?.to_be_bytes();
    slot.context_index_be = u32::try_from(context_index).ok()?.to_be_bytes();
    // Canonical snarkjs order (A,B,C,Z,T1,T2,T3,Wxi,Wxiw).
    let points = &mut slot.proof.transcript_points;
    points[0] = *proof.wire_commitments[0];
    points[1] = *proof.wire_commitments[1];
    points[2] = *proof.wire_commitments[2];
    points[3] = *proof.grand_product;
    points[4] = *proof.quotient[0];
    points[5] = *proof.quotient[1];
    points[6] = *proof.quotient[2];
    points[7] = *proof.opening;
    points[8] = *proof.shifted_opening;
    let evaluations = &mut slot.proof.evaluations;
    evaluations[0] = *proof.evaluations.a;
    evaluations[1] = *proof.evaluations.b;
    evaluations[2] = *proof.evaluations.c;
    evaluations[3] = *proof.evaluations.s_sigma1;
    evaluations[4] = *proof.evaluations.s_sigma2;
    evaluations[5] = *proof.evaluations.z_omega;
    Some(())
}

/// Reduce every proof equation through the runtime multi-VK reducer and
/// splice the returned coefficients onto the verifier-owned points.
///
/// Output is `9*contexts` shared coefficients followed by one eleven-slot row
/// per proof whose first two slots belong to the P stream, so neither MSM
/// receives a contiguous slice.
///
/// The reducer inverts the Lagrange denominators, while the in-guest kernel
/// instead scales the whole equation by their product to avoid the inversion.
/// Both operands therefore differ from [`optimized_reduced_pairs`] by one
/// nonzero field factor. The pairing equation is homogeneous, so the verdict
/// is identical while the G1 bytes are not.
#[inline(never)]
fn reduced_pairs_multi_vk(groups: &[Group]) -> Option<Vec<PodG1G2Pair>> {
    use solana_bn254_batch_syscall::{
        Version, alt_bn128_g1_msm, alt_bn128_snarkjs_plonk_multi_vk_batch_reduce,
    };

    let srs = shared_srs(groups)?;
    if srs[0].0 != G2_GENERATOR_BE {
        return None;
    }
    // Key authentication, structural validation and strict context ordering
    // stay in the guest. The transcript itself does not: the reducer derives
    // its own seed over the same contexts, inputs and public signals that the
    // marshalling below hands it, and nothing here ever reads a guest-side
    // seed. Hashing it again only reproduced a value that was then dropped.
    let total = validate_batch(groups)?;
    let mut contexts = zeroed_contexts(groups.len());
    let mut inputs = zeroed_inputs(total);
    let mut publics = Vec::new();
    let mut proof_index = 0usize;
    for (index, group) in groups.iter().enumerate() {
        fill_multi_vk_context(contexts.get_mut(index)?, index, group)?;
        for proof in &group.proofs {
            fill_multi_vk_input(inputs.get_mut(proof_index)?, proof_index, index, proof)?;
            publics.extend_from_slice(proof.public_inputs);
            proof_index += 1;
        }
    }
    if proof_index != total {
        return None;
    }
    let coefficients =
        alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(Version::V0, &contexts, &inputs, &publics)
            .ok()?;

    let shared_len = REDUCER_CONTEXT_TERMS.checked_mul(groups.len())?;
    let shared = coefficients.get(..shared_len)?;
    let rows = coefficients.get(shared_len..)?;
    if rows.len() != REDUCER_ROW_TERMS.checked_mul(total)? {
        return None;
    }

    let q_terms = shared_len
        .checked_add(total.checked_mul(REDUCER_ROW_TERMS.checked_sub(REDUCER_ROW_P_TERMS)?)?)?;
    let p_terms = total.checked_mul(REDUCER_ROW_P_TERMS)?;
    let mut p_points = Vec::with_capacity(p_terms);
    let mut p_scalars = Vec::with_capacity(p_terms);
    let mut q_points = Vec::with_capacity(q_terms);
    let mut q_scalars = Vec::with_capacity(q_terms);

    // Both MSMs consume the points the reducer was handed, not a second read
    // of the account, so an operand cannot drift from the record its
    // coefficient was derived for. Both records already hold them in canonical
    // snarkjs order, which lets whole runs move as slices.
    for (context, shared_row) in contexts
        .iter()
        .zip(shared.chunks_exact(REDUCER_CONTEXT_TERMS))
    {
        q_points.extend_from_slice(&context.reduction.transcript_vk_points);
        q_points.push(PodG1Point(OptimizedG1::GENERATOR.0));
        q_scalars.extend_from_slice(shared_row);
    }

    let mut proof_rows = rows.chunks_exact(REDUCER_ROW_TERMS);
    for input in &inputs {
        let row = proof_rows.next()?;
        // Records hold (A,B,C,Z,T1,T2,T3,Wxi,Wxiw). The P stream is the two
        // openings, and the Q coefficients arrive as (Z,T1,T2,T3,A,B,C) then
        // the same two openings.
        let points = &input.proof.transcript_points;
        p_points.extend_from_slice(points.get(7..9)?);
        p_scalars.extend_from_slice(row.get(..REDUCER_ROW_P_TERMS)?);
        q_points.extend_from_slice(points.get(3..7)?);
        q_points.extend_from_slice(points.get(0..3)?);
        q_points.extend_from_slice(points.get(7..9)?);
        q_scalars.extend_from_slice(row.get(REDUCER_ROW_P_TERMS..)?);
    }
    if proof_rows.next().is_some()
        || p_points.len() != p_terms
        || q_points.len() != q_terms
        || p_scalars.len() != p_terms
        || q_scalars.len() != q_terms
    {
        return None;
    }

    let p = alt_bn128_g1_msm(Version::V0, &p_points, &p_scalars).ok()?;
    let q = alt_bn128_g1_msm(Version::V0, &q_points, &q_scalars).ok()?;
    Some(vec![
        PodG1G2Pair { g1: p, g2: *srs[1] },
        PodG1G2Pair { g1: q, g2: *srs[0] },
    ])
}

/// Host-only differential gate: for every fixture proof, reduce the expanded
/// 2/18-term streams and require byte equality both with the legacy
/// proof-local operand construction and with independently rho-scaled
/// unbatched operands.
#[cfg(not(target_os = "solana"))]
fn diagnostic_contribution_operands(
    vk: &OptimizedVerifyingKey,
    proof: &OptimizedProof,
    publics: &[[u8; 32]],
    scale: BatchScalar,
) -> Option<(PodG1Point, PodG1Point)> {
    use solana_bn254_batch_syscall::{Version, alt_bn128_g1_msm};

    let mut p_points = Vec::with_capacity(P_CONTRIBUTIONS);
    let mut p_scalars = Vec::with_capacity(P_CONTRIBUTIONS);
    let mut q_points = Vec::with_capacity(Q_CONTRIBUTIONS);
    let mut q_scalars = Vec::with_capacity(Q_CONTRIBUTIONS);
    let mut contributions = ContributionVectors {
        p_points: &mut p_points,
        p_scalars: &mut p_scalars,
        q_points: &mut q_points,
        q_scalars: &mut q_scalars,
    };
    prepare_pairing_contributions(vk, proof, publics, scale, &mut contributions).ok()?;
    drop(contributions);
    Some((
        alt_bn128_g1_msm(Version::V0, &p_points, &p_scalars).ok()?,
        alt_bn128_g1_msm(Version::V0, &q_points, &q_scalars).ok()?,
    ))
}

#[cfg(not(target_os = "solana"))]
#[doc(hidden)]
pub fn diagnostic_scaled_operands_match(data: &[u8]) -> Option<bool> {
    use solana_bn254_batch_syscall::{Version, alt_bn128_g1_msm};

    let groups = parse_account(data)?;
    let seed = atomic_batch_digest(&groups)?;
    let mut proof_index = 0usize;
    for group in &groups {
        let vk = optimized_vk(group)?;
        for source_proof in &group.proofs {
            let proof = optimized_proof(source_proof)?;
            let publics: Vec<[u8; 32]> = source_proof
                .public_inputs
                .iter()
                .map(|scalar| scalar.0)
                .collect();
            let rho_bytes = outer_batch_scalar_bytes(&seed, proof_index);
            let rho = BatchScalar::from_be_bytes(&rho_bytes)?;
            let unscaled =
                prepare_pairing_operands(&vk, &proof, &publics, BatchScalar::ONE).ok()?;
            let scaled = prepare_pairing_operands(&vk, &proof, &publics, rho).ok()?;
            let (expanded_one_p, expanded_one_q) =
                diagnostic_contribution_operands(&vk, &proof, &publics, BatchScalar::ONE)?;
            let (expanded_p, expanded_q) =
                diagnostic_contribution_operands(&vk, &proof, &publics, rho)?;
            let scalar = [PodScalar(rho_bytes)];
            let expected_p =
                alt_bn128_g1_msm(Version::V0, &[PodG1Point(unscaled.neg_a1().0)], &scalar).ok()?;
            let expected_q =
                alt_bn128_g1_msm(Version::V0, &[PodG1Point(unscaled.b1().0)], &scalar).ok()?;
            if expanded_one_p.0 != unscaled.neg_a1().0
                || expanded_one_q.0 != unscaled.b1().0
                || expanded_p.0 != scaled.neg_a1().0
                || expanded_q.0 != scaled.b1().0
                || expected_p != expanded_p
                || expected_q != expanded_q
            {
                return Some(false);
            }
            proof_index += 1;
        }
    }
    Some(proof_index == groups.iter().map(|group| group.proofs.len()).sum::<usize>())
}

#[cfg(all(feature = "registry-syscall", target_os = "solana"))]
fn registered_pairing_check(pairs: &[PodG1RegisteredG2Pair]) -> Option<bool> {
    let full: [PodG1G2Pair; 0] = [];
    alt_bn128_pairing_check_registered(SyscallVersion::V0, 0, &full, pairs).ok()
}

/// `optimized_reduced_pairs` is sealed to `(P,[tau]_2), (Q,[1]_2)`, while
/// registry initialization is sealed to `([1]_2,[tau]_2)`. Instruction IDs
/// arrive in this function's fixed pairing order `(tau slot 1, generator slot
/// 0)`; no source scan or caller-controlled selection is involved. The
/// runtime authenticates both complete opaque IDs.
#[cfg(any(target_os = "solana", test))]
fn ordered_registered_pairs(
    pairs: &[PodG1G2Pair],
    pairing_order_ids: &[[u8; 32]; layout::REGISTRY_SOURCE_COUNT],
) -> Option<[PodG1RegisteredG2Pair; 2]> {
    let [p_tau, q_gen] = pairs else {
        return None;
    };
    Some([
        PodG1RegisteredG2Pair {
            g1: p_tau.g1,
            g2_id: pairing_order_ids[0],
        },
        PodG1RegisteredG2Pair {
            g1: q_gen.g1,
            g2_id: pairing_order_ids[1],
        },
    ])
}

/// RegistryB5 hot path after the entrypoint authenticated the fixture PDA,
/// registry PDA/owner/readonly/exact length and ordered instruction IDs.
/// The registered syscall authenticates the registry header, sealed consumer
/// and digest, and both complete IDs before it uses either prepared point.
#[cfg(all(feature = "registry-syscall", target_os = "solana"))]
#[inline(never)]
fn verify_groups_registered_hot(
    groups: &[Group],
    ids: &[[u8; 32]; layout::REGISTRY_SOURCE_COUNT],
) -> Option<bool> {
    let pairs = reduced_pairs_multi_vk(groups)?;
    let registered = ordered_registered_pairs(&pairs, ids)?;
    registered_pairing_check(&registered)
}

/// Verify through two runtime-owned, program-scoped opaque G2 handles. The
/// hot syscall receives only `(G1, ID)` terms; the authenticated frozen state
/// rebinds every ID to the exact allowlisted full key set and shared SRS.
#[cfg(any(feature = "registry-syscall", not(target_os = "solana")))]
fn verify_groups_registered(
    groups: &[Group],
    digest: &[u8; 32],
    registry_data: &[u8],
    program_id: &[u8; 32],
    registry_address: &[u8; 32],
) -> Option<bool> {
    let registry = parse_registry(registry_data, program_id, registry_address)?;
    authenticated_input_digest(groups)?;
    if registry.keyset_digest != digest || digest != &registry_keyset_digest_v3(groups)? {
        return None;
    }
    let sources = shared_srs(groups)?;
    for (entry, source) in registry.entries.iter().zip(&sources) {
        if entry.source != &source.0 {
            return None;
        }
    }
    let pairs = reduced_pairs_multi_vk(groups)?;
    if pairs.len() != 2 {
        return None;
    }
    let mut registered = Vec::with_capacity(pairs.len());
    for pair in &pairs {
        let entry = registry
            .entries
            .iter()
            .find(|entry| entry.source == &pair.g2.0)?;
        registered.push(PodG1RegisteredG2Pair {
            g1: pair.g1,
            g2_id: *entry.id,
        });
    }
    #[cfg(all(feature = "registry-syscall", target_os = "solana"))]
    {
        registered_pairing_check(&registered)
    }
    #[cfg(not(target_os = "solana"))]
    {
        use solana_bn254_batch_syscall::{Version, alt_bn128_pairing_check};
        let _ = registered;
        alt_bn128_pairing_check(Version::V0, &pairs).ok()
    }
}

#[cfg(any(feature = "registry-syscall", not(target_os = "solana")))]
pub fn verify_account_registered(
    data: &[u8],
    registry_data: &[u8],
    program_id: &[u8; 32],
    registry_address: &[u8; 32],
) -> Option<bool> {
    let groups = parse_account(data)?;
    let digest = registry_keyset_digest_v3(&groups)?;
    verify_groups_registered(
        &groups,
        &digest,
        registry_data,
        program_id,
        registry_address,
    )
}

/// Current: verify every committed fixture independently. Each proof performs
/// the original 20 G1 multiplications, 18 G1 additions, and one stock two-pair
/// check. No aggregate MSM is used.
///
/// Caller-authenticated: every `verify_groups_*` handler requires its caller to
/// have admitted the keyset already, which the entrypoint does by looking the
/// recomputed digest up in [`pinned_input_address`] and the host wrappers do
/// through [`authenticated_input_digest`].
fn verify_groups_current(groups: &[Group]) -> Option<bool> {
    let srs = shared_srs(groups)?;
    if srs[0].0 != G2_GENERATOR_BE {
        return None;
    }
    for group in groups {
        validate_group(group)?;
        let vk = optimized_vk(group)?;
        for source_proof in &group.proofs {
            let proof = optimized_proof(source_proof)?;
            let publics: Vec<[u8; 32]> = source_proof
                .public_inputs
                .iter()
                .map(|scalar| scalar.0)
                .collect();
            match verify_023(&vk, &proof, &publics) {
                Ok(()) => {}
                Err(plonk_solana::PlonkError::ProofVerificationFailed) => return Some(false),
                Err(_) => return None,
            }
        }
    }
    Some(true)
}

/// Host-side form of the authenticated singleton Current control. Production
/// callers use [`tag::CURRENT`], which also enforces owner/PDA/readonly state.
pub fn verify_account_current(data: &[u8]) -> Option<bool> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    verify_groups_current(&groups)
}

/// Current+Fp12: preserve the independent Current verifier arithmetic but
/// end each proof in an independent two-pair map and identity comparison.
/// This deliberately performs no G1 MSM.
fn verify_groups_current_fp12(groups: &[Group]) -> Option<bool> {
    let srs = shared_srs(groups)?;
    if srs[0].0 != G2_GENERATOR_BE {
        return None;
    }
    for group in groups {
        validate_group(group)?;
        let vk = optimized_vk(group)?;
        for source_proof in &group.proofs {
            let proof = optimized_proof(source_proof)?;
            let publics: Vec<[u8; 32]> = source_proof
                .public_inputs
                .iter()
                .map(|scalar| scalar.0)
                .collect();
            let operands =
                prepare_pairing_operands(&vk, &proof, &publics, BatchScalar::ONE).ok()?;
            let pairs = [
                PodG1G2Pair {
                    g1: PodG1Point(operands.neg_a1().0),
                    g2: *srs[1],
                },
                PodG1G2Pair {
                    g1: PodG1Point(operands.b1().0),
                    g2: *srs[0],
                },
            ];
            if pairing_map(&pairs)? != identity_bytes() {
                return Some(false);
            }
        }
    }
    Some(true)
}

pub fn verify_account_current_fp12(data: &[u8]) -> Option<bool> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    verify_groups_current_fp12(&groups)
}

fn verify_groups_map(groups: &[Group]) -> Option<bool> {
    let pairs = reduced_pairs_multi_vk(groups)?;
    Some(pairing_map(&pairs)? == identity_bytes())
}

fn verify_groups_boolean(groups: &[Group]) -> Option<bool> {
    use solana_bn254_batch_syscall::{Version, alt_bn128_pairing_check};

    let pairs = reduced_pairs_multi_vk(groups)?;
    alt_bn128_pairing_check(Version::V0, &pairs).ok()
}

/// Verify one authenticated canonical account atomically through the
/// expanded two-MSM kernel and FP12 map. `Some(false)` means every encoding
/// and syscall succeeded but the complete 384-byte GT value was not the identity.
pub fn verify_account(data: &[u8]) -> Option<bool> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    verify_groups_map(&groups)
}

/// The exact same optimized kernel and reconstructed two-pair equation as
/// [`verify_account`], ending in the existing boolean pairing-check syscall.
pub fn verify_account_boolean(data: &[u8]) -> Option<bool> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    verify_groups_boolean(&groups)
}

/// Exact number of pairs that a well-formed account sends to the map syscall.
pub fn expected_pair_count(data: &[u8]) -> Option<usize> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    let srs = shared_srs(&groups)?;
    (srs[0].0 == G2_GENERATOR_BE && atomic_batch_digest(&groups).is_some()).then_some(2)
}

/// Digest committed into the authenticated registry PDA for this exact
/// ordered PLONK key set.
#[cfg(any(feature = "registry-syscall", not(target_os = "solana")))]
pub fn registry_keyset_digest(data: &[u8]) -> Option<[u8; 32]> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    registry_keyset_digest_v3(&groups)
}

/// Fixture-set digest used by the input-account PDA. This is derived from
/// the complete ordered allowlisted VK set and is distinct from the v3
/// registry digest, which commits only the shared SRS sources.
pub fn input_keyset_digest(data: &[u8]) -> Option<[u8; 32]> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)
}

/// Exact Keccak seed input to the atomic outer `rho` derivation.
#[cfg(not(target_os = "solana"))]
pub fn canonical_transcript_digest(data: &[u8]) -> Option<[u8; 32]> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    shared_srs(&groups)?;
    atomic_batch_digest(&groups)
}

/// Host-only, retained-byte reconstruction used by the production campaign.
/// Every field is derived from the canonical account bytes and the same
/// verifier-owned contribution routine; callers cannot supply shape booleans.
#[cfg(not(target_os = "solana"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkCampaignReplayWitness {
    pub context_count: usize,
    pub proof_count: usize,
    pub public_input_count: usize,
    pub rho_count: usize,
    pub all_rhos_nonzero: bool,
    pub rho_folded_into_k_before_pairing: bool,
    pub p_msm_point_count: usize,
    pub q_msm_point_count: usize,
    pub pair_count: usize,
    pub nonidentity_pair_count: usize,
    pub shared_srs_authenticated: bool,
    pub shared_srs_bytes: Vec<u8>,
    pub transcript_digest: [u8; 32],
    pub recomputed_map: [u8; 384],
    pub expected_identity: [u8; 384],
}

/// Independently decode an atomic PLONK account, derive every outer rho,
/// verify that rho is absorbed into K before contribution expansion, rebuild
/// the ordered 2N/18N MSM streams, and recompute the complete two-pair FP12.
#[cfg(not(target_os = "solana"))]
pub fn campaign_replay_witness(data: &[u8]) -> Option<PlonkCampaignReplayWitness> {
    let groups = parse_account(data)?;
    authenticated_input_digest(&groups)?;
    let srs = shared_srs(&groups)?;
    if srs[0].0 != G2_GENERATOR_BE {
        return None;
    }
    let transcript_digest = atomic_batch_digest(&groups)?;
    let proof_count = groups.iter().map(|group| group.proofs.len()).sum::<usize>();
    let public_input_count = groups
        .iter()
        .map(|group| group.proofs.len() * group.vk.num_public_inputs as usize)
        .sum::<usize>();
    let rhos = (0..proof_count)
        .map(|index| outer_batch_scalar_bytes(&transcript_digest, index))
        .collect::<Vec<_>>();
    let all_rhos_nonzero = rhos.iter().all(|rho| rho.iter().any(|byte| *byte != 0));
    if !all_rhos_nonzero || !diagnostic_scaled_operands_match(data)? {
        return None;
    }
    let pairs = optimized_reduced_pairs(&groups)?;
    let nonidentity_pair_count = pairs
        .iter()
        .filter(|pair| {
            pair.g1.0.iter().any(|byte| *byte != 0) && pair.g2.0.iter().any(|byte| *byte != 0)
        })
        .count();
    let recomputed_map = pairing_map(&pairs)?;
    let mut shared_srs_bytes = Vec::with_capacity(2 * 128);
    shared_srs_bytes.extend_from_slice(&srs[0].0);
    shared_srs_bytes.extend_from_slice(&srs[1].0);
    Some(PlonkCampaignReplayWitness {
        context_count: groups.len(),
        proof_count,
        public_input_count,
        rho_count: rhos.len(),
        all_rhos_nonzero,
        rho_folded_into_k_before_pairing: true,
        p_msm_point_count: proof_count.checked_mul(P_CONTRIBUTIONS)?,
        q_msm_point_count: proof_count.checked_mul(Q_CONTRIBUTIONS)?,
        pair_count: pairs.len(),
        nonidentity_pair_count,
        shared_srs_authenticated: true,
        shared_srs_bytes,
        transcript_digest,
        recomputed_map,
        expected_identity: identity_bytes(),
    })
}

#[cfg(not(target_os = "solana"))]
fn campaign_group_ranges(data: &[u8]) -> Option<Vec<(usize, usize, usize, usize)>> {
    if data.get(..8)? != layout::MAGIC || *data.get(8)? != layout::VERSION {
        return None;
    }
    let groups = usize::from(*data.get(9)?);
    let mut offset = layout::HEADER_BYTES;
    let mut ranges = Vec::with_capacity(groups);
    for _ in 0..groups {
        let group_start = offset;
        let proof_count = usize::from(u16::from_be_bytes(
            data.get(offset..offset + 2)?.try_into().ok()?,
        ));
        if proof_count == 0 || data.get(offset + 2..offset + 4)? != [0, 0] {
            return None;
        }
        let vk_start = offset.checked_add(layout::GROUP_HEADER_BYTES)?;
        let public_count = usize::try_from(u32::from_be_bytes(
            data.get(vk_start + 8..vk_start + 12)?.try_into().ok()?,
        ))
        .ok()?;
        let proof_start = vk_start.checked_add(layout::VK_BYTES)?;
        let proof_bytes = layout::PROOF_BASE_BYTES.checked_add(public_count.checked_mul(32)?)?;
        offset = proof_start.checked_add(proof_count.checked_mul(proof_bytes)?)?;
        ranges.push((group_start, offset, vk_start, proof_start));
    }
    (offset == data.len() && ranges.len() == groups).then_some(ranges)
}

/// Code-owned semantic negative constructors.  Proof/public mutations remain
/// canonical and reach the final equation; all other mutations target a
/// precise authenticated structural property and must fail before acceptance.
#[cfg(not(target_os = "solana"))]
pub fn campaign_semantic_mutation(data: &[u8], id: &str) -> Option<Vec<u8>> {
    let ranges = campaign_group_ranges(data)?;
    let (_, _, first_vk, first_proof) = *ranges.first()?;
    let mut output = data.to_vec();
    let expected_equation_failure = match id {
        "changed_proof_rejected" | "committed_proof_variant_rejected" => {
            let second = first_proof.checked_add(64)?;
            let first_value = output.get(first_proof..second)?.to_vec();
            let second_value = output.get(second..second + 64)?.to_vec();
            output[first_proof..second].copy_from_slice(&second_value);
            output[second..second + 64].copy_from_slice(&first_value);
            true
        }
        "changed_public_input_rejected" => {
            let public = first_proof.checked_add(layout::PROOF_BASE_BYTES)?;
            output.get_mut(public..public + 32)?.fill(0);
            true
        }
        "changed_vk_rejected" => {
            let first = first_vk.checked_add(12)?;
            let second = first.checked_add(64)?;
            let a = output.get(first..second)?.to_vec();
            let b = output.get(second..second + 64)?.to_vec();
            output[first..second].copy_from_slice(&b);
            output[second..second + 64].copy_from_slice(&a);
            false
        }
        "mixed_srs_rejected" => {
            let srs = first_vk.checked_add(8 + 4 + 5 * 64 + 3 * 64 + 2 * 32)?;
            let second = srs.checked_add(128)?;
            let a = output.get(srs..second)?.to_vec();
            let b = output.get(second..second + 128)?.to_vec();
            output[srs..second].copy_from_slice(&b);
            output[second..second + 128].copy_from_slice(&a);
            false
        }
        "reordered_batch_rejected" => {
            let (a_start, a_end, _, _) = *ranges.first()?;
            let (b_start, b_end, _, _) = *ranges.get(1)?;
            let mut rebuilt = output[..a_start].to_vec();
            rebuilt.extend_from_slice(&output[b_start..b_end]);
            rebuilt.extend_from_slice(&output[a_start..a_end]);
            rebuilt.extend_from_slice(&output[b_end..]);
            output = rebuilt;
            false
        }
        "noncanonical_scalar_rejected" => {
            let public = first_proof.checked_add(layout::PROOF_BASE_BYTES)?;
            output.get_mut(public..public + 32)?.fill(0xff);
            false
        }
        "zero_outer_coefficient_rejected" => {
            output.extend_from_slice(&[0u8; 32]);
            false
        }
        "caller_supplied_intermediate_rejected" => {
            output.extend_from_slice(&[0u8; 64]);
            false
        }
        "truncated_input_rejected" => {
            output.pop()?;
            false
        }
        "trailing_input_rejected" => {
            output.push(0);
            false
        }
        _ => return None,
    };
    let verdict = verify_account(&output);
    if (expected_equation_failure && verdict == Some(false))
        || (!expected_equation_failure && verdict.is_none())
    {
        Some(output)
    } else {
        None
    }
}

#[cfg(not(target_os = "solana"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkCampaignFixtureBytes {
    pub verifying_keys: Vec<Vec<u8>>,
    pub proofs: Vec<Vec<u8>>,
    pub public_inputs: Vec<Vec<u8>>,
    pub proof_vk_indices: Vec<usize>,
    pub shared_srs: Vec<u8>,
}

/// Fixture directory names, in the order the rows compose them: row `n2` is the
/// first two, row `n3` all three. Order is part of the keyset digest.
#[cfg(not(target_os = "solana"))]
pub const PLONK_SOURCE_IDS: [&str; 3] = ["transact_1_1", "transact_2_2", "transact_2_3"];

/// The only source surface accepted by the native campaign exporter. Callers
/// provide the three clean snarkjs JSON triples in `PLONK_SOURCE_IDS` order;
/// binary account encodings are always constructed by this crate.
#[cfg(not(target_os = "solana"))]
pub struct CanonicalPlonkSourceInput<'a> {
    pub source_id: &'a str,
    pub verification_key_json: &'a [u8],
    pub proof_json: &'a [u8],
    pub public_json: &'a [u8],
}

#[cfg(not(target_os = "solana"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPlonkSourceIdentity {
    pub source_id: String,
    pub verification_key_file_sha256: String,
    pub proof_file_sha256: String,
    pub public_file_sha256: String,
    pub verification_key_payload_sha256: String,
    pub proof_payload_sha256: String,
    pub public_payload_sha256: String,
    pub authenticated_vk_keccak: String,
}

#[cfg(not(target_os = "solana"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPlonkRowExport {
    pub source_set_sha256: String,
    pub sources: Vec<CanonicalPlonkSourceIdentity>,
    /// Exact atomic one-group/one-proof accounts in `PLONK_SOURCE_IDS` order.
    pub singleton_accounts: Vec<Vec<u8>>,
    /// Exact ordered two-key combined account, row n2.
    pub n2_combined_account: Vec<u8>,
    /// Exact ordered three-key combined account, row n3.
    pub n3_combined_account: Vec<u8>,
}

#[cfg(not(target_os = "solana"))]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRawVerificationKey {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    num_public_inputs: u32,
    power: u32,
    k1: String,
    k2: String,
    #[serde(rename = "Qm")]
    q_m: [String; 3],
    #[serde(rename = "Ql")]
    q_l: [String; 3],
    #[serde(rename = "Qr")]
    q_r: [String; 3],
    #[serde(rename = "Qo")]
    q_o: [String; 3],
    #[serde(rename = "Qc")]
    q_c: [String; 3],
    #[serde(rename = "S1")]
    s_1: [String; 3],
    #[serde(rename = "S2")]
    s_2: [String; 3],
    #[serde(rename = "S3")]
    s_3: [String; 3],
    #[serde(rename = "X_2")]
    x_2: [[String; 2]; 3],
    w: String,
}

#[cfg(not(target_os = "solana"))]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRawProof {
    #[serde(rename = "A")]
    a: [String; 3],
    #[serde(rename = "B")]
    b: [String; 3],
    #[serde(rename = "C")]
    c: [String; 3],
    #[serde(rename = "Z")]
    z: [String; 3],
    #[serde(rename = "T1")]
    t_1: [String; 3],
    #[serde(rename = "T2")]
    t_2: [String; 3],
    #[serde(rename = "T3")]
    t_3: [String; 3],
    #[serde(rename = "Wxi")]
    w_xi: [String; 3],
    #[serde(rename = "Wxiw")]
    w_xiw: [String; 3],
    eval_a: String,
    eval_b: String,
    eval_c: String,
    eval_s1: String,
    eval_s2: String,
    eval_zw: String,
    protocol: String,
    curve: String,
}

#[cfg(not(target_os = "solana"))]
/// Canonical account bytes, not parsed objects. The exporter's product is the
/// encoding, and encoding once here keeps the authenticated VK digest and the
/// serialized account derived from the same bytes.
struct ExportFixture {
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
}

#[cfg(not(target_os = "solana"))]
struct ExportExpectedSource {
    source_id: &'static str,
    verification_key_file_sha256: &'static str,
    proof_file_sha256: &'static str,
    public_file_sha256: &'static str,
    verification_key_payload_sha256: &'static str,
    proof_payload_sha256: &'static str,
    public_payload_sha256: &'static str,
    authenticated_vk_keccak: &'static str,
}

#[cfg(not(target_os = "solana"))]
const EXPORT_EXPECTED_SOURCES: [ExportExpectedSource; 3] = [
    ExportExpectedSource {
        source_id: "transact_1_1",
        verification_key_file_sha256: "13e54542f5aa2a207b1cd5b0111f47ce234c17aa82d40cc41d3ab1152bd3a799",
        proof_file_sha256: "f7da7009f8c1608c3778e7bd9167c4b0b99ab8a72b939c609000cdf14400a29d",
        public_file_sha256: "d53bdf69a99370845befb77ad6c3ff53d33ccb381ee0bf6eb217e76417007807",
        verification_key_payload_sha256: "13e54542f5aa2a207b1cd5b0111f47ce234c17aa82d40cc41d3ab1152bd3a799",
        proof_payload_sha256: "f7da7009f8c1608c3778e7bd9167c4b0b99ab8a72b939c609000cdf14400a29d",
        public_payload_sha256: "d53bdf69a99370845befb77ad6c3ff53d33ccb381ee0bf6eb217e76417007807",
        authenticated_vk_keccak: "1ec1a54b3aadea2a308ef177cdec6a898cd0ab2153b52170667d948136381516",
    },
    ExportExpectedSource {
        source_id: "transact_2_2",
        verification_key_file_sha256: "5da364238a7184be8343db9e99057877fbd00039cf5e2b3abda52a676ea02e60",
        proof_file_sha256: "0e33f73c3f5f3af6c091fb76c9125ffadc74248a3c1e9bdf69d496c653b9d0d3",
        public_file_sha256: "65e81829706fe938af3c27cb6e42a55569ec76336d5c0fff9d6f7561d1caee06",
        verification_key_payload_sha256: "5da364238a7184be8343db9e99057877fbd00039cf5e2b3abda52a676ea02e60",
        proof_payload_sha256: "0e33f73c3f5f3af6c091fb76c9125ffadc74248a3c1e9bdf69d496c653b9d0d3",
        public_payload_sha256: "65e81829706fe938af3c27cb6e42a55569ec76336d5c0fff9d6f7561d1caee06",
        authenticated_vk_keccak: "676b3addcae83d1dcd702d5aa637cf2ed41fd08f3687612318dba0fbae90bff2",
    },
    ExportExpectedSource {
        source_id: "transact_2_3",
        verification_key_file_sha256: "83d7704fb23de72f1400b0f9972ee96a61cfc6873faeb244f9198ad40aa365c3",
        proof_file_sha256: "0b71de486acbb3781b6b7d395eec99227f78e8b4575fc8260bf6615fe076feac",
        public_file_sha256: "8a59522f8f89affc9e183d5adaa4e64f9a214e6a0e10bfefcda6ef481494935c",
        verification_key_payload_sha256: "83d7704fb23de72f1400b0f9972ee96a61cfc6873faeb244f9198ad40aa365c3",
        proof_payload_sha256: "0b71de486acbb3781b6b7d395eec99227f78e8b4575fc8260bf6615fe076feac",
        public_payload_sha256: "8a59522f8f89affc9e183d5adaa4e64f9a214e6a0e10bfefcda6ef481494935c",
        authenticated_vk_keccak: "8d5914d588d082eb87b71dbb7a17719ee7c4d6875aed7d2c49e0fa28eb5609ff",
    },
];

#[cfg(not(target_os = "solana"))]
fn export_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(not(target_os = "solana"))]
fn export_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    export_hex(&Sha256::digest(bytes))
}

#[cfg(not(target_os = "solana"))]
fn export_json_payload<'a>(bytes: &'a [u8], label: &str) -> Result<&'a [u8], String> {
    if !bytes.is_ascii() || bytes.is_empty() || bytes.contains(&b'\r') {
        return Err(format!("{label} is not canonical ASCII JSON"));
    }
    let payload = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if payload.is_empty() || payload.ends_with(b"\n") {
        return Err(format!("{label} has non-canonical trailing newlines"));
    }
    Ok(payload)
}

#[cfg(not(target_os = "solana"))]
fn export_scalar(value: &str, label: &str) -> Result<PodScalar, String> {
    use ark_bn254::Fr;

    value
        .parse::<Fr>()
        .map(|value| PodScalar::from(&value))
        .map_err(|_| format!("{label} is not a canonical BN254 scalar"))
}

#[cfg(not(target_os = "solana"))]
fn export_fq(value: &str, label: &str) -> Result<ark_bn254::Fq, String> {
    value
        .parse::<ark_bn254::Fq>()
        .map_err(|_| format!("{label} is not a canonical BN254 base-field value"))
}

#[cfg(not(target_os = "solana"))]
fn export_fq_be(value: ark_bn254::Fq) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};

    let encoded = value.into_bigint().to_bytes_be();
    let mut output = [0u8; 32];
    output[32 - encoded.len()..].copy_from_slice(&encoded);
    output
}

#[cfg(not(target_os = "solana"))]
fn export_g1(
    coords: &[String; 3],
    label: &str,
    allow_identity: bool,
) -> Result<PodG1Point, String> {
    use {ark_bn254::G1Affine, ark_ec::AffineRepr};

    if coords[2] == "0" {
        if allow_identity && coords[0] == "0" && coords[1] == "1" {
            return Ok(PodG1Point([0; 64]));
        }
        return Err(format!("{label} has a non-canonical identity"));
    }
    if coords[2] != "1" {
        return Err(format!("{label} is not affine-normalized"));
    }
    let point =
        G1Affine::new_unchecked(export_fq(&coords[0], label)?, export_fq(&coords[1], label)?);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() || point.is_zero()
    {
        return Err(format!("{label} is not a finite canonical BN254 G1 point"));
    }
    Ok(PodG1Point::from(&point))
}

#[cfg(not(target_os = "solana"))]
fn export_g2_bytes(point: &ark_bn254::G2Affine) -> Result<PodG2Point, String> {
    use ark_ec::AffineRepr;

    let (x, y) = point.xy().ok_or("canonical G2 point is identity")?;
    let mut output = [0u8; 128];
    output[..32].copy_from_slice(&export_fq_be(x.c1));
    output[32..64].copy_from_slice(&export_fq_be(x.c0));
    output[64..96].copy_from_slice(&export_fq_be(y.c1));
    output[96..].copy_from_slice(&export_fq_be(y.c0));
    Ok(PodG2Point(output))
}

#[cfg(not(target_os = "solana"))]
fn export_g2(coords: &[[String; 2]; 3], label: &str) -> Result<PodG2Point, String> {
    use {
        ark_bn254::{Fq2, G2Affine},
        ark_ec::AffineRepr,
    };

    if coords[2] != ["1", "0"] {
        return Err(format!("{label} is not affine-normalized"));
    }
    let point = G2Affine::new_unchecked(
        Fq2::new(
            export_fq(&coords[0][0], label)?,
            export_fq(&coords[0][1], label)?,
        ),
        Fq2::new(
            export_fq(&coords[1][0], label)?,
            export_fq(&coords[1][1], label)?,
        ),
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() || point.is_zero()
    {
        return Err(format!("{label} is not a finite canonical BN254 G2 point"));
    }
    export_g2_bytes(&point)
}

#[cfg(not(target_os = "solana"))]
fn export_source_set_sha256(sources: &[CanonicalPlonkSourceInput<'_>]) -> Result<String, String> {
    use sha2::{Digest, Sha256};

    let mut archive = b"BN254-PLONK-CANONICAL-SOURCE-SET-V1\0".to_vec();
    archive.extend_from_slice(
        &u32::try_from(sources.len())
            .map_err(|_| "too many PLONK sources")?
            .to_le_bytes(),
    );
    for source in sources {
        archive.extend_from_slice(&(source.source_id.len() as u64).to_le_bytes());
        archive.extend_from_slice(source.source_id.as_bytes());
        for bytes in [
            source.verification_key_json,
            source.proof_json,
            source.public_json,
        ] {
            archive.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            archive.extend_from_slice(bytes);
        }
    }
    Ok(export_hex(&Sha256::digest(&archive)))
}

#[cfg(not(target_os = "solana"))]
/// `expected` is `None` only when resealing, which recomputes the pinned table
/// from the files on disk. Every structural and curve check below runs either
/// way; what a reseal skips is the comparison against the previous seal, which
/// is the thing being replaced.
#[cfg(not(target_os = "solana"))]
fn export_load_fixture(
    source: &CanonicalPlonkSourceInput<'_>,
    expected: Option<&ExportExpectedSource>,
) -> Result<(ExportFixture, CanonicalPlonkSourceIdentity), String> {
    use {
        ark_bn254::{Fr, G2Affine},
        ark_ec::AffineRepr,
        ark_ff::FftField,
    };

    if expected.is_some_and(|expected| source.source_id != expected.source_id) {
        let expected = expected.expect("checked above");
        return Err(format!(
            "PLONK source order changed: expected {}, got {}",
            expected.source_id, source.source_id
        ));
    }
    let vk_payload = export_json_payload(source.verification_key_json, "PLONK VK JSON")?;
    let proof_payload = export_json_payload(source.proof_json, "PLONK proof JSON")?;
    let public_payload = export_json_payload(source.public_json, "PLONK public JSON")?;
    let mut identity = CanonicalPlonkSourceIdentity {
        source_id: source.source_id.into(),
        verification_key_file_sha256: export_sha256(source.verification_key_json),
        proof_file_sha256: export_sha256(source.proof_json),
        public_file_sha256: export_sha256(source.public_json),
        verification_key_payload_sha256: export_sha256(vk_payload),
        proof_payload_sha256: export_sha256(proof_payload),
        public_payload_sha256: export_sha256(public_payload),
        authenticated_vk_keccak: String::new(),
    };
    if expected.is_some_and(|expected| {
        identity.verification_key_file_sha256 != expected.verification_key_file_sha256
            || identity.proof_file_sha256 != expected.proof_file_sha256
            || identity.public_file_sha256 != expected.public_file_sha256
            || identity.verification_key_payload_sha256 != expected.verification_key_payload_sha256
            || identity.proof_payload_sha256 != expected.proof_payload_sha256
            || identity.public_payload_sha256 != expected.public_payload_sha256
    }) {
        return Err(format!(
            "{} source JSON differs from the pinned clean canonical bytes",
            source.source_id
        ));
    }
    let raw_vk: ExportRawVerificationKey = serde_json::from_slice(vk_payload)
        .map_err(|error| format!("strict PLONK VK JSON: {error}"))?;
    let raw_proof: ExportRawProof = serde_json::from_slice(proof_payload)
        .map_err(|error| format!("strict PLONK proof JSON: {error}"))?;
    let public: Vec<String> = serde_json::from_slice(public_payload)
        .map_err(|error| format!("strict PLONK public JSON: {error}"))?;
    if raw_vk.protocol != "plonk"
        || raw_vk.curve != "bn128"
        || raw_proof.protocol != "plonk"
        || raw_proof.curve != "bn128"
        || public.len() != raw_vk.num_public_inputs as usize
    {
        return Err(format!(
            "{} PLONK JSON identity/shape changed",
            source.source_id
        ));
    }
    let domain_size = 1u64
        .checked_shl(raw_vk.power)
        .ok_or("PLONK domain power exceeds u64")?;
    let mut vk_bytes = Vec::with_capacity(layout::VK_BYTES);
    vk_bytes.extend_from_slice(&domain_size.to_be_bytes());
    vk_bytes.extend_from_slice(&raw_vk.num_public_inputs.to_be_bytes());
    for point in [
        export_g1(&raw_vk.q_m, "Qm", false)?,
        export_g1(&raw_vk.q_l, "Ql", false)?,
        export_g1(&raw_vk.q_r, "Qr", true)?,
        export_g1(&raw_vk.q_o, "Qo", false)?,
        export_g1(&raw_vk.q_c, "Qc", true)?,
        export_g1(&raw_vk.s_1, "S1", false)?,
        export_g1(&raw_vk.s_2, "S2", false)?,
        export_g1(&raw_vk.s_3, "S3", false)?,
    ] {
        vk_bytes.extend_from_slice(&point.0);
    }
    vk_bytes.extend_from_slice(&export_scalar(&raw_vk.k1, "k1")?.0);
    vk_bytes.extend_from_slice(&export_scalar(&raw_vk.k2, "k2")?.0);
    vk_bytes.extend_from_slice(&export_g2_bytes(&G2Affine::generator())?.0);
    vk_bytes.extend_from_slice(&export_g2(&raw_vk.x_2, "X_2")?.0);
    if vk_bytes.len() != layout::VK_BYTES {
        return Err(format!("{} VK encoding length changed", source.source_id));
    }
    identity.authenticated_vk_keccak = export_hex(&authenticated_vk_digest(&vk_bytes));
    if expected.is_some_and(|expected| {
        identity.authenticated_vk_keccak != expected.authenticated_vk_keccak
    }) {
        return Err(format!(
            "{} binary VK authentication changed",
            source.source_id
        ));
    }
    let expected_omega = export_scalar(&raw_vk.w, "omega")?;
    let derived_omega =
        Fr::get_root_of_unity(domain_size).ok_or("PLONK domain has no canonical root")?;
    if expected_omega != PodScalar::from(&derived_omega) {
        return Err(format!("{} omega differs from domain", source.source_id));
    }
    let mut proof_bytes = Vec::with_capacity(layout::PROOF_BASE_BYTES + public.len() * 32);
    for point in [
        export_g1(&raw_proof.a, "proof A", false)?,
        export_g1(&raw_proof.b, "proof B", false)?,
        export_g1(&raw_proof.c, "proof C", false)?,
        export_g1(&raw_proof.z, "proof Z", false)?,
        export_g1(&raw_proof.t_1, "proof T1", false)?,
        export_g1(&raw_proof.t_2, "proof T2", false)?,
        export_g1(&raw_proof.t_3, "proof T3", false)?,
        export_g1(&raw_proof.w_xi, "proof Wxi", false)?,
        export_g1(&raw_proof.w_xiw, "proof Wxiw", false)?,
    ] {
        proof_bytes.extend_from_slice(&point.0);
    }
    for (value, label) in [
        (&raw_proof.eval_a, "eval_a"),
        (&raw_proof.eval_b, "eval_b"),
        (&raw_proof.eval_c, "eval_c"),
        (&raw_proof.eval_s1, "eval_s1"),
        (&raw_proof.eval_s2, "eval_s2"),
        (&raw_proof.eval_zw, "eval_zw"),
    ] {
        proof_bytes.extend_from_slice(&export_scalar(value, label)?.0);
    }
    for (index, value) in public.iter().enumerate() {
        proof_bytes.extend_from_slice(&export_scalar(value, &format!("public input {index}"))?.0);
    }
    Ok((
        ExportFixture {
            vk_bytes,
            proof_bytes,
        },
        identity,
    ))
}

#[cfg(not(target_os = "solana"))]
fn export_serialize(fixtures: &[ExportFixture]) -> Result<Vec<u8>, String> {
    if fixtures.is_empty() || fixtures.len() > u8::MAX as usize {
        return Err("PLONK export group count is invalid".into());
    }
    let mut output = Vec::new();
    output.extend_from_slice(layout::MAGIC);
    output.push(layout::VERSION);
    output.push(fixtures.len() as u8);
    output.extend_from_slice(&[0; 2]);
    for fixture in fixtures {
        output.extend_from_slice(&1u16.to_be_bytes());
        output.extend_from_slice(&[0; 2]);
        output.extend_from_slice(&fixture.vk_bytes);
        output.extend_from_slice(&fixture.proof_bytes);
    }
    Ok(output)
}

#[cfg(not(target_os = "solana"))]
fn validate_exported_account(
    data: &[u8],
    expected_proofs: usize,
    expected_vks: usize,
    current: bool,
) -> Result<PlonkCampaignFixtureBytes, String> {
    let replay = campaign_replay_witness(data).ok_or("exported PLONK account replay failed")?;
    if replay.proof_count != expected_proofs
        || replay.context_count != expected_vks
        || replay.recomputed_map != replay.expected_identity
        || (current && verify_account_current(data) != Some(true))
    {
        return Err("exported PLONK account identity/shape differs".into());
    }
    campaign_fixture_bytes(data).ok_or("exported PLONK semantic split failed".into())
}

#[cfg(not(target_os = "solana"))]
fn validate_exported_rows(export: &CanonicalPlonkRowExport) -> Result<(), String> {
    if export.sources.len() != 3 || export.singleton_accounts.len() != 3 {
        return Err("canonical PLONK export cardinality changed".into());
    }
    let singleton_semantics = export
        .singleton_accounts
        .iter()
        .map(|bytes| validate_exported_account(bytes, 1, 1, true))
        .collect::<Result<Vec<_>, _>>()?;
    let n2 = validate_exported_account(&export.n2_combined_account, 2, 2, false)?;
    let n3 = validate_exported_account(&export.n3_combined_account, 3, 3, false)?;
    let expected_vks = singleton_semantics
        .iter()
        .map(|semantic| semantic.verifying_keys[0].clone())
        .collect::<Vec<_>>();
    let expected_proofs = singleton_semantics
        .iter()
        .map(|semantic| semantic.proofs[0].clone())
        .collect::<Vec<_>>();
    let expected_publics = singleton_semantics
        .iter()
        .map(|semantic| semantic.public_inputs[0].clone())
        .collect::<Vec<_>>();
    if n2.verifying_keys != expected_vks[..2]
        || n2.proofs != expected_proofs[..2]
        || n2.public_inputs != expected_publics[..2]
        || n2.proof_vk_indices != [0, 1]
        || n3.verifying_keys != expected_vks
        || n3.proofs != expected_proofs
        || n3.public_inputs != expected_publics
        || n3.proof_vk_indices != [0, 1, 2]
        || singleton_semantics
            .iter()
            .any(|semantic| semantic.shared_srs != n3.shared_srs)
        || n2.shared_srs != n3.shared_srs
    {
        return Err("canonical PLONK row order/SRS/VK/proof identity changed".into());
    }
    Ok(())
}

/// Parse and authenticate the exact clean transact JSON source set,
/// then emit the only binary singleton/n2/n3 account encodings accepted by
/// the production campaign.
#[cfg(not(target_os = "solana"))]
pub fn export_canonical_plonk_rows(
    sources: &[CanonicalPlonkSourceInput<'_>],
) -> Result<CanonicalPlonkRowExport, String> {
    if sources.len() != EXPORT_EXPECTED_SOURCES.len() {
        return Err("canonical PLONK exporter requires exactly the three transact shapes".into());
    }
    let source_set_sha256 = export_source_set_sha256(sources)?;
    let loaded = sources
        .iter()
        .zip(&EXPORT_EXPECTED_SOURCES)
        .map(|(source, expected)| export_load_fixture(source, Some(expected)))
        .collect::<Result<Vec<_>, _>>()?;
    let identities = loaded
        .iter()
        .map(|(_, identity)| identity.clone())
        .collect::<Vec<_>>();
    let fixtures = loaded
        .into_iter()
        .map(|(fixture, _)| fixture)
        .collect::<Vec<_>>();
    let singleton_accounts = fixtures
        .iter()
        .map(|fixture| export_serialize(core::slice::from_ref(fixture)))
        .collect::<Result<Vec<_>, _>>()?;
    let output = CanonicalPlonkRowExport {
        source_set_sha256,
        sources: identities,
        singleton_accounts,
        n2_combined_account: export_serialize(&fixtures[..2])?,
        n3_combined_account: export_serialize(&fixtures)?,
    };
    validate_exported_rows(&output)?;
    Ok(output)
}

/// Recomputes the pinned source table, the three VK digests and the two keyset
/// digests from the files on disk. This is how a fixture-set replacement is
/// resealed: run it, paste the output into the constants, then the ordinary
/// sealed path must reproduce the same bytes. It writes nothing.
#[cfg(not(target_os = "solana"))]
pub fn plonk_reseal_report(sources: &[CanonicalPlonkSourceInput<'_>]) -> Result<String, String> {
    use core::fmt::Write;

    let loaded = sources
        .iter()
        .map(|source| export_load_fixture(source, None))
        .collect::<Result<Vec<_>, String>>()?;
    let mut report = String::new();
    writeln!(
        report,
        "source_set_sha256: {}",
        export_source_set_sha256(sources)?
    )
    .ok();
    for (_, identity) in &loaded {
        writeln!(
            report,
            "    ExportExpectedSource {{\n\
             \x20       source_id: {:?},\n\
             \x20       verification_key_file_sha256: {:?},\n\
             \x20       proof_file_sha256: {:?},\n\
             \x20       public_file_sha256: {:?},\n\
             \x20       verification_key_payload_sha256: {:?},\n\
             \x20       proof_payload_sha256: {:?},\n\
             \x20       public_payload_sha256: {:?},\n\
             \x20       authenticated_vk_keccak: {:?},\n\
             \x20   }},",
            identity.source_id,
            identity.verification_key_file_sha256,
            identity.proof_file_sha256,
            identity.public_file_sha256,
            identity.verification_key_payload_sha256,
            identity.proof_payload_sha256,
            identity.public_payload_sha256,
            identity.authenticated_vk_keccak,
        )
        .ok();
    }
    // The keyset digests bind the ordered VK set, so each row has its own. They
    // are the values POLICY_KEYSET_DIGESTS must admit.
    let fixtures = loaded
        .into_iter()
        .map(|(fixture, _)| fixture)
        .collect::<Vec<_>>();
    let singletons = (0..fixtures.len())
        .map(|index| (PLONK_SOURCE_IDS[index], &fixtures[index..=index]))
        .collect::<Vec<_>>();
    for (label, slice) in singletons
        .into_iter()
        .chain([("n2", &fixtures[..2]), ("n3", &fixtures[..])])
    {
        let bytes = export_serialize(slice)?;
        let groups = reseal_groups(&bytes)?;
        writeln!(
            report,
            "{label}: length {} keyset {} registry_v3 {}",
            bytes.len(),
            export_hex(&keyset_digest(&groups).ok_or("keyset digest")?),
            export_hex(&registry_keyset_digest_v3(&groups).ok_or("registry v3 digest")?),
        )
        .ok();
    }
    Ok(report)
}

/// `parse_account` refuses a VK whose digest is not yet allowlisted, which is
/// exactly the state a reseal starts from, so the groups are rebuilt here
/// without that gate. Nothing this returns is trusted: it is printed, and the
/// sealed path re-derives it under the full gate afterwards.
#[cfg(not(target_os = "solana"))]
fn reseal_groups(data: &[u8]) -> Result<Vec<Group<'_>>, String> {
    let mut offset = layout::HEADER_BYTES;
    let group_count = usize::from(data[9]);
    let mut groups = Vec::with_capacity(group_count);
    for index in 0..group_count {
        let proof_count = usize::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
        offset += layout::GROUP_HEADER_BYTES;
        let mut cursor = offset;
        let (key, vk_digest) = reseal_vk(data, &mut cursor).ok_or("reseal VK parse")?;
        let inputs = key.num_public_inputs as usize;
        let mut proofs = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            proofs.push(parse_proof(data, &mut cursor, inputs).ok_or("reseal proof parse")?);
        }
        offset = cursor;
        groups.push(Group {
            vk: key,
            vk_digest,
            application_context: application_context(index),
            proofs,
        });
    }
    Ok(groups)
}

#[cfg(not(target_os = "solana"))]
fn reseal_vk<'a>(data: &'a [u8], offset: &mut usize) -> Option<(VerifyingKey<'a>, [u8; 32])> {
    let vk_bytes = data.get(*offset..offset.checked_add(layout::VK_BYTES)?)?;
    let key = VerifyingKey {
        domain_size: u64::from_be_bytes(read::<8>(data, offset)?),
        num_public_inputs: u32::from_be_bytes(read::<4>(data, offset)?),
        q_m: view(data, offset)?,
        q_l: view(data, offset)?,
        q_r: view(data, offset)?,
        q_o: view(data, offset)?,
        q_c: view(data, offset)?,
        s_sigma: [
            view(data, offset)?,
            view(data, offset)?,
            view(data, offset)?,
        ],
        k1: view(data, offset)?,
        k2: view(data, offset)?,
        g2_gen: view(data, offset)?,
        g2_tau: view(data, offset)?,
    };
    Some((key, authenticated_vk_digest(vk_bytes)))
}

/// Hostile validation hook used by the create-new exporter before publish.
/// It regenerates the exact expected bytes, so order, SRS, VK, proof, public,
/// or source changes cannot be smuggled through caller-provided metadata.
#[cfg(not(target_os = "solana"))]
pub fn validate_canonical_plonk_row_export(
    sources: &[CanonicalPlonkSourceInput<'_>],
    candidate: &CanonicalPlonkRowExport,
) -> Result<(), String> {
    let expected = export_canonical_plonk_rows(sources)?;
    if candidate != &expected {
        return Err("candidate PLONK row export differs from code-derived canonical bytes".into());
    }
    validate_exported_rows(candidate)
}

#[cfg(not(target_os = "solana"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlonkCampaignRegistryMaterial {
    pub input_digest: [u8; 32],
    pub g2_sources: [[u8; 128]; layout::REGISTRY_SOURCE_COUNT],
}

/// Code-owned PDA/registry material for a canonical retained PLONK account.
/// This authenticates the allowlisted full key set and byte-identical shared
/// SRS before exposing either value to the campaign input generator.
#[cfg(not(target_os = "solana"))]
pub fn campaign_registry_material(data: &[u8]) -> Option<PlonkCampaignRegistryMaterial> {
    campaign_replay_witness(data)?;
    let groups = parse_account(data)?;
    let input_digest = authenticated_input_digest(&groups)?;
    let sources = shared_srs(&groups)?;
    Some(PlonkCampaignRegistryMaterial {
        input_digest,
        g2_sources: [sources[0].0, sources[1].0],
    })
}

/// Split canonical retained PLONK bytes into ordered semantic objects without
/// trusting a manifest or request-provided digest.
#[cfg(not(target_os = "solana"))]
pub fn campaign_fixture_bytes(data: &[u8]) -> Option<PlonkCampaignFixtureBytes> {
    campaign_replay_witness(data)?;
    let group_count = usize::from(*data.get(9)?);
    let mut offset = layout::HEADER_BYTES;
    let mut verifying_keys = Vec::with_capacity(group_count);
    let mut proofs = Vec::new();
    let mut public_inputs = Vec::new();
    let mut proof_vk_indices = Vec::new();
    let mut shared_srs = Vec::new();
    for group_index in 0..group_count {
        let proof_count = usize::from(u16::from_be_bytes(
            data.get(offset..offset + 2)?.try_into().ok()?,
        ));
        offset = offset.checked_add(layout::GROUP_HEADER_BYTES)?;
        let vk_start = offset;
        let public_count = usize::try_from(u32::from_be_bytes(
            data.get(vk_start + 8..vk_start + 12)?.try_into().ok()?,
        ))
        .ok()?;
        let vk_end = vk_start.checked_add(layout::VK_BYTES)?;
        verifying_keys.push(data.get(vk_start..vk_end)?.to_vec());
        let srs_start = vk_start.checked_add(8 + 4 + 5 * 64 + 3 * 64 + 2 * 32)?;
        let srs = data.get(srs_start..srs_start + 256)?;
        if shared_srs.is_empty() {
            shared_srs.extend_from_slice(srs);
        } else if shared_srs != srs {
            return None;
        }
        offset = vk_end;
        for _ in 0..proof_count {
            let proof_end = offset.checked_add(layout::PROOF_BASE_BYTES)?;
            proofs.push(data.get(offset..proof_end)?.to_vec());
            offset = proof_end;
            let mut publics = Vec::with_capacity(public_count * 32);
            for _ in 0..public_count {
                publics.extend_from_slice(data.get(offset..offset + 32)?);
                offset += 32;
            }
            public_inputs.push(publics);
            proof_vk_indices.push(group_index);
        }
    }
    (offset == data.len()).then_some(PlonkCampaignFixtureBytes {
        verifying_keys,
        proofs,
        public_inputs,
        proof_vk_indices,
        shared_srs,
    })
}

#[cfg(all(target_os = "solana", feature = "bpf-entrypoint"))]
mod entrypoint {
    use pinocchio::{AccountView, Address, ProgramResult, entrypoint, error::ProgramError};

    entrypoint!(process_instruction);

    fn verdict(value: Option<bool>) -> ProgramResult {
        match value {
            Some(true) => Ok(()),
            Some(false) => Err(ProgramError::Custom(1)),
            None => Err(ProgramError::InvalidAccountData),
        }
    }

    fn process_instruction(
        program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let tag = *instruction_data
            .first()
            .ok_or(ProgramError::InvalidInstructionData)?;
        let registry_ids = if tag == super::tag::REGISTRY_B5 {
            Some(
                super::registered_ids_from_instruction(instruction_data)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            )
        } else {
            if instruction_data.len() != 1 {
                return Err(ProgramError::InvalidInstructionData);
            }
            None
        };

        let expected_accounts =
            super::expected_account_count(tag).ok_or(ProgramError::InvalidInstructionData)?;
        if accounts.len() != expected_accounts {
            return Err(ProgramError::InvalidInstructionData);
        }
        let fixture_index = usize::from(expected_accounts == 2);

        let (registry, batch) = if fixture_index == 0 {
            (None, &accounts[0])
        } else {
            let (registry, fixtures) = accounts.split_at_mut(1);
            (
                registry.first_mut(),
                fixtures.first().ok_or(ProgramError::NotEnoughAccountKeys)?,
            )
        };
        // Both pinned address tables are derived under this consumer, so a
        // guest loaded at any other program id must reject rather than compare
        // against addresses that are not its own PDAs.
        if program_id.as_array() != &super::REGISTRY_V3_CONSUMER {
            return Err(ProgramError::IncorrectProgramId);
        }
        if !batch.owned_by(program_id) || batch.is_writable() {
            return Err(ProgramError::InvalidAccountData);
        }
        let data = batch
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        let groups = super::parse_account(&data).ok_or(ProgramError::InvalidAccountData)?;
        // The keyset digest is recomputed from the account on every column, so
        // the account still commits to its exact ordered key set. Only the
        // bump search is pinned.
        let input_digest = super::keyset_digest(&groups).ok_or(ProgramError::InvalidAccountData)?;
        let expected_batch =
            super::pinned_input_address(&input_digest).ok_or(ProgramError::InvalidSeeds)?;
        if batch.address().as_array() != expected_batch {
            return Err(ProgramError::InvalidSeeds);
        }

        if fixture_index == 0 {
            return verdict(match tag {
                super::tag::CURRENT => super::verify_groups_current(&groups),
                super::tag::BATCH_B5 => super::verify_groups_boolean(&groups),
                super::tag::BATCH_FP12_B5 => super::verify_groups_map(&groups),
                super::tag::CURRENT_FP12 => super::verify_groups_current_fp12(&groups),
                _ => unreachable!(),
            });
        }

        let registry = registry.ok_or(ProgramError::NotEnoughAccountKeys)?;
        let registry_digest = super::sealed_registry_keyset_digest_v3(&groups)
            .ok_or(ProgramError::InvalidAccountData)?;
        let expected_registry =
            super::pinned_registry_address(&registry_digest).ok_or(ProgramError::InvalidSeeds)?;
        if registry.address().as_array() != expected_registry || !registry.owned_by(program_id) {
            return Err(ProgramError::InvalidAccountOwner);
        }
        if registry.data_len()
            != solana_bn254_batch_syscall::registry_account_len(
                super::layout::REGISTRY_SOURCE_COUNT,
                0,
            )
        {
            return Err(ProgramError::InvalidAccountData);
        }

        if tag == super::tag::REGISTRY_INIT {
            if !registry.is_writable() {
                return Err(ProgramError::InvalidAccountData);
            }
            let mut registry_data = registry
                .try_borrow_mut()
                .map_err(|_| ProgramError::AccountBorrowFailed)?;
            if registry_data.iter().any(|byte| *byte != 0) {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
            return super::initialize_g2_registry_groups(
                &groups,
                &registry_digest,
                &mut registry_data,
            )
            .ok_or(ProgramError::InvalidAccountData);
        }

        if registry.is_writable() {
            return Err(ProgramError::InvalidAccountData);
        }
        verdict(match tag {
            super::tag::REGISTRY_B5 => super::verify_groups_registered_hot(
                &groups,
                registry_ids
                    .as_ref()
                    .ok_or(ProgramError::InvalidInstructionData)?,
            ),
            _ => unreachable!(),
        })
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
                &[layout::REGISTRY_PDA_SEED, &digest],
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

    #[test]
    fn pinned_input_addresses_derive() {
        for (index, digest) in POLICY_KEYSET_DIGESTS.iter().enumerate() {
            let (derived, _) = Address::find_program_address(
                &[layout::INPUT_PDA_SEED, digest],
                &Address::new_from_array(REGISTRY_V3_CONSUMER),
            );
            assert_eq!(
                derived.to_bytes(),
                POLICY_INPUT_ADDRESSES[index],
                "pinned input address {index} is not the PDA of its keyset digest"
            );
            assert_eq!(
                pinned_input_address(digest),
                Some(&POLICY_INPUT_ADDRESSES[index]),
                "allowlisted keyset {index} is not reachable by lookup"
            );
        }
    }

    #[test]
    fn unpinned_keyset_has_no_input_address() {
        assert!(pinned_input_address(&[0u8; 32]).is_none());
    }
}

#[cfg(all(test, not(target_os = "solana")))]
mod exporter_tests {
    use super::*;
    use std::sync::Mutex;

    static OBSERVER_LOCK: Mutex<()> = Mutex::new(());

    const SOURCE_BYTES: [(&str, &[u8], &[u8], &[u8]); 3] = [
        (
            "transact_1_1",
            include_bytes!(
                "../../../plonk-fixtures/zolana-shapes/transact_1_1/verification_key.json"
            ),
            include_bytes!("../../../plonk-fixtures/zolana-shapes/transact_1_1/proof.json"),
            include_bytes!("../../../plonk-fixtures/zolana-shapes/transact_1_1/public.json"),
        ),
        (
            "transact_2_2",
            include_bytes!(
                "../../../plonk-fixtures/zolana-shapes/transact_2_2/verification_key.json"
            ),
            include_bytes!("../../../plonk-fixtures/zolana-shapes/transact_2_2/proof.json"),
            include_bytes!("../../../plonk-fixtures/zolana-shapes/transact_2_2/public.json"),
        ),
        (
            "transact_2_3",
            include_bytes!(
                "../../../plonk-fixtures/zolana-shapes/transact_2_3/verification_key.json"
            ),
            include_bytes!("../../../plonk-fixtures/zolana-shapes/transact_2_3/proof.json"),
            include_bytes!("../../../plonk-fixtures/zolana-shapes/transact_2_3/public.json"),
        ),
    ];

    fn sources(order: [usize; 3]) -> Vec<CanonicalPlonkSourceInput<'static>> {
        order
            .into_iter()
            .map(|index| {
                let (source_id, verification_key_json, proof_json, public_json) =
                    SOURCE_BYTES[index];
                CanonicalPlonkSourceInput {
                    source_id,
                    verification_key_json,
                    proof_json,
                    public_json,
                }
            })
            .collect()
    }

    /// A verifying key carries its domain size but not its omega, so the guest
    /// derives one from the other. A wrong entry would evaluate the vanishing
    /// polynomial on the wrong domain and the proof would still parse.
    /// The registry account size the collector installs. It is derived, so it
    /// moves silently when the prepared-blob size does, and the collector then
    /// measures a registry that no fork would accept. Pinned here so the
    /// divergence from `PREPARED_G2_WIRE_BYTES = 16_712` stays one tracked
    /// number in one place.
    #[test]
    fn registry_account_size_is_pinned() {
        assert_eq!(layout::G2_PREPARED_BYTES, 37_584);
        assert_eq!(layout::REGISTRY_ENTRY_BYTES, 37_744);
        assert_eq!(layout::REGISTRY_BYTES, 75_568);
    }

    #[test]
    fn authenticated_omega_matches_every_fixture() {
        use {ark_bn254::Fr, ark_ff::FftField};

        for (power, omega) in AUTHENTICATED_OMEGA_BY_POWER {
            let canonical = Fr::get_root_of_unity(1u64 << power).expect("canonical root");
            assert_eq!(PodScalar::from(&canonical).0, omega, "power {power}");
        }
        for (_, vk_json, _, _) in SOURCE_BYTES {
            let raw: ExportRawVerificationKey =
                serde_json::from_slice(vk_json.strip_suffix(b"\n").unwrap_or(vk_json))
                    .expect("fixture VK JSON");
            let declared = export_scalar(&raw.w, "w").expect("fixture omega");
            let table = authenticated_omega(1u64 << raw.power).expect("power is in the table");
            assert_eq!(declared.0, table, "power {}", raw.power);
        }
    }

    #[test]
    fn canonical_export_replays_exact_singleton_n2_n3_rows() {
        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        let sources = sources([0, 1, 2]);
        let export = export_canonical_plonk_rows(&sources).unwrap();
        assert_eq!(export.sources.len(), 3);
        assert_eq!(export.singleton_accounts.len(), 3);
        assert_eq!(
            export
                .sources
                .iter()
                .map(|source| source.source_id.as_str())
                .collect::<Vec<_>>(),
            ["transact_1_1", "transact_2_2", "transact_2_3"]
        );
        assert!(validate_canonical_plonk_row_export(&sources, &export).is_ok());
    }

    #[test]
    fn canonical_export_rejects_wrong_source_or_account_order_srs_and_vk() {
        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        assert!(export_canonical_plonk_rows(&sources([1, 0, 2])).is_err());
        let sources = sources([0, 1, 2]);
        let export = export_canonical_plonk_rows(&sources).unwrap();

        let mut wrong_order = export.clone();
        wrong_order.singleton_accounts.swap(0, 1);
        assert!(validate_canonical_plonk_row_export(&sources, &wrong_order).is_err());

        let mut wrong_srs = export.clone();
        wrong_srs.n2_combined_account[612] ^= 1;
        assert!(validate_canonical_plonk_row_export(&sources, &wrong_srs).is_err());

        let mut wrong_vk = export;
        wrong_vk.n3_combined_account[28] ^= 1;
        assert!(validate_canonical_plonk_row_export(&sources, &wrong_vk).is_err());
    }

    #[test]
    fn canonical_export_rejects_any_source_byte_change() {
        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        let mut changed_vk = SOURCE_BYTES[0].1.to_vec();
        *changed_vk.get_mut(10).unwrap() ^= 1;
        let mut sources = sources([0, 1, 2]);
        sources[0].verification_key_json = &changed_vk;
        assert!(export_canonical_plonk_rows(&sources).is_err());
    }

    #[test]
    fn canonical_n2_n3_verify_and_have_exact_optimized_shapes() {
        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        let export = export_canonical_plonk_rows(&sources([0, 1, 2])).unwrap();
        for (n, account) in [
            (2usize, export.n2_combined_account.as_slice()),
            (3usize, export.n3_combined_account.as_slice()),
        ] {
            assert_eq!(verify_account_current(account), Some(true));
            assert_eq!(verify_account_current_fp12(account), Some(true));

            solana_bn254_batch_syscall::research_observer::reset();
            assert_eq!(verify_account_boolean(account), Some(true));
            assert_eq!(
                solana_bn254_batch_syscall::research_observer::observed_g1_msm_point_count_list(),
                [2 * n as u64, 18 * n as u64]
            );
            assert_eq!(
                solana_bn254_batch_syscall::research_observer::observed_pairing_check_shapes(),
                [(2, 2)]
            );
            assert!(
                solana_bn254_batch_syscall::research_observer::observed_pairing_map_shapes()
                    .is_empty()
            );

            solana_bn254_batch_syscall::research_observer::reset();
            assert_eq!(verify_account(account), Some(true));
            assert_eq!(
                solana_bn254_batch_syscall::research_observer::observed_g1_msm_point_count_list(),
                [2 * n as u64, 18 * n as u64]
            );
            assert_eq!(
                solana_bn254_batch_syscall::research_observer::observed_pairing_map_shapes(),
                [(2, 2)]
            );
            assert!(
                solana_bn254_batch_syscall::research_observer::observed_pairing_check_shapes()
                    .is_empty()
            );
        }
    }

    /// Reduce each canonical account and return the runtime coefficients
    /// beside the seed the in-guest kernel derives for the same account.
    fn reducer_coefficients(account: &[u8]) -> (Vec<Group<'_>>, [u8; 32], Vec<PodScalar>) {
        use solana_bn254_batch_syscall::{Version, alt_bn128_snarkjs_plonk_multi_vk_batch_reduce};

        let groups = parse_account(account).expect("canonical account");
        let seed = atomic_batch_digest(&groups).expect("batch digest");
        let total = groups.iter().map(|group| group.proofs.len()).sum();
        let mut contexts = zeroed_contexts(groups.len());
        let mut inputs = zeroed_inputs(total);
        let mut publics = Vec::new();
        let mut proof_index = 0usize;
        for (index, group) in groups.iter().enumerate() {
            fill_multi_vk_context(&mut contexts[index], index, group).expect("context");
            for proof in &group.proofs {
                fill_multi_vk_input(&mut inputs[proof_index], proof_index, index, proof)
                    .expect("input");
                publics.extend_from_slice(proof.public_inputs);
                proof_index += 1;
            }
        }
        let coefficients = alt_bn128_snarkjs_plonk_multi_vk_batch_reduce(
            Version::V0,
            &contexts,
            &inputs,
            &publics,
        )
        .expect("multi-VK reduce");
        (groups, seed, coefficients)
    }

    /// Pin the transcript, the outer randomizer and the sign of both streams
    /// against the in-guest kernel instead of arguing them.
    ///
    /// P slot 0 is the bare randomizer and the shared Qc coefficient is its
    /// negation, so an equal value on one stream and an equal magnitude with
    /// opposite sign on the other fixes the reducer's seed, its rho
    /// derivation, the slot order and the relative sign in one comparison.
    #[test]
    fn reducer_seed_rho_and_stream_signs_match_the_in_guest_kernel() {
        use ark_ff::PrimeField;

        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        let export = export_canonical_plonk_rows(&sources([0, 1, 2])).unwrap();
        let field = |scalar: &PodScalar| ark_bn254::Fr::from_be_bytes_mod_order(&scalar.0);
        for account in [
            export.n2_combined_account.as_slice(),
            export.n3_combined_account.as_slice(),
        ] {
            let (groups, seed, coefficients) = reducer_coefficients(account);
            let shared_len = REDUCER_CONTEXT_TERMS * groups.len();
            let (shared, rows) = coefficients.split_at(shared_len);
            assert!(groups.iter().all(|group| group.proofs.len() == 1));

            for (index, row) in rows.chunks_exact(REDUCER_ROW_TERMS).enumerate() {
                let rho = field(&PodScalar(outer_batch_scalar_bytes(&seed, index)));
                assert_ne!(rho, ark_bn254::Fr::from(0u64));
                assert_eq!(field(&row[0]), rho, "P slot 0 is rho at proof {index}");
                // Qc carries the constant one, so with one proof per context
                // the whole shared slot is the negated randomizer.
                let qc = &shared[REDUCER_CONTEXT_TERMS * index + 4];
                assert_eq!(field(qc), -rho, "shared Qc is -rho at context {index}");
            }
        }
    }

    /// The reducer's Q stream is `9*contexts + 9*proofs` against the kernel's
    /// `18*proofs`. Every measured row holds exactly one proof per context,
    /// which is the only reason the pinned MSM shape survives the swap. Point
    /// this path at a same-VK batch and the observed trace changes silently,
    /// so the equality is asserted together with that precondition.
    #[test]
    fn reducer_msm_shape_matches_the_kernel_only_at_one_proof_per_context() {
        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        let export = export_canonical_plonk_rows(&sources([0, 1, 2])).unwrap();
        for (n, account) in [
            (2usize, export.n2_combined_account.as_slice()),
            (3usize, export.n3_combined_account.as_slice()),
        ] {
            let groups = parse_account(account).expect("canonical account");
            let proofs = groups.iter().map(|group| group.proofs.len()).sum::<usize>();
            assert_eq!((groups.len(), proofs), (n, n));

            let q_terms = REDUCER_CONTEXT_TERMS * groups.len()
                + (REDUCER_ROW_TERMS - REDUCER_ROW_P_TERMS) * proofs;
            assert_eq!(q_terms, Q_CONTRIBUTIONS * proofs);
            assert_eq!(REDUCER_ROW_P_TERMS * proofs, P_CONTRIBUTIONS * proofs);

            // One context holding every proof reduces the Q stream instead.
            let folded = REDUCER_CONTEXT_TERMS + (REDUCER_ROW_TERMS - REDUCER_ROW_P_TERMS) * proofs;
            assert_ne!(folded, Q_CONTRIBUTIONS * proofs);
        }
    }

    #[test]
    fn fp12_tags_are_fixture_only_and_registry_is_exclusive_to_tag_three_and_init() {
        assert_eq!(expected_account_count(tag::CURRENT), Some(1));
        assert_eq!(expected_account_count(tag::BATCH_B5), Some(1));
        assert_eq!(expected_account_count(tag::BATCH_FP12_B5), Some(1));
        assert_eq!(expected_account_count(tag::CURRENT_FP12), Some(1));
        assert_eq!(expected_account_count(tag::REGISTRY_B5), Some(2));
        assert_eq!(expected_account_count(tag::REGISTRY_INIT), Some(2));
        assert_eq!(expected_account_count(1), None);
    }

    /// The pre-existing spelling of the authenticated VK digest, field by
    /// field, kept only so the block hash can be checked against it.
    fn field_wise_vk_digest(key: &VerifyingKey) -> [u8; 32] {
        hashv(&[
            &key.domain_size.to_be_bytes(),
            &key.num_public_inputs.to_be_bytes(),
            &key.q_m.0,
            &key.q_l.0,
            &key.q_r.0,
            &key.q_o.0,
            &key.q_c.0,
            &key.s_sigma[0].0,
            &key.s_sigma[1].0,
            &key.s_sigma[2].0,
            &key.k1.0,
            &key.k2.0,
            &key.g2_gen.0,
            &key.g2_tau.0,
        ])
        .to_bytes()
    }

    fn every_canonical_account() -> Vec<Vec<u8>> {
        let export = export_canonical_plonk_rows(&sources([0, 1, 2])).unwrap();
        let mut accounts = export.singleton_accounts.clone();
        accounts.push(export.n2_combined_account.clone());
        accounts.push(export.n3_combined_account.clone());
        accounts
    }

    /// Hashing the canonical VK block is the same statement as hashing its
    /// fields in order. If the layout ever grows a gap the two diverge, and the
    /// sealed `TRANSACT_*_KEY_DIGEST` constants would no longer mean what they
    /// were derived from.
    #[test]
    fn vk_digest_is_the_canonical_vk_block() {
        for account in every_canonical_account() {
            for group in parse_account(&account).expect("canonical account") {
                assert_eq!(field_wise_vk_digest(&group.vk), group.vk_digest);
            }
        }
    }

    /// `validate_group` no longer re-hashes the key it was handed, because
    /// `parse_vk` is the only thing that ever fills these two fields and it
    /// fills them from the same bytes. Pin that postcondition on every account
    /// the grid runs, so the dropped comparison stays unable to fire.
    #[test]
    fn parse_account_binds_every_group_to_its_key() {
        for account in every_canonical_account() {
            for group in parse_account(&account).expect("canonical account") {
                assert_eq!(field_wise_vk_digest(&group.vk), group.vk_digest);
                assert_eq!(
                    registry_context(&group.vk_digest),
                    Some(group.application_context)
                );
            }
        }
    }

    /// The batch handlers now admit through `validate_batch` instead of
    /// building a transcript they never read. Both must accept and reject the
    /// same batches: every sub-slice of every canonical account in both
    /// orders, plus each structural field the batch gate owns.
    #[test]
    fn validate_batch_rejects_what_the_transcript_rejected() {
        let export = export_canonical_plonk_rows(&sources([0, 1, 2])).unwrap();
        for account in [
            export.n2_combined_account.as_slice(),
            export.n3_combined_account.as_slice(),
        ] {
            let mut groups = parse_account(account).expect("canonical account");
            for reversed in [false, true] {
                if reversed {
                    groups.reverse();
                }
                for start in 0..=groups.len() {
                    for end in start..=groups.len() {
                        let slice = &groups[start..end];
                        assert_eq!(
                            validate_batch(slice).is_some(),
                            atomic_batch_digest(slice).is_some(),
                            "reversed={reversed} range={start}..{end}"
                        );
                    }
                }
            }
            groups.reverse();
            assert!(validate_batch(&groups).is_some());

            let domain = groups[0].vk.domain_size;
            for broken in [0u64, 2, 3, domain + 1, 1 << 29] {
                groups[0].vk.domain_size = broken;
                assert!(validate_batch(&groups).is_none(), "domain {broken}");
                assert!(atomic_batch_digest(&groups).is_none(), "domain {broken}");
            }
            groups[0].vk.domain_size = domain;

            let publics = groups[0].vk.num_public_inputs;
            groups[0].vk.num_public_inputs = publics + 1;
            assert!(validate_batch(&groups).is_none());
            assert!(atomic_batch_digest(&groups).is_none());
            groups[0].vk.num_public_inputs = publics;

            let proofs = core::mem::take(&mut groups[0].proofs);
            assert!(validate_batch(&groups).is_none());
            assert!(atomic_batch_digest(&groups).is_none());
            groups[0].proofs = proofs;

            let context = groups[0].application_context;
            groups[0].application_context = groups[1].application_context;
            assert!(validate_batch(&groups).is_none());
            assert!(atomic_batch_digest(&groups).is_none());
            groups[0].application_context = context;
            assert!(validate_batch(&groups).is_some());
        }
    }

    fn registry_fixture(
        account: &[u8],
        consumer: [u8; 32],
        address: [u8; 32],
    ) -> (Vec<u8>, [u8; 32]) {
        let material = campaign_registry_material(account).expect("registry material");
        let digest = registry_keyset_digest(account).expect("v3 digest");
        let mut data = vec![0u8; layout::REGISTRY_BYTES];
        data[..8].copy_from_slice(layout::REGISTRY_MAGIC);
        data[8] = layout::REGISTRY_VERSION;
        data[9] = layout::REGISTRY_FROZEN;
        data[10] = layout::REGISTRY_CURVE_BN254;
        data[11] = layout::REGISTRY_BACKEND_B5;
        data[12..14].copy_from_slice(&(layout::REGISTRY_SOURCE_COUNT as u16).to_le_bytes());
        data[14..16].copy_from_slice(&0u16.to_le_bytes());
        data[16..48].copy_from_slice(&consumer);
        data[48..80].copy_from_slice(&digest);
        for (index, source) in material.g2_sources.iter().enumerate() {
            let start = layout::REGISTRY_HEADER_BYTES + index * layout::REGISTRY_ENTRY_BYTES;
            let source_start = start + layout::OPAQUE_G2_ID_BYTES;
            data[source_start..source_start + layout::REGISTRY_SOURCE_BYTES]
                .copy_from_slice(source);
            let prepared_start = source_start + layout::REGISTRY_SOURCE_BYTES;
            let prepared: &[u8; layout::G2_PREPARED_BYTES] = data
                [prepared_start..prepared_start + layout::G2_PREPARED_BYTES]
                .try_into()
                .unwrap();
            let id = opaque_g2_id(&address, index, source, prepared);
            data[start..start + layout::OPAQUE_G2_ID_BYTES].copy_from_slice(&id);
        }
        (data, digest)
    }

    #[test]
    fn registry_hot_path_preserves_digest_order_id_and_address_binding() {
        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        let export = export_canonical_plonk_rows(&sources([0, 1, 2])).unwrap();
        for account in [
            export.n2_combined_account.as_slice(),
            export.n3_combined_account.as_slice(),
        ] {
            let groups = parse_account(account).unwrap();
            assert_eq!(
                sealed_registry_keyset_digest_v3(&groups),
                registry_keyset_digest_v3(&groups)
            );
            assert_eq!(
                sealed_registry_keyset_digest_v3(&groups),
                Some(AUTHENTICATED_REGISTRY_KEYSET_DIGEST_V3)
            );

            let consumer = [0x71u8; 32];
            let address = [0x82u8; 32];
            let (registry, digest) = registry_fixture(account, consumer, address);
            let ids = authenticated_registry_ids(&registry, &consumer, &digest).unwrap();
            assert_eq!(u16::from_le_bytes(ids[0][..2].try_into().unwrap()), 0);
            assert_eq!(u16::from_le_bytes(ids[1][..2].try_into().unwrap()), 1);
            assert!(parse_registry(&registry, &consumer, &address).is_some());

            let mut instruction = vec![tag::REGISTRY_B5];
            instruction.extend_from_slice(&ids[1]);
            instruction.extend_from_slice(&ids[0]);
            let pairing_order_ids = registered_ids_from_instruction(&instruction).unwrap();
            assert_eq!(pairing_order_ids, [ids[1], ids[0]]);
            let mut wrong_instruction_order = vec![tag::REGISTRY_B5];
            wrong_instruction_order.extend_from_slice(&ids[0]);
            wrong_instruction_order.extend_from_slice(&ids[1]);
            assert!(registered_ids_from_instruction(&wrong_instruction_order).is_none());
            instruction.push(0);
            assert!(registered_ids_from_instruction(&instruction).is_none());

            let mut swapped = registry.clone();
            let first = layout::REGISTRY_HEADER_BYTES;
            let second = first + layout::REGISTRY_ENTRY_BYTES;
            let first_id = swapped[first..first + 32].to_vec();
            let second_id = swapped[second..second + 32].to_vec();
            swapped[first..first + 32].copy_from_slice(&second_id);
            swapped[second..second + 32].copy_from_slice(&first_id);
            assert!(authenticated_registry_ids(&swapped, &consumer, &digest).is_none());

            let mut wrong_id = registry.clone();
            wrong_id[first + 7] ^= 1;
            assert!(parse_registry(&wrong_id, &consumer, &address).is_none());

            let mut wrong_digest = digest;
            wrong_digest[0] ^= 1;
            assert!(authenticated_registry_ids(&registry, &consumer, &wrong_digest).is_none());

            let mut wrong_consumer = consumer;
            wrong_consumer[0] ^= 1;
            assert!(authenticated_registry_ids(&registry, &wrong_consumer, &digest).is_none());

            let mut wrong_address = address;
            wrong_address[0] ^= 1;
            assert!(parse_registry(&registry, &consumer, &wrong_address).is_none());

            let pairs = [
                PodG1G2Pair {
                    g1: PodG1Point([0x11; 64]),
                    g2: PodG2Point([0x22; 128]),
                },
                PodG1G2Pair {
                    g1: PodG1Point([0x33; 64]),
                    g2: PodG2Point([0x44; 128]),
                },
            ];
            let registered = ordered_registered_pairs(&pairs, &pairing_order_ids).unwrap();
            assert_eq!(registered[0].g1, pairs[0].g1);
            assert_eq!(registered[0].g2_id, ids[1]);
            assert_eq!(registered[1].g1, pairs[1].g1);
            assert_eq!(registered[1].g2_id, ids[0]);
        }
    }

    #[test]
    fn canonical_proof_mutation_is_rejected_by_every_direct_finalizer() {
        let _guard = OBSERVER_LOCK.lock().expect("observer lock");
        let export = export_canonical_plonk_rows(&sources([0, 1, 2])).unwrap();
        let changed =
            campaign_semantic_mutation(&export.n2_combined_account, "changed_proof_rejected")
                .expect("code-owned semantic mutation");
        assert_ne!(verify_account_current(&changed), Some(true));
        assert_ne!(verify_account_boolean(&changed), Some(true));
        assert_ne!(verify_account_current_fp12(&changed), Some(true));
        assert_ne!(verify_account(&changed), Some(true));
    }
}
