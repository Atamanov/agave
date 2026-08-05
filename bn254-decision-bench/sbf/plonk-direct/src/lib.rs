//! Direct PLONK fixture program for the BN254 decision grid.
//!
//! Only the three byte-exact, committed Zolana snarkjs mul1/mul2/mul3 test
//! exceptions are admitted. They are explicitly test fixtures, not fresh or
//! production Zolana proofs. They share one authenticated SRS. The optimized
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
    0xbd, 0xc5, 0xc0, 0xab, 0xa5, 0xdd, 0xe4, 0xa6, 0x1f, 0x01, 0xef, 0x74, 0x2c, 0x4e, 0x7c, 0xbd,
    0x4f, 0xc6, 0xbb, 0xc3, 0xde, 0x71, 0x60, 0xe9, 0xc1, 0x9b, 0x34, 0xf3, 0x53, 0x89, 0x1d, 0x99,
];
#[cfg(not(target_os = "solana"))]
const OPAQUE_G2_ID_DOMAIN: &[u8] = b"agave:bn254:b5:g2-registry:v3";
const KEYSET_DIGEST_VERSION: u8 = 1;
const POLICY_KEYSET_DIGESTS: [[u8; 32]; 5] = [
    [
        0xec, 0x0c, 0xc4, 0x79, 0xcf, 0x76, 0xcb, 0xa9, 0x5f, 0xca, 0xa3, 0x50, 0x33, 0x44, 0x09,
        0x3d, 0x39, 0x3a, 0xa7, 0xa8, 0xe5, 0x27, 0xf8, 0xf0, 0xb8, 0x95, 0x97, 0x38, 0x2b, 0x3c,
        0x5a, 0x83,
    ],
    [
        0xc1, 0x22, 0x61, 0x08, 0x7b, 0xf6, 0x4e, 0xc9, 0xa3, 0xed, 0x9f, 0x28, 0x94, 0xe8, 0x32,
        0x0a, 0xf3, 0x1c, 0x38, 0x67, 0xa0, 0x8b, 0x51, 0x06, 0xa7, 0xff, 0xec, 0x74, 0x9f, 0x5a,
        0x3b, 0x4d,
    ],
    [
        0x63, 0x75, 0x4b, 0x29, 0x2d, 0x89, 0x4f, 0x81, 0xe8, 0x54, 0xa9, 0x44, 0x50, 0x72, 0xee,
        0xac, 0x29, 0xae, 0xd7, 0x84, 0xf1, 0x10, 0x2a, 0x12, 0x07, 0x06, 0xe0, 0x9d, 0x6c, 0x3d,
        0x2e, 0x1e,
    ],
    [
        0x08, 0x4f, 0x33, 0x96, 0x33, 0xf8, 0xa9, 0xc2, 0xf2, 0x2a, 0x05, 0x56, 0x4e, 0xb7, 0x8f,
        0x9b, 0x4d, 0x43, 0x71, 0xa0, 0x54, 0x76, 0x0e, 0x72, 0x62, 0x6b, 0x76, 0x61, 0x76, 0x36,
        0x85, 0x97,
    ],
    [
        0x17, 0x13, 0xc6, 0x4b, 0xd9, 0x09, 0x02, 0xc6, 0x11, 0xf6, 0x10, 0x5f, 0x19, 0xf9, 0x68,
        0xcf, 0xef, 0x2c, 0x11, 0x5c, 0xa2, 0xdb, 0x3f, 0xb3, 0x80, 0x5a, 0x5b, 0x00, 0x93, 0xf4,
        0xe0, 0x27,
    ],
];

const MUL1_KEY_DIGEST: [u8; 32] = [
    0x6b, 0x37, 0x6b, 0x8d, 0xb1, 0x9c, 0x8c, 0x21, 0xe7, 0xe0, 0x96, 0xee, 0xf4, 0x33, 0x31, 0x34,
    0x24, 0xeb, 0x27, 0x74, 0x6d, 0x68, 0x4e, 0x14, 0x28, 0x0b, 0x57, 0xac, 0xc6, 0xf0, 0xf2, 0x1d,
];
const MUL2_KEY_DIGEST: [u8; 32] = [
    0x97, 0xd0, 0xd3, 0x51, 0xc7, 0x8a, 0xb5, 0xad, 0x01, 0xb5, 0xcd, 0xb2, 0x1d, 0xef, 0xd4, 0x19,
    0x7c, 0x3a, 0xb6, 0x69, 0xf4, 0x64, 0xb0, 0x65, 0x6e, 0xf4, 0xef, 0x44, 0x99, 0xca, 0xdc, 0xa4,
];
const MUL3_KEY_DIGEST: [u8; 32] = [
    0x65, 0x73, 0xca, 0x8d, 0xb0, 0x19, 0x12, 0x59, 0x00, 0x8f, 0x56, 0x7f, 0xec, 0x3a, 0xc3, 0x48,
    0xab, 0x73, 0x4f, 0xd9, 0x44, 0xb1, 0xea, 0x81, 0xe3, 0x5f, 0xe6, 0x5d, 0xd4, 0x6f, 0xe6, 0x5a,
];

// Canonical snarkjs omega for the authenticated power-3 fixture keys.
const AUTHENTICATED_OMEGA: [u8; 32] = [
    0x2b, 0x33, 0x7d, 0xe1, 0xc8, 0xc1, 0x4f, 0x22, 0xec, 0x9b, 0x9e, 0x2f, 0x96, 0xaf, 0xef, 0x36,
    0x52, 0x62, 0x73, 0x66, 0xf8, 0x17, 0x0a, 0x0a, 0x94, 0x8d, 0xad, 0x4a, 0xc1, 0xbd, 0x5e, 0x80,
];

struct Group {
    vk: VerifyingKey,
    vk_digest: [u8; 32],
    application_context: [u8; 32],
    proofs: Vec<Proof>,
}

struct VerifyingKey {
    domain_size: u64,
    num_public_inputs: u32,
    q_m: PodG1Point,
    q_l: PodG1Point,
    q_r: PodG1Point,
    q_o: PodG1Point,
    q_c: PodG1Point,
    s_sigma: [PodG1Point; 3],
    k1: PodScalar,
    k2: PodScalar,
    g2_gen: PodG2Point,
    g2_tau: PodG2Point,
}

struct Evaluations {
    a: PodScalar,
    b: PodScalar,
    c: PodScalar,
    s_sigma1: PodScalar,
    s_sigma2: PodScalar,
    z_omega: PodScalar,
}

struct Proof {
    wire_commitments: [PodG1Point; 3],
    grand_product: PodG1Point,
    quotient: [PodG1Point; 3],
    opening: PodG1Point,
    shifted_opening: PodG1Point,
    evaluations: Evaluations,
    public_inputs: Vec<PodScalar>,
}

fn read<const N: usize>(data: &[u8], offset: &mut usize) -> Option<[u8; N]> {
    let bytes = data.get(*offset..offset.checked_add(N)?)?;
    *offset += N;
    let mut output = [0u8; N];
    output.copy_from_slice(bytes);
    Some(output)
}

fn registry_context(digest: &[u8; 32]) -> Option<[u8; 32]> {
    let ordinal = match *digest {
        MUL1_KEY_DIGEST => 0usize,
        MUL2_KEY_DIGEST => 1usize,
        MUL3_KEY_DIGEST => 2usize,
        _ => return None,
    };
    // The custom-recursion circuit commits to these zero-based fixture
    // contexts. Every PLONK batching column uses the same transcript bytes.
    Some(application_context(ordinal))
}

fn authenticated_vk_digest(key: &VerifyingKey) -> [u8; 32] {
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

#[inline(never)]
fn parse_vk(data: &[u8], offset: &mut usize) -> Option<(VerifyingKey, [u8; 32], [u8; 32])> {
    let key = VerifyingKey {
        domain_size: u64::from_be_bytes(read::<8>(data, offset)?),
        num_public_inputs: u32::from_be_bytes(read::<4>(data, offset)?),
        q_m: PodG1Point(read::<64>(data, offset)?),
        q_l: PodG1Point(read::<64>(data, offset)?),
        q_r: PodG1Point(read::<64>(data, offset)?),
        q_o: PodG1Point(read::<64>(data, offset)?),
        q_c: PodG1Point(read::<64>(data, offset)?),
        s_sigma: [
            PodG1Point(read::<64>(data, offset)?),
            PodG1Point(read::<64>(data, offset)?),
            PodG1Point(read::<64>(data, offset)?),
        ],
        k1: PodScalar(read::<32>(data, offset)?),
        k2: PodScalar(read::<32>(data, offset)?),
        g2_gen: PodG2Point(read::<128>(data, offset)?),
        g2_tau: PodG2Point(read::<128>(data, offset)?),
    };
    // These authenticated snarkjs fixtures spell the unused Qr and Qc
    // selectors as canonical projective infinity. That exception is confined
    // to the allowlisted keys: all other commitments and both SRS points must
    // remain finite. The ordinary untrusted VerifyingKey::validate path is not
    // weakened.
    // Qr and Qc are infinity only when the circuit never uses those selectors,
    // which the multiplier fixtures did and no real circuit does. Both spellings
    // are admitted, and a finite one is validated like every other commitment.
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
    if key.g2_gen.0 == [0u8; 128]
        || key.g2_tau.0 == [0u8; 128]
    {
        return None;
    }
    #[cfg(not(target_os = "solana"))]
    {
        use ark_ec::AffineRepr;
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
    let digest = authenticated_vk_digest(&key);
    let context = registry_context(&digest)?;
    Some((key, digest, context))
}

#[inline(never)]
fn parse_proof(data: &[u8], offset: &mut usize, inputs: usize) -> Option<Proof> {
    let point = |data: &[u8], offset: &mut usize| read::<64>(data, offset).map(PodG1Point);
    let scalar = |data: &[u8], offset: &mut usize| read::<32>(data, offset).map(PodScalar);
    let wire_commitments = [
        point(data, offset)?,
        point(data, offset)?,
        point(data, offset)?,
    ];
    let grand_product = point(data, offset)?;
    let quotient = [
        point(data, offset)?,
        point(data, offset)?,
        point(data, offset)?,
    ];
    let opening = point(data, offset)?;
    let shifted_opening = point(data, offset)?;
    let evaluations = Evaluations {
        a: scalar(data, offset)?,
        b: scalar(data, offset)?,
        c: scalar(data, offset)?,
        s_sigma1: scalar(data, offset)?,
        s_sigma2: scalar(data, offset)?,
        z_omega: scalar(data, offset)?,
    };
    let mut public_inputs = Vec::with_capacity(inputs);
    for _ in 0..inputs {
        public_inputs.push(scalar(data, offset)?);
    }
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
fn parse_account(data: &[u8]) -> Option<Vec<Group>> {
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

/// Common identity policy for every measured PLONK column. Account metadata
/// is enforced by the SBF entrypoint; this helper authenticates the exact
/// ordered full-VK set admitted at that address.
fn authenticated_input_digest(groups: &[Group]) -> Option<[u8; 32]> {
    let digest = keyset_digest(groups)?;
    policy_allows_keyset(&digest).then_some(digest)
}

fn shared_srs(groups: &[Group]) -> Option<[PodG2Point; layout::REGISTRY_SOURCE_COUNT]> {
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
    let sources = shared_srs(groups)?;
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
    if key.domain_size != 8 || key.domain_size.trailing_zeros() != 3 {
        return None;
    }
    Some(OptimizedVerifyingKey {
        n_public: key.num_public_inputs,
        power: key.domain_size.trailing_zeros(),
        k1: optimized_fr(&key.k1)?,
        k2: optimized_fr(&key.k2)?,
        w: OptimizedFr::from_be_bytes(&AUTHENTICATED_OMEGA)?,
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
        eval_a: optimized_fr(&proof.evaluations.a)?,
        eval_b: optimized_fr(&proof.evaluations.b)?,
        eval_c: optimized_fr(&proof.evaluations.c)?,
        eval_s1: optimized_fr(&proof.evaluations.s_sigma1)?,
        eval_s2: optimized_fr(&proof.evaluations.s_sigma2)?,
        eval_zw: optimized_fr(&proof.evaluations.z_omega)?,
    })
}

fn validate_group(group: &Group) -> Option<()> {
    if group.proofs.is_empty()
        || authenticated_vk_digest(&group.vk) != group.vk_digest
        || registry_context(&group.vk_digest)? != group.application_context
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
            || [
                &proof.evaluations.a,
                &proof.evaluations.b,
                &proof.evaluations.c,
                &proof.evaluations.s_sigma1,
                &proof.evaluations.s_sigma2,
                &proof.evaluations.z_omega,
            ]
            .into_iter()
            .chain(proof.public_inputs.iter())
            .any(|scalar| optimized_fr(scalar).is_none())
        {
            return None;
        }
    }
    Some(())
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
    if groups.is_empty()
        || groups
            .windows(2)
            .any(|pair| pair[0].application_context >= pair[1].application_context)
    {
        return None;
    }
    let total = groups.iter().try_fold(0usize, |count, group| {
        validate_group(group)?;
        count.checked_add(group.proofs.len())
    })?;
    if total == 0 || total > layout::MAX_TOTAL_PROOFS {
        return None;
    }

    let context_frames: Vec<DigestContext> = groups
        .iter()
        .enumerate()
        .map(|(index, group)| {
            let key = &group.vk;
            Some(DigestContext {
                index: u32::try_from(index).ok()?.to_be_bytes(),
                domain_size: key.domain_size.to_be_bytes(),
                public_count: key.num_public_inputs.to_be_bytes(),
                omega: (key.domain_size == 8).then_some(AUTHENTICATED_OMEGA)?,
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
            for public in &proof.public_inputs {
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
        PodG1G2Pair { g1: p, g2: srs[1] },
        PodG1G2Pair { g1: q, g2: srs[0] },
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
    let pairs = optimized_reduced_pairs(groups)?;
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
    let pairs = optimized_reduced_pairs(groups)?;
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
fn verify_groups_current(groups: &[Group]) -> Option<bool> {
    authenticated_input_digest(groups)?;
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
    verify_groups_current(&groups)
}

/// Current+Fp12: preserve the independent Current verifier arithmetic but
/// end each proof in an independent two-pair map and identity comparison.
/// This deliberately performs no G1 MSM.
fn verify_groups_current_fp12(groups: &[Group]) -> Option<bool> {
    authenticated_input_digest(groups)?;
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
                    g2: srs[1],
                },
                PodG1G2Pair {
                    g1: PodG1Point(operands.b1().0),
                    g2: srs[0],
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
    verify_groups_current_fp12(&groups)
}

fn verify_groups_map(groups: &[Group]) -> Option<bool> {
    authenticated_input_digest(groups)?;
    let pairs = optimized_reduced_pairs(groups)?;
    Some(pairing_map(&pairs)? == identity_bytes())
}

fn verify_groups_boolean(groups: &[Group]) -> Option<bool> {
    use solana_bn254_batch_syscall::{Version, alt_bn128_pairing_check};

    authenticated_input_digest(groups)?;
    let pairs = optimized_reduced_pairs(groups)?;
    alt_bn128_pairing_check(Version::V0, &pairs).ok()
}

/// Verify one authenticated canonical account atomically through the
/// expanded two-MSM kernel and FP12 map. `Some(false)` means every encoding
/// and syscall succeeded but the complete 384-byte GT value was not the identity.
pub fn verify_account(data: &[u8]) -> Option<bool> {
    let groups = parse_account(data)?;
    verify_groups_map(&groups)
}

/// The exact same optimized kernel and reconstructed two-pair equation as
/// [`verify_account`], ending in the existing boolean pairing-check syscall.
pub fn verify_account_boolean(data: &[u8]) -> Option<bool> {
    let groups = parse_account(data)?;
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

/// The only source surface accepted by the native campaign exporter. Callers
/// provide the three clean snarkjs JSON triples in the fixed mul1/mul2/mul3
/// order; binary account encodings are always constructed by this crate.
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
    /// Exact atomic one-group/one-proof accounts in mul1,mul2,mul3 order.
    pub singleton_accounts: Vec<Vec<u8>>,
    /// Exact ordered mul1,mul2 combined account.
    pub n2_combined_account: Vec<u8>,
    /// Exact ordered mul1,mul2,mul3 combined account.
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
struct ExportFixture {
    key: VerifyingKey,
    proof: Proof,
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
        source_id: "mul1",
        verification_key_file_sha256: "28c03da271eb07571213fc9847dacb07843dfe4ed6901e4517fb57dd263694b5",
        proof_file_sha256: "e83bf34c9ee7d9c150a69d28b9cf37ce17a534c04ac8413e8e617e8142116670",
        public_file_sha256: "16e83046941abbbe3196719fedd9cac00ce22a33e7c593cea3910c1bb25d9ac1",
        verification_key_payload_sha256: "34749fdf28225b7bd6131b89437087a628485848820a0ef494fdda7997dc4ea7",
        proof_payload_sha256: "5c9a83928f71e02eea3f0aca91285c2fcf953a4fadef15d41be398fbc6c9fa1e",
        public_payload_sha256: "68104caf9db5c74fc58f69a349ce3b1149634489c6d9917e206ef7b6184d4870",
        authenticated_vk_keccak: "6b376b8db19c8c21e7e096eef433313424eb27746d684e14280b57acc6f0f21d",
    },
    ExportExpectedSource {
        source_id: "mul2",
        verification_key_file_sha256: "3deeb70be57ccb3b370bbc0bf43a19990fcbc9d965afeadfcab4b0fda2e224a6",
        proof_file_sha256: "910d8ca382f845ed6137128572a27c2249a6299759999e2eaab4befdb087e9d3",
        public_file_sha256: "b37e80d45f207decb1dd683675d1ed8186dd9b1a9db4028cbff63c96c2fd972d",
        verification_key_payload_sha256: "c31ac08db74bdd3ec71547020004fe04490210704bc43104a2f29f9d9bc63946",
        proof_payload_sha256: "16b9fb1451a8264c9c1d2ae422a254b797260013133d15e987bd7f1768f3e599",
        public_payload_sha256: "e0387a81b91ed432b83ecce6aa9be25d71081694620d8794b363ade7faedc06d",
        authenticated_vk_keccak: "97d0d351c78ab5ad01b5cdb21defd4197c3ab669f464b0656ef4ef4499cadca4",
    },
    ExportExpectedSource {
        source_id: "mul3",
        verification_key_file_sha256: "cf5443a8d764dedacd2a3bc22d1ac9c0ab2425d10da849112ed0663ea0d1269d",
        proof_file_sha256: "0f62952f0144f62be1c26d4a0ea56a2ff63430eb67e94cc956586206535aed55",
        public_file_sha256: "8348e0afaed33f7d5d4258af4535a9bc8ce44ee8b4eb7ead909b958fce366b35",
        verification_key_payload_sha256: "ebd109f570a720b5cb10d5aa36a29c931f52249f15a45590e6776dde905968a6",
        proof_payload_sha256: "00bdbaf0249300758b667c17bc4c3bde5d2d59959d85d5b56c01b1f63b724bce",
        public_payload_sha256: "6af68d696f015f6b154d3ccd5787e98cd09872f2a366d9e8d078d9581f0fa1a4",
        authenticated_vk_keccak: "6573ca8db0191259008f567fec3ac348ab734fd944b1ea81e35fe65dd46fe65a",
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
fn export_load_fixture(
    source: &CanonicalPlonkSourceInput<'_>,
    expected: &ExportExpectedSource,
) -> Result<(ExportFixture, CanonicalPlonkSourceIdentity), String> {
    use {
        ark_bn254::{Fr, G2Affine},
        ark_ec::AffineRepr,
        ark_ff::FftField,
    };

    if source.source_id != expected.source_id {
        return Err(format!(
            "PLONK source order changed: expected {}, got {}",
            expected.source_id, source.source_id
        ));
    }
    let vk_payload = export_json_payload(source.verification_key_json, "PLONK VK JSON")?;
    let proof_payload = export_json_payload(source.proof_json, "PLONK proof JSON")?;
    let public_payload = export_json_payload(source.public_json, "PLONK public JSON")?;
    let identity = CanonicalPlonkSourceIdentity {
        source_id: source.source_id.into(),
        verification_key_file_sha256: export_sha256(source.verification_key_json),
        proof_file_sha256: export_sha256(source.proof_json),
        public_file_sha256: export_sha256(source.public_json),
        verification_key_payload_sha256: export_sha256(vk_payload),
        proof_payload_sha256: export_sha256(proof_payload),
        public_payload_sha256: export_sha256(public_payload),
        authenticated_vk_keccak: expected.authenticated_vk_keccak.into(),
    };
    if identity.verification_key_file_sha256 != expected.verification_key_file_sha256
        || identity.proof_file_sha256 != expected.proof_file_sha256
        || identity.public_file_sha256 != expected.public_file_sha256
        || identity.verification_key_payload_sha256 != expected.verification_key_payload_sha256
        || identity.proof_payload_sha256 != expected.proof_payload_sha256
        || identity.public_payload_sha256 != expected.public_payload_sha256
    {
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
    let key = VerifyingKey {
        domain_size,
        num_public_inputs: raw_vk.num_public_inputs,
        q_m: export_g1(&raw_vk.q_m, "Qm", false)?,
        q_l: export_g1(&raw_vk.q_l, "Ql", false)?,
        q_r: export_g1(&raw_vk.q_r, "Qr", true)?,
        q_o: export_g1(&raw_vk.q_o, "Qo", false)?,
        q_c: export_g1(&raw_vk.q_c, "Qc", true)?,
        s_sigma: [
            export_g1(&raw_vk.s_1, "S1", false)?,
            export_g1(&raw_vk.s_2, "S2", false)?,
            export_g1(&raw_vk.s_3, "S3", false)?,
        ],
        k1: export_scalar(&raw_vk.k1, "k1")?,
        k2: export_scalar(&raw_vk.k2, "k2")?,
        g2_gen: export_g2_bytes(&G2Affine::generator())?,
        g2_tau: export_g2(&raw_vk.x_2, "X_2")?,
    };
    if export_hex(&authenticated_vk_digest(&key)) != expected.authenticated_vk_keccak {
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
    let proof = Proof {
        wire_commitments: [
            export_g1(&raw_proof.a, "proof A", false)?,
            export_g1(&raw_proof.b, "proof B", false)?,
            export_g1(&raw_proof.c, "proof C", false)?,
        ],
        grand_product: export_g1(&raw_proof.z, "proof Z", false)?,
        quotient: [
            export_g1(&raw_proof.t_1, "proof T1", false)?,
            export_g1(&raw_proof.t_2, "proof T2", false)?,
            export_g1(&raw_proof.t_3, "proof T3", false)?,
        ],
        opening: export_g1(&raw_proof.w_xi, "proof Wxi", false)?,
        shifted_opening: export_g1(&raw_proof.w_xiw, "proof Wxiw", false)?,
        evaluations: Evaluations {
            a: export_scalar(&raw_proof.eval_a, "eval_a")?,
            b: export_scalar(&raw_proof.eval_b, "eval_b")?,
            c: export_scalar(&raw_proof.eval_c, "eval_c")?,
            s_sigma1: export_scalar(&raw_proof.eval_s1, "eval_s1")?,
            s_sigma2: export_scalar(&raw_proof.eval_s2, "eval_s2")?,
            z_omega: export_scalar(&raw_proof.eval_zw, "eval_zw")?,
        },
        public_inputs: public
            .iter()
            .enumerate()
            .map(|(index, value)| export_scalar(value, &format!("public input {index}")))
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok((ExportFixture { key, proof }, identity))
}

#[cfg(not(target_os = "solana"))]
fn export_append_vk(output: &mut Vec<u8>, key: &VerifyingKey) {
    output.extend_from_slice(&key.domain_size.to_be_bytes());
    output.extend_from_slice(&key.num_public_inputs.to_be_bytes());
    for point in [&key.q_m, &key.q_l, &key.q_r, &key.q_o, &key.q_c] {
        output.extend_from_slice(&point.0);
    }
    for point in &key.s_sigma {
        output.extend_from_slice(&point.0);
    }
    output.extend_from_slice(&key.k1.0);
    output.extend_from_slice(&key.k2.0);
    output.extend_from_slice(&key.g2_gen.0);
    output.extend_from_slice(&key.g2_tau.0);
}

#[cfg(not(target_os = "solana"))]
fn export_append_proof(output: &mut Vec<u8>, proof: &Proof) {
    for point in &proof.wire_commitments {
        output.extend_from_slice(&point.0);
    }
    output.extend_from_slice(&proof.grand_product.0);
    for point in &proof.quotient {
        output.extend_from_slice(&point.0);
    }
    output.extend_from_slice(&proof.opening.0);
    output.extend_from_slice(&proof.shifted_opening.0);
    for scalar in [
        &proof.evaluations.a,
        &proof.evaluations.b,
        &proof.evaluations.c,
        &proof.evaluations.s_sigma1,
        &proof.evaluations.s_sigma2,
        &proof.evaluations.z_omega,
    ] {
        output.extend_from_slice(&scalar.0);
    }
    for public in &proof.public_inputs {
        output.extend_from_slice(&public.0);
    }
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
        export_append_vk(&mut output, &fixture.key);
        export_append_proof(&mut output, &fixture.proof);
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

/// Parse and authenticate the exact clean mul1/mul2/mul3 JSON source set,
/// then emit the only binary singleton/n2/n3 account encodings accepted by
/// the production campaign.
#[cfg(not(target_os = "solana"))]
pub fn export_canonical_plonk_rows(
    sources: &[CanonicalPlonkSourceInput<'_>],
) -> Result<CanonicalPlonkRowExport, String> {
    if sources.len() != EXPORT_EXPECTED_SOURCES.len() {
        return Err("canonical PLONK exporter requires exactly mul1,mul2,mul3".into());
    }
    let source_set_sha256 = export_source_set_sha256(sources)?;
    let loaded = sources
        .iter()
        .zip(&EXPORT_EXPECTED_SOURCES)
        .map(|(source, expected)| export_load_fixture(source, expected))
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
        if !batch.owned_by(program_id) || batch.is_writable() {
            return Err(ProgramError::InvalidAccountData);
        }
        let data = batch
            .try_borrow()
            .map_err(|_| ProgramError::AccountBorrowFailed)?;
        let groups = super::parse_account(&data).ok_or(ProgramError::InvalidAccountData)?;
        let input_digest =
            super::authenticated_input_digest(&groups).ok_or(ProgramError::InvalidAccountData)?;
        let (expected_batch, _) = Address::find_program_address(
            &[super::layout::INPUT_PDA_SEED, &input_digest],
            program_id,
        );
        if batch.address() != &expected_batch {
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
        let (expected_registry, _) = Address::find_program_address(
            &[super::layout::REGISTRY_PDA_SEED, &registry_digest],
            program_id,
        );
        if registry.address() != &expected_registry || !registry.owned_by(program_id) {
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
mod exporter_tests {
    use super::*;
    use std::sync::Mutex;

    static OBSERVER_LOCK: Mutex<()> = Mutex::new(());

    const SOURCE_BYTES: [(&str, &[u8], &[u8], &[u8]); 3] = [
        (
            "mul1",
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul1/verification_key.json"
            ),
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul1/proof.json"
            ),
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul1/public.json"
            ),
        ),
        (
            "mul2",
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul2/verification_key.json"
            ),
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul2/proof.json"
            ),
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul2/public.json"
            ),
        ),
        (
            "mul3",
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul3/verification_key.json"
            ),
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul3/proof.json"
            ),
            include_bytes!(
                "../../../../research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions/mul3/public.json"
            ),
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
            ["mul1", "mul2", "mul3"]
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
