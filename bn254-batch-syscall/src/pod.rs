use {
    crate::encoding::{
        FQ12_BYTES, G1_BYTES, G2_BYTES, PLONK_CHALLENGES, PLONK_EVALUATIONS, SCALAR_BYTES,
        SNARKJS_PLONK_PROOF_POINTS, SNARKJS_PLONK_VK_POINTS,
    },
    bytemuck_derive::{Pod, Zeroable},
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encoding::{parse_fq12, parse_fr, parse_g1, parse_g2, serialize_fq12, serialize_g1},
        validation::{AltBn128BatchError, validate_g1, validate_g2},
    },
    ark_bn254::{Fq12, Fr, G1Affine, G2Affine},
    ark_ff::{One, PrimeField},
};

/// G1 affine point: 64 big-endian bytes (x | y), all-zeros = infinity. The wire
/// encoding, never Montgomery limbs; the arkworks type stays inside `to_affine`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG1Point(pub [u8; G1_BYTES]);

/// G2 affine point: 128 big-endian bytes (x1 | x0 | y1 | y0), all-zeros = infinity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodG2Point(pub [u8; G2_BYTES]);

/// Scalar in the BN254 scalar field: 32 big-endian bytes, canonical (< q).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodScalar(pub [u8; SCALAR_BYTES]);

/// Scalar-only context shared by a same-key PLONK reduction batch.
///
/// `omega`, `k1`, and `k2` are canonical BN254 Fr encodings. The byte-array
/// integer fields make the wire layout endian-stable and alignment-1 on every
/// host. `reserved` is zero in V0 and must be rejected otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodPlonkReductionContext {
    pub domain_size_be: [u8; 8],
    pub num_public_inputs_be: [u8; 4],
    pub reserved: [u8; 4],
    pub omega: PodScalar,
    pub k1: PodScalar,
    pub k2: PodScalar,
}

impl PodPlonkReductionContext {
    pub const fn domain_size(&self) -> u64 {
        u64::from_be_bytes(self.domain_size_be)
    }

    pub const fn num_public_inputs(&self) -> u32 {
        u32::from_be_bytes(self.num_public_inputs_be)
    }
}

/// Dynamic scalar inputs for one proof in the non-production synthetic
/// baseline. Canonical snarkjs integrations use
/// [`PodSnarkjsPlonkReductionInput`] instead.
///
/// Challenge slots are the raw 32-byte Keccak digests for
/// `(beta, gamma, alpha, zeta, v, u)`, not canonical scalars. Reducing these
/// digests modulo Fr inside the syscall is byte-for-byte equivalent to the
/// verifier's former `from_be_bytes_mod_order` calls and avoids doing that
/// Montgomery work in SBF. Evaluation slots are canonical
/// `(a, b, c, sigma1, sigma2, z_omega)`. `rho` is the nonzero, canonical outer
/// batch randomizer derived by the caller over the frozen transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodPlonkReductionInput {
    pub challenge_digests: [[u8; SCALAR_BYTES]; PLONK_CHALLENGES],
    pub evaluations: [PodScalar; PLONK_EVALUATIONS],
    pub rho: PodScalar,
}

/// Scalar parameters and raw verification-key bytes for the canonical
/// snarkjs PLONK transcript. Curve validation deliberately remains the MSM
/// and pairing syscalls' responsibility; this record only binds the exact
/// bytes into Fiat-Shamir and validates the scalar/domain context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodSnarkjsPlonkReductionContext {
    pub domain_size_be: [u8; 8],
    pub num_public_inputs_be: [u8; 4],
    pub reserved: [u8; 4],
    pub omega: PodScalar,
    pub k1: PodScalar,
    pub k2: PodScalar,
    pub transcript_vk_points: [PodG1Point; SNARKJS_PLONK_VK_POINTS],
    /// Raw snarkjs `X_2` bytes. This point is deliberately excluded from the
    /// six inner Fiat-Shamir challenges, but included in the outer frozen-batch
    /// seed because changing it changes the final pairing verdict.
    pub x_2: PodG2Point,
}

impl PodSnarkjsPlonkReductionContext {
    pub const fn domain_size(&self) -> u64 {
        u64::from_be_bytes(self.domain_size_be)
    }

    pub const fn num_public_inputs(&self) -> u32 {
        u32::from_be_bytes(self.num_public_inputs_be)
    }
}

/// Raw proof bytes and canonical scalar evaluations for one canonical
/// snarkjs PLONK reduction. Point order is
/// `(A,B,C,Z,T1,T2,T3,Wxi,Wxiw)`. Outer batch randomizers are derived
/// natively from a domain-separated hash of the complete canonical batch;
/// callers cannot choose or omit them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodSnarkjsPlonkReductionInput {
    pub transcript_points: [PodG1Point; SNARKJS_PLONK_PROOF_POINTS],
    pub evaluations: [PodScalar; PLONK_EVALUATIONS],
}

/// One verifier-resolved context in an atomic multi-VK PLONK batch.
///
/// `application_context` is an application-owned circuit/registry binding,
/// not an authorization claim supplied by a proof. The verifier constructs
/// this record only after resolving and validating the allowed key. Both the
/// explicit context index and every byte that affects the final pairing are
/// frozen into the outer transcript. `g2_gen` is separate from the canonical
/// snarkjs `X_2` field because both pairing operands affect the verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodSnarkjsPlonkMultiVkContext {
    pub context_index_be: [u8; 4],
    pub reserved: [u8; 4],
    pub application_context: [u8; 32],
    pub reduction: PodSnarkjsPlonkReductionContext,
    pub g2_gen: PodG2Point,
}

impl PodSnarkjsPlonkMultiVkContext {
    pub const fn context_index(&self) -> u32 {
        u32::from_be_bytes(self.context_index_be)
    }
}

/// One indexed proof in an atomic multi-VK PLONK batch.
///
/// The global proof index must equal its position in the input array. The
/// context index selects the already verifier-resolved context; neither index
/// is inferred from client-controlled offsets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodSnarkjsPlonkMultiVkInput {
    pub proof_index_be: [u8; 4],
    pub context_index_be: [u8; 4],
    pub proof: PodSnarkjsPlonkReductionInput,
}

impl PodSnarkjsPlonkMultiVkInput {
    pub const fn proof_index(&self) -> u32 {
        u32::from_be_bytes(self.proof_index_be)
    }

    pub const fn context_index(&self) -> u32 {
        u32::from_be_bytes(self.context_index_be)
    }
}

/// One pairing input, a G1 point then its G2 partner: 192 contiguous bytes with
/// no padding, so a raw pair buffer casts to `&[PodG1G2Pair]` directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodG1G2Pair {
    pub g1: PodG1Point,
    pub g2: PodG2Point,
}

/// One hot-path pairing operand whose G2 value is resolved by opaque ID from
/// an authenticated immutable registry account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodG1RegisteredG2Pair {
    pub g1: PodG1Point,
    pub g2_id: [u8; 32],
}

/// One authenticated registry GT target plus its canonical Fr exponent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(C)]
pub struct PodTrustedGtExponent {
    pub target_id: [u8; 32],
    pub exponent: PodScalar,
}

/// The 32-byte pairing verdict word, byte-identical to the group-op pairing
/// output: big-endian 1 iff the product is the identity, all zeros otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodPairingResult(pub [u8; 32]);

/// Canonical wire representation of the post-final-exponentiation BN254
/// pairing target.  Despite being an Fq12 value, this type is deliberately
/// named GT: callers must not mistake it for a raw Miller-loop intermediate.
/// Coefficient order is specified by `encoding::serialize_fq12` and never
/// depends on an arithmetic backend's in-memory/Montgomery representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct PodGtElement(pub [u8; FQ12_BYTES]);

#[cfg(not(target_os = "solana"))]
impl PodG1Point {
    /// Canonical coordinates, on-curve; G1 cofactor is 1 so on-curve implies
    /// subgroup membership. Infinity is a valid group element here.
    pub fn to_affine(&self) -> Result<G1Affine, AltBn128BatchError> {
        let point = parse_g1(&self.0)?;
        validate_g1(&point)?;
        Ok(point)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&G1Affine> for PodG1Point {
    fn from(point: &G1Affine) -> Self {
        Self(serialize_g1(point))
    }
}

#[cfg(not(target_os = "solana"))]
impl PodG2Point {
    /// Canonical coordinates, on-curve, r-order subgroup membership.
    pub fn to_affine(&self) -> Result<G2Affine, AltBn128BatchError> {
        let point = parse_g2(&self.0)?;
        validate_g2(&point)?;
        Ok(point)
    }
}

#[cfg(not(target_os = "solana"))]
impl PodScalar {
    pub fn to_fr(&self) -> Result<Fr, AltBn128BatchError> {
        parse_fr(&self.0)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&Fr> for PodScalar {
    fn from(scalar: &Fr) -> Self {
        // serialize the four limbs big-endian in place; no allocation, unlike
        // into_bigint().to_bytes_be(), so batch_invert stays alloc-free per element
        let limbs = scalar.into_bigint().0;
        let mut out = [0u8; SCALAR_BYTES];
        for (out, limb) in out.rchunks_exact_mut(8).zip(limbs) {
            out.copy_from_slice(&limb.to_be_bytes());
        }
        Self(out)
    }
}

#[cfg(not(target_os = "solana"))]
impl PodGtElement {
    pub fn to_fq12(&self) -> Result<Fq12, AltBn128BatchError> {
        parse_fq12(&self.0)
    }

    pub fn identity() -> Self {
        Self(serialize_fq12(&Fq12::one()))
    }
}

#[cfg(not(target_os = "solana"))]
impl From<&Fq12> for PodGtElement {
    fn from(value: &Fq12) -> Self {
        Self(serialize_fq12(value))
    }
}

impl PodPairingResult {
    pub fn from_verdict(verdict: bool) -> Self {
        let mut word = [0u8; 32];
        word[31] = u8::from(verdict);
        Self(word)
    }

    pub fn verdict(&self) -> bool {
        self == &Self::from_verdict(true)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::PAIR_BYTES,
            test_utils::{random_g1, rng},
        },
        core::mem::{align_of, offset_of, size_of},
    };

    // the pointer casts in the host boundary and the test seams are sound only
    // if these hold: exact wire sizes, no padding in the pair, align 1 so any
    // guest byte buffer is trivially aligned
    #[test]
    fn test_pod_layout_matches_wire() {
        assert_eq!(size_of::<PodG1Point>(), G1_BYTES);
        assert_eq!(size_of::<PodG2Point>(), G2_BYTES);
        assert_eq!(size_of::<PodScalar>(), SCALAR_BYTES);
        assert_eq!(size_of::<PodG1G2Pair>(), PAIR_BYTES);
        assert_eq!(size_of::<PodG1RegisteredG2Pair>(), G1_BYTES + 32);
        assert_eq!(size_of::<PodTrustedGtExponent>(), 64);
        assert_eq!(size_of::<PodPairingResult>(), 32);
        assert_eq!(size_of::<PodGtElement>(), FQ12_BYTES);
        assert_eq!(size_of::<PodPlonkReductionContext>(), 112);
        assert_eq!(size_of::<PodPlonkReductionInput>(), 416);
        assert_eq!(size_of::<PodSnarkjsPlonkReductionContext>(), 752);
        assert_eq!(size_of::<PodSnarkjsPlonkReductionInput>(), 768);
        assert_eq!(size_of::<PodSnarkjsPlonkMultiVkContext>(), 920);
        assert_eq!(size_of::<PodSnarkjsPlonkMultiVkInput>(), 776);
        assert_eq!(align_of::<PodG1G2Pair>(), 1);
        assert_eq!(align_of::<PodG1RegisteredG2Pair>(), 1);
        assert_eq!(align_of::<PodTrustedGtExponent>(), 1);
        assert_eq!(align_of::<PodPlonkReductionContext>(), 1);
        assert_eq!(align_of::<PodPlonkReductionInput>(), 1);
        assert_eq!(align_of::<PodSnarkjsPlonkReductionContext>(), 1);
        assert_eq!(align_of::<PodSnarkjsPlonkReductionInput>(), 1);
        assert_eq!(align_of::<PodSnarkjsPlonkMultiVkContext>(), 1);
        assert_eq!(align_of::<PodSnarkjsPlonkMultiVkInput>(), 1);
        assert_eq!(offset_of!(PodG1G2Pair, g1), 0);
        assert_eq!(offset_of!(PodG1G2Pair, g2), G1_BYTES);
        assert_eq!(offset_of!(PodPlonkReductionContext, omega), 16);
        assert_eq!(offset_of!(PodPlonkReductionInput, evaluations), 192);
        assert_eq!(offset_of!(PodPlonkReductionInput, rho), 384);
        assert_eq!(
            offset_of!(PodSnarkjsPlonkReductionContext, transcript_vk_points),
            112
        );
        assert_eq!(offset_of!(PodSnarkjsPlonkReductionContext, x_2), 624);
        assert_eq!(offset_of!(PodSnarkjsPlonkReductionInput, evaluations), 576);
        assert_eq!(offset_of!(PodSnarkjsPlonkMultiVkContext, reduction), 40);
        assert_eq!(offset_of!(PodSnarkjsPlonkMultiVkContext, g2_gen), 792);
        assert_eq!(offset_of!(PodSnarkjsPlonkMultiVkInput, proof), 8);
    }
    #[test]
    fn test_pair_cast_splits_bytes() {
        let mut bytes = [0u8; 2 * PAIR_BYTES];
        bytes[G1_BYTES] = 0xab;
        let pairs: &[PodG1G2Pair] = bytemuck::cast_slice(&bytes);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].g1.0, [0u8; G1_BYTES]);
        assert_eq!(pairs[0].g2.0[0], 0xab);
    }

    #[test]
    fn test_g1_pod_round_trip() {
        let mut rng = rng();
        let point = random_g1(&mut rng);
        assert_eq!(PodG1Point::from(&point).to_affine().unwrap(), point);
    }

    #[test]
    fn test_pairing_result_word() {
        assert_eq!(PodPairingResult::from_verdict(false).0, [0u8; 32]);
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(PodPairingResult::from_verdict(true).0, one);
        assert!(PodPairingResult::from_verdict(true).verdict());
        assert!(!PodPairingResult::from_verdict(false).verdict());

        // A corrupt or non-conforming runtime result must never be interpreted
        // as acceptance merely because its last byte happens to be one.
        let mut non_canonical_true = one;
        non_canonical_true[0] = 1;
        assert!(!PodPairingResult(non_canonical_true).verdict());
        let mut out_of_range = [0u8; 32];
        out_of_range[31] = 2;
        assert!(!PodPairingResult(out_of_range).verdict());
    }

    #[test]
    fn test_gt_identity_is_canonical_and_round_trips() {
        let identity = PodGtElement::identity();
        assert_eq!(identity.to_fq12().unwrap(), Fq12::one());
        assert_eq!(identity.0[..31], [0u8; 31]);
        assert_eq!(identity.0[31], 1);
        assert_eq!(identity.0[32..], [0u8; FQ12_BYTES - 32]);
    }
}
