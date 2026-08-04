//! Agave-shaped, alt_bn128-compatible batch operations.
//!
//! This facade deliberately accepts canonical wire values. It measures and
//! optimizes the work a validator actually performs: decode, validate,
//! arithmetic, and encode. All algorithms in this module are variable-time and
//! are suitable only when their inputs are public.
//!
//! # Encoding contract
//!
//! All values are canonical big-endian, alt_bn128 style. A G1 point is
//! `x | y` (64 bytes); a G2 point is `x1 | x0 | y1 | y0` (128 bytes, Fp2
//! imaginary limb first); a scalar is a canonical 32-byte Fr element. The
//! all-zero point encoding is the point at infinity. Non-canonical field
//! elements (`>= p`, or scalars `>= r`) are rejected, never reduced.
//!
//! # Validation order
//!
//! Error precedence is consensus-visible and fixed: length checks first
//! (mismatch, then empty, then cap), then per-element decoding in input
//! order with G1 validated before G2 within a pair and all points validated
//! before any scalar. G2 points get a full r-subgroup check; G1 needs none
//! (its cofactor is 1).

use alloc::{vec, vec::Vec};
use core::fmt;

use crate::{
    Fp, Fp2, Fp6, Fp12, Fr, G1Affine, G2Affine,
    consts::{FR_MONT_ONE, FR_MONT_R2, R},
    fr::{invert_raw as fr_invert_raw, mont_mul as fr_mont_mul},
    limb,
    msm::msm_variable_time_affine,
    pairing::multi_pairing,
};

/// Per-call cap on [`g1_msm`] points; exceeding it is [`InputError::CapExceeded`].
pub const MSM_MAX_POINTS: usize = 2048;
/// Per-call cap on [`pairing_product_is_one`] pairs.
pub const PAIRING_MAX_PAIRS: usize = 256;
/// Per-call cap on immutable registry targets consumed by
/// [`trusted_gt_multiexp`].
pub const TRUSTED_GT_MAX_TARGETS: usize = 16;
/// Per-call cap on [`fr_lincomb`] and [`fr_batch_invert`] elements.
pub const FR_MAX_ELEMS: usize = 2048;
/// Encoded G1 point size: `x | y`, 32 bytes each.
pub const G1_BYTES: usize = 64;
/// Encoded G2 point size: `x1 | x0 | y1 | y0`, 32 bytes each.
pub const G2_BYTES: usize = 128;
/// Encoded pairing input size: one G1 point followed by one G2 point.
pub const PAIR_BYTES: usize = G1_BYTES + G2_BYTES;
/// Encoded scalar size: one canonical big-endian Fr element.
pub const SCALAR_BYTES: usize = 32;
/// Encoded post-final-exponentiation pairing target: twelve canonical Fp
/// coefficients, 32 bytes each.
pub const GT_BYTES: usize = 12 * 32;

/// Version marker matching Agave's batch-syscall crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// Initial syscall ABI: the caps, encodings, and error precedence above.
    V0,
}

/// G1 affine point encoded as alt_bn128 `x | y`, or all zeroes for infinity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct G1Bytes(pub [u8; 64]);

/// G2 affine point encoded as alt_bn128 `x1 | x0 | y1 | y0`, or all zeroes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct G2Bytes(pub [u8; 128]);

/// Canonical big-endian scalar-field element.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct ScalarBytes(pub [u8; 32]);

/// One contiguous alt_bn128 pairing input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct PairBytes {
    /// G1 partner, validated first within the pair.
    pub g1: G1Bytes,
    /// G2 partner; validation includes the r-subgroup check.
    pub g2: G2Bytes,
}

/// alt_bn128 pairing verdict word used at the syscall boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct PodPairingResult(pub [u8; 32]);

/// Canonical, post-final-exponentiation pairing target.
///
/// Coefficients use the crate's public tower order
/// `c0.c0.{c0,c1}, c0.c1.{c0,c1}, c0.c2.{c0,c1},
/// c1.c0.{c0,c1}, c1.c1.{c0,c1}, c1.c2.{c0,c1}`. Each coefficient is a
/// canonical 32-byte big-endian Fp value. Pairing-map is an output-only
/// operation: no checked-facade operation accepts caller-supplied GT/Fp12
/// bytes as arithmetic or equality input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct GtBytes(pub [u8; GT_BYTES]);

/// An immutable post-final-exponentiation target minted from a checked pair.
///
/// The wrapped field value is deliberately private and this type has no byte
/// decoder. A validator runtime is expected to create these entries while
/// installing a verification key, bind the original pair and entry identifier
/// into that key's authenticated digest, and expose only registry identifiers
/// to programs. The hot operation then resolves those identifiers to this
/// type; caller-originated GT/Fp12 bytes never cross the syscall boundary.
#[derive(Clone, Debug)]
pub struct TrustedGt {
    value: Fp12,
}

// Exact Agave-facing spellings. `pub use` preserves tuple-struct constructors,
// unlike type aliases, while the shorter names remain convenient internally.
pub use G1Bytes as PodG1Point;
pub use G2Bytes as PodG2Point;
pub use GtBytes as PodGt;
pub use PairBytes as PodG1G2Pair;
pub use ScalarBytes as PodScalar;

/// Stable validation taxonomy shared with the Agave batch-syscall design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    /// Input length is not a whole number of encoded elements.
    InvalidLength,
    /// Field element or scalar encoding is `>= p` (or `>= r`).
    NonCanonical,
    /// Decoded point does not satisfy the curve equation.
    NotOnCurve,
    /// G2 point is on the twist but outside the r-order subgroup.
    NotInSubgroup,
    /// Input is empty, or a batch-inversion element is zero.
    ZeroInput,
    /// Element count exceeds the operation's per-call cap.
    CapExceeded,
    /// Paired input slices disagree in element count.
    LengthMismatch,
}

pub use InputError as AltBn128BatchError;

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "input length is not a whole number of elements",
            Self::NonCanonical => "field element encoding is not canonical",
            Self::NotOnCurve => "point is not on the curve",
            Self::NotInSubgroup => "G2 point is not in the r-order subgroup",
            Self::ZeroInput => "input is empty or contains a non-invertible zero",
            Self::CapExceeded => "input exceeds the per-call cap",
            Self::LengthMismatch => "input arrays disagree in count",
        })
    }
}

// `core::error::Error` keeps the Agave-facing error usable by `thiserror`
// consumers without forcing the arithmetic crate to enable `std`.
impl core::error::Error for InputError {}

impl G1Bytes {
    /// Decode and fully validate: canonical coordinates, then on-curve.
    /// All-zero bytes decode to infinity. G1 needs no subgroup check.
    #[inline]
    pub fn to_affine(&self) -> Result<G1Affine, InputError> {
        decode_g1(self)
    }

    /// Encode to canonical `x | y` bytes; infinity encodes as all zeroes.
    #[inline]
    pub fn from_affine(point: &G1Affine) -> Self {
        encode_g1(point)
    }
}

impl G2Bytes {
    /// Decode and fully validate: canonical coordinates, on-curve, then
    /// r-subgroup membership. All-zero bytes decode to infinity.
    #[inline]
    pub fn to_affine(&self) -> Result<G2Affine, InputError> {
        decode_g2(self)
    }

    /// Encode to canonical `x1 | x0 | y1 | y0` bytes; infinity is all zeroes.
    #[inline]
    pub fn from_affine(point: &G2Affine) -> Self {
        encode_g2(point)
    }
}

impl ScalarBytes {
    /// Decode a canonical big-endian scalar; values `>= r` are
    /// [`InputError::NonCanonical`], never reduced.
    #[inline]
    pub fn to_fr(&self) -> Result<Fr, InputError> {
        Fr::from_bytes_be(&self.0).ok_or(InputError::NonCanonical)
    }

    /// Encode to canonical big-endian bytes.
    #[inline]
    pub fn from_fr(scalar: Fr) -> Self {
        Self(scalar.to_bytes_be())
    }
}

impl PodPairingResult {
    /// Encode a pairing verdict: 32 bytes, big-endian 1 for true, 0 for false.
    #[inline]
    pub fn from_verdict(verdict: bool) -> Self {
        let mut output = [0u8; 32];
        output[31] = u8::from(verdict);
        Self(output)
    }

    /// True iff the word encodes a passing pairing check.
    #[inline]
    pub fn verdict(&self) -> bool {
        self.0[31] == 1
    }
}

impl GtBytes {
    /// Encode a trusted pairing result in canonical tower order.
    #[inline]
    fn from_gt(value: &Fp12) -> Self {
        let coefficients = [
            value.c0.c0.c0,
            value.c0.c0.c1,
            value.c0.c1.c0,
            value.c0.c1.c1,
            value.c0.c2.c0,
            value.c0.c2.c1,
            value.c1.c0.c0,
            value.c1.c0.c1,
            value.c1.c1.c0,
            value.c1.c1.c1,
            value.c1.c2.c0,
            value.c1.c2.c1,
        ];
        let mut output = [0u8; GT_BYTES];
        for (slot, coefficient) in output.chunks_exact_mut(32).zip(coefficients) {
            slot.copy_from_slice(&coefficient.to_bytes_be());
        }
        Self(output)
    }

    /// True iff these bytes equal the canonical GT identity encoding.
    ///
    /// This is only a byte comparison and is intended for values returned by
    /// [`pairing_map`], not arbitrary caller-originated bytes.
    #[inline]
    pub fn is_identity(&self) -> bool {
        let mut identity = [0u8; GT_BYTES];
        identity[31] = 1;
        self.0 == identity
    }
}

impl TrustedGt {
    /// Mint a registry target from one canonical, fully validated G1/G2 pair.
    ///
    /// This performs the expensive pairing and final exponentiation once on
    /// the registry/install path. Authentication and ownership of the
    /// resulting registry entry are runtime responsibilities; subgroup
    /// membership alone does not authenticate a verification-key target.
    pub fn from_pair(pair: &PairBytes) -> Result<Self, InputError> {
        pairing_product(core::slice::from_ref(pair)).map(|value| Self { value })
    }

    /// Decode a canonical GT value from an authenticated, immutable registry.
    ///
    /// Every coefficient is checked for canonical Fp encoding and the decoded
    /// Fp12 value is checked to be a nonzero member of the r-order subgroup.
    /// This constructor is intentionally not a general caller-byte facade: it
    /// exists for validator runtimes which persist a pairing-map result in a
    /// program-owned registry and later resolve only opaque entry identifiers.
    ///
    /// # Safety
    ///
    /// The caller must have authenticated `bytes` as part of immutable state
    /// owned by the consuming program, including binding it to the original
    /// checked G1/G2 pair and opaque identifier. Subgroup membership alone
    /// does not establish that provenance.
    pub unsafe fn from_authenticated_registry_bytes(bytes: &GtBytes) -> Result<Self, InputError> {
        let mut coefficients = [Fp::ZERO; 12];
        for (coefficient, encoded) in coefficients.iter_mut().zip(bytes.0.chunks_exact(32)) {
            let encoded: &[u8; 32] = encoded.try_into().expect("fixed GT coefficient length");
            *coefficient = Fp::from_bytes_be(encoded).ok_or(InputError::NonCanonical)?;
        }

        let value = Fp12::new(
            Fp6::new(
                Fp2::new(coefficients[0], coefficients[1]),
                Fp2::new(coefficients[2], coefficients[3]),
                Fp2::new(coefficients[4], coefficients[5]),
            ),
            Fp6::new(
                Fp2::new(coefficients[6], coefficients[7]),
                Fp2::new(coefficients[8], coefficients[9]),
                Fp2::new(coefficients[10], coefficients[11]),
            ),
        );

        let scalar_bits: Vec<bool> = (0..256)
            .map(|bit| ((R[bit / 64] >> (bit % 64)) & 1) != 0)
            .collect();
        if value.is_zero() || value.pow_bits(&scalar_bits) != Fp12::ONE {
            return Err(InputError::NotInSubgroup);
        }

        Ok(Self { value })
    }
}

/// Agave-compatible spelling of [`g1_msm`].
#[inline]
pub fn alt_bn128_g1_msm(
    _version: Version,
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, AltBn128BatchError> {
    g1_msm(points, scalars)
}

/// Agave-compatible spelling of [`pairing_product_is_one`].
#[inline]
pub fn alt_bn128_pairing_check(
    _version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<bool, AltBn128BatchError> {
    pairing_product_is_one(pairs)
}

/// Agave-shaped spelling of [`pairing_map`].
#[inline]
pub fn alt_bn128_pairing_map(
    _version: Version,
    pairs: &[PodG1G2Pair],
) -> Result<PodGt, AltBn128BatchError> {
    pairing_map(pairs)
}

/// Agave-compatible spelling of [`fr_lincomb`].
#[inline]
pub fn alt_bn128_fr_lincomb(
    _version: Version,
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    fr_lincomb(a, b)
}

/// Agave-compatible spelling of [`fr_batch_invert`].
#[inline]
pub fn alt_bn128_fr_batch_invert(
    _version: Version,
    values: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    fr_batch_invert(values)
}

/// Variable-time G1 multi-scalar multiplication with Agave validation order.
///
/// Returns the canonical encoding of `sum(scalars[i] * points[i])`.
/// Precedence: [`InputError::LengthMismatch`], [`InputError::ZeroInput`]
/// (empty), [`InputError::CapExceeded`] (over [`MSM_MAX_POINTS`]), then every
/// point validated in order before any scalar is examined.
pub fn g1_msm(points: &[G1Bytes], scalars: &[ScalarBytes]) -> Result<G1Bytes, InputError> {
    if points.len() != scalars.len() {
        return Err(InputError::LengthMismatch);
    }
    if points.is_empty() {
        return Err(InputError::ZeroInput);
    }
    if points.len() > MSM_MAX_POINTS {
        return Err(InputError::CapExceeded);
    }

    // Consensus-visible precedence: every point is validated before any scalar.
    let mut bases = Vec::with_capacity(points.len());
    for point in points {
        bases.push(point.to_affine()?);
    }
    let mut exponents = Vec::with_capacity(scalars.len());
    for scalar in scalars {
        exponents.push(decode_scalar_raw(scalar)?);
    }

    Ok(encode_g1(&msm_variable_time_affine(&bases, &exponents)))
}

/// True iff the product of all pairings is the GT identity.
///
/// Precedence: [`InputError::ZeroInput`] (empty), [`InputError::CapExceeded`]
/// (over [`PAIRING_MAX_PAIRS`]), then pairs validated in order, G1 before G2
/// within each pair. Every pair is validated even when its partner is
/// infinity; a batch whose pairs all involve infinity yields `Ok(true)`.
pub fn pairing_product_is_one(pairs: &[PairBytes]) -> Result<bool, InputError> {
    Ok(pairing_product(pairs)?.is_one())
}

/// Return the canonical post-final-exponentiation product of all pairings.
///
/// Inputs, caps, validation order, infinity handling, G2 cache behavior, and
/// arithmetic dispatch are exactly those of [`pairing_product_is_one`]. The
/// only extra work is canonical serialization of the trusted GT result. No
/// inverse conversion exists on this checked facade.
pub fn pairing_map(pairs: &[PairBytes]) -> Result<GtBytes, InputError> {
    pairing_product(pairs).map(|value| GtBytes::from_gt(&value))
}

/// Exponentiate runtime-resolved registry targets and return canonical GT.
///
/// This is the arithmetic core for an opaque-target syscall whose public
/// operands are immutable registry identifiers plus canonical Fr exponents.
/// The runtime resolves the identifiers to [`TrustedGt`] entries before this
/// call; no caller-supplied GT/Fp12 bytes are accepted. The returned bytes can
/// be compared directly with [`pairing_map`]'s output by an SBF program.
///
/// This arithmetic layer does not authenticate a [`TrustedGt`] by itself.
/// The runtime must bind every identifier and source pair into the owning
/// program's authenticated verification-key digest. Empty target/exponent
/// slices return the canonical GT identity.
pub fn trusted_gt_multiexp(
    targets: &[TrustedGt],
    exponents: &[ScalarBytes],
) -> Result<GtBytes, InputError> {
    trusted_gt_multiexp_value(targets, exponents).map(|value| GtBytes::from_gt(&value))
}

fn trusted_gt_multiexp_value(
    targets: &[TrustedGt],
    exponents: &[ScalarBytes],
) -> Result<Fp12, InputError> {
    if targets.len() != exponents.len() {
        return Err(InputError::LengthMismatch);
    }
    if targets.len() > TRUSTED_GT_MAX_TARGETS {
        return Err(InputError::CapExceeded);
    }
    if targets.is_empty() {
        return Ok(Fp12::ONE);
    }

    let mut scalar_limbs = Vec::with_capacity(exponents.len());
    for exponent in exponents {
        scalar_limbs.push(decode_scalar_raw(exponent)?);
    }

    // Four-bit fixed windows keep the table bounded (16 GT values per trusted
    // entry) while reducing the hot multiplies from about 127 to about 60 per
    // random exponent. Even table powers use cyclotomic squaring because every
    // target is a post-final-exponentiation pairing image.
    let mut tables = Vec::<[Fp12; 16]>::with_capacity(targets.len());
    for target in targets {
        let mut table = [Fp12::ONE; 16];
        table[1] = target.value;
        for digit in 2..16 {
            table[digit] = if digit & 1 == 0 {
                table[digit / 2].cyclotomic_square()
            } else {
                table[digit - 1] * target.value
            };
        }
        tables.push(table);
    }

    let mut expected = Fp12::ONE;
    for window in (0..64).rev() {
        for _ in 0..4 {
            expected = expected.cyclotomic_square();
        }
        let limb = window / 16;
        let shift = (window % 16) * 4;
        for (table, scalar) in tables.iter().zip(&scalar_limbs) {
            let digit = ((scalar[limb] >> shift) & 0x0f) as usize;
            if digit != 0 {
                expected *= table[digit];
            }
        }
    }
    Ok(expected)
}

fn pairing_product(pairs: &[PairBytes]) -> Result<Fp12, InputError> {
    if pairs.is_empty() {
        return Err(InputError::ZeroInput);
    }
    if pairs.len() > PAIRING_MAX_PAIRS {
        return Err(InputError::CapExceeded);
    }

    // Validate both partners before deciding whether an infinity pair can be
    // removed from the arithmetic product.
    let mut decoded = Vec::with_capacity(pairs.len());
    let mut validated_g2 = Vec::<(G2Bytes, G2Affine)>::with_capacity(pairs.len());
    for pair in pairs {
        // G1 validation is consensus-visible and must precede both G2
        // validation and cache lookup for this pair.
        let g1 = pair.g1.to_affine()?;
        let g2 = if let Some((_, point)) = validated_g2
            .iter()
            .find(|(encoding, _)| encoding == &pair.g2)
        {
            *point
        } else {
            let point = pair.g2.to_affine()?;
            validated_g2.push((pair.g2, point));
            point
        };
        if !g1.infinity && !g2.infinity {
            decoded.push((g1, g2));
        }
    }
    if decoded.is_empty() {
        return Ok(Fp12::ONE);
    }

    // With >= 8 non-identity terms an AVX-512 IFMA build runs the Miller loops
    // 8-wide ([`crate::batch8::multi_pairing8`]) under one shared final
    // exponentiation. Below 8 the scalar path wins: it keeps the common-Q
    // bilinearity fold and pays no radix-52 domain conversion.
    #[cfg(helios_avx512_ifma)]
    if decoded.len() >= 8 {
        return Ok(crate::batch8::multi_pairing8(&decoded));
    }
    let refs: Vec<_> = decoded.iter().map(|(g1, g2)| (g1, g2)).collect();
    Ok(multi_pairing(&refs))
}

/// `sum(a[i] * b[i])` in Fr, with one canonical output reduction.
///
/// Precedence: [`InputError::LengthMismatch`], [`InputError::ZeroInput`]
/// (empty), [`InputError::CapExceeded`] (over [`FR_MAX_ELEMS`]), then pairs
/// decoded in order; any scalar `>= r` is [`InputError::NonCanonical`].
pub fn fr_lincomb(a: &[ScalarBytes], b: &[ScalarBytes]) -> Result<ScalarBytes, InputError> {
    if a.len() != b.len() {
        return Err(InputError::LengthMismatch);
    }
    if a.is_empty() {
        return Err(InputError::ZeroInput);
    }
    if a.len() > FR_MAX_ELEMS {
        return Err(InputError::CapExceeded);
    }

    // A raw/raw Montgomery multiply produces `a*b/R`. Accumulating those
    // products and multiplying by R^2 once at the end gives the canonical dot
    // product. This removes two Montgomery multiplications per input pair.
    let mut acc = [0u64; 4];
    for (x, y) in a.iter().zip(b) {
        let x = decode_scalar_raw(x)?;
        let y = decode_scalar_raw(y)?;
        let product = fr_mont_mul(&x, &y).0;
        acc = limb::add_mod(&acc, &product, &R);
    }
    let canonical = fr_mont_mul(&acc, &FR_MONT_R2).0;
    Ok(ScalarBytes(encode_scalar_raw(canonical)))
}

/// Montgomery's batch inversion trick: one inversion and `3n - 3` products.
///
/// Returns the canonical inverse of every element, in input order.
/// Precedence: [`InputError::ZeroInput`] (empty), [`InputError::CapExceeded`]
/// (over [`FR_MAX_ELEMS`]), then elements decoded in order; a zero element is
/// also [`InputError::ZeroInput`], surfaced at its position in that scan.
pub fn fr_batch_invert(values: &[ScalarBytes]) -> Result<Vec<ScalarBytes>, InputError> {
    if values.is_empty() {
        return Err(InputError::ZeroInput);
    }
    if values.len() > FR_MAX_ELEMS {
        return Err(InputError::CapExceeded);
    }

    // Keep all values in their canonical-limb scale. Starting the prefix at R
    // makes its scale descend by one per raw input. The raw inverse of the
    // final scaled product then has exactly the compensating scale, so every
    // backward output is canonical without per-element Montgomery conversion.
    // The first `M(R, a[0])` and final `M(a[0]^-1, R)` identities are elided,
    // as is the unused last accumulator update: exactly 3n-3 products remain.
    let mut field = Vec::with_capacity(values.len());
    let mut prefix = Vec::with_capacity(values.len());
    let mut product = FR_MONT_ONE;
    for (index, value) in values.iter().enumerate() {
        let value = decode_scalar_raw(value)?;
        if limb::is_zero(&value) {
            return Err(InputError::ZeroInput);
        }
        prefix.push(product);
        product = if index == 0 {
            value
        } else {
            fr_mont_mul(&product, &value).0
        };
        field.push(value);
    }

    let mut product_inverse =
        fr_invert_raw(product).expect("product of nonzero field elements is nonzero");
    let mut output = vec![ScalarBytes([0; 32]); field.len()];
    for i in (0..field.len()).rev() {
        if i == 0 {
            output[0] = ScalarBytes(encode_scalar_raw(product_inverse));
            break;
        }
        let inverse = fr_mont_mul(&product_inverse, &prefix[i]).0;
        output[i] = ScalarBytes(encode_scalar_raw(inverse));
        product_inverse = fr_mont_mul(&product_inverse, &field[i]).0;
    }
    Ok(output)
}

#[inline]
fn decode_g1(bytes: &G1Bytes) -> Result<G1Affine, InputError> {
    if bytes.0.iter().all(|byte| *byte == 0) {
        return Ok(G1Affine::identity());
    }
    let x = decode_fp(&bytes.0[0..32])?;
    let y = decode_fp(&bytes.0[32..64])?;
    let point = G1Affine {
        x,
        y,
        infinity: false,
    };
    if !point.is_on_curve() {
        return Err(InputError::NotOnCurve);
    }
    Ok(point)
}

#[inline]
fn decode_g2(bytes: &G2Bytes) -> Result<G2Affine, InputError> {
    if bytes.0.iter().all(|byte| *byte == 0) {
        return Ok(G2Affine::identity());
    }
    let x1 = decode_fp(&bytes.0[0..32])?;
    let x0 = decode_fp(&bytes.0[32..64])?;
    let y1 = decode_fp(&bytes.0[64..96])?;
    let y0 = decode_fp(&bytes.0[96..128])?;
    let point = G2Affine {
        x: Fp2::new(x0, x1),
        y: Fp2::new(y0, y1),
        infinity: false,
    };
    if !point.is_on_curve() {
        return Err(InputError::NotOnCurve);
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(InputError::NotInSubgroup);
    }
    Ok(point)
}

#[inline]
fn decode_fp(bytes: &[u8]) -> Result<Fp, InputError> {
    let bytes: &[u8; 32] = bytes.try_into().map_err(|_| InputError::InvalidLength)?;
    Fp::from_bytes_be(bytes).ok_or(InputError::NonCanonical)
}

#[inline]
fn decode_scalar_raw(bytes: &ScalarBytes) -> Result<[u64; 4], InputError> {
    let bytes = &bytes.0;
    let limbs = [
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
    ];
    if limb::gte(&limbs, &R) {
        return Err(InputError::NonCanonical);
    }
    Ok(limbs)
}

#[inline]
fn encode_scalar_raw(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let start = 24 - 8 * i;
        out[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    out
}

#[inline]
fn encode_g1(point: &G1Affine) -> G1Bytes {
    if point.infinity {
        return G1Bytes([0; 64]);
    }
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&point.x.to_bytes_be());
    out[32..64].copy_from_slice(&point.y.to_bytes_be());
    G1Bytes(out)
}

#[inline]
fn encode_g2(point: &G2Affine) -> G2Bytes {
    if point.infinity {
        return G2Bytes([0; 128]);
    }
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&point.x.c1.to_bytes_be());
    out[32..64].copy_from_slice(&point.x.c0.to_bytes_be());
    out[64..96].copy_from_slice(&point.y.c1.to_bytes_be());
    out[96..128].copy_from_slice(&point.y.c0.to_bytes_be());
    G2Bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn be_field_round_trips() {
        for value in [0, 1, 2, u64::MAX] {
            let fp = Fp::from_u64(value);
            assert_eq!(Fp::from_bytes_be(&fp.to_bytes_be()), Some(fp));
            let fr = Fr::from_u64(value);
            assert_eq!(Fr::from_bytes_be(&fr.to_bytes_be()), Some(fr));
        }
    }

    #[test]
    fn g2_generator_passes_subgroup_check() {
        let generator = G2Affine::arkworks_generator();
        assert!(generator.is_on_curve());
        assert!(generator.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn authenticated_registry_gt_round_trips_pairing_map() {
        let pair = PairBytes {
            g1: G1Bytes::from_affine(&G1Affine::generator()),
            g2: G2Bytes::from_affine(&G2Affine::arkworks_generator()),
        };
        let encoded = pairing_map(core::slice::from_ref(&pair)).unwrap();
        // SAFETY: this test authenticates `encoded` by deriving it directly
        // from the checked source pair immediately above.
        let target = unsafe { TrustedGt::from_authenticated_registry_bytes(&encoded) }.unwrap();
        let one = ScalarBytes::from_fr(Fr::ONE);
        assert_eq!(trusted_gt_multiexp(&[target], &[one]).unwrap(), encoded);
    }

    #[test]
    fn authenticated_registry_gt_rejects_noncanonical_and_non_subgroup() {
        let mut noncanonical = GtBytes([0; GT_BYTES]);
        noncanonical.0[..32].fill(0xff);
        // SAFETY: the test deliberately exercises the decoder; there is no
        // caller-controlled syscall path involved.
        assert!(matches!(
            unsafe { TrustedGt::from_authenticated_registry_bytes(&noncanonical) },
            Err(InputError::NonCanonical)
        ));

        let mut not_in_subgroup = GtBytes([0; GT_BYTES]);
        not_in_subgroup.0[31] = 2;
        // SAFETY: as above, this is a direct negative decoder test.
        assert!(matches!(
            unsafe { TrustedGt::from_authenticated_registry_bytes(&not_in_subgroup) },
            Err(InputError::NotInSubgroup)
        ));
    }
}
