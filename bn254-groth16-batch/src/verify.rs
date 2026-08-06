use {
    crate::{
        Groth16BatchError, Version,
        transcript::{RandomizerMode, derive_randomizer_scalars, derive_seed},
        vk::ValidatedVerifyingKey,
    },
    ark_bn254::Fr,
    ark_ff::{BigInteger, PrimeField},
    solana_bn254_batch_syscall::{
        PAIRING_MAX_PAIRS, PodG1G2Pair, PodG1Point, PodG2Point, PodScalar, alt_bn128_fr_lincomb,
        alt_bn128_g1_msm, alt_bn128_pairing_check,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofCommitment {
    pub com: PodG1Point,
    pub pok: PodG1Point,
}

/// One batch record, in the typed wire encoding of the batch syscalls.
/// `vk_index` names the proof's key within the batch's key list; whether
/// `commitment` must be present is a function of that key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub vk_index: u16,
    pub a: PodG1Point,
    pub b: PodG2Point,
    pub c: PodG1Point,
    pub commitment: Option<ProofCommitment>,
    pub public_inputs: Vec<PodScalar>,
}

/// Batched Groth16 verification over the two batch syscalls, the reference the
/// on-chain program layer follows.
///
/// Every randomizer folds into the G1 side by bilinearity, so the whole fold
/// is G1 MSMs; the fixed-G2 terms collapse per key, giving n + 3 pair terms
/// per vanilla key and n + 5 per committed key in a single boolean pairing
/// check. Randomizers attach to verification equations, not proofs: a
/// committed proof draws r_i for the Groth16 relation and a separate s_i for
/// the Pedersen proof of knowledge.
pub fn groth16_batch_verify(
    _version: Version,
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    mode: RandomizerMode,
) -> Result<bool, Groth16BatchError> {
    let pairs = fold_pairs_for_verification(vks, proofs, mode)?;
    Ok(alt_bn128_pairing_check(
        solana_bn254_batch_syscall::Version::V0,
        &pairs,
    )?)
}

/// Build the exact pair list consumed by [`groth16_batch_verify`], including
/// the verifier's canonical transcript-derived randomizers. Registry-backed
/// runtimes use this composition surface to send the leading proof terms as
/// full pairs and the fixed-key suffix as authenticated prepared-G2 terms
/// without reimplementing or drifting the B5 transcript.
#[inline]
pub fn fold_pairs_for_verification(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    mode: RandomizerMode,
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    // Shape and canonicality checks come before any hashing.
    validate_batch_shape(vks, proofs)?;
    let seed = derive_seed(mode, vks, proofs);
    let randomizers = derive_randomizer_scalars(&seed, equation_count(proofs), mode);
    fold_pairs_scalars_prevalidated(vks, proofs, &randomizers)
}

/// One verification equation per proof plus one more for a committed proof's
/// Pedersen proof of knowledge; the randomizer stream is indexed by equation.
#[inline]
pub fn equation_count(proofs: &[Proof]) -> u64 {
    proofs
        .iter()
        .map(|proof| if proof.commitment.is_some() { 2u64 } else { 1 })
        .sum()
}

/// Shape and canonicality checks over the frozen batch, before any hashing.
/// Public as a composition surface: a joint (multi-scheme) verifier runs the
/// same checks before absorbing this batch into its own transcript.
#[inline]
pub fn validate_batch_shape(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
) -> Result<(), Groth16BatchError> {
    if proofs.is_empty() {
        // an empty batch would vacuously accept; the syscall rejects zero
        // pairs too, but the SDK boundary rejects first
        return Err(Groth16BatchError::EmptyBatch);
    }
    // vk_index is a u16 and the transcript frames the key count as a u16, so a
    // longer key list both leaves keys unaddressable and truncates the count
    // prefix, desyncing the digest list from the proof region
    if vks.len() > usize::from(u16::MAX) {
        return Err(Groth16BatchError::TooManyVerifyingKeys);
    }
    if proofs.len() > PAIRING_MAX_PAIRS {
        return Err(Groth16BatchError::TooManyPairs);
    }
    let mut key_seen = vec![false; vks.len()];
    let mut pair_count = proofs.len();
    for proof in proofs {
        let key_index = usize::from(proof.vk_index);
        let vk = vks
            .get(key_index)
            .ok_or(Groth16BatchError::UnknownVerifyingKey)?;
        if !key_seen[key_index] {
            key_seen[key_index] = true;
            pair_count = pair_count
                .checked_add(if vk.key().pedersen.is_some() { 5 } else { 3 })
                .ok_or(Groth16BatchError::TooManyPairs)?;
            if pair_count > PAIRING_MAX_PAIRS {
                return Err(Groth16BatchError::TooManyPairs);
            }
        }
        if proof.public_inputs.len() != vk.key().num_public_inputs() {
            return Err(Groth16BatchError::InputCountMismatch);
        }
        if proof.commitment.is_some() != vk.key().pedersen.is_some() {
            return Err(Groth16BatchError::CommitmentMismatch);
        }
        // the syscall would skip an infinity pair as the identity factor;
        // in a proof position that is a degenerate proof, so reject here

        if is_infinity_g1(&proof.a) || all_zero(&proof.b.0) || is_infinity_g1(&proof.c) {
            return Err(Groth16BatchError::InfinityInProofPosition);
        }
        if let Some(commitment) = &proof.commitment {
            if is_infinity_g1(&commitment.com) || is_infinity_g1(&commitment.pok) {
                return Err(Groth16BatchError::InfinityInProofPosition);
            }
        }
        for input in &proof.public_inputs {
            // Canonicality only: the value itself is never used here. Building
            // the field element to test it costs a Montgomery conversion per
            // input, ~2,000 CU on SBF against ~60 for the comparison.
            if !is_canonical_fr_be(input) {
                return Err(Groth16BatchError::NonCanonicalInput);
            }
        }
    }
    Ok(())
}

/// The folded pair list: per proof e([r_i]A_i, B_i), then per key the
/// MSM-fed fixed-G2 terms. Negations fold into the MSM scalars ((r - s)P
/// = -[s]P), so no point is ever negated outside the field.
///
/// Checked public composition surface. A joint verifier may concatenate this
/// pair list with other schemes' pairs into one pairing check. `randomizers`
/// are one per verification equation ([`equation_count`]) in proof order, the
/// Groth16 equation before the PoK within a committed proof.
pub fn fold_pairs(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    randomizers: &[Fr],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    validate_batch_shape(vks, proofs)?;
    fold_pairs_prevalidated(vks, proofs, randomizers)
}

/// Fold helper for composition layers that already called
/// [`validate_batch_shape`] before freezing a joint transcript. Prefer
/// [`fold_pairs`] everywhere else.
#[doc(hidden)]
pub fn fold_pairs_prevalidated(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    randomizers: &[Fr],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    let randomizers: Vec<PodScalar> = randomizers.iter().map(fr_to_pod).collect();
    fold_pairs_scalars_prevalidated(vks, proofs, &randomizers)
}

/// The fold itself, over randomizers already in the syscalls' wire encoding.
///
/// Nothing here builds a field element. Every coefficient is a canonical
/// big-endian scalar produced by the scalar-field syscall, which reduces once
/// per call, and the public inputs go to that syscall as the wire bytes they
/// already are.
#[inline]
fn fold_pairs_scalars_prevalidated(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    randomizers: &[PodScalar],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    if randomizers.len() as u64 != equation_count(proofs) {
        return Err(Groth16BatchError::RandomizerCountMismatch);
    }

    // Equation index of each proof's r_i; a committed proof's s_i is the next
    // one. A batch with no committed proof draws one equation per proof, so
    // the map is the identity and the table is not built at all.
    let committed = proofs.iter().any(|proof| proof.commitment.is_some());
    let mut equation_of_proof: Vec<u32> = Vec::new();
    if committed {
        equation_of_proof.reserve_exact(proofs.len());
        let mut equation = 0usize;
        for proof in proofs {
            equation_of_proof
                .push(u32::try_from(equation).map_err(|_| Groth16BatchError::TooManyPairs)?);
            equation = equation
                .checked_add(if proof.commitment.is_some() { 2 } else { 1 })
                .ok_or(Groth16BatchError::TooManyPairs)?;
        }
    }
    let equation_of = |index: usize| -> Result<usize, Groth16BatchError> {
        if committed {
            equation_of_proof
                .get(index)
                .map(|equation| *equation as usize)
                .ok_or(Groth16BatchError::RandomizerCountMismatch)
        } else {
            Ok(index)
        }
    };
    let randomizer_at = |equation: usize| -> Result<&PodScalar, Groth16BatchError> {
        randomizers
            .get(equation)
            .ok_or(Groth16BatchError::RandomizerCountMismatch)
    };
    let proof_at = |index: u32| -> Result<&Proof, Groth16BatchError> {
        proofs
            .get(index as usize)
            .ok_or(Groth16BatchError::UnknownVerifyingKey)
    };

    let mut pairs: Vec<PodG1G2Pair> =
        Vec::with_capacity(proofs.len().saturating_add(vks.len().saturating_mul(5)));
    let mut sink = PairSink::over(&mut pairs);

    // e([r_i]A_i, B_i): the per-proof G2 points are the only ones that
    // resist folding
    for (index, proof) in proofs.iter().enumerate() {
        sink.push(
            msm(
                core::slice::from_ref(&proof.a),
                core::slice::from_ref(randomizer_at(equation_of(index)?)?),
            )?,
            proof.b,
        )?;
    }

    // Per-key scratch, allocated once for the whole fold.
    let mut members: Vec<u32> = Vec::with_capacity(proofs.len());
    let mut neg_r: Vec<PodScalar> = Vec::with_capacity(proofs.len());
    let mut column: Vec<PodScalar> = Vec::with_capacity(proofs.len());
    let mut points: Vec<PodG1Point> = Vec::with_capacity(proofs.len());
    let mut scalars: Vec<PodScalar> = Vec::with_capacity(proofs.len());

    for (key_index, vk) in vks.iter().enumerate() {
        members.clear();
        for (index, proof) in proofs.iter().enumerate() {
            if usize::from(proof.vk_index) == key_index {
                members.push(u32::try_from(index).map_err(|_| Groth16BatchError::TooManyPairs)?);
            }
        }
        if members.is_empty() {
            continue;
        }
        let key = vk.key();
        // every proof-side term of this key enters the fold negated, so -r_i
        // is derived once and reused; (-sum r_i) is the sum of those
        neg_r.clear();
        for &index in &members {
            neg_r.push(fr_negate(randomizer_at(equation_of(index as usize)?)?)?);
        }
        let neg_r_sum = fr_sum(&neg_r)?;

        // e(-[sum r_i] alpha, beta)
        sink.push(
            msm(
                core::slice::from_ref(&key.alpha_g1),
                core::slice::from_ref(&neg_r_sum),
            )?,
            key.beta_g2,
        )?;

        // e(-sum_i [r_i] L_i, gamma) with L_i = IC_0 + sum_j x_ij IC_j
        // (+ com_i on the committed rail), all folded into one MSM. Column j
        // is the inner product <-r, x_j>, one scalar-field call.
        points.clear();
        scalars.clear();
        points.push(
            *key.ic
                .first()
                .ok_or(Groth16BatchError::InvalidVerifyingKey("ic must contain IC_0"))?,
        );
        scalars.push(neg_r_sum);
        for (j, ic) in key.ic.iter().enumerate().skip(1) {
            let input_index = j
                .checked_sub(1)
                .ok_or(Groth16BatchError::InputCountMismatch)?;
            column.clear();
            for &index in &members {
                let input = proof_at(index)?
                    .public_inputs
                    .get(input_index)
                    .ok_or(Groth16BatchError::InputCountMismatch)?;
                // The syscall also rejects a non-canonical scalar, but the
                // reject stays here so an unvalidated batch fails with the
                // input error rather than a backend-shaped one.
                if !is_canonical_fr_be(input) {
                    return Err(Groth16BatchError::NonCanonicalInput);
                }
                column.push(*input);
            }
            points.push(*ic);
            scalars.push(fr_inner_product(&neg_r, &column)?);
        }
        for (&index, neg_r) in members.iter().zip(&neg_r) {
            if let Some(commitment) = &proof_at(index)?.commitment {
                points.push(commitment.com);
                scalars.push(*neg_r);
            }
        }
        sink.push(msm(&points, &scalars)?, key.gamma_g2)?;

        // e(-sum [r_i] C_i, delta)
        points.clear();
        for &index in &members {
            points.push(proof_at(index)?.c);
        }
        sink.push(msm(&points, &neg_r)?, key.delta_g2)?;

        // committed rail: e(sum [s_i] com_i, g2) * e(-sum [s_i] pok_i,
        // sigma_g2), two pair terms per key whatever n is; the PoK equations
        // take their own s_i, never the proof's r_i
        if let Some(pedersen) = &key.pedersen {
            points.clear();
            scalars.clear();
            let mut pok_points: Vec<PodG1Point> = Vec::with_capacity(members.len());
            let mut pok_scalars: Vec<PodScalar> = Vec::with_capacity(members.len());
            for &index in &members {
                let proof = proof_at(index)?;
                let commitment = proof
                    .commitment
                    .as_ref()
                    .ok_or(Groth16BatchError::CommitmentMismatch)?;
                let equation = equation_of(index as usize)?
                    .checked_add(1)
                    .ok_or(Groth16BatchError::RandomizerCountMismatch)?;
                let s = randomizer_at(equation)?;
                points.push(commitment.com);
                scalars.push(*s);
                pok_points.push(commitment.pok);
                pok_scalars.push(fr_negate(s)?);
            }
            sink.push(msm(&points, &scalars)?, pedersen.g2)?;
            sink.push(msm(&pok_points, &pok_scalars)?, pedersen.sigma_g2)?;
        }
    }
    let written = sink.written;
    // SAFETY: the sink wrote slots 0..written inside the capacity reserved
    // above. A pair is plain data, so an early return leaves nothing to drop.
    unsafe { pairs.set_len(written) };
    Ok(pairs)
}

/// Writes into a vector's reserved tail, so a 192-byte pair is built once
/// rather than built and then moved.
pub(crate) struct PairSink<'a> {
    slots: &'a mut [core::mem::MaybeUninit<PodG1G2Pair>],
    written: usize,
}

impl<'a> PairSink<'a> {
    pub(crate) fn over(pairs: &'a mut Vec<PodG1G2Pair>) -> Self {
        Self {
            slots: pairs.spare_capacity_mut(),
            written: 0,
        }
    }

    #[inline]
    pub(crate) fn push(
        &mut self,
        g1: PodG1Point,
        g2: PodG2Point,
    ) -> Result<(), Groth16BatchError> {
        self.slots
            .get_mut(self.written)
            .ok_or(Groth16BatchError::TooManyPairs)?
            .write(PodG1G2Pair { g1, g2 });
        self.written = self
            .written
            .checked_add(1)
            .ok_or(Groth16BatchError::TooManyPairs)?;
        Ok(())
    }
}

// The syscall skips infinity points as identity factors. Proof points cannot be infinity.
fn is_infinity_g1(point: &PodG1Point) -> bool {
    all_zero(&point.0)
}

/// The wire encoding of infinity. Scanning stops at the first nonzero byte,
/// which a valid point has in its first coordinate.
#[inline]
pub(crate) fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[inline]
pub(crate) fn msm(
    points: &[PodG1Point],
    scalars: &[PodScalar],
) -> Result<PodG1Point, Groth16BatchError> {
    Ok(alt_bn128_g1_msm(
        solana_bn254_batch_syscall::Version::V0,
        points,
        scalars,
    )?)
}

/// `r - 1`, the field's `-1`, big-endian.
pub(crate) const MINUS_ONE_BE: PodScalar = PodScalar([
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x00,
]);

pub(crate) const ONE_BE: PodScalar = PodScalar([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);

/// `-x mod r`. One scalar-field call beats a borrow-propagating byte
/// subtraction, and it maps zero to zero where `r - x` would not.
#[inline]
pub(crate) fn fr_negate(scalar: &PodScalar) -> Result<PodScalar, Groth16BatchError> {
    fr_inner_product(
        core::slice::from_ref(scalar),
        core::slice::from_ref(&MINUS_ONE_BE),
    )
}

/// `sum_i values[i] mod r`, reducing once.
#[inline]
pub(crate) fn fr_sum(values: &[PodScalar]) -> Result<PodScalar, Groth16BatchError> {
    match values {
        [] => Err(Groth16BatchError::EmptyBatch),
        [single] => Ok(*single),
        _ => match ONES.get(..values.len()) {
            Some(ones) => fr_inner_product(values, ones),
            None => fr_inner_product(values, &vec![ONE_BE; values.len()]),
        },
    }
}

/// Right operand of the summing inner product, so the common batch widths need
/// no allocation. Longer sums fall back to a built vector.
const ONES: [PodScalar; 32] = [ONE_BE; 32];

/// `sum_i left[i] * right[i] mod r`. Every operand must be canonical; the
/// syscall rejects one that is not.
#[inline]
pub(crate) fn fr_inner_product(
    left: &[PodScalar],
    right: &[PodScalar],
) -> Result<PodScalar, Groth16BatchError> {
    Ok(alt_bn128_fr_lincomb(
        solana_bn254_batch_syscall::Version::V0,
        left,
        right,
    )?)
}

pub(crate) fn fr_to_pod(scalar: &Fr) -> PodScalar {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&scalar.into_bigint().to_bytes_be());
    PodScalar(bytes)
}

/// Big-endian `x < r`, without building the field element.
///
/// Lexicographic comparison of equal-length big-endian byte strings is integer
/// comparison, so this is the same predicate `Fr::from_bigint` applies when it
/// returns `None`, and `fr_from_be_rejects_exactly_what_the_byte_compare_does`
/// pins the equivalence over the boundary values and a random sweep.
#[inline]
pub(crate) fn is_canonical_fr_be(scalar: &PodScalar) -> bool {
    const MODULUS_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    scalar.0 < MODULUS_BE
}

#[cfg(test)]
pub(crate) fn fr_from_be(scalar: &PodScalar) -> Result<Fr, Groth16BatchError> {
    // Parse big-endian Fr without host-only PodScalar::to_fr (SBF-safe).
    use ark_ff::PrimeField;
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(scalar.0.rchunks_exact(8)) {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(bytes);
        *limb = u64::from_be_bytes(chunk);
    }
    let bi = <Fr as PrimeField>::BigInt::new(limbs);
    Fr::from_bigint(bi).ok_or(Groth16BatchError::NonCanonicalInput)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            test_utils::{
                TrapdoorKey, fr_bytes, g1, g1_bytes, g2_bytes, make_proof, make_vk,
                non_subgroup_g2, rng,
            },
            transcript::{
                RandomizerMode, RandomizerMode::Independent, derive_randomizers, derive_seed,
            },
        },
        ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective},
        ark_ec::{CurveGroup, PrimeGroup, pairing::Pairing},
        ark_ff::{Field, One, PrimeField, UniformRand},
        ark_std::rand::rngs::StdRng,
        core::ops::{Add, Mul, Neg, Sub},
        solana_bn254_batch_syscall::{AltBn128BatchError, G1_BYTES},
    };

    fn verify(vks: &[ValidatedVerifyingKey], proofs: &[Proof]) -> Result<bool, Groth16BatchError> {
        groth16_batch_verify(Version::V0, vks, proofs, Independent)
    }

    fn vanilla_batch(
        rng: &mut StdRng,
        n: usize,
    ) -> (TrapdoorKey, Vec<ValidatedVerifyingKey>, Vec<Proof>) {
        let (key, vk) = make_vk(rng, 1, false);
        let proofs = (0..n)
            .map(|_| {
                let x = Fr::rand(rng);
                make_proof(rng, &key, 0, &[x])
            })
            .collect();
        (key, vec![vk], proofs)
    }

    fn parse_g1(point: &PodG1Point) -> G1Affine {
        G1Affine::new(
            Fq::from_be_bytes_mod_order(&point.0[..32]),
            Fq::from_be_bytes_mod_order(&point.0[32..]),
        )
    }

    fn parse_g2(point: &PodG2Point) -> G2Affine {
        let x1 = Fq::from_be_bytes_mod_order(&point.0[0..32]);
        let x0 = Fq::from_be_bytes_mod_order(&point.0[32..64]);
        let y1 = Fq::from_be_bytes_mod_order(&point.0[64..96]);
        let y0 = Fq::from_be_bytes_mod_order(&point.0[96..128]);
        G2Affine::new(Fq2::new(x0, x1), Fq2::new(y0, y1))
    }

    #[test]
    fn test_valid_batches_verify() {
        let mut rng = rng();
        for n in [1usize, 2, 5] {
            let (_, vks, proofs) = vanilla_batch(&mut rng, n);
            assert_eq!(verify(&vks, &proofs), Ok(true), "n = {n}");
        }
    }

    #[test]
    fn test_invalid_proof_fails_the_batch() {
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 4);
        // perturb one C: individually invalid, and the batch must see it
        let c = parse_g1(&proofs[2].c);
        proofs[2].c = g1_bytes(&c.add(g1(Fr::one())).into_affine());
        assert_eq!(verify(&vks, &proofs), Ok(false));
    }

    #[test]
    fn test_cancelling_perturbations_need_the_randomizers() {
        // perturb one proof's C by +D and another's by -D. The
        // error terms e(D, delta) and e(-D, delta) cancel in the naive
        // product, so with randomizers forced to one the batch accepts two
        // individually invalid proofs; the derived randomizers reject them.
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 2);
        let d = g1(Fr::rand(&mut rng));
        let c0 = parse_g1(&proofs[0].c);
        let c1 = parse_g1(&proofs[1].c);
        proofs[0].c = g1_bytes(&c0.add(d).into_affine());
        proofs[1].c = g1_bytes(&c1.sub(d).into_affine());

        let ones = vec![Fr::one(); 2];
        let pairs = fold_pairs(&vks, &proofs, &ones).unwrap();
        let naive = alt_bn128_pairing_check(solana_bn254_batch_syscall::Version::V0, &pairs);
        assert_eq!(
            naive,
            Ok(true),
            "the unrandomized product must cancel, that is the attack"
        );

        assert_eq!(verify(&vks, &proofs), Ok(false), "the challenge kills it");
    }

    #[test]
    fn test_committed_rail_verifies_and_counts_pairs() {
        let mut rng = rng();
        let (key, vk) = make_vk(&mut rng, 1, true);
        let proofs: Vec<Proof> = (0..3)
            .map(|_| {
                let x = Fr::rand(&mut rng);
                make_proof(&mut rng, &key, 0, &[x])
            })
            .collect();
        let vks = vec![vk];
        assert_eq!(verify(&vks, &proofs), Ok(true));

        // n + 5 pair terms for one committed key
        let seed = derive_seed(Independent, &vks, &proofs);
        let randomizers = derive_randomizers(&seed, 6, Independent);
        let pairs = fold_pairs(&vks, &proofs, &randomizers).unwrap();
        assert_eq!(pairs.len(), 8);

        // ... and a committed proof draws two distinct randomizers
        assert_eq!(randomizers.len(), proofs.len().checked_mul(2).unwrap());
        assert_ne!(randomizers[0], randomizers[1]);
    }

    #[test]
    fn test_fold_rejects_short_and_excess_randomizer_slices() {
        let mut rng = rng();
        let (key, vk) = make_vk(&mut rng, 1, true);
        let x = Fr::rand(&mut rng);
        let proofs = vec![make_proof(&mut rng, &key, 0, &[x])];
        let vks = vec![vk];
        assert_eq!(equation_count(&proofs), 2);

        for wrong_count in [0usize, 1, 3] {
            let randomizers = vec![Fr::one(); wrong_count];
            assert_eq!(
                fold_pairs(&vks, &proofs, &randomizers),
                Err(Groth16BatchError::RandomizerCountMismatch),
                "wrong_count = {wrong_count}"
            );
        }

        assert!(fold_pairs(&vks, &proofs, &[Fr::one(), Fr::one()]).is_ok());
    }

    #[test]
    fn test_public_fold_rejects_unvalidated_shapes() {
        let mut rng = rng();
        let (_, vks, proofs) = vanilla_batch(&mut rng, 1);

        assert_eq!(
            fold_pairs(&[], &[], &[]),
            Err(Groth16BatchError::EmptyBatch)
        );

        let mut unknown_key = proofs.clone();
        unknown_key[0].vk_index = 7;
        assert_eq!(
            fold_pairs(&vks, &unknown_key, &[Fr::one()]),
            Err(Groth16BatchError::UnknownVerifyingKey)
        );

        let mut infinity = proofs.clone();
        infinity[0].a = PodG1Point([0u8; G1_BYTES]);
        assert_eq!(
            fold_pairs(&vks, &infinity, &[Fr::one()]),
            Err(Groth16BatchError::InfinityInProofPosition)
        );

        let over_cap = vec![proofs[0].clone(); PAIRING_MAX_PAIRS.checked_add(1).unwrap()];
        let randomizers = vec![Fr::one(); over_cap.len()];
        assert_eq!(
            fold_pairs(&vks, &over_cap, &randomizers),
            Err(Groth16BatchError::TooManyPairs)
        );
    }

    #[test]
    fn test_vanilla_batch_is_n_plus_3_pairs() {
        let mut rng = rng();
        let (_, vks, proofs) = vanilla_batch(&mut rng, 4);
        let seed = derive_seed(Independent, &vks, &proofs);
        let randomizers = derive_randomizers(&seed, 4, Independent);
        let pairs = fold_pairs(&vks, &proofs, &randomizers).unwrap();
        assert_eq!(pairs.len(), 7);
    }

    #[test]
    fn test_mixed_batch_two_keys() {
        let mut rng = rng();
        let (vanilla_key, vanilla_vk) = make_vk(&mut rng, 1, false);
        let (committed_key, committed_vk) = make_vk(&mut rng, 2, true);
        let inputs: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let proofs = vec![
            make_proof(&mut rng, &vanilla_key, 0, &inputs[0..1]),
            make_proof(&mut rng, &committed_key, 1, &inputs[1..3]),
            make_proof(&mut rng, &vanilla_key, 0, &inputs[3..4]),
        ];
        let vks = vec![vanilla_vk, committed_vk];
        assert_eq!(verify(&vks, &proofs), Ok(true));

        // n + 3 + 5 pair terms for one vanilla and one committed key
        let seed = derive_seed(Independent, &vks, &proofs);
        let randomizers = derive_randomizers(&seed, 4, Independent);
        let pairs = fold_pairs(&vks, &proofs, &randomizers).unwrap();
        assert_eq!(pairs.len(), 11);

        // one bad proof anywhere fails the mixed batch
        let mut bad = proofs.clone();
        let c = parse_g1(&bad[1].c);
        bad[1].c = g1_bytes(&c.add(g1(Fr::one())).into_affine());
        assert_eq!(verify(&vks, &bad), Ok(false));
    }

    #[test]
    fn test_duplicate_invalid_proof_still_rejected() {
        // a duplicated bad proof contributes E^(r_a + r_b),
        // which is 1 only with probability 2^-128
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 2);
        let c = parse_g1(&proofs[0].c);
        proofs[0].c = g1_bytes(&c.add(g1(Fr::one())).into_affine());
        proofs[1] = proofs[0].clone();
        assert_eq!(verify(&vks, &proofs), Ok(false));
    }

    #[test]
    fn test_batch_of_one_matches_direct_verification() {
        // n = 1 is a batch of one, checked like any other; pin
        // it against an independent direct computation of the Groth16
        // equation e(A,B) e(-alpha,beta) e(-L,gamma) e(-C,delta) == 1 with
        // arkworks' own multi_pairing
        let mut rng = rng();
        let (key, vks, proofs) = vanilla_batch(&mut rng, 1);
        let proof = &proofs[0];
        let x = super::fr_from_be(&proof.public_inputs[0]).unwrap();
        let l = key.ic[0].add(x.mul(key.ic[1]));
        let direct = Bn254::multi_pairing(
            [
                parse_g1(&proof.a),
                G1Projective::from(g1(key.alpha)).neg().into_affine(),
                G1Projective::from(g1(l)).neg().into_affine(),
                G1Projective::from(parse_g1(&proof.c)).neg().into_affine(),
            ],
            [
                parse_g2(&proof.b),
                G2Projective::generator().mul(key.beta).into_affine(),
                G2Projective::generator().mul(key.gamma).into_affine(),
                G2Projective::generator().mul(key.delta).into_affine(),
            ],
        );
        assert!(direct.0.is_one(), "fixture must verify directly");
        assert_eq!(verify(&vks, &proofs), Ok(true));

        // and a directly-invalid proof is a false batch of one
        let mut bad = proofs.clone();
        let c = parse_g1(&bad[0].c);
        bad[0].c = g1_bytes(&c.add(g1(Fr::one())).into_affine());
        assert_eq!(verify(&vks, &bad), Ok(false));
    }

    #[test]
    fn test_groth16_malleability_is_real() {
        // (A, B, C) -> (sA, s^-1 B + t delta, C + st A) is a
        // distinct valid proof of the same statement; proof bytes are not an
        // identity, so replay protection must key on the statement
        let mut rng = rng();
        let (key, vks, mut proofs) = vanilla_batch(&mut rng, 1);
        let s = Fr::rand(&mut rng);
        let t = Fr::rand(&mut rng);
        let a = parse_g1(&proofs[0].a);
        let b = parse_g2(&proofs[0].b);
        let c = parse_g1(&proofs[0].c);
        let delta_g2 = G2Projective::generator().mul(key.delta);

        let original = proofs[0].clone();
        proofs[0].a = g1_bytes(&G1Projective::from(a).mul(s).into_affine());
        proofs[0].b = g2_bytes(
            &G2Projective::from(b)
                .mul(s.inverse().unwrap())
                .add(delta_g2.mul(t))
                .into_affine(),
        );
        proofs[0].c = g1_bytes(
            &G1Projective::from(c)
                .add(G1Projective::from(a).mul(s.mul(t)))
                .into_affine(),
        );
        assert_ne!(
            proofs[0], original,
            "the malleated proof has distinct bytes"
        );
        assert_eq!(verify(&vks, &proofs), Ok(true), "and it still verifies");
    }

    #[test]
    fn test_shape_errors() {
        let mut rng = rng();
        let (key, vks, mut proofs) = vanilla_batch(&mut rng, 1);

        assert_eq!(verify(&vks, &[]), Err(Groth16BatchError::EmptyBatch));

        // wrong input count, caught before any hashing
        proofs[0].public_inputs.push(fr_bytes(&Fr::one()));
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::InputCountMismatch)
        );
        proofs[0].public_inputs.truncate(1);

        // unknown key index
        proofs[0].vk_index = 7;
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::UnknownVerifyingKey)
        );
        proofs[0].vk_index = 0;

        // key list longer than the u16 count/index can frame, rejected before
        // hashing so the count prefix never truncates
        let padded: Vec<ValidatedVerifyingKey> = std::iter::repeat_with(|| vks[0].clone())
            .take(usize::from(u16::MAX).checked_add(1).unwrap())
            .collect();
        assert_eq!(
            verify(&padded, &proofs),
            Err(Groth16BatchError::TooManyVerifyingKeys)
        );

        // rail mismatch: a commitment on a vanilla key has no framing
        proofs[0].commitment = Some(ProofCommitment {
            com: g1_bytes(&g1(Fr::one())),
            pok: g1_bytes(&g1(Fr::one())),
        });
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::CommitmentMismatch)
        );
        proofs[0].commitment = None;

        // infinity in a proof position
        let saved = proofs[0].a;
        proofs[0].a = PodG1Point([0u8; 64]);
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::InfinityInProofPosition)
        );
        proofs[0].a = saved;

        // non-canonical public input
        proofs[0].public_inputs[0] = PodScalar([0xffu8; 32]);
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::NonCanonicalInput)
        );
        proofs[0].public_inputs[0] = fr_bytes(&Fr::one());

        // zero-input circuit: L degenerates to the constant IC_0 and the
        // batch still verifies
        let (zero_key, zero_vk) = make_vk(&mut rng, 0, false);
        let zero_proofs = vec![make_proof(&mut rng, &zero_key, 0, &[])];
        assert_eq!(verify(&[zero_vk], &zero_proofs), Ok(true));

        let _ = key;
    }

    #[test]
    fn test_bad_proof_points_surface_as_syscall_errors() {
        let mut rng = rng();
        let (_, vks, mut proofs) = vanilla_batch(&mut rng, 1);
        // a non-subgroup B lands in the pairing check's validation
        proofs[0].b = g2_bytes(&non_subgroup_g2());
        assert_eq!(
            verify(&vks, &proofs),
            Err(Groth16BatchError::Syscall(
                AltBn128BatchError::NotInSubgroup
            ))
        );
    }

    #[test]
    fn test_powers_mode_verifies() {
        let mut rng = rng();
        let (_, vks, proofs) = vanilla_batch(&mut rng, 3);
        assert_eq!(
            groth16_batch_verify(Version::V0, &vks, &proofs, RandomizerMode::Powers),
            Ok(true)
        );
    }
}

/// The fold this crate shipped before the scalars moved into the scalar-field
/// syscall, kept as the bit-exactness reference for [`fold_identity_tests`].
#[cfg(test)]
fn reference_fold_pairs(
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
    randomizers: &[Fr],
) -> Result<Vec<PodG1G2Pair>, Groth16BatchError> {
    use core::ops::{AddAssign, Mul, Neg};

    fn msm_fr(points: &[PodG1Point], scalars: &[Fr]) -> Result<PodG1Point, Groth16BatchError> {
        let scalars: Vec<PodScalar> = scalars.iter().map(fr_to_pod).collect();
        msm(points, &scalars)
    }

    if randomizers.len() as u64 != equation_count(proofs) {
        return Err(Groth16BatchError::RandomizerCountMismatch);
    }
    let mut next = randomizers.iter().copied();
    let assigned: Vec<(Fr, Option<Fr>)> = proofs
        .iter()
        .map(|proof| -> Result<_, Groth16BatchError> {
            let r = next
                .next()
                .ok_or(Groth16BatchError::RandomizerCountMismatch)?;
            let s = if proof.commitment.is_some() {
                Some(
                    next.next()
                        .ok_or(Groth16BatchError::RandomizerCountMismatch)?,
                )
            } else {
                None
            };
            Ok((r, s))
        })
        .collect::<Result<_, _>>()?;

    let mut pairs: Vec<PodG1G2Pair> = Vec::new();
    let mut push_pair = |g1: PodG1Point, g2: PodG2Point| pairs.push(PodG1G2Pair { g1, g2 });
    for (proof, (r, _)) in proofs.iter().zip(&assigned) {
        push_pair(msm_fr(&[proof.a], &[*r])?, proof.b);
    }
    for (key_index, vk) in vks.iter().enumerate() {
        let key_proofs: Vec<(&Proof, Fr, Option<Fr>)> = proofs
            .iter()
            .zip(&assigned)
            .filter(|(proof, _)| usize::from(proof.vk_index) == key_index)
            .map(|(proof, (r, s))| (proof, *r, *s))
            .collect();
        if key_proofs.is_empty() {
            continue;
        }
        let key = vk.key();
        let r_sum: Fr = key_proofs.iter().map(|(_, r, _)| *r).sum();
        push_pair(msm_fr(&[key.alpha_g1], &[r_sum.neg()])?, key.beta_g2);

        let mut gamma_points: Vec<PodG1Point> = vec![key.ic[0]];
        let mut gamma_scalars: Vec<Fr> = vec![r_sum.neg()];
        for (j, ic) in key.ic.iter().enumerate().skip(1) {
            let mut coefficient = Fr::from(0u64);
            let input_index = j
                .checked_sub(1)
                .ok_or(Groth16BatchError::InputCountMismatch)?;
            for (proof, r, _) in &key_proofs {
                let input = proof
                    .public_inputs
                    .get(input_index)
                    .ok_or(Groth16BatchError::InputCountMismatch)?;
                coefficient.add_assign(r.mul(&fr_from_be(input)?));
            }
            gamma_points.push(*ic);
            gamma_scalars.push(coefficient.neg());
        }
        for (proof, r, _) in &key_proofs {
            if let Some(commitment) = &proof.commitment {
                gamma_points.push(commitment.com);
                gamma_scalars.push(r.neg());
            }
        }
        push_pair(msm_fr(&gamma_points, &gamma_scalars)?, key.gamma_g2);

        let mut delta_points: Vec<PodG1Point> = Vec::new();
        let mut delta_scalars: Vec<Fr> = Vec::new();
        for (proof, r, _) in &key_proofs {
            delta_points.push(proof.c);
            delta_scalars.push(r.neg());
        }
        push_pair(msm_fr(&delta_points, &delta_scalars)?, key.delta_g2);

        if let Some(pedersen) = &key.pedersen {
            let mut com_points: Vec<PodG1Point> = Vec::new();
            let mut pok_points: Vec<PodG1Point> = Vec::new();
            let mut com_scalars: Vec<Fr> = Vec::new();
            let mut pok_scalars: Vec<Fr> = Vec::new();
            for (proof, _, s) in &key_proofs {
                let commitment = proof
                    .commitment
                    .as_ref()
                    .ok_or(Groth16BatchError::CommitmentMismatch)?;
                let s = s.ok_or(Groth16BatchError::RandomizerCountMismatch)?;
                com_points.push(commitment.com);
                com_scalars.push(s);
                pok_points.push(commitment.pok);
                pok_scalars.push(s.neg());
            }
            push_pair(msm_fr(&com_points, &com_scalars)?, pedersen.g2);
            push_pair(msm_fr(&pok_points, &pok_scalars)?, pedersen.sigma_g2);
        }
    }
    Ok(pairs)
}

#[cfg(test)]
mod fold_identity_tests {
    use {
        super::*,
        crate::{
            test_utils::{fr_bytes, make_proof, make_vk, rng},
            transcript::{
                RandomizerMode, RandomizerMode::Independent, RandomizerMode::Powers,
                derive_randomizers, derive_seed,
            },
        },
        ark_ff::{One, UniformRand, Zero},
        core::ops::Sub,
    };

    const R_BE: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    /// Every batch shape the fold distinguishes: one proof, several proofs
    /// sharing one key, a zero-input circuit, a committed (BSB22/Pedersen)
    /// key, and a mixed batch where two proofs share a key and a third does
    /// not. Names are only for assertion messages.
    fn batches() -> Vec<(&'static str, Vec<ValidatedVerifyingKey>, Vec<Proof>)> {
        let mut rng = rng();
        let mut out = Vec::new();
        for (label, n) in [("n1", 1usize), ("n2_shared_key", 2), ("n5_shared_key", 5)] {
            let (key, vk) = make_vk(&mut rng, 1, false);
            let proofs = (0..n)
                .map(|_| {
                    let input = Fr::rand(&mut rng);
                    make_proof(&mut rng, &key, 0, &[input])
                })
                .collect();
            out.push((label, vec![vk], proofs));
        }

        let (zero_key, zero_vk) = make_vk(&mut rng, 0, false);
        out.push((
            "zero_inputs",
            vec![zero_vk],
            vec![make_proof(&mut rng, &zero_key, 0, &[])],
        ));

        let (wide_key, wide_vk) = make_vk(&mut rng, 4, false);
        let wide_proofs = (0..3)
            .map(|_| {
                let inputs: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
                make_proof(&mut rng, &wide_key, 0, &inputs)
            })
            .collect();
        out.push(("n3_four_inputs", vec![wide_vk], wide_proofs));

        let (committed_key, committed_vk) = make_vk(&mut rng, 1, true);
        let committed_proofs = (0..3)
            .map(|_| {
                let input = Fr::rand(&mut rng);
                make_proof(&mut rng, &committed_key, 0, &[input])
            })
            .collect();
        out.push(("committed_n3", vec![committed_vk], committed_proofs));

        let (vanilla_key, vanilla_vk) = make_vk(&mut rng, 1, false);
        let (other_key, other_vk) = make_vk(&mut rng, 2, true);
        let first = Fr::rand(&mut rng);
        let second = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let third = Fr::rand(&mut rng);
        let mixed = vec![
            make_proof(&mut rng, &vanilla_key, 0, &[first]),
            make_proof(&mut rng, &other_key, 1, &second),
            make_proof(&mut rng, &vanilla_key, 0, &[third]),
        ];
        out.push(("mixed_two_keys", vec![vanilla_vk, other_vk], mixed));
        out
    }

    fn assert_same_fold(
        label: &str,
        vks: &[ValidatedVerifyingKey],
        proofs: &[Proof],
        randomizers: &[Fr],
    ) {
        let expected = reference_fold_pairs(vks, proofs, randomizers);
        let folded = fold_pairs_prevalidated(vks, proofs, randomizers);
        match (&expected, &folded) {
            (Ok(expected), Ok(folded)) => {
                assert_eq!(expected.len(), folded.len(), "{label}: pair count");
                for (index, (expected, folded)) in expected.iter().zip(folded).enumerate() {
                    assert_eq!(expected, folded, "{label}: pair {index}");
                }
            }
            _ => assert_eq!(expected, folded, "{label}"),
        }
    }

    /// The fold must be bit-identical to the field-arithmetic reference over
    /// the transcript's own randomizers, in both modes.
    #[test]
    fn derived_randomizers_fold_identically() {
        for (label, vks, proofs) in batches() {
            for mode in [Independent, Powers] {
                let seed = derive_seed(mode, &vks, &proofs);
                let randomizers = derive_randomizers(&seed, equation_count(&proofs), mode);
                assert_same_fold(&format!("{label}/{mode:?}"), &vks, &proofs, &randomizers);

                // and the byte path the verifier now takes reaches the same pairs
                let expected = reference_fold_pairs(&vks, &proofs, &randomizers);
                assert_eq!(
                    fold_pairs_for_verification(&vks, &proofs, mode),
                    expected,
                    "{label}/{mode:?}: verification fold"
                );
            }
        }
    }

    /// Randomizer values the derivation can produce at its edges, plus the
    /// first two stream indices, which a batch of one and a batch of two use.
    #[test]
    fn edge_randomizers_fold_identically() {
        let mut rng = rng();
        let edges = [
            Fr::one(),
            Fr::zero(),
            Fr::zero().sub(Fr::one()),
            Fr::from(2u64),
            Fr::from(1u128 << 127),
            Fr::from(u128::MAX) + Fr::one(),
        ];
        for (label, vks, proofs) in batches() {
            let count = equation_count(&proofs) as usize;
            for (index, edge) in edges.iter().enumerate() {
                let randomizers = vec![*edge; count];
                assert_same_fold(
                    &format!("{label}/uniform{index}"),
                    &vks,
                    &proofs,
                    &randomizers,
                );
            }
            // a distinct value per equation, so no two positions can alias
            let mixed: Vec<Fr> = (0..count).map(|_| Fr::rand(&mut rng)).collect();
            assert_same_fold(&format!("{label}/random"), &vks, &proofs, &mixed);
        }
    }

    /// Public inputs at the ends of the canonical range, where a byte path
    /// that skipped the field would be most likely to diverge.
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

        for (label, vks, proofs) in batches() {
            let seed = derive_seed(Independent, &vks, &proofs);
            let randomizers = derive_randomizers(&seed, equation_count(&proofs), Independent);
            for (index, edge) in edges.iter().enumerate() {
                let mut mutated = proofs.clone();
                for proof in &mut mutated {
                    for input in &mut proof.public_inputs {
                        *input = *edge;
                    }
                }
                assert_same_fold(
                    &format!("{label}/all-inputs-{index}"),
                    &vks,
                    &mutated,
                    &randomizers,
                );

                // and one input at a time, so a column with mixed values is
                // also covered
                let mut single = proofs.clone();
                if let Some(input) = single
                    .first_mut()
                    .and_then(|proof| proof.public_inputs.first_mut())
                {
                    *input = *edge;
                    assert_same_fold(
                        &format!("{label}/first-input-{index}"),
                        &vks,
                        &single,
                        &randomizers,
                    );
                }
            }
        }
    }

    /// A public input at or above r stays rejected, with the same error, on
    /// both the checked surface and the prevalidated one.
    #[test]
    fn non_canonical_public_input_is_still_rejected() {
        let mut rng = rng();
        let (key, vk) = make_vk(&mut rng, 1, false);
        let inputs = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let proofs = vec![
            make_proof(&mut rng, &key, 0, &inputs[..1]),
            make_proof(&mut rng, &key, 0, &inputs[1..]),
        ];
        let vks = vec![vk];
        let mut r_plus_one = R_BE;
        r_plus_one[31] = 0x02;

        for bad in [R_BE, r_plus_one, [0xffu8; 32]] {
            for position in [0usize, 1] {
                let mut mutated = proofs.clone();
                mutated[position].public_inputs[0] = PodScalar(bad);
                assert_eq!(
                    fold_pairs(&vks, &mutated, &[Fr::one(), Fr::one()]),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "checked surface, position {position}"
                );
                assert_eq!(
                    fold_pairs_prevalidated(&vks, &mutated, &[Fr::one(), Fr::one()]),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "prevalidated surface, position {position}"
                );
                assert_eq!(
                    fold_pairs_for_verification(&vks, &mutated, Independent),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "verification fold, position {position}"
                );
                assert_eq!(
                    groth16_batch_verify(Version::V0, &vks, &mutated, RandomizerMode::Independent),
                    Err(Groth16BatchError::NonCanonicalInput),
                    "verify, position {position}"
                );
            }
        }
    }

    /// What the scalar-field syscall itself does with a non-canonical operand,
    /// which is what the fold would rely on if the explicit check were removed.
    #[test]
    fn the_scalar_syscall_rejects_non_canonical_operands() {
        let mut r_plus_one = R_BE;
        r_plus_one[31] = 0x02;
        for bad in [R_BE, r_plus_one, [0xffu8; 32]] {
            assert!(fr_inner_product(&[PodScalar(bad)], &[ONE_BE]).is_err());
            assert!(fr_inner_product(&[ONE_BE], &[PodScalar(bad)]).is_err());
            assert!(fr_negate(&PodScalar(bad)).is_err());
        }
    }

    /// The scalar helpers against arkworks, element by element.
    #[test]
    fn scalar_helpers_match_field_arithmetic() {
        use core::ops::Neg;

        // the folded constants, derived here rather than trusted
        assert_eq!(MINUS_ONE_BE, fr_to_pod(&Fr::one().neg()));
        assert_eq!(ONE_BE, fr_to_pod(&Fr::one()));

        let mut rng = rng();
        let mut values = vec![
            Fr::zero(),
            Fr::one(),
            Fr::zero().sub(Fr::one()),
            Fr::from(u128::MAX) + Fr::one(),
        ];
        values.extend((0..8).map(|_| Fr::rand(&mut rng)));

        for value in &values {
            assert_eq!(fr_negate(&fr_to_pod(value)), Ok(fr_to_pod(&value.neg())));
        }
        for width in 1..=values.len() {
            let window = &values[..width];
            let pods: Vec<PodScalar> = window.iter().map(fr_to_pod).collect();
            let sum: Fr = window.iter().copied().sum();
            assert_eq!(fr_sum(&pods), Ok(fr_to_pod(&sum)), "sum of {width}");

            let other: Vec<Fr> = (0..width).map(|_| Fr::rand(&mut rng)).collect();
            let other_pods: Vec<PodScalar> = other.iter().map(fr_to_pod).collect();
            let inner: Fr = window.iter().zip(&other).map(|(x, y)| *x * y).sum();
            assert_eq!(
                fr_inner_product(&pods, &other_pods),
                Ok(fr_to_pod(&inner)),
                "inner product of {width}"
            );
        }
        assert_eq!(fr_sum(&[]), Err(Groth16BatchError::EmptyBatch));
    }
}

#[cfg(test)]
mod canonicality_tests {
    use super::*;

    /// The scanning form must accept and reject exactly what comparing against
    /// a zero array does. It replaced that comparison in every infinity check,
    /// so any divergence lets an infinity point through or rejects a valid one.
    #[test]
    fn all_zero_is_the_zero_array_comparison() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for len in [32usize, 64, 128] {
            let mut bytes = vec![0u8; len];
            assert!(all_zero(&bytes));
            for index in 0..len {
                for value in [1u8, 0x80, 0xff] {
                    bytes[index] = value;
                    assert_eq!(
                        all_zero(&bytes),
                        bytes.iter().all(|byte| *byte == 0),
                        "len {len} byte {index} = {value}"
                    );
                    assert!(!all_zero(&bytes));
                    bytes[index] = 0;
                }
            }
            for _ in 0..256 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let sparse: Vec<u8> = (0..len)
                    .map(|index| u8::from(state >> (index % 64) & 1 == 1) * (state as u8))
                    .collect();
                assert_eq!(
                    all_zero(&sparse),
                    sparse.iter().all(|byte| *byte == 0),
                    "random pattern"
                );
            }
        }
    }

    /// The byte compare must accept and reject exactly what building the field
    /// element does. It replaced that construction on the hot path, so any
    /// divergence is a validation hole, not a performance regression.
    #[test]
    fn fr_from_be_rejects_exactly_what_the_byte_compare_does() {
        const R_MINUS_ONE: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x00,
        ];
        let mut r = R_MINUS_ONE;
        r[31] = 0x01;
        let mut r_plus_one = r;
        r_plus_one[31] = 0x02;

        let mut cases: Vec<[u8; 32]> = vec![[0u8; 32], [0xff; 32], R_MINUS_ONE, r, r_plus_one, {
            let mut top = [0u8; 32];
            top[0] = 0x30;
            top
        }];
        // A deterministic sweep either side of the modulus, so the agreement is
        // not only checked at the boundaries.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut value = r;
            let offset = (state % 512) as u8;
            if state & 1 == 0 {
                value[31] = value[31].wrapping_sub(offset);
            } else {
                value[0] = (state >> 32) as u8;
            }
            cases.push(value);
        }

        for bytes in cases {
            let scalar = PodScalar(bytes);
            assert_eq!(
                is_canonical_fr_be(&scalar),
                fr_from_be(&scalar).is_ok(),
                "disagreement on {bytes:02x?}"
            );
        }
    }
}
