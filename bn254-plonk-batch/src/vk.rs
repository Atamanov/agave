#[cfg(not(target_os = "solana"))]
use ark_ec::AffineRepr;
use {
    crate::{PlonkBatchError, scalar::fr_from_be},
    ark_bn254::Fr,
    ark_ff::{FftField, Field, One, Zero},
    core::ops::Div,
    solana_bn254_batch_syscall::{PodG1Point, PodG2Point, PodScalar},
    solana_keccak_hasher::hashv,
};

// BN254 Fr has 2-adicity 28, so 2^28 is the largest power-of-two subgroup
// order for which a root of unity exists at all
const MAX_DOMAIN_SIZE: u64 = 1 << 28;
const MIN_DOMAIN_SIZE: u64 = 4;

/// A KZG PLONK verifying key in the typed wire encoding of the batch
/// syscalls: the selector and permutation commitments, the coset shifts, and
/// the two SRS points the final pairing check needs. The verifier assumes the
/// SRS G1 basis starts at the standard generator (the E term rides on it); a
/// nonstandard-basis SRS fails completeness, never soundness, since valid
/// and forged proofs meet the same wrong point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    /// |H|, a power of two; omega is derived from it during validation
    pub domain_size: u64,
    pub num_public_inputs: u32,
    pub q_m: PodG1Point,
    pub q_l: PodG1Point,
    pub q_r: PodG1Point,
    pub q_o: PodG1Point,
    pub q_c: PodG1Point,
    pub s_sigma: [PodG1Point; 3],
    /// coset shifts: identity labels are X, k1 X, k2 X per wire column
    pub k1: PodScalar,
    pub k2: PodScalar,
    /// [1]_2 from the SRS
    pub g2_gen: PodG2Point,
    /// [tau]_2 from the SRS
    pub g2_tau: PodG2Point,
}

/// The only key form the verifier accepts. [`VerifyingKey::validate`] fully
/// validates every point off-chain. [`VerifyingKey::trust`] is the explicit
/// static-key SBF path: it rejects infinity for permutation and SRS points but
/// assumes canonical, on-curve, subgroup-checked constants supplied by the
/// program. A selector commitment can be infinity when its polynomial is zero.
/// Omega and the coset shifts are derived and checked here so the reduction
/// never re-validates them.
#[derive(Clone, Debug)]
pub struct ValidatedVerifyingKey {
    key: VerifyingKey,
    digest: [u8; 32],
    omega: Fr,
    k1: Fr,
    k2: Fr,
}

impl VerifyingKey {
    pub fn validate(self) -> Result<ValidatedVerifyingKey, PlonkBatchError> {
        self.check_domain_shape()?;
        validate_selector_g1(&self.q_m, "q_m")?;
        validate_selector_g1(&self.q_l, "q_l")?;
        validate_selector_g1(&self.q_r, "q_r")?;
        validate_selector_g1(&self.q_o, "q_o")?;
        validate_selector_g1(&self.q_c, "q_c")?;
        validate_g1(&self.s_sigma[0], "s_sigma1")?;
        validate_g1(&self.s_sigma[1], "s_sigma2")?;
        validate_g1(&self.s_sigma[2], "s_sigma3")?;
        validate_g2(&self.g2_gen, "g2_gen")?;
        validate_g2(&self.g2_tau, "g2_tau")?;
        self.finish_scalar_side()
    }

    /// Shape, domain, coset-shift, required nonzero-point checks, and the
    /// digest, without full curve validation. For compile-time constant keys
    /// on SBF where curve checks are not available (host should still prefer
    /// [`Self::validate`]).
    pub fn trust(self) -> Result<ValidatedVerifyingKey, PlonkBatchError> {
        self.check_domain_shape()?;
        self.validate_required_nonzero_points()?;
        self.finish_scalar_side()
    }

    fn check_domain_shape(&self) -> Result<(), PlonkBatchError> {
        let invalid = PlonkBatchError::InvalidVerifyingKey;
        let n = self.domain_size;
        if !n.is_power_of_two() || !(MIN_DOMAIN_SIZE..=MAX_DOMAIN_SIZE).contains(&n) {
            return Err(invalid("domain_size must be a power of two in [4, 2^28]"));
        }
        if u64::from(self.num_public_inputs) >= n {
            return Err(invalid("num_public_inputs must be below domain_size"));
        }
        Ok(())
    }

    fn validate_required_nonzero_points(&self) -> Result<(), PlonkBatchError> {
        reject_infinity_g1(&self.s_sigma[0], "s_sigma1")?;
        reject_infinity_g1(&self.s_sigma[1], "s_sigma2")?;
        reject_infinity_g1(&self.s_sigma[2], "s_sigma3")?;
        reject_infinity_g2(&self.g2_gen, "g2_gen")?;
        reject_infinity_g2(&self.g2_tau, "g2_tau")?;
        Ok(())
    }

    // coset-shift and omega derivations; only Fr arithmetic, runs on every
    // target
    fn finish_scalar_side(self) -> Result<ValidatedVerifyingKey, PlonkBatchError> {
        let invalid = PlonkBatchError::InvalidVerifyingKey;
        let n = self.domain_size;
        let k1 = fr_from_be(&self.k1).ok_or(invalid("k1"))?;
        let k2 = fr_from_be(&self.k2).ok_or(invalid("k2"))?;
        if k1.is_zero() || k2.is_zero() {
            return Err(invalid("coset shifts must be nonzero"));
        }
        // the wire identity labels live on H, k1 H, and k2 H; the permutation
        // argument needs these cosets pairwise disjoint, which for nonzero
        // shifts is exactly k1^n != 1, k2^n != 1, and (k2 / k1)^n != 1. This
        // subsumes k1 != 1, k2 != 1, and k1 != k2.
        let one = Fr::one();
        if k1.pow([n]) == one || k2.pow([n]) == one || k2.div(k1).pow([n]) == one {
            return Err(invalid("coset shifts must give disjoint wire cosets"));
        }

        let omega = Fr::get_root_of_unity(n).ok_or(invalid("domain_size has no root of unity"))?;
        // self-check the derivation: omega must have order exactly n
        let half_n = n
            .checked_div(2)
            .ok_or(invalid("domain_size must be nonzero"))?;
        if omega.pow([n]) != one || omega.pow([half_n]) == one {
            return Err(invalid("derived omega does not have order domain_size"));
        }

        let digest = digest(&self);
        Ok(ValidatedVerifyingKey {
            key: self,
            digest,
            omega,
            k1,
            k2,
        })
    }
}

impl ValidatedVerifyingKey {
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }

    /// keccak256 over the canonical key bytes; the `vkd` value both
    /// transcripts bind
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn omega(&self) -> Fr {
        self.omega
    }

    pub(crate) fn k1(&self) -> Fr {
        self.k1
    }

    pub(crate) fn k2(&self) -> Fr {
        self.k2
    }

    pub(crate) fn domain_size(&self) -> u64 {
        self.key.domain_size
    }

    pub(crate) fn num_public_inputs(&self) -> usize {
        self.key.num_public_inputs as usize
    }
}

// every field, in fixed order with fixed-width framing, so no two distinct
// keys can serialize to one byte string; the digest must cover the selector
// and permutation commitments and the SRS points, and the domain shape and
// coset shifts are verdict inputs just the same
fn digest(key: &VerifyingKey) -> [u8; 32] {
    // hashv over ordered chunks equals sequential Hasher updates and works on
    // SBF, where the streaming Hasher is not available
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

fn reject_infinity_g1(point: &PodG1Point, what: &'static str) -> Result<(), PlonkBatchError> {
    if point.0 == [0u8; 64] {
        return Err(PlonkBatchError::InvalidVerifyingKey(what));
    }
    Ok(())
}

fn reject_infinity_g2(point: &PodG2Point, what: &'static str) -> Result<(), PlonkBatchError> {
    if point.0 == [0u8; 128] {
        return Err(PlonkBatchError::InvalidVerifyingKey(what));
    }
    Ok(())
}

// A zero selector polynomial has the identity as its KZG commitment. The
// decoder must still reject non-canonical and off-curve selector encodings.
#[cfg(not(target_os = "solana"))]
fn validate_selector_g1(point: &PodG1Point, what: &'static str) -> Result<(), PlonkBatchError> {
    point
        .to_affine()
        .map(|_| ())
        .map_err(|_| PlonkBatchError::InvalidVerifyingKey(what))
}

#[cfg(target_os = "solana")]
fn validate_selector_g1(_point: &PodG1Point, _what: &'static str) -> Result<(), PlonkBatchError> {
    Ok(())
}

// `to_affine` does the canonical, on-curve, and (for G2) subgroup checks.
// Permutation and SRS points must not be infinity because infinity would erase
// soundness-critical terms. SBF retains the byte-level infinity check when
// full curve validation is not available.
#[cfg(not(target_os = "solana"))]
fn validate_g1(point: &PodG1Point, what: &'static str) -> Result<(), PlonkBatchError> {
    let invalid = || PlonkBatchError::InvalidVerifyingKey(what);
    if point.to_affine().map_err(|_| invalid())?.is_zero() {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(not(target_os = "solana"))]
fn validate_g2(point: &PodG2Point, what: &'static str) -> Result<(), PlonkBatchError> {
    let invalid = || PlonkBatchError::InvalidVerifyingKey(what);
    if point.to_affine().map_err(|_| invalid())?.is_zero() {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "solana")]
fn validate_g1(point: &PodG1Point, what: &'static str) -> Result<(), PlonkBatchError> {
    reject_infinity_g1(point, what)
}

#[cfg(target_os = "solana")]
fn validate_g2(point: &PodG2Point, what: &'static str) -> Result<(), PlonkBatchError> {
    reject_infinity_g2(point, what)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_support::{fr_bytes, g2_bytes, make_vk, non_subgroup_g2, rng},
    };

    fn assert_infinity_rejected(
        template: &VerifyingKey,
        name: &'static str,
        set_infinity: fn(&mut VerifyingKey),
    ) {
        let mut vk = template.clone();
        set_infinity(&mut vk);
        assert_eq!(
            vk.clone().validate().unwrap_err(),
            PlonkBatchError::InvalidVerifyingKey(name)
        );
        assert_eq!(
            vk.trust().unwrap_err(),
            PlonkBatchError::InvalidVerifyingKey(name)
        );
    }

    #[test]
    fn test_valid_key_validates() {
        let mut rng = rng();
        let (_, vk) = make_vk(&mut rng);
        assert_eq!(vk.key().num_public_inputs, 1);
        // omega self-checks hold for the derived root
        let n = vk.domain_size();
        assert!(vk.omega().pow([n]).is_one());
        assert!(!vk.omega().pow([n / 2]).is_one());
    }

    #[test]
    fn test_infinity_selector_commitments_validate() {
        let mut rng = rng();
        let (_, valid) = make_vk(&mut rng);
        let template = valid.key();
        let set_infinity: [fn(&mut VerifyingKey); 5] = [
            |vk| vk.q_m = PodG1Point([0u8; 64]),
            |vk| vk.q_l = PodG1Point([0u8; 64]),
            |vk| vk.q_r = PodG1Point([0u8; 64]),
            |vk| vk.q_o = PodG1Point([0u8; 64]),
            |vk| vk.q_c = PodG1Point([0u8; 64]),
        ];

        for set_selector_infinity in set_infinity {
            let mut vk = template.clone();
            set_selector_infinity(&mut vk);
            assert!(vk.clone().validate().is_ok());
            assert!(vk.trust().is_ok());
        }
    }

    #[test]
    fn test_degenerate_keys_rejected() {
        let mut rng = rng();
        let (_, valid) = make_vk(&mut rng);
        let template = valid.key();

        // Infinity permutation commitments remove soundness-critical terms.
        let infinity = PodG1Point([0u8; 64]);
        for (index, name) in ["s_sigma1", "s_sigma2", "s_sigma3"].into_iter().enumerate() {
            let mut vk = template.clone();
            vk.s_sigma[index] = infinity;
            assert_eq!(
                vk.clone().validate().unwrap_err(),
                PlonkBatchError::InvalidVerifyingKey(name)
            );
            assert_eq!(
                vk.trust().unwrap_err(),
                PlonkBatchError::InvalidVerifyingKey(name)
            );
        }

        // Selector commitments can be infinity but must still be on-curve.
        let mut vk = template.clone();
        vk.q_r.0[63] = vk.q_r.0[63].wrapping_add(1);
        assert_eq!(
            vk.validate().unwrap_err(),
            PlonkBatchError::InvalidVerifyingKey("q_r")
        );

        // off-curve permutation commitment
        let mut vk = template.clone();
        vk.s_sigma[1].0[63] = vk.s_sigma[1].0[63].wrapping_add(1);
        assert_eq!(
            vk.validate().unwrap_err(),
            PlonkBatchError::InvalidVerifyingKey("s_sigma2")
        );

        // non-subgroup [tau]_2: the SRS is as trusted as the rest of the key
        // and validated with it
        let mut vk = template.clone();
        vk.g2_tau = g2_bytes(&non_subgroup_g2());
        assert_eq!(
            vk.validate().unwrap_err(),
            PlonkBatchError::InvalidVerifyingKey("g2_tau")
        );

        // Both SRS points are required by the final pairing equation.
        assert_infinity_rejected(template, "g2_gen", |vk| {
            vk.g2_gen = PodG2Point([0u8; 128]);
        });
        assert_infinity_rejected(template, "g2_tau", |vk| {
            vk.g2_tau = PodG2Point([0u8; 128]);
        });

        // bad domain sizes: zero, not a power of two, too small, too large
        for bad in [0u64, 6, 2, 1 << 29] {
            let mut vk = template.clone();
            vk.domain_size = bad;
            assert!(
                matches!(vk.validate(), Err(PlonkBatchError::InvalidVerifyingKey(_))),
                "domain_size = {bad}"
            );
        }

        // as many public inputs as rows leaves no gate rows
        let mut vk = template.clone();
        vk.num_public_inputs = vk.domain_size as u32;
        assert!(matches!(
            vk.validate(),
            Err(PlonkBatchError::InvalidVerifyingKey(_))
        ));

        // degenerate coset shifts: zero, one, equal, and k1 inside H itself
        let one = fr_bytes(&Fr::one());
        for (k1, k2) in [
            (fr_bytes(&Fr::zero()), template.k2),
            (one, template.k2),
            (template.k2, template.k2),
            (fr_bytes(&valid.omega()), template.k2),
        ] {
            let mut vk = template.clone();
            vk.k1 = k1;
            vk.k2 = k2;
            assert!(matches!(
                vk.validate(),
                Err(PlonkBatchError::InvalidVerifyingKey(_))
            ));
        }

        // non-canonical coset shift
        let mut vk = template.clone();
        vk.k2 = PodScalar([0xffu8; 32]);
        assert_eq!(
            vk.validate().unwrap_err(),
            PlonkBatchError::InvalidVerifyingKey("k2")
        );
    }

    #[test]
    fn test_digest_binds_every_field() {
        let mut rng = rng();
        let (_, valid) = make_vk(&mut rng);
        let baseline = *valid.digest();
        let template = valid.key();

        let mut mutated = template.clone();
        mutated.domain_size = 16;
        assert_ne!(baseline, *mutated.validate().unwrap().digest());

        let mut mutated = template.clone();
        mutated.num_public_inputs = 2;
        assert_ne!(baseline, *mutated.validate().unwrap().digest());

        // swapping two selector commitments must move the digest: position is
        // part of the framing
        let mut mutated = template.clone();
        core::mem::swap(&mut mutated.q_l, &mut mutated.q_r);
        assert_ne!(baseline, *mutated.validate().unwrap().digest());

        let mut mutated = template.clone();
        mutated.k1 = fr_bytes(&Fr::from(5u64));
        assert_ne!(baseline, *mutated.validate().unwrap().digest());

        // the SRS points are digest inputs
        let mut mutated = template.clone();
        core::mem::swap(&mut mutated.g2_gen, &mut mutated.g2_tau);
        assert_ne!(baseline, *mutated.validate().unwrap().digest());
    }
}
