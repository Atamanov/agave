#[cfg(not(target_os = "solana"))]
use ark_ec::AffineRepr;
use {
    crate::{Groth16BatchError, verify::all_zero},
    solana_bn254_batch_syscall::{PodG1Point, PodG2Point},
    solana_keccak_hasher::hashv,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenKey {
    pub g2: PodG2Point,
    pub sigma_g2: PodG2Point,
}

/// A Groth16 verifying key in the typed wire encoding of the batch syscalls.
/// `ic` holds IC_0..IC_m, so the key expects `ic.len() - 1` public inputs.
/// `pedersen` present makes this a BSB22-committed key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub alpha_g1: PodG1Point,
    pub beta_g2: PodG2Point,
    pub gamma_g2: PodG2Point,
    pub delta_g2: PodG2Point,
    pub ic: Vec<PodG1Point>,
    pub pedersen: Option<PedersenKey>,
}

/// The only key form the verifier accepts. [`VerifyingKey::validate`] fully
/// validates every point off-chain. [`VerifyingKey::trust`] is the explicit
/// static-key SBF path: it rejects infinity but assumes canonical, on-curve,
/// subgroup-checked constants supplied by the program. The transcript digest
/// is precomputed over the supplied bytes.
#[derive(Clone, Debug)]
pub struct ValidatedVerifyingKey {
    key: VerifyingKey,
    digest: [u8; 32],
}

impl VerifyingKey {
    pub fn num_public_inputs(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }

    /// Shape, no-infinity, and digest checks only. For compile-time constant
    /// keys on SBF where full curve checks are not available (host should still
    /// prefer [`Self::validate`]).
    #[inline]
    pub fn trust(self) -> Result<ValidatedVerifyingKey, Groth16BatchError> {
        self.validate_shape()?;
        self.validate_no_infinities()?;
        let digest = digest(&self);
        Ok(ValidatedVerifyingKey { key: self, digest })
    }

    pub fn validate(self) -> Result<ValidatedVerifyingKey, Groth16BatchError> {
        self.validate_shape()?;
        validate_g1(&self.alpha_g1, "alpha_g1")?;
        for ic in &self.ic {
            validate_g1(ic, "ic")?;
        }
        validate_g2(&self.beta_g2, "beta_g2")?;
        validate_g2(&self.gamma_g2, "gamma_g2")?;
        validate_g2(&self.delta_g2, "delta_g2")?;
        if let Some(pedersen) = &self.pedersen {
            validate_g2(&pedersen.g2, "pedersen g2")?;
            validate_g2(&pedersen.sigma_g2, "pedersen sigma_g2")?;
        }
        let digest = digest(&self);
        Ok(ValidatedVerifyingKey { key: self, digest })
    }

    #[inline]
    fn validate_shape(&self) -> Result<(), Groth16BatchError> {
        if self.ic.is_empty() {
            return Err(Groth16BatchError::InvalidVerifyingKey(
                "ic must contain IC_0",
            ));
        }
        if self.ic.len() > usize::from(u16::MAX) {
            return Err(Groth16BatchError::InvalidVerifyingKey("too many IC points"));
        }
        Ok(())
    }

    #[inline]
    fn validate_no_infinities(&self) -> Result<(), Groth16BatchError> {
        reject_infinity_g1(&self.alpha_g1, "alpha_g1")?;
        for ic in &self.ic {
            reject_infinity_g1(ic, "ic")?;
        }
        reject_infinity_g2(&self.beta_g2, "beta_g2")?;
        reject_infinity_g2(&self.gamma_g2, "gamma_g2")?;
        reject_infinity_g2(&self.delta_g2, "delta_g2")?;
        if let Some(pedersen) = &self.pedersen {
            reject_infinity_g2(&pedersen.g2, "pedersen g2")?;
            reject_infinity_g2(&pedersen.sigma_g2, "pedersen sigma_g2")?;
        }
        Ok(())
    }
}

impl ValidatedVerifyingKey {
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }

    /// keccak256 over the canonical key bytes; this is the `vkd` value the
    /// transcript binds
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[inline]
fn digest(key: &VerifyingKey) -> [u8; 32] {
    // the tag byte fixes the committed-vs-vanilla layout so two rails can
    // never serialize to one byte string
    let tag = [u8::from(key.pedersen.is_some())];
    let ic_len = (key.ic.len() as u16).to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(key.ic.len().saturating_add(8));
    parts.push(&tag);
    parts.push(&key.alpha_g1.0);
    parts.push(&key.beta_g2.0);
    parts.push(&key.gamma_g2.0);
    parts.push(&key.delta_g2.0);
    parts.push(&ic_len);
    for ic in &key.ic {
        parts.push(&ic.0);
    }
    if let Some(pedersen) = &key.pedersen {
        parts.push(&pedersen.g2.0);
        parts.push(&pedersen.sigma_g2.0);
    }
    hashv(&parts).to_bytes()
}

#[inline]
fn reject_infinity_g1(point: &PodG1Point, what: &'static str) -> Result<(), Groth16BatchError> {
    if all_zero(&point.0) {
        return Err(Groth16BatchError::InvalidVerifyingKey(what));
    }
    Ok(())
}

#[inline]
fn reject_infinity_g2(point: &PodG2Point, what: &'static str) -> Result<(), Groth16BatchError> {
    if all_zero(&point.0) {
        return Err(Groth16BatchError::InvalidVerifyingKey(what));
    }
    Ok(())
}

// `to_affine` does the canonical, on-curve, and (for G2) subgroup checks; a key
// point must additionally never be infinity, which would void everything
// downstream. On SBF the byte-level infinity check remains available even
// though full curve validation does not.
#[cfg(not(target_os = "solana"))]
fn validate_g1(point: &PodG1Point, what: &'static str) -> Result<(), Groth16BatchError> {
    let invalid = || Groth16BatchError::InvalidVerifyingKey(what);
    if point.to_affine().map_err(|_| invalid())?.is_zero() {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(not(target_os = "solana"))]
fn validate_g2(point: &PodG2Point, what: &'static str) -> Result<(), Groth16BatchError> {
    let invalid = || Groth16BatchError::InvalidVerifyingKey(what);
    if point.to_affine().map_err(|_| invalid())?.is_zero() {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "solana")]
fn validate_g1(point: &PodG1Point, what: &'static str) -> Result<(), Groth16BatchError> {
    reject_infinity_g1(point, what)
}

#[cfg(target_os = "solana")]
fn validate_g2(point: &PodG2Point, what: &'static str) -> Result<(), Groth16BatchError> {
    reject_infinity_g2(point, what)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{g2_bytes, make_vk, non_subgroup_g2, rng},
    };

    #[test]
    fn test_valid_keys_validate() {
        let mut rng = rng();
        for (num_inputs, committed) in [(1, false), (0, false), (3, true)] {
            let (_, vk) = make_vk(&mut rng, num_inputs, committed);
            assert_eq!(vk.key().num_public_inputs(), num_inputs);
        }
    }

    #[test]
    fn test_degenerate_keys_rejected() {
        let mut rng = rng();
        let (_, valid) = make_vk(&mut rng, 1, true);
        let template = valid.key();

        // infinity alpha
        let mut vk = template.clone();
        vk.alpha_g1 = PodG1Point([0u8; 64]);
        assert!(matches!(
            vk.validate(),
            Err(Groth16BatchError::InvalidVerifyingKey("alpha_g1"))
        ));
        let mut vk = template.clone();
        vk.alpha_g1 = PodG1Point([0u8; 64]);
        assert!(matches!(
            vk.trust(),
            Err(Groth16BatchError::InvalidVerifyingKey("alpha_g1"))
        ));

        // off-curve beta
        let mut vk = template.clone();
        vk.beta_g2.0[127] = vk.beta_g2.0[127].wrapping_add(1);
        assert!(matches!(
            vk.validate(),
            Err(Groth16BatchError::InvalidVerifyingKey("beta_g2"))
        ));

        // non-subgroup gamma
        let mut vk = template.clone();
        vk.gamma_g2 = g2_bytes(&non_subgroup_g2());
        assert!(matches!(
            vk.validate(),
            Err(Groth16BatchError::InvalidVerifyingKey("gamma_g2"))
        ));
        let mut vk = template.clone();
        vk.gamma_g2 = PodG2Point([0u8; 128]);
        assert!(matches!(
            vk.trust(),
            Err(Groth16BatchError::InvalidVerifyingKey("gamma_g2"))
        ));

        // non-subgroup Pedersen CRS: the commitment key is as trusted as the
        // rest of the key and validated with it
        let mut vk = template.clone();
        vk.pedersen.as_mut().unwrap().sigma_g2 = g2_bytes(&non_subgroup_g2());
        assert!(matches!(
            vk.validate(),
            Err(Groth16BatchError::InvalidVerifyingKey("pedersen sigma_g2"))
        ));

        // empty IC
        let mut vk = template.clone();
        vk.ic.clear();
        assert!(matches!(
            vk.validate(),
            Err(Groth16BatchError::InvalidVerifyingKey(_))
        ));
    }

    #[test]
    fn test_digest_binds_every_field_and_the_rail_tag() {
        let mut rng = rng();
        let (_, committed) = make_vk(&mut rng, 1, true);
        let mut vanilla_key = committed.key().clone();
        vanilla_key.pedersen = None;
        let vanilla = vanilla_key.validate().unwrap();
        assert_ne!(committed.digest(), vanilla.digest());

        let (_, other) = make_vk(&mut rng, 1, true);
        assert_ne!(committed.digest(), other.digest());
    }
}
