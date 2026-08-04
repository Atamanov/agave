//! Legacy-current Groth16 composition with a post-final-exponentiation target.
//!
//! This path deliberately preserves the old verifier's per-public-input G1
//! multiplication/addition sequence. It is not a batch fold and does not call
//! the batch MSM syscall. One proof maps exactly three dynamic pairs and
//! compares them with an authenticated cached e(alpha, beta) target.

use {
    crate::{
        Groth16BatchError,
        verify::{Proof, validate_batch_shape},
        vk::ValidatedVerifyingKey,
    },
    solana_bn254::prelude::{
        ALT_BN128_G1_ADDITION_INPUT_SIZE, ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE,
        alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be,
    },
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodGtElement, Version as SyscallVersion, alt_bn128_pairing_map,
    },
};

const FQ_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// Authenticated cached target for one complete verifying-key digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentFp12Target {
    vk_digest: [u8; 32],
    target: PodGtElement,
}

impl CurrentFp12Target {
    /// Construct only after a concrete handler authenticated target provenance.
    pub const fn new(vk_digest: [u8; 32], target: PodGtElement) -> Self {
        Self { vk_digest, target }
    }

    pub const fn target(&self) -> &PodGtElement {
        &self.target
    }

    fn for_key(&self, vk: &ValidatedVerifyingKey) -> Result<&PodGtElement, Groth16BatchError> {
        if self.vk_digest != *vk.digest() {
            return Err(Groth16BatchError::SameVkTargetKeyMismatch);
        }
        Ok(&self.target)
    }
}

/// Reproduce the legacy current verifier's public-input accumulation:
/// IC[0], followed by one G1 multiplication and one G1 addition per input.
pub fn legacy_current_vk_x(
    vk: &ValidatedVerifyingKey,
    proof: &Proof,
) -> Result<PodG1Point, Groth16BatchError> {
    if proof.public_inputs.len() != vk.key().num_public_inputs() {
        return Err(Groth16BatchError::InputCountMismatch);
    }
    let mut accumulator = vk.key().ic[0];
    for (input, base) in proof.public_inputs.iter().zip(vk.key().ic.iter().skip(1)) {
        let mut multiplication = [0u8; ALT_BN128_G1_MULTIPLICATION_INPUT_SIZE];
        multiplication[..64].copy_from_slice(&base.0);
        multiplication[64..].copy_from_slice(&input.0);
        let product = alt_bn128_g1_multiplication_be(&multiplication)
            .map_err(|_| Groth16BatchError::LegacyGroupOperationFailed)?;
        let product: [u8; 64] = product
            .try_into()
            .map_err(|_| Groth16BatchError::LegacyGroupOperationFailed)?;

        let mut addition = [0u8; ALT_BN128_G1_ADDITION_INPUT_SIZE];
        addition[..64].copy_from_slice(&accumulator.0);
        addition[64..].copy_from_slice(&product);
        let sum = alt_bn128_g1_addition_be(&addition)
            .map_err(|_| Groth16BatchError::LegacyGroupOperationFailed)?;
        accumulator = PodG1Point(
            sum.try_into()
                .map_err(|_| Groth16BatchError::LegacyGroupOperationFailed)?,
        );
        #[cfg(feature = "research-observer")]
        solana_bn254_batch_syscall::research_observer::record_legacy_group_ops(1, 1);
    }
    Ok(accumulator)
}

/// Build the exact three-pair Current+FP12 map input with no batch MSM.
pub fn current_fp12_pairs(
    vk: &ValidatedVerifyingKey,
    proof: &Proof,
) -> Result<[PodG1G2Pair; 3], Groth16BatchError> {
    validate_current_shape(vk, proof)?;
    let vk_x = legacy_current_vk_x(vk, proof)?;
    Ok([
        PodG1G2Pair {
            g1: proof.a,
            g2: proof.b,
        },
        PodG1G2Pair {
            g1: negate_g1(vk_x)?,
            g2: vk.key().gamma_g2,
        },
        PodG1G2Pair {
            g1: negate_g1(proof.c)?,
            g2: vk.key().delta_g2,
        },
    ])
}

/// Verify one proof using legacy G1 mul/add construction, one three-pair map,
/// and a direct authenticated-target comparison.
pub fn groth16_current_fp12_verify(
    vk: &ValidatedVerifyingKey,
    proof: &Proof,
    authenticated_target: &CurrentFp12Target,
) -> Result<bool, Groth16BatchError> {
    let target = authenticated_target.for_key(vk)?;
    let pairs = current_fp12_pairs(vk, proof)?;
    Ok(alt_bn128_pairing_map(SyscallVersion::V0, &pairs)? == *target)
}

fn validate_current_shape(
    vk: &ValidatedVerifyingKey,
    proof: &Proof,
) -> Result<(), Groth16BatchError> {
    if vk.key().pedersen.is_some() {
        return Err(Groth16BatchError::SameVkTargetRequiresVanillaKey);
    }
    validate_batch_shape(core::slice::from_ref(vk), core::slice::from_ref(proof))
}

fn negate_g1(point: PodG1Point) -> Result<PodG1Point, Groth16BatchError> {
    if point.0.iter().all(|byte| *byte == 0) {
        return Ok(point);
    }
    let y: [u8; 32] = point.0[32..]
        .try_into()
        .map_err(|_| Groth16BatchError::LegacyGroupOperationFailed)?;
    if y >= FQ_MODULUS_BE {
        return Err(Groth16BatchError::LegacyGroupOperationFailed);
    }
    let mut neg_y = FQ_MODULUS_BE;
    let mut borrow = false;
    for index in (0..32).rev() {
        let (first, first_borrow) = neg_y[index].overflowing_sub(y[index]);
        let (second, second_borrow) = first.overflowing_sub(u8::from(borrow));
        neg_y[index] = second;
        borrow = first_borrow || second_borrow;
    }
    if y.iter().all(|byte| *byte == 0) {
        neg_y.fill(0);
    }
    let mut output = point.0;
    output[32..].copy_from_slice(&neg_y);
    Ok(PodG1Point(output))
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_utils::{make_proof, make_vk, rng},
        ark_bn254::Fr,
        ark_ff::UniformRand,
        solana_bn254_batch_syscall::{Version, alt_bn128_pairing_check, alt_bn128_pairing_map},
    };

    #[test]
    fn four_pair_current_equals_three_pair_map_target() {
        let mut rng = rng();
        let (key, vk) = make_vk(&mut rng, 2, false);
        let inputs = [Fr::rand(&mut rng), Fr::rand(&mut rng)];
        let proof = make_proof(&mut rng, &key, 0, &inputs);
        let target_pair = PodG1G2Pair {
            g1: vk.key().alpha_g1,
            g2: vk.key().beta_g2,
        };
        let target = alt_bn128_pairing_map(Version::V0, &[target_pair]).unwrap();
        let dynamic = current_fp12_pairs(&vk, &proof).unwrap();
        let mut current = dynamic.to_vec();
        current.insert(
            1,
            PodG1G2Pair {
                g1: negate_g1(vk.key().alpha_g1).unwrap(),
                g2: vk.key().beta_g2,
            },
        );
        assert!(alt_bn128_pairing_check(Version::V0, &current).unwrap());
        assert_eq!(
            alt_bn128_pairing_map(Version::V0, &dynamic).unwrap(),
            target
        );
        assert!(groth16_current_fp12_verify(
            &vk,
            &proof,
            &CurrentFp12Target::new(*vk.digest(), target),
        )
        .unwrap());
    }

    #[test]
    fn target_binding_and_three_pair_shape_are_enforced() {
        let mut rng = rng();
        let (key, vk) = make_vk(&mut rng, 1, false);
        let inputs = [Fr::rand(&mut rng)];
        let proof = make_proof(&mut rng, &key, 0, &inputs);
        let target = alt_bn128_pairing_map(
            Version::V0,
            &[PodG1G2Pair {
                g1: vk.key().alpha_g1,
                g2: vk.key().beta_g2,
            }],
        )
        .unwrap();
        assert_eq!(current_fp12_pairs(&vk, &proof).unwrap().len(), 3);
        let mut wrong = *vk.digest();
        wrong[0] ^= 1;
        assert!(matches!(
            groth16_current_fp12_verify(&vk, &proof, &CurrentFp12Target::new(wrong, target)),
            Err(Groth16BatchError::SameVkTargetKeyMismatch)
        ));
    }
}
