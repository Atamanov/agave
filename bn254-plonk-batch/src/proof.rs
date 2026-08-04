use {
    crate::{PlonkBatchError, vk::ValidatedVerifyingKey},
    solana_bn254_batch_syscall::{G1_BYTES, PodG1Point, PodScalar},
};

/// The six field evaluations a PLONK proof carries, in the fixed transcript
/// order: a, b, c, s_sigma1, s_sigma2, then z at zeta * omega.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluations {
    pub a: PodScalar,
    pub b: PodScalar,
    pub c: PodScalar,
    pub s_sigma1: PodScalar,
    pub s_sigma2: PodScalar,
    pub z_omega: PodScalar,
}

impl Evaluations {
    /// fixed absorb/serialize order shared by validation and both transcripts
    pub(crate) fn slots(&self) -> [&PodScalar; 6] {
        [
            &self.a,
            &self.b,
            &self.c,
            &self.s_sigma1,
            &self.s_sigma2,
            &self.z_omega,
        ]
    }
}

/// One PLONK proof plus its statement, in the typed wire encoding of the
/// batch syscalls. All commitments are G1; the proof carries no G2 element,
/// which is what lets the batch amortize the pairing step entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// round 1: [a]_1, [b]_1, [c]_1
    pub wire_commitments: [PodG1Point; 3],
    /// round 2: [z]_1
    pub grand_product: PodG1Point,
    /// round 3: [t_lo]_1, [t_mid]_1, [t_hi]_1
    pub quotient: [PodG1Point; 3],
    /// round 5: W_zeta
    pub opening: PodG1Point,
    /// round 5: W_zeta_omega
    pub shifted_opening: PodG1Point,
    pub evaluations: Evaluations,
    pub public_inputs: Vec<PodScalar>,
}

impl Proof {
    /// fixed absorb/serialize order shared by validation and both transcripts
    pub(crate) fn commitment_slots(&self) -> [&PodG1Point; 9] {
        [
            &self.wire_commitments[0],
            &self.wire_commitments[1],
            &self.wire_commitments[2],
            &self.grand_product,
            &self.quotient[0],
            &self.quotient[1],
            &self.quotient[2],
            &self.opening,
            &self.shifted_opening,
        ]
    }

    /// Shape and canonicality checks, before any transcript hashing: the
    /// input count must match the key, no commitment or opening slot may be
    /// infinity, and every evaluation and public input must be a canonical
    /// scalar so the transcript never sees two byte strings for one semantic
    /// value.
    pub(crate) fn validate(&self, vk: &ValidatedVerifyingKey) -> Result<(), PlonkBatchError> {
        if self.public_inputs.len() != vk.num_public_inputs() {
            return Err(PlonkBatchError::InputCountMismatch);
        }
        for point in self.commitment_slots() {
            if point.0 == [0u8; G1_BYTES] {
                return Err(PlonkBatchError::InfinityInProofPosition);
            }
        }
        for scalar in self.evaluations.slots() {
            crate::scalar::fr_from_be(scalar).ok_or(PlonkBatchError::NonCanonicalScalar)?;
        }
        for input in &self.public_inputs {
            crate::scalar::fr_from_be(input).ok_or(PlonkBatchError::NonCanonicalScalar)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_support::{make_proof, make_vk, rng},
        ark_bn254::Fr,
        ark_ff::UniformRand,
    };

    #[test]
    fn test_valid_proof_passes_validation() {
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng);
        let proof = make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng));
        assert_eq!(proof.validate(&vk), Ok(()));
    }

    #[test]
    fn test_input_count_mismatch() {
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng);
        let valid = make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng));

        let mut proof = valid.clone();
        proof.public_inputs.push(PodScalar([0u8; 32]));
        assert_eq!(
            proof.validate(&vk),
            Err(PlonkBatchError::InputCountMismatch)
        );

        let mut proof = valid.clone();
        proof.public_inputs.clear();
        assert_eq!(
            proof.validate(&vk),
            Err(PlonkBatchError::InputCountMismatch)
        );
    }

    #[test]
    fn test_infinity_rejected_in_every_slot() {
        // infinity absorbs randomizers and degenerates pairing
        // terms, so every one of the nine point slots rejects it
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng);
        let valid = make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng));
        for slot in 0..9 {
            let mut proof = valid.clone();
            let point = match slot {
                0..=2 => &mut proof.wire_commitments[slot],
                3 => &mut proof.grand_product,
                4..=6 => &mut proof.quotient[slot - 4],
                7 => &mut proof.opening,
                _ => &mut proof.shifted_opening,
            };
            *point = PodG1Point([0u8; G1_BYTES]);
            assert_eq!(
                proof.validate(&vk),
                Err(PlonkBatchError::InfinityInProofPosition),
                "slot {slot}"
            );
        }
    }

    #[test]
    fn test_noncanonical_scalars_rejected() {
        // both the carried evaluations and the public inputs
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng);
        let valid = make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng));

        let mut proof = valid.clone();
        proof.evaluations.z_omega = PodScalar([0xffu8; 32]);
        assert_eq!(
            proof.validate(&vk),
            Err(PlonkBatchError::NonCanonicalScalar)
        );

        let mut proof = valid.clone();
        proof.public_inputs[0] = PodScalar([0xffu8; 32]);
        assert_eq!(
            proof.validate(&vk),
            Err(PlonkBatchError::NonCanonicalScalar)
        );
    }

    #[test]
    fn test_validation_precedence() {
        // count mismatch outranks infinity, which outranks canonicality
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng);
        let valid = make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng));

        let mut proof = valid.clone();
        proof.opening = PodG1Point([0u8; G1_BYTES]);
        proof.public_inputs.clear();
        assert_eq!(
            proof.validate(&vk),
            Err(PlonkBatchError::InputCountMismatch)
        );

        let mut proof = valid.clone();
        proof.opening = PodG1Point([0u8; G1_BYTES]);
        proof.evaluations.a = PodScalar([0xffu8; 32]);
        assert_eq!(
            proof.validate(&vk),
            Err(PlonkBatchError::InfinityInProofPosition)
        );
    }
}
