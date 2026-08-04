#[cfg(any(test, feature = "test-fixtures"))]
use {crate::proof::Evaluations, ark_ff::PrimeField, solana_bn254_batch_syscall::PodG1Point};
use {
    crate::{proof::Proof, vk::ValidatedVerifyingKey},
    ark_bn254::Fr,
    ark_ff::One,
    core::ops::{Add, MulAssign},
    solana_bn254_batch_syscall::PodScalar,
    solana_keccak_hasher::hashv,
};

/// One proof's internal challenges in round order. Batch-independent by
/// construction: they are a function of the proof-local transcript only (VK
/// digest, statement, commitments in phase order), never of the batch, so a
/// proof's challenges are identical alone or in any batch.
// item-level pub for the test_support re-export; the module stays pub(crate),
// so the only external path is the fixture surface
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(any(test, feature = "test-fixtures"))]
pub struct InnerChallenges {
    pub beta: Fr,
    pub gamma: Fr,
    pub alpha: Fr,
    pub zeta: Fr,
    pub v: Fr,
    pub u: Fr,
}

/// Raw Keccak squeezes for the same six inner challenges. The verifier passes
/// these bytes to the native scalar-reduction syscall, which performs exactly
/// the `from_be_bytes_mod_order` mapping. Keeping the raw form avoids
/// six 256-bit modular reductions per proof in SBF without moving or changing
/// any transcript hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InnerChallengeDigests {
    pub beta: [u8; 32],
    pub gamma: [u8; 32],
    pub alpha: [u8; 32],
    pub zeta: [u8; 32],
    pub v: [u8; 32],
    pub u: [u8; 32],
}

/// How the per-proof outer randomizers derive from the seed. `Independent`
/// gives a per-proof batch soundness error of 2^-128 with no dependence on
/// the batch size; `Powers` derives all N from one draw at (N-1) * 2^-128.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomizerMode {
    Independent,
    Powers,
}

impl InnerChallengeDigests {
    pub(crate) fn slots(&self) -> [[u8; 32]; 6] {
        [self.beta, self.gamma, self.alpha, self.zeta, self.v, self.u]
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn to_scalars(self) -> InnerChallenges {
        let reduce = |digest: &[u8; 32]| Fr::from_be_bytes_mod_order(digest);
        InnerChallenges {
            beta: reduce(&self.beta),
            gamma: reduce(&self.gamma),
            alpha: reduce(&self.alpha),
            zeta: reduce(&self.zeta),
            v: reduce(&self.v),
            u: reduce(&self.u),
        }
    }
}

/// Verifier-side transcript replay that returns the six raw Keccak squeezes.
/// It uses the same absorb order, phase tags, and hash inputs as scalar replay.
#[inline(never)]
pub fn derive_inner_digests(vk: &ValidatedVerifyingKey, proof: &Proof) -> InnerChallengeDigests {
    let mut transcript = InnerTranscript::new(vk, &proof.public_inputs);
    transcript.absorb(&[
        &proof.wire_commitments[0].0,
        &proof.wire_commitments[1].0,
        &proof.wire_commitments[2].0,
    ]);
    let beta = transcript.challenge_digest(b'B');
    let gamma = transcript.challenge_digest(b'G');
    transcript.absorb(&[&proof.grand_product.0]);
    let alpha = transcript.challenge_digest(b'A');
    transcript.absorb(&[
        &proof.quotient[0].0,
        &proof.quotient[1].0,
        &proof.quotient[2].0,
    ]);
    let zeta = transcript.challenge_digest(b'Z');
    let slots = proof.evaluations.slots();
    transcript.absorb(&[
        &slots[0].0,
        &slots[1].0,
        &slots[2].0,
        &slots[3].0,
        &slots[4].0,
        &slots[5].0,
    ]);
    let v = transcript.challenge_digest(b'V');
    transcript.absorb(&[&proof.opening.0, &proof.shifted_opening.0]);
    let u = transcript.challenge_digest(b'U');
    InnerChallengeDigests {
        beta,
        gamma,
        alpha,
        zeta,
        v,
        u,
    }
}

/// The verifier-side derivation: replay the whole proof through the phased
/// transcript.
#[inline(never)]
#[cfg(any(test, feature = "test-fixtures"))]
pub fn derive_inner(vk: &ValidatedVerifyingKey, proof: &Proof) -> InnerChallenges {
    derive_inner_digests(vk, proof).to_scalars()
}

/// The outer Fiat-Shamir seed over the frozen batch: everything the verdict
/// depends on is hashed, in canonical bytes, with fixed-width framing.
/// Per-proof records need no length prefixes: the single VK
/// fixes the layout of every record, and validation pinned each proof's
/// public input count to that key before any hashing.
/// Public as a composition surface: a joint (multi-scheme) verifier absorbs
/// this seed as a PLONK section digest, so one collision-resistant value
/// binds the section's whole framing.
#[inline(never)]
pub fn derive_seed(mode: RandomizerMode, vk: &ValidatedVerifyingKey, proofs: &[Proof]) -> [u8; 32] {
    let proof_count = (proofs.len() as u64).to_be_bytes();
    let capacity = proofs.len().saturating_mul(16).saturating_add(3);
    let mut parts: Vec<&[u8]> = Vec::with_capacity(capacity);
    parts.push(mode.domain_tag());
    parts.push(vk.digest());
    parts.push(&proof_count);
    for proof in proofs {
        for point in proof.commitment_slots() {
            parts.push(&point.0);
        }
        for evaluation in proof.evaluations.slots() {
            parts.push(&evaluation.0);
        }
        for input in &proof.public_inputs {
            parts.push(&input.0);
        }
    }
    keccak_parts(&parts)
}

/// rho_k = 1 + lo128(keccak256(seed || be64(k))): uniform on [1, 2^128],
/// exactly 2^128 values, no zero and no bias. k is
/// 1-based in proof order. In `Powers` mode the k-th randomizer is r^k of the
/// single k = 1 draw.
pub fn derive_randomizers(seed: &[u8; 32], num_proofs: u64, mode: RandomizerMode) -> Vec<Fr> {
    let draw = |k: u64| -> Fr {
        let digest = hashv(&[seed, &k.to_be_bytes()]).to_bytes();
        let mut lo = [0u8; 16];
        lo.copy_from_slice(&digest[16..]);
        Fr::from(u128::from_be_bytes(lo)).add(Fr::one())
    };
    match mode {
        RandomizerMode::Independent => (1..=num_proofs).map(draw).collect(),
        RandomizerMode::Powers => {
            let r = draw(1);
            let mut power = Fr::one();
            (0..num_proofs)
                .map(|_| {
                    power.mul_assign(r);
                    power
                })
                .collect()
        }
    }
}

impl RandomizerMode {
    pub(crate) fn domain_tag(self) -> &'static [u8] {
        match self {
            RandomizerMode::Independent => b"solana-bn254-plonk-batch:v1:independent",
            RandomizerMode::Powers => b"solana-bn254-plonk-batch:v1:powers",
        }
    }
}

const INNER_DOMAIN_TAG: &[u8] = b"solana-bn254-plonk-batch:v1:inner";

/// Transcript state for one validated proof. Phase tags separate challenges
/// from the same state. The reduction matches snarkjs. The maximum probability
/// of each value is less than 2^-253. Validation gives each field value one
/// encoding.
pub(crate) struct InnerTranscript {
    state: [u8; 32],
}

impl InnerTranscript {
    /// Bind the domain, key, and statement before the first prover message.
    pub(crate) fn new(vk: &ValidatedVerifyingKey, public_inputs: &[PodScalar]) -> Self {
        let count = (public_inputs.len() as u32).to_be_bytes();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(public_inputs.len().saturating_add(3));
        parts.push(INNER_DOMAIN_TAG);
        parts.push(vk.digest());
        parts.push(&count);
        for input in public_inputs {
            parts.push(&input.0);
        }
        Self {
            state: keccak_parts(&parts),
        }
    }

    /// Absorb round 1 and return beta and gamma.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(crate) fn wire_commitments(&mut self, wires: &[PodG1Point; 3]) -> (Fr, Fr) {
        self.absorb(&[&wires[0].0, &wires[1].0, &wires[2].0]);
        (self.challenge(b'B'), self.challenge(b'G'))
    }

    /// Absorb round 2 and return alpha.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(crate) fn grand_product(&mut self, z: &PodG1Point) -> Fr {
        self.absorb(&[&z.0]);
        self.challenge(b'A')
    }

    /// Absorb round 3 and return zeta.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(crate) fn quotient(&mut self, quotient: &[PodG1Point; 3]) -> Fr {
        self.absorb(&[&quotient[0].0, &quotient[1].0, &quotient[2].0]);
        self.challenge(b'Z')
    }

    /// Absorb round 4 and return v.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(crate) fn evaluations(&mut self, evaluations: &Evaluations) -> Fr {
        let slots = evaluations.slots();
        self.absorb(&[
            &slots[0].0,
            &slots[1].0,
            &slots[2].0,
            &slots[3].0,
            &slots[4].0,
            &slots[5].0,
        ]);
        self.challenge(b'V')
    }

    fn absorb(&mut self, parts: &[&[u8]]) {
        // Six evaluation slots are the largest absorb operation.
        const MAX_PARTS: usize = 6;
        debug_assert!(parts.len() <= MAX_PARTS);
        let mut all: [&[u8]; MAX_PARTS + 1] = [&[]; MAX_PARTS + 1];
        all[0] = &self.state;
        all[1..=parts.len()].copy_from_slice(parts);
        self.state = keccak_parts(&all[..=parts.len()]);
    }

    fn challenge_digest(&self, phase_tag: u8) -> [u8; 32] {
        hashv(&[&self.state, &[phase_tag]]).to_bytes()
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn challenge(&self, phase_tag: u8) -> Fr {
        Fr::from_be_bytes_mod_order(&self.challenge_digest(phase_tag))
    }
}

/// Hash ordered chunks on native and SBF targets.
fn keccak_parts(parts: &[&[u8]]) -> [u8; 32] {
    hashv(parts).to_bytes()
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_support::{make_proof, make_vk, rng},
        ark_ff::{BigInteger, PrimeField, UniformRand, Zero},
        core::ops::{Mul, Sub},
    };

    fn setup() -> (ValidatedVerifyingKey, Vec<Proof>) {
        let mut rng = rng();
        let (trapdoor, vk) = make_vk(&mut rng);
        let proofs = (0..2)
            .map(|_| make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng)))
            .collect();
        (vk, proofs)
    }

    #[test]
    fn test_seed_binds_every_byte_the_verdict_depends_on() {
        // the weak-Fiat-Shamir class: any omitted input
        // would let an adversary grind it after learning the challenge, so
        // flipping any byte anywhere must change the seed
        let (vk, proofs) = setup();
        let baseline = derive_seed(RandomizerMode::Independent, &vk, &proofs);

        // one representative byte per record region: wires, grand product,
        // quotient, openings, evaluations, statement
        type Mutation = Box<dyn Fn(&mut Proof)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|p| p.wire_commitments[0].0[10] ^= 1),
            Box::new(|p| p.grand_product.0[0] ^= 1),
            Box::new(|p| p.quotient[2].0[63] ^= 1),
            Box::new(|p| p.opening.0[5] ^= 1),
            Box::new(|p| p.shifted_opening.0[5] ^= 1),
            Box::new(|p| p.evaluations.s_sigma2.0[31] ^= 1),
            Box::new(|p| p.evaluations.z_omega.0[0] ^= 1),
            Box::new(|p| p.public_inputs[0].0[31] ^= 1),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut mutated = proofs.clone();
            mutate(&mut mutated[1]);
            assert_ne!(
                baseline,
                derive_seed(RandomizerMode::Independent, &vk, &mutated),
                "mutation {i}"
            );
        }

        // order and count
        let mut mutated = proofs.clone();
        mutated.swap(0, 1);
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vk, &mutated)
        );
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vk, &proofs[..1])
        );

        // the verifying key, via its digest (skip the seeded rng's first key,
        // which is bit-identical to vk)
        let mut rng = rng();
        let _ = make_vk(&mut rng);
        let (_, other_vk) = make_vk(&mut rng);
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &other_vk, &proofs)
        );

        // the domain tag: cross-mode replay is cross-context replay
        assert_ne!(baseline, derive_seed(RandomizerMode::Powers, &vk, &proofs));
    }

    #[test]
    fn test_inner_challenges_bind_phases_in_order() {
        // each challenge depends on exactly the messages absorbed before it:
        // mutating a later round must leave earlier challenges fixed and move
        // every later one (a later challenge equal to baseline would mean its
        // phase input was not absorbed, the weak-FS hole)
        let (vk, proofs) = setup();
        let proof = &proofs[0];
        let baseline = derive_inner(&vk, proof);
        assert_ne!(baseline.beta, baseline.gamma);

        let changed_from = |mutated: &Proof| -> [bool; 6] {
            let challenges = derive_inner(&vk, mutated);
            [
                challenges.beta != baseline.beta,
                challenges.gamma != baseline.gamma,
                challenges.alpha != baseline.alpha,
                challenges.zeta != baseline.zeta,
                challenges.v != baseline.v,
                challenges.u != baseline.u,
            ]
        };

        let mut mutated = proof.clone();
        mutated.public_inputs[0].0[31] ^= 1;
        assert_eq!(changed_from(&mutated), [true; 6], "statement");

        let mut mutated = proof.clone();
        mutated.wire_commitments[1].0[7] ^= 1;
        assert_eq!(changed_from(&mutated), [true; 6], "round 1");

        let mut mutated = proof.clone();
        mutated.grand_product.0[7] ^= 1;
        assert_eq!(
            changed_from(&mutated),
            [false, false, true, true, true, true],
            "round 2"
        );

        let mut mutated = proof.clone();
        mutated.quotient[0].0[7] ^= 1;
        assert_eq!(
            changed_from(&mutated),
            [false, false, false, true, true, true],
            "round 3"
        );

        let mut mutated = proof.clone();
        mutated.evaluations.b.0[7] ^= 1;
        assert_eq!(
            changed_from(&mutated),
            [false, false, false, false, true, true],
            "round 4"
        );

        let mut mutated = proof.clone();
        mutated.shifted_opening.0[7] ^= 1;
        assert_eq!(
            changed_from(&mutated),
            [false, false, false, false, false, true],
            "round 5"
        );

        // the VK digest is bound before round 1
        let mut rng = rng();
        let _ = make_vk(&mut rng);
        let (_, other_vk) = make_vk(&mut rng);
        let challenges = derive_inner(&other_vk, proof);
        assert_ne!(challenges.beta, baseline.beta);
    }

    #[test]
    fn test_inner_challenges_do_not_depend_on_the_batch() {
        // derive_inner takes only (vk, proof), so batch
        // independence holds by signature; pin the determinism half, and that
        // distinct proofs still get distinct challenges
        let (vk, proofs) = setup();
        assert_eq!(derive_inner(&vk, &proofs[0]), derive_inner(&vk, &proofs[0]));
        assert_ne!(
            derive_inner(&vk, &proofs[0]).zeta,
            derive_inner(&vk, &proofs[1]).zeta
        );
    }

    #[test]
    fn test_randomizers_are_the_128_bit_draw_plus_one() {
        // pins the derivation byte-for-byte: rho_k - 1 must equal the low 16
        // bytes of keccak256(seed || be64(k)), so rho_k is uniform on
        // [1, 2^128] with no zero
        let (vk, proofs) = setup();
        let seed = derive_seed(RandomizerMode::Independent, &vk, &proofs);
        let randomizers = derive_randomizers(&seed, 3, RandomizerMode::Independent);
        assert_eq!(randomizers.len(), 3);
        for (i, r) in randomizers.iter().enumerate() {
            assert!(!r.is_zero());
            let k = u64::try_from(i.checked_add(1).unwrap()).unwrap();
            let digest = hashv(&[&seed, &k.to_be_bytes()]).to_bytes();
            let minus_one = r.sub(&Fr::one()).into_bigint().to_bytes_be();
            assert_eq!(&minus_one[16..], &digest[16..], "k = {k}");
            assert_eq!(&minus_one[..16], &[0u8; 16], "high bytes must be zero");
        }
    }

    #[test]
    fn test_powers_mode_is_powers_of_the_first_draw() {
        let (vk, proofs) = setup();
        let seed = derive_seed(RandomizerMode::Powers, &vk, &proofs);
        let randomizers = derive_randomizers(&seed, 4, RandomizerMode::Powers);
        let r = randomizers[0];
        let r2 = r.mul(r);
        let r3 = r2.mul(r);
        let r4 = r3.mul(r);
        assert_eq!(randomizers[1], r2);
        assert_eq!(randomizers[2], r3);
        assert_eq!(randomizers[3], r4);
    }

    #[test]
    fn test_domain_tags_are_versioned_and_distinct() {
        let independent = RandomizerMode::Independent.domain_tag();
        let powers = RandomizerMode::Powers.domain_tag();
        assert_ne!(independent, powers);
        assert_ne!(independent, INNER_DOMAIN_TAG);
        for tag in [independent, powers, INNER_DOMAIN_TAG] {
            let tag = core::str::from_utf8(tag).unwrap();
            assert!(tag.contains(":v1:"), "tag must carry a version: {tag}");
        }
    }
}
