use {
    crate::{
        proof::{Evaluations, Proof},
        vk::ValidatedVerifyingKey,
    },
    ark_bn254::Fr,
    ark_ff::{One, PrimeField},
    solana_bn254_batch_syscall::{PodG1Point, PodScalar},
    solana_keccak_hasher::{Hasher, hashv},
};

// versioned ASCII constant carrying the protocol name, transcript version,
// and lane; distinct per scheme and deployment
const INNER_DOMAIN_TAG: &[u8] = b"solana-bn254-plonk-batch:v1:inner";

/// One proof's internal challenges in round order. Batch-independent by
/// construction: they are a function of the proof-local transcript only (VK
/// digest, statement, commitments in phase order), never of the batch, so a
/// proof's challenges are identical alone or in any batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InnerChallenges {
    pub beta: Fr,
    pub gamma: Fr,
    pub alpha: Fr,
    pub zeta: Fr,
    pub v: Fr,
    pub u: Fr,
}

/// Running-state Fiat-Shamir transcript: absorbing sets
/// state = keccak256(state || bytes); squeezing maps
/// keccak256(state || phase_tag) to Fr via from_be_bytes_mod_order, whose
/// mod-r bias is below 2^-125 and irrelevant here. Phase tags are distinct
/// ASCII bytes so two challenges squeezed from one state (beta, gamma)
/// differ. Every absorbed element is canonical bytes: proof validation runs
/// before any hashing, so one semantic value has one byte string.
///
/// The fixture prover drives the same phases interleaved with its rounds;
/// completeness of the batch is the test that the phase layout matches.
pub(crate) struct InnerTranscript {
    state: [u8; 32],
}

impl InnerTranscript {
    /// binds the context before any prover message: domain tag, VK digest,
    /// then the statement with a fixed-width count prefix
    pub(crate) fn new(vk: &ValidatedVerifyingKey, public_inputs: &[PodScalar]) -> Self {
        let mut hasher = Hasher::default();
        hasher.hash(INNER_DOMAIN_TAG);
        hasher.hash(vk.digest());
        hasher.hash(&(public_inputs.len() as u32).to_be_bytes());
        for input in public_inputs {
            hasher.hash(&input.0);
        }
        Self {
            state: hasher.result().to_bytes(),
        }
    }

    fn absorb(&mut self, parts: &[&[u8]]) {
        let mut hasher = Hasher::default();
        hasher.hash(&self.state);
        for part in parts {
            hasher.hash(part);
        }
        self.state = hasher.result().to_bytes();
    }

    fn challenge(&self, phase_tag: u8) -> Fr {
        Fr::from_be_bytes_mod_order(&hashv(&[&self.state, &[phase_tag]]).to_bytes())
    }

    /// round 1 -> beta, gamma
    pub(crate) fn wire_commitments(&mut self, wires: &[PodG1Point; 3]) -> (Fr, Fr) {
        self.absorb(&[&wires[0].0, &wires[1].0, &wires[2].0]);
        (self.challenge(b'B'), self.challenge(b'G'))
    }

    /// round 2 -> alpha
    pub(crate) fn grand_product(&mut self, z: &PodG1Point) -> Fr {
        self.absorb(&[&z.0]);
        self.challenge(b'A')
    }

    /// round 3 -> zeta
    pub(crate) fn quotient(&mut self, quotient: &[PodG1Point; 3]) -> Fr {
        self.absorb(&[&quotient[0].0, &quotient[1].0, &quotient[2].0]);
        self.challenge(b'Z')
    }

    /// round 4 -> v
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

    /// round 5 -> u
    pub(crate) fn openings(&mut self, opening: &PodG1Point, shifted: &PodG1Point) -> Fr {
        self.absorb(&[&opening.0, &shifted.0]);
        self.challenge(b'U')
    }
}

/// The verifier-side derivation: replay the whole proof through the phased
/// transcript.
pub(crate) fn derive_inner(vk: &ValidatedVerifyingKey, proof: &Proof) -> InnerChallenges {
    let mut transcript = InnerTranscript::new(vk, &proof.public_inputs);
    let (beta, gamma) = transcript.wire_commitments(&proof.wire_commitments);
    let alpha = transcript.grand_product(&proof.grand_product);
    let zeta = transcript.quotient(&proof.quotient);
    let v = transcript.evaluations(&proof.evaluations);
    let u = transcript.openings(&proof.opening, &proof.shifted_opening);
    InnerChallenges {
        beta,
        gamma,
        alpha,
        zeta,
        v,
        u,
    }
}

/// How the per-proof outer randomizers derive from the seed. `Independent`
/// gives a per-proof batch soundness error of 2^-128 with no dependence on
/// the batch size; `Powers` derives all N from one draw at (N-1) * 2^-128.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomizerMode {
    Independent,
    Powers,
}

impl RandomizerMode {
    pub(crate) fn domain_tag(self) -> &'static [u8] {
        match self {
            RandomizerMode::Independent => b"solana-bn254-plonk-batch:v1:independent",
            RandomizerMode::Powers => b"solana-bn254-plonk-batch:v1:powers",
        }
    }
}

/// The outer Fiat-Shamir seed over the frozen batch: everything the verdict
/// depends on is hashed, in canonical bytes, with fixed-width framing.
/// Per-proof records need no length prefixes: the single VK
/// fixes the layout of every record, and validation pinned each proof's
/// public input count to that key before any hashing.
pub(crate) fn derive_seed(
    mode: RandomizerMode,
    vk: &ValidatedVerifyingKey,
    proofs: &[Proof],
) -> [u8; 32] {
    let mut hasher = Hasher::default();
    hasher.hash(mode.domain_tag());
    hasher.hash(vk.digest());
    hasher.hash(&(proofs.len() as u64).to_be_bytes());
    for proof in proofs {
        for point in proof.commitment_slots() {
            hasher.hash(&point.0);
        }
        for evaluation in proof.evaluations.slots() {
            hasher.hash(&evaluation.0);
        }
        for input in &proof.public_inputs {
            hasher.hash(&input.0);
        }
    }
    hasher.result().to_bytes()
}

/// rho_k = 1 + lo128(keccak256(seed || be64(k))): uniform on [1, 2^128],
/// exactly 2^128 values, no zero and no bias. k is
/// 1-based in proof order. In `Powers` mode the k-th randomizer is r^k of the
/// single k = 1 draw.
pub(crate) fn derive_randomizers(
    seed: &[u8; 32],
    num_proofs: u64,
    mode: RandomizerMode,
) -> Vec<Fr> {
    let draw = |k: u64| -> Fr {
        let digest = hashv(&[seed, &k.to_be_bytes()]).to_bytes();
        let mut lo = [0u8; 16];
        lo.copy_from_slice(&digest[16..]);
        Fr::from(u128::from_be_bytes(lo)) + Fr::one()
    };
    match mode {
        RandomizerMode::Independent => (1..=num_proofs).map(draw).collect(),
        RandomizerMode::Powers => {
            let r = draw(1);
            let mut power = Fr::one();
            (0..num_proofs)
                .map(|_| {
                    power *= r;
                    power
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::test_support::{make_proof, make_vk, rng},
        ark_ff::{BigInteger, PrimeField, UniformRand, Zero},
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
            let k = (i + 1) as u64;
            let digest = hashv(&[&seed, &k.to_be_bytes()]).to_bytes();
            let minus_one = (*r - Fr::one()).into_bigint().to_bytes_be();
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
        assert_eq!(randomizers[1], r * r);
        assert_eq!(randomizers[2], r * r * r);
        assert_eq!(randomizers[3], r * r * r * r);
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
