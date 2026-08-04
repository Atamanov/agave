use {
    crate::{verify::Proof, vk::ValidatedVerifyingKey},
    ark_bn254::Fr,
    ark_ff::One,
    core::ops::{Add, MulAssign},
    solana_keccak_hasher::hashv,
};

/// How the per-equation randomizers derive from the seed. `Independent` gives
/// a per-equation batch soundness error of 2^-128 with no dependence on the
/// batch size; `Powers` derives all N from one draw at (N-1) * 2^-128.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomizerMode {
    Independent,
    Powers,
}

/// The Fiat-Shamir seed over the frozen batch: everything the verdict depends
/// on is hashed, in canonical bytes, with fixed-width framing. The per-record
/// key index does double duty: it binds each proof to its
/// circuit and it fixes the record layout, since whether `com`/`pok` are
/// present is a function of the named key.
/// Public as a composition surface: a joint (multi-scheme) verifier absorbs
/// this seed as its Groth16 section digest, so one collision-resistant value
/// binds the section's whole framing.
pub fn derive_seed(
    mode: RandomizerMode,
    vks: &[ValidatedVerifyingKey],
    proofs: &[Proof],
) -> [u8; 32] {
    // callers must bound the key list first (validate_batch_shape), or the u16
    // count prefix truncates and stops framing the digest list
    debug_assert!(vks.len() <= usize::from(u16::MAX));
    let vk_count = (vks.len() as u16).to_be_bytes();
    let proof_count = (proofs.len() as u64).to_be_bytes();
    let capacity = vks
        .len()
        .saturating_add(proofs.len().saturating_mul(8))
        .saturating_add(4);
    let mut parts: Vec<&[u8]> = Vec::with_capacity(capacity);
    parts.push(mode.domain_tag());
    parts.push(&vk_count);
    for vk in vks {
        parts.push(vk.digest());
    }
    parts.push(&proof_count);
    // owned buffers for per-proof framing that must outlive the hash call
    let mut owned: Vec<[u8; 8]> = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let mut idx = [0u8; 8];
        idx[..2].copy_from_slice(&proof.vk_index.to_be_bytes());
        owned.push(idx);
    }
    for (proof, idx) in proofs.iter().zip(owned.iter()) {
        parts.push(&idx[..2]);
        parts.push(&proof.a.0);
        parts.push(&proof.b.0);
        parts.push(&proof.c.0);
        if let Some(commitment) = &proof.commitment {
            parts.push(&commitment.com.0);
            parts.push(&commitment.pok.0);
        }
        for input in &proof.public_inputs {
            parts.push(&input.0);
        }
    }
    keccak_parts(&parts)
}

/// r_k = 1 + lo128(keccak256(seed || be64(k))): uniform on [1, 2^128], exactly
/// 2^128 values, no zero and no bias. k is 1-based and runs over verification
/// equations in proof order, the Groth16 equation before the PoK within a
/// committed proof. In `Powers` mode the k-th randomizer is r^k of the single
/// k = 1 draw.
pub fn derive_randomizers(seed: &[u8; 32], num_equations: u64, mode: RandomizerMode) -> Vec<Fr> {
    let draw = |k: u64| -> Fr {
        let k_be = k.to_be_bytes();
        let digest = keccak_parts(&[seed, &k_be]);
        let mut lo = [0u8; 16];
        lo.copy_from_slice(&digest[16..]);
        Fr::from(u128::from_be_bytes(lo)).add(Fr::one())
    };
    match mode {
        RandomizerMode::Independent => (1..=num_equations).map(draw).collect(),
        RandomizerMode::Powers => {
            let r = draw(1);
            let mut power = Fr::one();
            (0..num_equations)
                .map(|_| {
                    power.mul_assign(r);
                    power
                })
                .collect()
        }
    }
}

impl RandomizerMode {
    // The domain separates each mode, protocol, and transcript version.
    pub(crate) fn domain_tag(self) -> &'static [u8] {
        match self {
            RandomizerMode::Independent => b"solana-bn254-groth16-batch:v1:independent",
            RandomizerMode::Powers => b"solana-bn254-groth16-batch:v1:powers",
        }
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
        crate::test_utils::{make_proof, make_vk, rng},
        ark_ff::{BigInteger, PrimeField, UniformRand, Zero},
        core::ops::{Mul, Sub},
    };

    fn setup() -> (Vec<ValidatedVerifyingKey>, Vec<Proof>) {
        let mut rng = rng();
        let (key, vk) = make_vk(&mut rng, 1, false);
        let (committed_key, committed_vk) = make_vk(&mut rng, 1, true);
        let x0 = Fr::rand(&mut rng);
        let x1 = Fr::rand(&mut rng);
        let proofs = vec![
            make_proof(&mut rng, &key, 0, &[x0]),
            make_proof(&mut rng, &committed_key, 1, &[x1]),
        ];
        (vec![vk, committed_vk], proofs)
    }

    #[test]
    fn test_seed_binds_every_byte_the_verdict_depends_on() {
        // the weak-Fiat-Shamir class: any omitted input
        // would let an adversary grind it after learning the challenge, so
        // flipping any byte anywhere must change the seed
        let (vks, proofs) = setup();
        let baseline = derive_seed(RandomizerMode::Independent, &vks, &proofs);

        let mut mutated = proofs.clone();
        mutated[0].a.0[10] ^= 1;
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );

        let mut mutated = proofs.clone();
        mutated[1].b.0[100] ^= 1;
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );

        let mut mutated = proofs.clone();
        mutated[0].c.0[0] ^= 1;
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );

        let mut mutated = proofs.clone();
        mutated[1].commitment.as_mut().unwrap().com.0[5] ^= 1;
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );

        let mut mutated = proofs.clone();
        mutated[1].commitment.as_mut().unwrap().pok.0[5] ^= 1;
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );

        // the statement: grinding the public input is the other half of that class
        let mut mutated = proofs.clone();
        mutated[0].public_inputs[0].0[31] ^= 1;
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );

        // the key index: without it a mixed batch has no record framing
        let mut mutated = proofs.clone();
        mutated[0].vk_index = 1;
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );

        // order and count
        let mut mutated = proofs.clone();
        mutated.swap(0, 1);
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &mutated)
        );
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &vks, &proofs[..1])
        );

        // the verifying keys, via their digests (skip the seeded rng's first
        // key, which is bit-identical to vks[0])
        let mut rng = rng();
        let _ = make_vk(&mut rng, 1, false);
        let (_, other_vk) = make_vk(&mut rng, 1, false);
        let mutated_vks = vec![other_vk, vks[1].clone()];
        assert_ne!(
            baseline,
            derive_seed(RandomizerMode::Independent, &mutated_vks, &proofs)
        );

        // the domain tag: cross-mode replay is cross-context replay
        assert_ne!(baseline, derive_seed(RandomizerMode::Powers, &vks, &proofs));
    }

    #[test]
    fn test_randomizers_are_the_128_bit_draw_plus_one() {
        // pins the derivation byte-for-byte: r_k - 1 must equal the low 16
        // bytes of keccak256(seed || be64(k)), so r_k is uniform on
        // [1, 2^128] with no zero
        let (vks, proofs) = setup();
        let seed = derive_seed(RandomizerMode::Independent, &vks, &proofs);
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
        let (vks, proofs) = setup();
        let seed = derive_seed(RandomizerMode::Powers, &vks, &proofs);
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
        for tag in [independent, powers] {
            let tag = core::str::from_utf8(tag).unwrap();
            assert!(tag.contains(":v1:"), "tag must carry a version: {tag}");
        }
    }
}
