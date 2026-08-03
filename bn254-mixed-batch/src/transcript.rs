use {
    ark_bn254::Fr,
    solana_bn254_groth16_batch as groth16, solana_bn254_plonk_batch as plonk,
    solana_keccak_hasher::hashv,
};

/// How the per-equation randomizers derive from the joint seed; the same
/// semantics as the single-scheme verifiers, one stream across both sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RandomizerMode {
    Independent,
    Powers,
}

impl RandomizerMode {
    // versioned ASCII constant carrying the protocol name, the transcript
    // version, and the randomizer mode; distinct from both section tags
    pub(crate) fn domain_tag(self) -> &'static [u8] {
        match self {
            RandomizerMode::Independent => b"solana-bn254-mixed-batch:v1:independent",
            RandomizerMode::Powers => b"solana-bn254-mixed-batch:v1:powers",
        }
    }

    pub(crate) fn groth16(self) -> groth16::RandomizerMode {
        match self {
            RandomizerMode::Independent => groth16::RandomizerMode::Independent,
            RandomizerMode::Powers => groth16::RandomizerMode::Powers,
        }
    }

    pub(crate) fn plonk(self) -> plonk::RandomizerMode {
        match self {
            RandomizerMode::Independent => plonk::RandomizerMode::Independent,
            RandomizerMode::Powers => plonk::RandomizerMode::Powers,
        }
    }
}

/// The joint seed: the mixed domain tag, then each section's own seed as a
/// 32-byte digest. A section seed already binds that section's whole frozen
/// batch (keys, counts, proof bytes, statements) under its scheme tag, so
/// absorbing the digests binds everything the verdict depends on, with the
/// section boundary fixed by position.
pub(crate) fn derive_seed(
    mode: RandomizerMode,
    groth16_seed: &[u8; 32],
    plonk_group_seeds: &[[u8; 32]],
) -> [u8; 32] {
    let group_count = (plonk_group_seeds.len() as u16).to_be_bytes();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + plonk_group_seeds.len());
    parts.push(mode.domain_tag());
    parts.push(groth16_seed);
    parts.push(&group_count);
    for seed in plonk_group_seeds {
        parts.push(seed);
    }
    hashv(&parts).to_bytes()
}

/// One stream over every verification equation: Groth16 equations first in
/// proof order (the PoK equation after its proof's main equation), then the
/// PLONK rho_i in group order then proof order. The draw is the shared
/// 1 + lo128(keccak(seed || be64(k))) derivation.
pub(crate) fn derive_randomizers(
    seed: &[u8; 32],
    num_equations: u64,
    mode: RandomizerMode,
) -> Vec<Fr> {
    // byte-identical derivation; reuse the groth16 implementation
    groth16::derive_randomizers(seed, num_equations, mode.groth16())
}
