//! Fr batch operations over raw Montgomery residues.
//!
//! A canonical wire integer can serve as stored Montgomery limbs. The field
//! value is then `a * R^-1`. Each operation applies one correction to restore
//! the canonical result.

use {
    crate::{
        Version,
        encoding::{FR_MAX_ELEMS, bigint_from_be},
        pod::PodScalar,
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    ark_bn254::{Fr, FrConfig},
    ark_ff::{BigInt, BigInteger, Field, MontConfig, PrimeField, Zero, batch_inversion_and_mul},
    core::ops::{Add, Mul},
};

/// This width matches the measured optimum for the supported input range.
const SOP_CHUNK: usize = 16;

/// The two-chain path is faster at these measured input ranges.
const CHAIN_SPLIT_MIN: usize = 64;
const CHAIN_SPLIT_SMALL_MIN: usize = 2;
const CHAIN_SPLIT_SMALL_MAX: usize = 16;

/// Inner product over the BN254 scalar field: `sum_i a[i] * b[i] mod q`.
///
/// The slices can alias. They must have the same nonzero length at or below
/// `FR_MAX_ELEMS`.
pub fn alt_bn128_fr_lincomb(
    _version: Version,
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    validate_equal_lengths(a.len(), b.len())?;
    if a.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if a.len() > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    // Raw products have one extra R^-2 factor. This value restores the sum.
    let acc = lincomb_acc::<SOP_CHUNK>(a, b)?;
    let r_squared = Fr::from_bigint(<FrConfig as MontConfig<4>>::R2)
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    Ok(PodScalar::from(&acc.mul(r_squared)))
}

/// Batch inverse over the BN254 scalar field via Montgomery's trick:
/// `out[i] = a[i]^-1 mod q`, one field inversion and 3(n-1) muls for n inputs.
///
/// All elements must be canonical and nonzero. Validation completes before
/// inversion, so an error cannot return partial output.
pub fn alt_bn128_fr_batch_invert(
    _version: Version,
    a: &[PodScalar],
) -> Result<Vec<PodScalar>, AltBn128BatchError> {
    if a.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if a.len() > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    let mut scalars = Vec::with_capacity(a.len());
    for s in a {
        let raw = bigint_from_be(&s.0);
        if raw >= Fr::MODULUS {
            return Err(AltBn128BatchError::NonCanonical);
        }
        if raw.is_zero() {
            // zero never reaches an inversion core, which would otherwise
            // leave it as zero and silently return a wrong "inverse"
            return Err(AltBn128BatchError::ZeroInput);
        }
        scalars.push(Fr::new_unchecked(raw));
    }
    // Raw limbs 1 represent R^-1 and cancel the extra R after inversion.
    let coeff = Fr::new_unchecked(BigInt::one());
    let n = scalars.len();
    if n >= CHAIN_SPLIT_MIN || (CHAIN_SPLIT_SMALL_MIN..=CHAIN_SPLIT_SMALL_MAX).contains(&n) {
        batch_invert_two_chains(&mut scalars, &coeff)?;
    } else {
        batch_inversion_and_mul(&mut scalars, &coeff);
    }
    Ok(scalars.iter().map(PodScalar::from).collect())
}

/// Accumulate raw residues in fixed stack chunks. Validation remains in input
/// order, so chunk width does not change error precedence.
fn lincomb_acc<const C: usize>(a: &[PodScalar], b: &[PodScalar]) -> Result<Fr, AltBn128BatchError> {
    if C == 0 {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    let mut acc = Fr::zero();
    for (a, b) in a.chunks(C).zip(b.chunks(C)) {
        let mut xs = [Fr::zero(); C];
        let mut ys = [Fr::zero(); C];
        for ((x_out, y_out), (x, y)) in xs.iter_mut().zip(&mut ys).zip(a.iter().zip(b)) {
            *x_out = parse_raw_residue(x)?;
            *y_out = parse_raw_residue(y)?;
        }
        acc = acc.add(Fr::sum_of_products(&xs, &ys));
    }
    Ok(acc)
}

/// Interpret a canonical wire scalar as Montgomery limbs. The canonical check
/// makes `Fr::new_unchecked` safe without a reduction.
fn parse_raw_residue(s: &PodScalar) -> Result<Fr, AltBn128BatchError> {
    let raw = bigint_from_be(&s.0);
    if raw >= Fr::MODULUS {
        return Err(AltBn128BatchError::NonCanonical);
    }
    Ok(Fr::new_unchecked(raw))
}

/// Batch inversion over two interleaved multiplication chains and one inverse.
///
/// Each half builds a prefix product. One inverse of their product seeds both
/// reverse walks. The coefficient is applied once to each result. The caller
/// provides at least two nonzero elements.
fn batch_invert_two_chains(v: &mut [Fr], coeff: &Fr) -> Result<(), AltBn128BatchError> {
    let n = v.len();
    if n < 2 {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    let half = n.div_ceil(2);
    let mut prefix = vec![Fr::zero(); n];
    let (values_a, values_b) = v.split_at(half);
    let (prefix_a, prefix_b) = prefix.split_at_mut(half);
    let run_a = prefix_products(values_a, prefix_a)?;
    let run_b = prefix_products(values_b, prefix_b)?;
    let tinv = run_a
        .mul(run_b)
        .inverse()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    let inv_a = tinv.mul(run_b).mul(coeff);
    let inv_b = tinv.mul(run_a).mul(coeff);
    let (values_a, values_b) = v.split_at_mut(half);
    invert_chain(values_a, prefix_a, inv_a)?;
    invert_chain(values_b, prefix_b, inv_b)?;
    Ok(())
}

fn prefix_products(values: &[Fr], output: &mut [Fr]) -> Result<Fr, AltBn128BatchError> {
    let (first_value, remaining_values) = values
        .split_first()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    let (first_output, remaining_output) = output
        .split_first_mut()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    if remaining_values.len() != remaining_output.len() {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    let mut product = *first_value;
    *first_output = product;
    for (value, output) in remaining_values.iter().zip(remaining_output) {
        product = product.mul(*value);
        *output = product;
    }
    Ok(product)
}

fn invert_chain(
    values: &mut [Fr],
    prefix: &[Fr],
    mut inverse: Fr,
) -> Result<(), AltBn128BatchError> {
    let (first_value, remaining_values) = values
        .split_first_mut()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    let (_, previous_prefixes) = prefix
        .split_last()
        .ok_or(AltBn128BatchError::BackendInvariant)?;
    if remaining_values.len() != previous_prefixes.len() {
        return Err(AltBn128BatchError::BackendInvariant);
    }
    for (value, previous_prefix) in remaining_values
        .iter_mut()
        .rev()
        .zip(previous_prefixes.iter().rev())
    {
        let next = inverse.mul(*value);
        *value = inverse.mul(*previous_prefix);
        inverse = next;
    }
    *first_value = inverse;
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::SCALAR_BYTES,
            test_utils::{be_add_one, fr_bytes, fr_modulus_be, rng},
        },
        ark_ff::{One, UniformRand},
        ark_std::rand::Rng,
    };

    // byte-oriented bodies drive the typed entry points through a zero-cost cast
    fn lincomb(a: &[u8], b: &[u8]) -> Result<[u8; SCALAR_BYTES], AltBn128BatchError> {
        alt_bn128_fr_lincomb(
            Version::V0,
            bytemuck::cast_slice(a),
            bytemuck::cast_slice(b),
        )
        .map(|s| s.0)
    }

    fn batch_invert(a: &[u8]) -> Result<Vec<[u8; SCALAR_BYTES]>, AltBn128BatchError> {
        alt_bn128_fr_batch_invert(Version::V0, bytemuck::cast_slice(a))
            .map(|v| v.into_iter().map(|s| s.0).collect())
    }

    fn concat(frs: &[Fr]) -> Vec<u8> {
        frs.iter().flat_map(fr_bytes).collect()
    }

    #[test]
    fn test_lincomb_matches_independent_sum() {
        let mut rng = rng();
        for n in [1usize, 2, 3, 17, 64] {
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let b: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let expected: Fr = a.iter().zip(&b).map(|(x, y)| *x * y).sum();
            assert_eq!(
                lincomb(&concat(&a), &concat(&b)).unwrap(),
                fr_bytes(&expected),
                "n = {n}"
            );
        }
    }

    #[test]
    fn test_lincomb_single_is_product() {
        let mut rng = rng();
        let x = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        assert_eq!(
            lincomb(&fr_bytes(&x), &fr_bytes(&y)).unwrap(),
            fr_bytes(&(x * y))
        );
    }

    #[test]
    fn test_lincomb_accepts_aliased_inputs() {
        // a == b: the syscall computes sum a_i^2, a legitimate call
        let mut rng = rng();
        let a: Vec<Fr> = (0..4).map(|_| Fr::rand(&mut rng)).collect();
        let bytes = concat(&a);
        let expected: Fr = a.iter().map(|x| x.square()).sum();
        assert_eq!(lincomb(&bytes, &bytes).unwrap(), fr_bytes(&expected));
    }

    #[test]
    fn test_lincomb_rejects_empty() {
        assert_eq!(lincomb(&[], &[]), Err(AltBn128BatchError::ZeroInput));
    }

    #[test]
    fn test_lincomb_rejects_count_mismatch() {
        let mut rng = rng();
        let a = concat(&[Fr::rand(&mut rng), Fr::rand(&mut rng)]);
        let b = fr_bytes(&Fr::rand(&mut rng));
        assert_eq!(lincomb(&a, &b), Err(AltBn128BatchError::LengthMismatch));
        assert_eq!(lincomb(&[], &b), Err(AltBn128BatchError::LengthMismatch));
    }

    #[test]
    fn test_lincomb_rejects_over_cap() {
        let n = FR_MAX_ELEMS + 1;
        let a = vec![1u8; n * SCALAR_BYTES];
        assert_eq!(lincomb(&a, &a), Err(AltBn128BatchError::CapExceeded));
        assert!(
            lincomb(
                &a[..FR_MAX_ELEMS * SCALAR_BYTES],
                &a[..FR_MAX_ELEMS * SCALAR_BYTES]
            )
            .is_ok()
        );
    }

    #[test]
    fn test_lincomb_rejects_noncanonical() {
        let mut rng = rng();
        let mut plus_one = fr_modulus_be();
        be_add_one(&mut plus_one);
        for bad in [fr_modulus_be(), plus_one, [0xffu8; 32]] {
            let good = fr_bytes(&Fr::rand(&mut rng));
            assert_eq!(lincomb(&bad, &good), Err(AltBn128BatchError::NonCanonical));
            assert_eq!(lincomb(&good, &bad), Err(AltBn128BatchError::NonCanonical));
        }
    }

    #[test]
    fn test_lincomb_chunk_width_only_reassociates() {
        assert_eq!(
            lincomb_acc::<0>(&[], &[]),
            Err(AltBn128BatchError::BackendInvariant)
        );
        // C only re-associates the exact modular sum, so every width agrees;
        // sizes straddle both the C = 4 and C = 16 chunk boundaries
        let mut rng = rng();
        for n in [1usize, 3, 4, 5, 15, 16, 17, 33] {
            let a: Vec<PodScalar> = (0..n)
                .map(|_| PodScalar::from(&Fr::rand(&mut rng)))
                .collect();
            let b: Vec<PodScalar> = (0..n)
                .map(|_| PodScalar::from(&Fr::rand(&mut rng)))
                .collect();
            let wide = lincomb_acc::<16>(&a, &b).unwrap();
            assert_eq!(lincomb_acc::<4>(&a, &b).unwrap(), wide, "n = {n}");
            assert_eq!(lincomb_acc::<1>(&a, &b).unwrap(), wide, "n = {n}");
        }
    }

    #[test]
    fn test_batch_invert_matches_per_element() {
        let mut rng = rng();
        for n in [1usize, 2, 3, 17, 64] {
            let a: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let out = batch_invert(&concat(&a)).unwrap();
            assert_eq!(out.len(), n, "n = {n}");
            for (got, x) in out.iter().zip(&a) {
                // independent reference: per-element Fermat inverse, not the trick
                assert_eq!(*got, fr_bytes(&x.inverse().unwrap()));
            }
        }
    }

    #[test]
    fn test_batch_invert_is_involutive() {
        let mut rng = rng();
        let a: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
        let once = batch_invert(&concat(&a)).unwrap();
        let twice = batch_invert(&once.concat()).unwrap();
        assert_eq!(twice, a.iter().map(fr_bytes).collect::<Vec<_>>());
    }

    #[test]
    fn test_batch_invert_rejects_zero_at_any_position() {
        let mut rng = rng();
        for position in [0usize, 3, 7] {
            let mut a: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
            a[position] = Fr::zero();
            assert_eq!(
                batch_invert(&concat(&a)),
                Err(AltBn128BatchError::ZeroInput),
                "position {position}"
            );
        }
    }

    #[test]
    fn test_batch_invert_rejects_empty_and_cap() {
        assert_eq!(batch_invert(&[]), Err(AltBn128BatchError::ZeroInput));
        let over = vec![1u8; (FR_MAX_ELEMS + 1) * SCALAR_BYTES];
        assert_eq!(batch_invert(&over), Err(AltBn128BatchError::CapExceeded));
    }

    #[test]
    fn test_batch_invert_rejects_noncanonical() {
        let mut rng = rng();
        let good = fr_bytes(&Fr::rand(&mut rng));
        for slot in [0usize, 1] {
            let mut a = [good, good].concat();
            a[slot * SCALAR_BYTES..(slot + 1) * SCALAR_BYTES].copy_from_slice(&[0xffu8; 32]);
            assert_eq!(batch_invert(&a), Err(AltBn128BatchError::NonCanonical));
        }
    }

    #[test]
    fn test_two_chain_invert_matches_library_bytes() {
        // the two-chain core only re-associates exact field products, so its
        // bytes must equal the library path's; sizes cover both dispatch
        // boundaries, both n mod 2 parities, and the large-band entry
        let mut rng = rng();
        for n in [2usize, 3, 15, 16, 17, 63, 64, 65, 127, 256] {
            let input: Vec<Fr> = (0..n)
                .map(|_| Fr::new_unchecked(Fr::rand(&mut rng).into_bigint()))
                .collect();
            let coeff = Fr::new_unchecked(BigInt::one());
            let mut library = input.clone();
            batch_inversion_and_mul(&mut library, &coeff);
            let mut two = input;
            batch_invert_two_chains(&mut two, &coeff).unwrap();
            for (i, (want, got)) in library.iter().zip(&two).enumerate() {
                assert_eq!(
                    want.into_bigint(),
                    got.into_bigint(),
                    "byte mismatch at n = {n}, index = {i}"
                );
            }
        }
    }

    #[test]
    fn test_two_chain_invert_rejects_short_input() {
        let coeff = Fr::one();
        let mut value = [Fr::one()];
        assert_eq!(
            batch_invert_two_chains(&mut value, &coeff),
            Err(AltBn128BatchError::BackendInvariant)
        );
    }

    #[test]
    fn test_fr_total_on_random_bytes_and_deterministic() {
        let mut rng = rng();
        for _ in 0..2_000 {
            let n = rng.gen_range(1..8usize);
            let mut a = vec![0u8; n * SCALAR_BYTES];
            let mut b = vec![0u8; n * SCALAR_BYTES];
            rng.fill(&mut a[..]);
            rng.fill(&mut b[..]);
            // must never panic; determinism holds for both success and error
            assert_eq!(lincomb(&a, &b), lincomb(&a, &b));
            assert_eq!(batch_invert(&a), batch_invert(&a));
        }
    }

    #[test]
    fn test_lincomb_zero_vector_is_zero() {
        let zeros = vec![0u8; 4 * SCALAR_BYTES];
        let mut rng = rng();
        let b = concat(&(0..4).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>());
        assert_eq!(lincomb(&zeros, &b).unwrap(), fr_bytes(&Fr::zero()));
        // one is the multiplicative identity: <ones, b> == sum b
        let ones = concat(&[Fr::one(); 4]);
        let expected: Fr = bytemuck::cast_slice::<u8, PodScalar>(&b)
            .iter()
            .map(|s| s.to_fr().unwrap())
            .sum();
        assert_eq!(lincomb(&ones, &b).unwrap(), fr_bytes(&expected));
    }
}
