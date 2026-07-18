//! Fr batch ops over raw Montgomery residues.
//!
//! Both ops skip the to-Montgomery conversion of a full parse: the canonical
//! wire bigint is taken directly as an element's stored limbs, making its
//! field value a*R^-1. That residue map is linear and multiplicative in the
//! right places, so one constant correction per call (R^2 for the lincomb
//! sum, R^-1 folded into the inversion coefficient) restores the true
//! result, and the parse phase drops from ~75% of lincomb to near zero
//! (measured -81% lincomb, -40% batch invert).

use {
    crate::{
        Version,
        encoding::{FR_MAX_ELEMS, bigint_from_be},
        pod::PodScalar,
        validation::AltBn128BatchError,
    },
    ark_bn254::{Fr, FrConfig},
    ark_ff::{BigInt, BigInteger, Field, MontConfig, PrimeField, Zero, batch_inversion_and_mul},
};

/// Stack-chunk width for `sum_of_products`: measurement chose 16 over 8 at
/// n = 2048, re-confirmed at the plonk lincomb@16 cell.
const SOP_CHUNK: usize = 16;

/// Smallest n routed to the two-chain inversion core at large sizes:
/// the two-chain path measured faster than the library path from 64 up.
const CHAIN_SPLIT_MIN: usize = 64;

/// Small band also routed to the two-chain core: measured at the invert@8
/// cell; the unmeasured 17..=63 keeps the library path.
const CHAIN_SPLIT_SMALL_MIN: usize = 2;
const CHAIN_SPLIT_SMALL_MAX: usize = 16;

/// Canonical wire scalar reinterpreted as Montgomery limbs, giving the field
/// value a*R^-1. Sound because the canonical (< r) rejection runs first,
/// exactly the check `parse_fr` performs; `new_unchecked` then only skips
/// that re-validation, never a reduction.
fn parse_raw_residue(s: &PodScalar) -> Result<Fr, AltBn128BatchError> {
    let raw = bigint_from_be(&s.0);
    if raw >= Fr::MODULUS {
        return Err(AltBn128BatchError::NonCanonical);
    }
    Ok(Fr::new_unchecked(raw))
}

/// Inner product over the BN254 scalar field: `sum_i a[i] * b[i] mod q`.
///
/// Reduces once at the end. Delayed reduction is a valid faster host path; only
/// the canonical result is consensus-pinned, so an implementation may sum the
/// double-width products and reduce in one pass. Arrays must be equal length,
/// at most `FR_MAX_ELEMS` each; empty is an error. Element width is fixed by the
/// pod type, so a malformed byte length faults at the syscall boundary, not here.
/// `a` and `b` may alias.
pub fn alt_bn128_fr_lincomb(
    _version: Version,
    a: &[PodScalar],
    b: &[PodScalar],
) -> Result<PodScalar, AltBn128BatchError> {
    if a.len() != b.len() {
        return Err(AltBn128BatchError::LengthMismatch);
    }
    if a.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if a.len() > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    // residues multiply to S*R^-2 term by term; the map is linear, so one
    // final mul by the field value R^2 restores S
    let acc = lincomb_acc::<SOP_CHUNK>(a, b)?;
    let r_squared =
        Fr::from_bigint(<FrConfig as MontConfig<4>>::R2).expect("R^2 mod q is canonical");
    Ok(PodScalar::from(&(acc * r_squared)))
}

/// Raw-residue accumulation via `sum_of_products` in C-wide stack chunks.
/// Elements are consumed and validated strictly in input order for every C
/// (the inner while breaks on exhaustion, not on chunk boundaries), so the
/// first non-canonical element raises `NonCanonical` at the same position
/// regardless of C, and chunking only re-associates the exact modular sum.
fn lincomb_acc<const C: usize>(a: &[PodScalar], b: &[PodScalar]) -> Result<Fr, AltBn128BatchError> {
    let mut acc = Fr::zero();
    let mut ai = a.iter();
    let mut bi = b.iter();
    loop {
        let mut xs = [Fr::zero(); C];
        let mut ys = [Fr::zero(); C];
        let mut k = 0;
        while k < C {
            let (Some(x), Some(y)) = (ai.next(), bi.next()) else {
                break;
            };
            xs[k] = parse_raw_residue(x)?;
            ys[k] = parse_raw_residue(y)?;
            k += 1;
        }
        if k == 0 {
            break;
        }
        acc += Fr::sum_of_products(&xs, &ys);
    }
    Ok(acc)
}

/// Batch inverse over the BN254 scalar field via Montgomery's trick:
/// `out[i] = a[i]^-1 mod q`, one field inversion and 3(n-1) muls for n inputs.
///
/// Every element must be nonzero (the inverse of zero is undefined) and
/// canonical; at most `FR_MAX_ELEMS`; empty is an error. Every element is parsed
/// and checked before any inversion, so the output is written only when the
/// whole input is valid.
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
    // raw limbs 1 have field value R^-1: an element's value a*R^-1 inverts
    // to a^-1*R, and this coefficient cancels the extra R in the same pass
    let coeff = Fr::new_unchecked(BigInt::one());
    let n = scalars.len();
    if n >= CHAIN_SPLIT_MIN || (CHAIN_SPLIT_SMALL_MIN..=CHAIN_SPLIT_SMALL_MAX).contains(&n) {
        batch_invert_two_chains(&mut scalars, &coeff);
    } else {
        batch_inversion_and_mul(&mut scalars, &coeff);
    }
    Ok(scalars.iter().map(PodScalar::from).collect())
}

/// Batch inversion over TWO interleaved Montgomery mul chains with exactly
/// ONE field inversion (two chains fill the mul
/// pipeline's ILP headroom where the library's single prefix chain is
/// latency-bound, and four chains only added register pressure).
///
/// The slice splits into contiguous halves A = v[..half], B = v[half..]
/// with half = n - n/2 (A takes the odd extra element). The forward loop
/// advances two prefix-product accumulators; then T = C_A * C_B is inverted
/// once, C_A^-1 = T^-1 * C_B and C_B^-1 = T^-1 * C_A; the backward loop
/// unwinds both chains, seeded with C^-1 * coeff so every element receives
/// coeff exactly once (the library semantics). Field arithmetic is exact,
/// so re-associating the products cannot change a byte (unit-checked).
/// Requires nonzero elements and len >= 2 (dispatch guarantees both).
fn batch_invert_two_chains(v: &mut [Fr], coeff: &Fr) {
    let n = v.len();
    let half = n - n / 2;
    let len_b = n / 2;
    let mut prefix = vec![Fr::zero(); n];
    let mut run_a = v[0];
    let mut run_b = v[half];
    prefix[0] = run_a;
    prefix[half] = run_b;
    for i in 1..len_b {
        run_a *= v[i];
        prefix[i] = run_a;
        run_b *= v[half + i];
        prefix[half + i] = run_b;
    }
    if half > len_b {
        run_a *= v[half - 1];
        prefix[half - 1] = run_a;
    }
    let tinv = (run_a * run_b).inverse().expect("zeros rejected at parse");
    let mut inv_a = tinv * run_b * coeff;
    let mut inv_b = tinv * run_a * coeff;
    for j in 0..len_b {
        let ia = half - 1 - j;
        if ia == 0 {
            v[ia] = inv_a;
        } else {
            let next_a = inv_a * v[ia];
            v[ia] = inv_a * prefix[ia - 1];
            inv_a = next_a;
        }
        let ib = n - 1 - j;
        if ib == half {
            v[ib] = inv_b;
        } else {
            let next_b = inv_b * v[ib];
            v[ib] = inv_b * prefix[ib - 1];
            inv_b = next_b;
        }
    }
    if half > len_b {
        // odd n: chain A holds one more element than B, its head unwinds here
        v[0] = inv_a;
    }
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
            batch_invert_two_chains(&mut two, &coeff);
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
