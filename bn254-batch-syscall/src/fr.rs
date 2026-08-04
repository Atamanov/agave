use {
    crate::{
        Version,
        encoding::FR_MAX_ELEMS,
        pod::PodScalar,
        validation::{AltBn128BatchError, validate_equal_lengths},
    },
    ark_bn254::Fr,
    ark_ff::{Field, Zero, batch_inversion},
};

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
    validate_equal_lengths(a.len(), b.len())?;
    if a.is_empty() {
        return Err(AltBn128BatchError::ZeroInput);
    }
    if a.len() > FR_MAX_ELEMS {
        return Err(AltBn128BatchError::CapExceeded);
    }

    // arkworks' delayed-reduction inner product. Fixed 16-wide chunks match the
    // sum_of_products array API; a[i] then b[i] decode in order, so the first
    // non-canonical element faults at the same position as the naive path.
    let mut acc = Fr::zero();
    for (a, b) in a.chunks(16).zip(b.chunks(16)) {
        let mut xs = [Fr::zero(); 16];
        let mut ys = [Fr::zero(); 16];
        for ((x_out, y_out), (x, y)) in xs.iter_mut().zip(&mut ys).zip(a.iter().zip(b)) {
            *x_out = x.to_fr()?;
            *y_out = y.to_fr()?;
        }
        acc = core::ops::Add::add(acc, Fr::sum_of_products(&xs, &ys));
    }
    Ok(PodScalar::from(&acc))
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
        let fr = s.to_fr()?;
        if fr.is_zero() {
            // zero never reaches batch_inversion, which would otherwise leave it
            // as zero and silently return a wrong "inverse"
            return Err(AltBn128BatchError::ZeroInput);
        }
        scalars.push(fr);
    }
    batch_inversion(&mut scalars);
    Ok(scalars.iter().map(PodScalar::from).collect())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encoding::SCALAR_BYTES,
            test_utils::{be_add_one, fr_bytes, fr_modulus_be, rng},
        },
        ark_ff::{Field, One, UniformRand},
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
