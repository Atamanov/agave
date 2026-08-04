pub mod agave_fixtures;

use agave_fixtures::{
    fq_modulus, fr_modulus, g1_generator, g1_off_curve, g2_non_subgroup, g2_off_curve, pair, scalar,
};
use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq12 as ArkFq12, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM, pairing::Pairing};
use ark_ff::{BigInteger, Field, One, PrimeField, UniformRand, Zero};
use helius_bn254::{
    FR_MAX_ELEMS, G1Bytes, G2Bytes, GtBytes, InputError, MSM_MAX_POINTS, PAIRING_MAP_MAX_PAIRS,
    PAIRING_MAX_PAIRS, PairBytes, ScalarBytes, TRUSTED_GT_MAX_TARGETS, TrustedGt, fr_batch_invert,
    fr_lincomb, g1_msm, pairing_map, pairing_product_is_one, trusted_gt_multiexp,
};
use rand::{SeedableRng, rngs::StdRng};

const SEED: u64 = 0x0a17_b428_2540_0005;

fn rng() -> StdRng {
    StdRng::seed_from_u64(SEED)
}

fn ark_fr_nonzero(rng: &mut StdRng) -> ArkFr {
    loop {
        let value = ArkFr::rand(rng);
        if !value.is_zero() {
            return value;
        }
    }
}

fn ark_g1(rng: &mut StdRng) -> ArkG1Affine {
    (ArkG1Projective::generator() * ark_fr_nonzero(rng)).into_affine()
}

fn ark_g2(rng: &mut StdRng) -> ArkG2Affine {
    (ArkG2Projective::generator() * ark_fr_nonzero(rng)).into_affine()
}

fn copy_big_endian<const N: usize>(bytes: Vec<u8>) -> [u8; N] {
    assert!(bytes.len() <= N);
    let mut out = [0u8; N];
    out[N - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn fq_be(value: &ArkFq) -> [u8; 32] {
    copy_big_endian(value.into_bigint().to_bytes_be())
}

fn scalar_be(value: &ArkFr) -> ScalarBytes {
    ScalarBytes(copy_big_endian(value.into_bigint().to_bytes_be()))
}

fn g1_be(point: &ArkG1Affine) -> G1Bytes {
    let mut out = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        out[..32].copy_from_slice(&fq_be(&x));
        out[32..].copy_from_slice(&fq_be(&y));
    }
    G1Bytes(out)
}

fn g2_be(point: &ArkG2Affine) -> G2Bytes {
    let mut out = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        // EIP-197 orders each Fq2 value imaginary component first.
        out[..32].copy_from_slice(&fq_be(&x.c1));
        out[32..64].copy_from_slice(&fq_be(&x.c0));
        out[64..96].copy_from_slice(&fq_be(&y.c1));
        out[96..].copy_from_slice(&fq_be(&y.c0));
    }
    G2Bytes(out)
}

fn fq12_be(value: &ArkFq12) -> GtBytes {
    let coefficients = [
        value.c0.c0.c0,
        value.c0.c0.c1,
        value.c0.c1.c0,
        value.c0.c1.c1,
        value.c0.c2.c0,
        value.c0.c2.c1,
        value.c1.c0.c0,
        value.c1.c0.c1,
        value.c1.c1.c0,
        value.c1.c1.c1,
        value.c1.c2.c0,
        value.c1.c2.c1,
    ];
    let mut output = [0u8; 384];
    for (slot, coefficient) in output.chunks_exact_mut(32).zip(coefficients) {
        slot.copy_from_slice(&fq_be(&coefficient));
    }
    GtBytes(output)
}

fn ark_fq_from_be(bytes: &[u8]) -> ArkFq {
    let value = ArkFq::from_be_bytes_mod_order(bytes);
    assert_eq!(fq_be(&value), bytes, "fixture must be canonical");
    value
}

fn ark_g2_from_be(bytes: G2Bytes) -> ArkG2Affine {
    if bytes.0 == [0; 128] {
        return ArkG2Affine::zero();
    }
    let x1 = ark_fq_from_be(&bytes.0[0..32]);
    let x0 = ark_fq_from_be(&bytes.0[32..64]);
    let y1 = ark_fq_from_be(&bytes.0[64..96]);
    let y0 = ark_fq_from_be(&bytes.0[96..128]);
    ArkG2Affine::new_unchecked(ArkFq2::new(x0, x1), ArkFq2::new(y0, y1))
}

#[test]
fn fr_batch_operations_match_arkworks() {
    let mut rng = rng();
    for n in [1usize, 2, 17, 64] {
        let a: Vec<_> = (0..n).map(|_| ark_fr_nonzero(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| ArkFr::rand(&mut rng)).collect();
        let a_bytes: Vec<_> = a.iter().map(scalar_be).collect();
        let b_bytes: Vec<_> = b.iter().map(scalar_be).collect();

        let expected_lincomb: ArkFr = a.iter().zip(&b).map(|(x, y)| *x * y).sum();
        assert_eq!(
            fr_lincomb(&a_bytes, &b_bytes),
            Ok(scalar_be(&expected_lincomb)),
            "lincomb n={n}"
        );

        let expected_inverses: Vec<_> = a
            .iter()
            .map(|value| scalar_be(&value.inverse().expect("nonzero fixture")))
            .collect();
        assert_eq!(
            fr_batch_invert(&a_bytes),
            Ok(expected_inverses),
            "batch inversion n={n}"
        );
    }
}

#[test]
fn scalar_big_endian_round_trips_match_arkworks() {
    let mut rng = rng();
    let edge_values = [ArkFr::zero(), ArkFr::one(), -ArkFr::one()];
    for value in edge_values
        .into_iter()
        .chain((0..32).map(|_| ArkFr::rand(&mut rng)))
    {
        let encoded = scalar_be(&value);
        assert_eq!(ScalarBytes::from_fr(encoded.to_fr().unwrap()), encoded);
    }
}

#[test]
fn g1_msm_matches_arkworks_across_window_boundaries() {
    let mut rng = rng();
    let point_pool: Vec<_> = (0..64).map(|_| ark_g1(&mut rng)).collect();
    let mut half_modulus = ArkFr::MODULUS;
    half_modulus.div2();
    let half_modulus = ArkFr::from_bigint(half_modulus).unwrap();
    let edge_scalars = [ArkFr::zero(), ArkFr::one(), -ArkFr::one(), half_modulus];

    // Exercise both sides of every tiny/GLV-Pippenger dispatch and window
    // boundary, including the full Agave cap. Repeating r-1 and half-modulus
    // values stresses signed decomposition and terminal carries.
    for n in [
        1usize, 8, 9, 47, 48, 95, 96, 191, 192, 383, 384, 1535, 1536, 2048,
    ] {
        let points: Vec<_> = point_pool.iter().copied().cycle().take(n).collect();
        let scalars: Vec<_> = (0..n)
            .map(|index| {
                if index % 5 < edge_scalars.len() {
                    edge_scalars[index % 5]
                } else {
                    ArkFr::rand(&mut rng)
                }
            })
            .collect();
        let point_bytes: Vec<_> = points.iter().map(g1_be).collect();
        let scalar_bytes: Vec<_> = scalars.iter().map(scalar_be).collect();

        let expected = ArkG1Projective::msm_unchecked(&points, &scalars).into_affine();
        assert_eq!(
            g1_msm(&point_bytes, &scalar_bytes),
            Ok(g1_be(&expected)),
            "MSM n={n}"
        );
    }
}

#[test]
fn public_point_encodings_match_arkworks() {
    let mut rng = rng();
    for _ in 0..16 {
        let g1 = g1_be(&ark_g1(&mut rng));
        assert_eq!(g1_msm(&[g1], &[scalar(1)]), Ok(g1));
        assert_eq!(G1Bytes::from_affine(&g1.to_affine().unwrap()), g1);

        let g2 = g2_be(&ark_g2(&mut rng));
        assert_eq!(G2Bytes::from_affine(&g2.to_affine().unwrap()), g2);
    }
    assert_eq!(g1_be(&ArkG1Affine::zero()), G1Bytes([0; 64]));
    assert_eq!(g2_be(&ArkG2Affine::zero()), G2Bytes([0; 128]));
}

#[test]
fn pairing_products_match_arkworks() {
    let mut rng = rng();
    // n >= 8 crosses the AVX-512 IFMA 8-wide dispatch threshold in
    // pairing_product_is_one, so on an IFMA build this gates the batched path
    // against arkworks; on a scalar build it gates multi_pairing.
    for n in [1usize, 2, 4, 7, 8, 9, 16, 18, 53] {
        let g1: Vec<_> = (0..n).map(|_| ark_g1(&mut rng)).collect();
        let g2: Vec<_> = (0..n).map(|_| ark_g2(&mut rng)).collect();
        let pairs: Vec<_> = g1
            .iter()
            .zip(&g2)
            .map(|(p, q)| PairBytes {
                g1: g1_be(p),
                g2: g2_be(q),
            })
            .collect();
        let expected = Bn254::multi_pairing(g1.iter().copied(), g2.iter().copied()).0;
        assert_eq!(
            pairing_product_is_one(&pairs),
            Ok(expected == ArkFq12::one()),
            "n={n}"
        );
        if n <= PAIRING_MAP_MAX_PAIRS {
            assert_eq!(
                pairing_map(&pairs),
                Ok(fq12_be(&expected)),
                "GT bytes n={n}"
            );
        } else {
            assert_eq!(pairing_map(&pairs), Err(InputError::CapExceeded), "n={n}");
        }
    }

    // Independent bilinear identity: e([a]P,Q) * e(-P,[a]Q) = 1.
    let scalar = ark_fr_nonzero(&mut rng);
    let p = ArkG1Projective::generator() * ark_fr_nonzero(&mut rng);
    let q = ArkG2Projective::generator() * ark_fr_nonzero(&mut rng);
    let identity = [
        PairBytes {
            g1: g1_be(&(p * scalar).into_affine()),
            g2: g2_be(&q.into_affine()),
        },
        PairBytes {
            g1: g1_be(&(-p).into_affine()),
            g2: g2_be(&(q * scalar).into_affine()),
        },
    ];
    assert_eq!(pairing_product_is_one(&identity), Ok(true));
    assert_eq!(
        pairing_map(&identity).map(|value| value.is_identity()),
        Ok(true)
    );
}

#[test]
fn pairing_map_has_a_fixed_canonical_generator_vector() {
    let p = ArkG1Affine::generator();
    let q = ArkG2Affine::generator();
    let pair = PairBytes {
        g1: g1_be(&p),
        g2: g2_be(&q),
    };
    let expected: [u8; 384] = hex::decode(concat!(
        "262b253feda94cfe0da01bde280a3ed6f87e5feb898578b55e1f63739d870e95",
        "02e02d2cc795a2000a1b1f823879abbd397c4dea0918ed66b49d34b48efb8a4a",
        "13a9f2d6e29b128da5b1ad44b31977935fd2957387ecb1fc4e135402fdbd1de0",
        "040ba9fa500f1a5c4b31984a74e68659c4b420bd699ce630b130b08a6ea1162b",
        "0afc2f3fd870678fbe359d7f9873f052478f590b211ce30bf5e3eeaef89eafdb",
        "1c54a530398c9064bdc662d929e645cadda9a712cc5a8243f9cddbd2d98dd1f0",
        "095c0fbf5d5a1ac023794a0d856f92591ba990ecfd4b7aef5c0d58c5dc2429fe",
        "14d3d6ca72d8a950a31dc10f7b4053c9e9ad9ebb590cb4a60f8215d4b99f2b4a",
        "1dc0e7bbc3d70e6689dc206b4b91c85759dc1a23043c585fdfaf545838ca7429",
        "0b53320e5a6488cb98a855ffc837d2a75ab90d61ac16cc1b7ab2cd3ed5e22b97",
        "13a8afd3085dae4c6c91476ef36cd1d318ce07bac42a9c0f9bd7fddaf5ebd723",
        "00f97b5221474526b601f3730a3afa965ceee1b343940c383e5314859e762c97"
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let actual = pairing_map(&[pair]).expect("generator pair is valid");
    assert_eq!(actual, GtBytes(expected));
    assert_eq!(actual, fq12_be(&Bn254::pairing(p, q).0));
    assert!(!actual.is_identity());
}

#[test]
fn trusted_gt_multiexp_matches_ark_and_pairing_map() {
    let mut rng = rng();

    assert_eq!(
        trusted_gt_multiexp(&[], &[]).map(|value| value.is_identity()),
        Ok(true)
    );

    let edge_p = ark_g1(&mut rng);
    let edge_q = ark_g2(&mut rng);
    let edge_pair = PairBytes {
        g1: g1_be(&edge_p),
        g2: g2_be(&edge_q),
    };
    let edge_target = TrustedGt::from_pair(&edge_pair).unwrap();
    for exponent in [ArkFr::zero(), ArkFr::one(), -ArkFr::one()] {
        let dynamic = PairBytes {
            g1: g1_be(&(edge_p * exponent).into_affine()),
            g2: g2_be(&edge_q),
        };
        assert_eq!(
            pairing_map(&[dynamic]),
            trusted_gt_multiexp(core::slice::from_ref(&edge_target), &[scalar_be(&exponent)]),
            "canonical GT edge exponent {exponent}"
        );
    }
    for bit in [63usize, 64, 127, 128, 191, 192, 252, 253] {
        let mut limbs = [0u64; 4];
        limbs[bit / 64] = 1u64 << (bit % 64);
        let exponent = ArkFr::from_bigint(ark_ff::BigInt::new(limbs)).unwrap();
        let dynamic = PairBytes {
            g1: g1_be(&(edge_p * exponent).into_affine()),
            g2: g2_be(&edge_q),
        };
        assert_eq!(
            pairing_map(&[dynamic]),
            trusted_gt_multiexp(core::slice::from_ref(&edge_target), &[scalar_be(&exponent)]),
            "canonical GT single bit {bit}"
        );
    }

    for target_count in [1usize, 2, 3] {
        let mut targets = Vec::with_capacity(target_count);
        let mut exponents = Vec::with_capacity(target_count);
        let mut dynamic = Vec::with_capacity(target_count);
        let mut ark_expected = ArkFq12::one();

        for _ in 0..target_count {
            let p = ark_g1(&mut rng);
            let q = ark_g2(&mut rng);
            let exponent = ark_fr_nonzero(&mut rng);
            let target_pair = PairBytes {
                g1: g1_be(&p),
                g2: g2_be(&q),
            };
            targets.push(TrustedGt::from_pair(&target_pair).unwrap());
            exponents.push(scalar_be(&exponent));
            dynamic.push(PairBytes {
                g1: g1_be(&(p * exponent).into_affine()),
                g2: g2_be(&q),
            });
            ark_expected *= Bn254::pairing(p, q).0.pow(exponent.into_bigint());
        }

        let dynamic_gt = pairing_map(&dynamic);
        assert_eq!(dynamic_gt, Ok(fq12_be(&ark_expected)));
        assert_eq!(dynamic_gt, trusted_gt_multiexp(&targets, &exponents));
    }

    // A different, perfectly valid subgroup target must not be substitutable.
    let p = ark_g1(&mut rng);
    let q = ark_g2(&mut rng);
    let exponent = ark_fr_nonzero(&mut rng);
    let dynamic = PairBytes {
        g1: g1_be(&(p * exponent).into_affine()),
        g2: g2_be(&q),
    };
    let wrong = PairBytes {
        g1: g1_be(&ark_g1(&mut rng)),
        g2: g2_be(&ark_g2(&mut rng)),
    };
    let wrong_target = TrustedGt::from_pair(&wrong).unwrap();
    assert_ne!(
        pairing_map(&[dynamic]).unwrap(),
        trusted_gt_multiexp(
            core::slice::from_ref(&wrong_target),
            &[scalar_be(&exponent)]
        )
        .unwrap()
    );
}

#[test]
fn trusted_gt_multiexp_pins_shape_and_validation() {
    let valid_pair = pair(g1_generator(), G2Bytes([0; 128]));
    let trusted = TrustedGt::from_pair(&valid_pair).unwrap();
    assert_eq!(
        trusted_gt_multiexp(core::slice::from_ref(&trusted), &[]),
        Err(InputError::LengthMismatch)
    );
    assert_eq!(
        trusted_gt_multiexp(core::slice::from_ref(&trusted), &[ScalarBytes([0xff; 32])]),
        Err(InputError::NonCanonical)
    );
    assert_eq!(
        trusted_gt_multiexp(
            &vec![trusted.clone(); TRUSTED_GT_MAX_TARGETS + 1],
            &vec![scalar(0); TRUSTED_GT_MAX_TARGETS + 1],
        ),
        Err(InputError::CapExceeded)
    );

    let malformed = pair(g1_off_curve(), G2Bytes([0; 128]));
    assert!(matches!(
        TrustedGt::from_pair(&malformed),
        Err(InputError::NotOnCurve)
    ));
}

#[test]
fn g2_subgroup_and_curve_boundaries_agree_with_arkworks() {
    let non_subgroup_bytes = g2_non_subgroup();
    let non_subgroup = ark_g2_from_be(non_subgroup_bytes);
    assert!(non_subgroup.is_on_curve());
    assert!(!non_subgroup.is_in_correct_subgroup_assuming_on_curve());
    assert_eq!(
        non_subgroup_bytes.to_affine(),
        Err(InputError::NotInSubgroup)
    );

    let off_curve_bytes = g2_off_curve();
    let off_curve = ark_g2_from_be(off_curve_bytes);
    assert!(!off_curve.is_on_curve());
    assert_eq!(off_curve_bytes.to_affine(), Err(InputError::NotOnCurve));
}

#[test]
fn malformed_and_batch_boundaries_match_the_reference_contract() {
    assert!(ArkFr::from_bigint(ArkFr::MODULUS).is_none());
    assert!(ArkFq::from_bigint(ArkFq::MODULUS).is_none());
    assert_eq!(
        fr_lincomb(&[fr_modulus()], &[scalar(1)]),
        Err(InputError::NonCanonical)
    );

    let mut noncanonical_g1 = g1_generator();
    noncanonical_g1.0[..32].copy_from_slice(&fq_modulus());
    assert_eq!(
        g1_msm(&[noncanonical_g1], &[scalar(1)]),
        Err(InputError::NonCanonical)
    );
    assert_eq!(
        g1_msm(&[g1_off_curve()], &[fr_modulus()]),
        Err(InputError::NotOnCurve),
        "points must be validated before scalars"
    );

    assert_eq!(g1_msm(&[], &[scalar(1)]), Err(InputError::LengthMismatch));
    assert_eq!(fr_lincomb(&[], &[]), Err(InputError::ZeroInput));
    assert_eq!(fr_batch_invert(&[scalar(0)]), Err(InputError::ZeroInput));
    assert_eq!(pairing_product_is_one(&[]), Err(InputError::ZeroInput));

    assert_eq!(
        g1_msm(
            &vec![G1Bytes([0; 64]); MSM_MAX_POINTS + 1],
            &vec![scalar(0); MSM_MAX_POINTS + 1],
        ),
        Err(InputError::CapExceeded)
    );
    assert_eq!(
        fr_lincomb(
            &vec![scalar(0); FR_MAX_ELEMS + 1],
            &vec![scalar(0); FR_MAX_ELEMS + 1],
        ),
        Err(InputError::CapExceeded)
    );
    assert_eq!(
        pairing_product_is_one(&vec![
            pair(G1Bytes([0; 64]), G2Bytes([0; 128]));
            PAIRING_MAX_PAIRS + 1
        ]),
        Err(InputError::CapExceeded)
    );
}
