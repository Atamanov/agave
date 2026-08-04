use {
    super::b2,
    crate::{
        Version,
        encoding::{G1_BYTES, G2_BYTES, PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS, parse_g1},
        fr as b1_fr, msm as b1_msm, pairing as b1_pairing,
        pod::{PodG1G2Pair, PodG1Point, PodG2Point, PodScalar},
        test_utils::{
            fq_modulus_be, fr_bytes, g1_bytes, pair_bytes, random_g1, random_g2, rng,
            telescoping_pairs,
        },
        validation::AltBn128BatchError,
    },
    ark_bn254::{Fr, G1Projective},
    ark_ec::{CurveGroup, PrimeGroup},
    ark_ff::{BigInt, One, Zero},
    core::{
        fmt::Debug,
        ops::{Mul, Neg},
    },
};

#[cfg(feature = "backend-b3-mcl")]
use super::b3;

const DIFFERENTIAL_SIZES: [usize; 17] = [
    1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 63, 64, 65, 96, 256, 1024, 2048,
];

fn indexed_scalar(index: usize, offset: u64) -> Fr {
    let value = u64::try_from(index)
        .ok()
        .and_then(|index| index.checked_add(offset))
        .unwrap();
    Fr::from(value)
}

fn edge_scalars() -> [Fr; 5] {
    [
        Fr::zero(),
        Fr::one(),
        Fr::one().neg(),
        Fr::from(1u128 << 64),
        Fr::from(BigInt::new([0, 0, 1, 0])),
    ]
}

fn assert_same<T>(b1: Result<T, AltBn128BatchError>, b2: Result<T, AltBn128BatchError>, case: &str)
where
    T: Debug + PartialEq,
{
    assert_eq!(b2, b1, "{case}");
}

#[test]
fn fr_backends_match() {
    for n in DIFFERENTIAL_SIZES {
        let mut a: Vec<_> = (0..n).map(|index| indexed_scalar(index, 1)).collect();
        for (slot, edge) in a.iter_mut().zip(edge_scalars()) {
            *slot = edge;
        }
        let b: Vec<_> = (0..n).map(|index| indexed_scalar(index, 19)).collect();
        let a: Vec<_> = a.iter().map(|value| PodScalar(fr_bytes(value))).collect();
        let b: Vec<_> = b.iter().map(|value| PodScalar(fr_bytes(value))).collect();
        let invertible: Vec<_> = a
            .iter()
            .map(|value| {
                if *value == PodScalar(fr_bytes(&Fr::zero())) {
                    PodScalar(fr_bytes(&Fr::one()))
                } else {
                    *value
                }
            })
            .collect();

        assert_same(
            b1_fr::alt_bn128_fr_lincomb(Version::V0, &a, &b),
            b2::alt_bn128_fr_lincomb(Version::V0, &a, &b),
            &format!("Fr lincomb at {n}"),
        );
        assert_same(
            b1_fr::alt_bn128_fr_batch_invert(Version::V0, &invertible),
            b2::alt_bn128_fr_batch_invert(Version::V0, &invertible),
            &format!("Fr batch inverse at {n}"),
        );
    }

    let one = PodScalar(fr_bytes(&Fr::one()));
    let zero = PodScalar(fr_bytes(&Fr::zero()));
    assert_same(
        b1_fr::alt_bn128_fr_lincomb(Version::V0, &[one], &[]),
        b2::alt_bn128_fr_lincomb(Version::V0, &[one], &[]),
        "Fr length mismatch",
    );
    assert_same(
        b1_fr::alt_bn128_fr_batch_invert(Version::V0, &[zero]),
        b2::alt_bn128_fr_batch_invert(Version::V0, &[zero]),
        "Fr zero inverse",
    );
}

#[test]
fn msm_backends_match() {
    let generator = G1Projective::generator();
    for n in DIFFERENTIAL_SIZES {
        let mut points: Vec<_> = (0..n)
            .map(|index| {
                let point = generator.mul(indexed_scalar(index, 1)).into_affine();
                PodG1Point(g1_bytes(&point))
            })
            .collect();
        let mut scalars: Vec<_> = (0..n)
            .map(|index| PodScalar(fr_bytes(&indexed_scalar(index, 7))))
            .collect();
        for (slot, edge) in scalars.iter_mut().zip(edge_scalars()) {
            *slot = PodScalar(fr_bytes(&edge));
        }
        let middle = n.checked_div(2).unwrap();
        *points.get_mut(middle).unwrap() = PodG1Point([0u8; G1_BYTES]);

        assert_same(
            b1_msm::alt_bn128_g1_msm(Version::V0, &points, &scalars),
            b2::alt_bn128_g1_msm(Version::V0, &points, &scalars),
            &format!("G1 MSM at {n}"),
        );
    }

    let point = PodG1Point(g1_bytes(&generator.into_affine()));
    let scalar = PodScalar(fr_bytes(&Fr::one()));
    assert_same(
        b1_msm::alt_bn128_g1_msm(Version::V0, &[point], &[]),
        b2::alt_bn128_g1_msm(Version::V0, &[point], &[]),
        "MSM length mismatch",
    );
    assert_same(
        b1_msm::alt_bn128_g1_msm(Version::V0, &[], &[scalar]),
        b2::alt_bn128_g1_msm(Version::V0, &[], &[scalar]),
        "MSM empty mismatch",
    );
}

#[test]
fn pairing_backends_match() {
    let mut rng = rng();
    for n in [2usize, 3, 8, 16, 17, 18, 31, 32, 33, 256] {
        let bytes = telescoping_pairs(&mut rng, n);
        let pairs = bytemuck::cast_slice(&bytes);
        assert_same(
            b1_pairing::alt_bn128_pairing_check(Version::V0, pairs),
            b2::alt_bn128_pairing_check(Version::V0, pairs),
            &format!("pairing check at {n}"),
        );
        if n <= PAIRING_MAP_MAX_PAIRS {
            assert_same(
                b1_pairing::alt_bn128_pairing_map(Version::V0, pairs),
                b2::alt_bn128_pairing_map(Version::V0, pairs),
                &format!("pairing map at {n}"),
            );
        }

        let first = bytes
            .get(..G1_BYTES)
            .and_then(|bytes| parse_g1(bytes).ok())
            .unwrap();
        let mut flipped = bytes.clone();
        flipped
            .get_mut(..G1_BYTES)
            .unwrap()
            .copy_from_slice(&g1_bytes(&first.neg()));
        let flipped = bytemuck::cast_slice(&flipped);
        assert_same(
            b1_pairing::alt_bn128_pairing_check(Version::V0, flipped),
            b2::alt_bn128_pairing_check(Version::V0, flipped),
            &format!("flipped pairing check at {n}"),
        );
    }

    let false_pair = pair_bytes(&random_g1(&mut rng), &random_g2(&mut rng));
    let false_pairs = bytemuck::cast_slice(&false_pair);
    assert_same(
        b1_pairing::alt_bn128_pairing_check(Version::V0, false_pairs),
        b2::alt_bn128_pairing_check(Version::V0, false_pairs),
        "false pairing check",
    );
    assert_same(
        b1_pairing::alt_bn128_pairing_map(Version::V0, false_pairs),
        b2::alt_bn128_pairing_map(Version::V0, false_pairs),
        "false pairing map",
    );
}

#[test]
fn pairing_backend_errors_match() {
    let zero_pair = PodG1G2Pair {
        g1: PodG1Point([0u8; G1_BYTES]),
        g2: PodG2Point([0u8; G2_BYTES]),
    };
    let map_over_cap = vec![zero_pair; PAIRING_MAP_MAX_PAIRS + 1];
    assert_same(
        b1_pairing::alt_bn128_pairing_map(Version::V0, &map_over_cap),
        b2::alt_bn128_pairing_map(Version::V0, &map_over_cap),
        "pairing map cap",
    );

    let check_over_cap = vec![zero_pair; PAIRING_MAX_PAIRS + 1];
    assert_same(
        b1_pairing::alt_bn128_pairing_check(Version::V0, &check_over_cap),
        b2::alt_bn128_pairing_check(Version::V0, &check_over_cap),
        "pairing check cap",
    );
    assert_same(
        b1_pairing::alt_bn128_pairing_check(Version::V0, &[]),
        b2::alt_bn128_pairing_check(Version::V0, &[]),
        "empty pairing check",
    );

    let mut noncanonical = zero_pair;
    noncanonical.g1.0[..32].copy_from_slice(&fq_modulus_be());
    assert_same(
        b1_pairing::alt_bn128_pairing_check(Version::V0, &[noncanonical]),
        b2::alt_bn128_pairing_check(Version::V0, &[noncanonical]),
        "noncanonical pairing input",
    );
}

#[cfg(feature = "backend-b3-mcl")]
#[test]
fn mcl_backend_matches_the_reference_backend() {
    for n in [1usize, 2, 3, 17, 64, 65, 128] {
        let points: Vec<_> = (0..n)
            .map(|index| {
                PodG1Point(g1_bytes(
                    &G1Projective::generator()
                        .mul(indexed_scalar(index, 1))
                        .into_affine(),
                ))
            })
            .collect();
        let scalars: Vec<_> = (0..n)
            .map(|index| PodScalar(fr_bytes(&indexed_scalar(index, 7))))
            .collect();
        assert_same(
            b1_msm::alt_bn128_g1_msm(Version::V0, &points, &scalars),
            b3::alt_bn128_g1_msm(Version::V0, &points, &scalars),
            &format!("B3 G1 MSM at {n}"),
        );

        let left: Vec<_> = (0..n)
            .map(|index| PodScalar(fr_bytes(&indexed_scalar(index, 1))))
            .collect();
        let right: Vec<_> = (0..n)
            .map(|index| PodScalar(fr_bytes(&indexed_scalar(index, 19))))
            .collect();
        assert_same(
            b1_fr::alt_bn128_fr_lincomb(Version::V0, &left, &right),
            b3::alt_bn128_fr_lincomb(Version::V0, &left, &right),
            &format!("B3 Fr lincomb at {n}"),
        );
        assert_same(
            b1_fr::alt_bn128_fr_batch_invert(Version::V0, &left),
            b3::alt_bn128_fr_batch_invert(Version::V0, &left),
            &format!("B3 Fr inverse at {n}"),
        );
    }

    let mut rng = rng();
    for n in [2usize, 3, 8, 16, 18] {
        let bytes = telescoping_pairs(&mut rng, n);
        let pairs = bytemuck::cast_slice(&bytes);
        assert_same(
            b1_pairing::alt_bn128_pairing_map(Version::V0, pairs),
            b3::alt_bn128_pairing_map(Version::V0, pairs),
            &format!("B3 pairing map at {n}"),
        );
        assert_same(
            b1_pairing::alt_bn128_pairing_check(Version::V0, pairs),
            b3::alt_bn128_pairing_check(Version::V0, pairs),
            &format!("B3 pairing check at {n}"),
        );

        let capacity = n.checked_mul(crate::encoding::PAIR_BYTES).unwrap();
        let mut non_identity = Vec::with_capacity(capacity);
        for _ in 0..n {
            non_identity.extend_from_slice(&pair_bytes(&random_g1(&mut rng), &random_g2(&mut rng)));
        }
        let non_identity = bytemuck::cast_slice(&non_identity);
        assert_same(
            b1_pairing::alt_bn128_pairing_map(Version::V0, non_identity),
            b3::alt_bn128_pairing_map(Version::V0, non_identity),
            &format!("B3 non-identity pairing map at {n}"),
        );
    }

    let bytes = telescoping_pairs(&mut rng, PAIRING_MAX_PAIRS);
    let pairs = bytemuck::cast_slice(&bytes);
    assert_same(
        b1_pairing::alt_bn128_pairing_check(Version::V0, pairs),
        b3::alt_bn128_pairing_check(Version::V0, pairs),
        "B3 live pairing check at the cap",
    );

    let false_pair = pair_bytes(&random_g1(&mut rng), &random_g2(&mut rng));
    let false_pairs = bytemuck::cast_slice(&false_pair);
    assert_same(
        b1_pairing::alt_bn128_pairing_map(Version::V0, false_pairs),
        b3::alt_bn128_pairing_map(Version::V0, false_pairs),
        "B3 false pairing map",
    );
    assert_same(
        b1_pairing::alt_bn128_pairing_check(Version::V0, false_pairs),
        b3::alt_bn128_pairing_check(Version::V0, false_pairs),
        "B3 false pairing check",
    );

    let zero_pair = PodG1G2Pair {
        g1: PodG1Point([0u8; G1_BYTES]),
        g2: PodG2Point([0u8; G2_BYTES]),
    };
    let map_over_cap = vec![zero_pair; PAIRING_MAP_MAX_PAIRS + 1];
    assert_same(
        b1_pairing::alt_bn128_pairing_map(Version::V0, &map_over_cap),
        b3::alt_bn128_pairing_map(Version::V0, &map_over_cap),
        "B3 pairing map cap",
    );
    let check_over_cap = vec![zero_pair; PAIRING_MAX_PAIRS + 1];
    assert_same(
        b1_pairing::alt_bn128_pairing_check(Version::V0, &check_over_cap),
        b3::alt_bn128_pairing_check(Version::V0, &check_over_cap),
        "B3 pairing check cap",
    );
}
