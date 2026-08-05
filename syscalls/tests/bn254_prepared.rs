#![cfg(all(
    feature = "agave-unstable-api",
    any(feature = "backend-b4-helius", feature = "backend-b5-helius-ifma"),
    not(feature = "backend-b1-arkworks"),
    not(feature = "backend-b2-arkworks-optimized"),
    not(feature = "backend-b3-mcl")
))]

use {
    ark_bn254::{Fr, G1Affine, G2Affine},
    ark_ec::{AffineRepr, CurveGroup},
    ark_ff::{BigInteger, PrimeField, UniformRand},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    solana_bn254_batch_syscall::{
        AltBn128BatchError, PodG1G2Pair, PodG1Point, PodG2Point, Version, alt_bn128_pairing_check,
        alt_bn128_pairing_map,
    },
    solana_syscalls::bn254_prepared::{
        MAX_PREPARED_PAIRS, PREPARED_G2_WIRE_BYTES, g2_prepare_wire, pairing_check_prepared_blobs,
        pairing_map_prepared_blobs, prepared_blob_header,
    },
    std::ops::Mul,
};

fn fq(value: &ark_bn254::Fq) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let offset = 32usize.checked_sub(bytes.len()).unwrap();
    out[offset..].copy_from_slice(&bytes);
    out
}

fn g1(point: G1Affine) -> PodG1Point {
    if point.is_zero() {
        return PodG1Point([0; 64]);
    }
    let (x, y) = point.xy().unwrap();
    let mut out = [0; 64];
    out[..32].copy_from_slice(&fq(&x));
    out[32..].copy_from_slice(&fq(&y));
    PodG1Point(out)
}

fn g2(point: G2Affine) -> PodG2Point {
    let (x, y) = point.xy().unwrap();
    let mut out = [0; 128];
    out[..32].copy_from_slice(&fq(&x.c1));
    out[32..64].copy_from_slice(&fq(&x.c0));
    out[64..96].copy_from_slice(&fq(&y.c1));
    out[96..].copy_from_slice(&fq(&y.c0));
    PodG2Point(out)
}

fn rng() -> StdRng {
    StdRng::seed_from_u64(0x9d2f31)
}

fn random_pair(rng: &mut StdRng) -> PodG1G2Pair {
    PodG1G2Pair {
        g1: g1(G1Affine::generator().mul(Fr::rand(rng)).into_affine()),
        g2: g2(G2Affine::generator().mul(Fr::rand(rng)).into_affine()),
    }
}

#[test]
fn prepared_blobs_match_the_full_pairing_at_every_split() {
    let mut rng = rng();
    for total in 1usize..=9 {
        let pairs: Vec<PodG1G2Pair> = (0..total).map(|_| random_pair(&mut rng)).collect();
        let expected = alt_bn128_pairing_map(Version::V0, &pairs).unwrap();
        let blobs: Vec<Vec<u8>> = pairs
            .iter()
            .map(|pair| g2_prepare_wire(&pair.g2).unwrap())
            .collect();
        for split in 0..=total {
            let prepared: Vec<(PodG1Point, &[u8])> = pairs[split..]
                .iter()
                .zip(&blobs[split..])
                .map(|(pair, blob)| (pair.g1, blob.as_slice()))
                .collect();
            assert_eq!(
                pairing_map_prepared_blobs(&pairs[..split], &prepared).unwrap(),
                expected,
                "total {total} split {split}"
            );
            assert_eq!(
                pairing_check_prepared_blobs(&pairs[..split], &prepared, None).unwrap(),
                alt_bn128_pairing_check(Version::V0, &pairs).unwrap(),
            );
            assert!(
                pairing_check_prepared_blobs(&pairs[..split], &prepared, Some(&expected)).unwrap()
            );
        }
    }
}

/// The Groth16 shape with a cached target: `e(A,B) e(-L,gamma) e(-C,delta)`
/// must equal the stored `e(alpha,beta)`, with gamma and delta prepared.
#[test]
fn groth16_target_form_verifies_and_flips_on_a_wrong_input() {
    let mut rng = rng();
    let (x, y, z) = (Fr::rand(&mut rng), Fr::rand(&mut rng), Fr::rand(&mut rng));
    let alpha = G1Affine::generator().mul(z).into_affine();
    let beta = G2Affine::generator();
    let gamma = G2Affine::generator();
    let delta = G2Affine::generator();
    let l_pub = G1Affine::generator().mul(x).into_affine();
    let c = G1Affine::generator().mul(y).into_affine();
    let a = G1Affine::generator().mul(z + x + y).into_affine();
    let b = G2Affine::generator();

    let target = alt_bn128_pairing_map(
        Version::V0,
        &[PodG1G2Pair {
            g1: g1(alpha),
            g2: g2(beta),
        }],
    )
    .unwrap();

    let gamma_blob = g2_prepare_wire(&g2(gamma)).unwrap();
    let delta_blob = g2_prepare_wire(&g2(delta)).unwrap();
    let full = [PodG1G2Pair {
        g1: g1(a),
        g2: g2(b),
    }];
    let prepared = [
        (g1(-l_pub), gamma_blob.as_slice()),
        (g1(-c), delta_blob.as_slice()),
    ];
    assert!(pairing_check_prepared_blobs(&full, &prepared, Some(&target)).unwrap());

    // The identity form: also prepare beta and fold the target back in.
    let beta_blob = g2_prepare_wire(&g2(beta)).unwrap();
    let identity_full = [PodG1G2Pair {
        g1: g1(-a),
        g2: g2(b),
    }];
    let identity_prepared = [
        (g1(alpha), beta_blob.as_slice()),
        (g1(l_pub), gamma_blob.as_slice()),
        (g1(c), delta_blob.as_slice()),
    ];
    assert!(pairing_check_prepared_blobs(&identity_full, &identity_prepared, None).unwrap());

    // A wrong public input contributes a wrong exponent and must fail closed.
    let wrong = [
        (g1(-(l_pub.mul(Fr::from(2u64)).into_affine())), gamma_blob.as_slice()),
        (g1(-c), delta_blob.as_slice()),
    ];
    assert!(!pairing_check_prepared_blobs(&full, &wrong, Some(&target)).unwrap());
}

#[test]
fn hostile_blobs_and_shapes_fail_closed() {
    let mut rng = rng();
    let pair = random_pair(&mut rng);
    let blob = g2_prepare_wire(&pair.g2).unwrap();

    let mut bad_header = blob.clone();
    bad_header[6] ^= 1;
    assert_eq!(
        pairing_check_prepared_blobs(&[], &[(pair.g1, bad_header.as_slice())], None).unwrap_err(),
        AltBn128BatchError::InvalidPreparedBlob,
    );
    assert_eq!(
        pairing_check_prepared_blobs(&[], &[(pair.g1, &blob[..blob.len() - 1])], None)
            .unwrap_err(),
        AltBn128BatchError::InvalidPreparedBlob,
    );

    let mut noncanonical = blob.clone();
    noncanonical[8..40].fill(0xff);
    assert_eq!(
        pairing_check_prepared_blobs(&[], &[(pair.g1, noncanonical.as_slice())], None)
            .unwrap_err(),
        AltBn128BatchError::NonCanonical,
    );

    // A structurally valid but meaningless blob is not an error; it just
    // yields a deterministic non-identity verdict.
    let mut meaningless = vec![0u8; PREPARED_G2_WIRE_BYTES];
    meaningless[..8].copy_from_slice(&prepared_blob_header());
    assert!(
        !pairing_check_prepared_blobs(&[], &[(pair.g1, meaningless.as_slice())], None).unwrap()
    );

    assert_eq!(
        pairing_check_prepared_blobs(&[], &[], None).unwrap_err(),
        AltBn128BatchError::ZeroInput,
    );
    // The 16-prepared cap binds at the syscall boundary; the arithmetic layer
    // enforces the per-op totals.
    let overflow: Vec<(PodG1Point, &[u8])> = (0..MAX_PREPARED_PAIRS + 3)
        .map(|_| (pair.g1, blob.as_slice()))
        .collect();
    assert_eq!(
        pairing_map_prepared_blobs(&[], &overflow).unwrap_err(),
        AltBn128BatchError::CapExceeded,
    );

    assert_eq!(
        g2_prepare_wire(&PodG2Point([0u8; 128])).unwrap_err(),
        AltBn128BatchError::ZeroInput,
    );
}
