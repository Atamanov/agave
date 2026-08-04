#![cfg(feature = "agave-unstable-api")]

use {
    ark_bn254::{Fq, Fq2, G1Affine, G2Affine},
    ark_ec::AffineRepr,
    ark_ff::{BigInteger, PrimeField},
    solana_bn254_batch_syscall::{
        PodG1G2Pair, PodG1Point, PodG2Point, Version, alt_bn128_pairing_check,
        alt_bn128_pairing_map, encode_final_exponentiation_result,
        prepare_final_exponentiation_probe, prepare_g2_subgroup_probe,
        run_final_exponentiation_probe, run_g2_subgroup_probe,
    },
};

#[cfg(feature = "research-observer")]
static OBSERVER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fq(value: &ark_bn254::Fq) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    let offset = 32usize.checked_sub(bytes.len()).unwrap();
    out[offset..].copy_from_slice(&bytes);
    out
}

fn g2(point: G2Affine) -> PodG2Point {
    let (x, y) = point.xy().unwrap();
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&fq(&x.c1));
    out[32..64].copy_from_slice(&fq(&x.c0));
    out[64..96].copy_from_slice(&fq(&y.c1));
    out[96..].copy_from_slice(&fq(&y.c0));
    PodG2Point(out)
}

#[cfg(feature = "research-observer")]
#[test]
fn ordered_pairing_observer_retains_repeated_current_calls() {
    use solana_bn254_batch_syscall::research_observer;

    let _observer_guard = OBSERVER_TEST_LOCK.lock().unwrap();
    let pair = pair();
    research_observer::reset();
    alt_bn128_pairing_check(Version::V0, &[pair]).unwrap();
    alt_bn128_pairing_check(Version::V0, &[pair, pair]).unwrap();
    for count in 1..=3 {
        alt_bn128_pairing_map(Version::V0, &vec![pair; count]).unwrap();
    }
    assert_eq!(
        research_observer::observed_pairing_check_shapes(),
        vec![(1, 1), (2, 2)]
    );
    assert_eq!(
        research_observer::observed_pairing_map_shapes(),
        vec![(1, 1), (2, 2), (3, 3)]
    );
}

fn pair() -> PodG1G2Pair {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let (px, py) = p.xy().unwrap();
    let (qx, qy) = q.xy().unwrap();
    let mut g1 = [0u8; 64];
    g1[..32].copy_from_slice(&fq(&px));
    g1[32..].copy_from_slice(&fq(&py));
    let mut g2 = [0u8; 128];
    g2[..32].copy_from_slice(&fq(&qx.c1));
    g2[32..64].copy_from_slice(&fq(&qx.c0));
    g2[64..96].copy_from_slice(&fq(&qy.c1));
    g2[96..].copy_from_slice(&fq(&qy.c0));
    PodG1G2Pair {
        g1: PodG1Point(g1),
        g2: PodG2Point(g2),
    }
}

fn non_subgroup_g2() -> G2Affine {
    (0u64..)
        .find_map(|value| {
            let x = Fq2::new(Fq::from(value), Fq::from(0));
            G2Affine::get_point_from_x_unchecked(x, true)
                .filter(|point| !point.is_in_correct_subgroup_assuming_on_curve())
        })
        .expect("BN254 twist has a nontrivial cofactor")
}

#[test]
fn selected_backend_standalone_probes_match_full_pairing() {
    #[cfg(feature = "research-observer")]
    let _observer_guard = OBSERVER_TEST_LOCK.lock().unwrap();
    let pair = pair();
    #[cfg(feature = "research-observer")]
    solana_bn254_batch_syscall::research_observer::reset();
    let subgroup_probe = prepare_g2_subgroup_probe(&pair.g2).unwrap();
    assert_eq!(run_g2_subgroup_probe(&subgroup_probe), Ok(true));
    let nonmember_probe = prepare_g2_subgroup_probe(&g2(non_subgroup_g2())).unwrap();
    assert_eq!(run_g2_subgroup_probe(&nonmember_probe), Ok(false));
    let probe = prepare_final_exponentiation_probe(&[pair]).unwrap();
    let result = run_final_exponentiation_probe(&probe).unwrap();
    assert_eq!(
        encode_final_exponentiation_result(&result).unwrap(),
        alt_bn128_pairing_map(Version::V0, &[pair]).unwrap()
    );
    #[cfg(feature = "research-observer")]
    assert_eq!(
        solana_bn254_batch_syscall::research_observer::observed_standalone_probe_calls(),
        (2, 1)
    );
}
