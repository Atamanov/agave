//! Compares portable MCL paths with Arkworks on the current host. Run with:
//! `cargo test --release -p solana-bn254-mcl-sys --test perf_probe -- --ignored --nocapture`

use {
    ark_bn254::{Fq, Fq2, Fr, G1Projective, G2Affine, G2Projective},
    ark_ec::{AffineRepr, CurveGroup, PrimeGroup},
    ark_ff::{BigInteger, PrimeField, UniformRand},
    ark_std::rand::{SeedableRng, rngs::StdRng},
    solana_bn254_mcl_sys::api,
    std::time::Instant,
};

fn fq_be(x: &Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

fn fr_be(x: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

fn g2_mcl(p: &G2Affine) -> solana_bn254_mcl_sys::MclG2OnCurve {
    let (x, y) = p.xy().unwrap();
    api::g2_affine(
        api::fp_from_be(&fq_be(&x.c0)).unwrap(),
        api::fp_from_be(&fq_be(&x.c1)).unwrap(),
        api::fp_from_be(&fq_be(&y.c0)).unwrap(),
        api::fp_from_be(&fq_be(&y.c1)).unwrap(),
    )
    .unwrap()
}

fn median_ns(reps: usize, mut old: impl FnMut(), mut new: impl FnMut()) -> (u64, u64) {
    let mut olds = Vec::with_capacity(reps);
    let mut news = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        old();
        olds.push(t.elapsed().as_nanos() as u64);
        let t = Instant::now();
        new();
        news.push(t.elapsed().as_nanos() as u64);
    }
    olds.sort_unstable();
    news.sort_unstable();
    (olds[reps / 2], news[reps / 2])
}

#[test]
#[ignore = "indicative timing only; run release with --nocapture"]
fn perf_g2_subgroup_and_mulvec1() {
    let mut rng = StdRng::seed_from_u64(0x9e7f);

    // This count matches the largest measured pairing batch shape.
    let points: Vec<G2Affine> = (0..53)
        .map(|_| {
            let x = Fq2::new(Fq::rand(&mut rng), Fq::rand(&mut rng));
            G2Affine::get_point_from_x_unchecked(x, true)
                .map(|p| p.clear_cofactor())
                .unwrap_or_else(|| (G2Projective::generator() * Fr::rand(&mut rng)).into_affine())
        })
        .collect();
    let mcl_points: Vec<_> = points.iter().map(g2_mcl).collect();
    let (old, new) = median_ns(
        21,
        || {
            for p in &points {
                assert!(core::hint::black_box(
                    p.is_in_correct_subgroup_assuming_on_curve()
                ));
            }
        },
        || {
            for p in &mcl_points {
                assert!(core::hint::black_box(api::g2_into_subgroup(*p).is_ok()));
            }
        },
    );
    println!(
        "g2_subgroup@53: ark endo {old} ns, mcl isValidOrder {new} ns, ratio {:.3}",
        new as f64 / old as f64
    );

    let base = (G1Projective::generator() * Fr::rand(&mut rng)).into_affine();
    let (bx, by) = base.xy().unwrap();
    let p = api::g1_affine(
        api::fp_from_be(&fq_be(&bx)).unwrap(),
        api::fp_from_be(&fq_be(&by)).unwrap(),
    )
    .unwrap();
    let s = api::fr_from_be(&fr_be(&Fr::rand(&mut rng))).unwrap();
    let (old, new) = median_ns(
        201,
        || {
            core::hint::black_box(api::g1_mul(&p, &s).unwrap());
        },
        || {
            let mut points = [p];
            core::hint::black_box(api::g1_mul_vec(&mut points, &[s]).unwrap());
        },
    );
    println!(
        "g1_mul@1: mul {old} ns, mulVec {new} ns, ratio {:.3}",
        new as f64 / old as f64
    );
}
