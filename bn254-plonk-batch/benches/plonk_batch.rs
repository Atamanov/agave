/*
    To run this benchmark:
    `cargo bench -p solana-bn254-plonk-batch --features agave-unstable-api,test-fixtures`
*/

use {
    ark_bn254::Fr,
    ark_ff::UniformRand,
    criterion::{Criterion, criterion_group, criterion_main},
    solana_bn254_plonk_batch::{
        Proof, RandomizerMode, Version, plonk_batch_verify,
        test_support::{make_proof, make_vk, rng},
    },
    std::hint::black_box,
};

static BATCH_SIZES: &[usize] = &[1, 2, 5, 10, 20, 50];

fn bench_plonk_batch_verify(c: &mut Criterion) {
    let mut rng = rng();
    let (trapdoor, vk) = make_vk(&mut rng);
    let mut group = c.benchmark_group("plonk_batch_verify");
    for &n in BATCH_SIZES {
        let proofs: Vec<Proof> = (0..n)
            .map(|_| make_proof(&trapdoor, Fr::rand(&mut rng), Fr::rand(&mut rng)))
            .collect();
        for (mode, label) in [
            (RandomizerMode::Independent, "independent"),
            (RandomizerMode::Powers, "powers"),
        ] {
            group.bench_function(format!("{label}/n_{n}"), |b| {
                b.iter(|| {
                    let verdict =
                        plonk_batch_verify(Version::V0, black_box(&vk), black_box(&proofs), mode)
                            .unwrap();
                    assert!(verdict);
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_plonk_batch_verify);
criterion_main!(benches);
