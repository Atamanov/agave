use criterion::{Criterion, black_box, criterion_group, criterion_main};
use helius_bn254::{G1Affine, G2Affine, pairing};

fn bench_pairing(c: &mut Criterion) {
    let p = G1Affine::generator();
    let q = G2Affine::test_generator();
    c.bench_function("pairing", |ben| {
        ben.iter(|| pairing(black_box(&p), black_box(&q)));
    });
}

criterion_group!(benches, bench_pairing);
criterion_main!(benches);
