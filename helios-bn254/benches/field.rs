use criterion::{Criterion, black_box, criterion_group, criterion_main};
use helios_bn254::Fp;

fn bench_fp_mul(c: &mut Criterion) {
    let a = Fp::from_u64(123456789);
    let b = Fp::from_u64(987654321);
    c.bench_function("fp_mul", |ben| {
        ben.iter(|| black_box(a) * black_box(b));
    });
}

fn bench_fp_square(c: &mut Criterion) {
    let a = Fp::from_u64(123456789);
    c.bench_function("fp_square", |ben| {
        ben.iter(|| black_box(a).square());
    });
}

criterion_group!(benches, bench_fp_mul, bench_fp_square);
criterion_main!(benches);
