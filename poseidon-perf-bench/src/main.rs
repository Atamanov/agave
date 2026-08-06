//! Measures where the on-chain Poseidon syscall spends its time.
//!
//! The runtime prices the syscall as `61*n^2 + 542` CU at an assumed 33 ns per
//! CU. This binary measures the same code the syscall runs (`solana_poseidon::
//! hashv`, the `poseidon_enforce_padding` path) and splits it into parameter
//! construction and permutation, then compares against a no-alloc reference.
//!
//! Numbers here come from an Apple M4 Max, aarch64. The shipped tariff was
//! fitted on x86, so treat the absolute nanoseconds as this-host-only and the
//! ratios between arities as the transferable result.
//!
//! `cargo test --release` proves the two reference implementations are
//! bit-identical to `solana_poseidon::hashv` at every supported width.

use {
    ark_bn254::Fr,
    ark_ff::{AdditiveGroup, BigInt, BigInteger, Field, PrimeField},
    light_poseidon::{Poseidon, PoseidonBytesHasher},
    solana_poseidon::{Endianness, Parameters},
    std::{hint::black_box, time::Instant},
};

const NS_PER_CU: f64 = 33.0;

fn bench<F: FnMut()>(mut f: F, target_ns: u128) -> f64 {
    // Calibrate.
    let mut iters: u64 = 1;
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let el = t.elapsed().as_nanos();
        if el >= target_ns || iters >= 1 << 30 {
            break;
        }
        iters = (iters * 2).max(1);
    }
    // Keep the fastest rep. The minimum is the right statistic here: every
    // source of noise on this host adds time, none removes it.
    let mut best = f64::MAX;
    for _ in 0..40 {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let per = t.elapsed().as_nanos() as f64 / iters as f64;
        if per < best {
            best = per;
        }
    }
    best
}

fn inputs_bytes(n: usize) -> Vec<[u8; 32]> {
    // Deterministic, all strictly below the BN254 Fr modulus.
    (0..n)
        .map(|i| {
            let mut b = [0u8; 32];
            b[0] = 0x0a;
            for (j, x) in b.iter_mut().enumerate().skip(1) {
                *x = ((i * 31 + j * 7 + 1) % 251) as u8;
            }
            b
        })
        .collect()
}

// ---------------------------------------------------------------------------
// No-alloc reference permutation, const width, params built once.
// ---------------------------------------------------------------------------

struct FastParams<const W: usize> {
    ark: Vec<[Fr; W]>,
    mds: [[Fr; W]; W],
    full_rounds: usize,
    partial_rounds: usize,
}

impl<const W: usize> FastParams<W> {
    fn build() -> Self {
        let p = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(W as u8)
            .expect("width supported");
        assert_eq!(p.width, W);
        assert_eq!(p.alpha, 5);
        let rounds = p.full_rounds + p.partial_rounds;
        let ark = (0..rounds)
            .map(|r| std::array::from_fn(|i| p.ark[r * W + i]))
            .collect();
        let mds = std::array::from_fn(|i| std::array::from_fn(|j| p.mds[i][j]));
        Self {
            ark,
            mds,
            full_rounds: p.full_rounds,
            partial_rounds: p.partial_rounds,
        }
    }

    #[inline(always)]
    fn permute(&self, state: &mut [Fr; W]) {
        let half = self.full_rounds / 2;
        let mut scratch = [Fr::ZERO; W];
        for round in 0..self.full_rounds + self.partial_rounds {
            let ark = &self.ark[round];
            for i in 0..W {
                state[i] += ark[i];
            }
            if round < half || round >= half + self.partial_rounds {
                for s in state.iter_mut() {
                    *s = pow5(*s);
                }
            } else {
                state[0] = pow5(state[0]);
            }
            for i in 0..W {
                let row = &self.mds[i];
                let mut acc = Fr::ZERO;
                for j in 0..W {
                    acc += state[j] * row[j];
                }
                scratch[i] = acc;
            }
            *state = scratch;
        }
    }

    /// Bytes in, bytes out, matching `solana_poseidon::hashv` semantics for
    /// big-endian inputs of exactly 32 bytes.
    fn hash_bytes_be(&self, inputs: &[&[u8]]) -> Option<[u8; 32]> {
        let mut state = [Fr::ZERO; W];
        if inputs.len() != W - 1 {
            return None;
        }
        for (slot, input) in state.iter_mut().skip(1).zip(inputs) {
            *slot = fr_from_be_checked(input)?;
        }
        self.permute(&mut state);
        let mut out = [0u8; 32];
        out.copy_from_slice(&state[0].into_bigint().to_bytes_be());
        Some(out)
    }
}

#[inline(always)]
fn pow5(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// Canonical big-endian 32-byte decode without the `num_bigint` detour that
/// `light-poseidon` takes. Rejects anything at or above the modulus.
#[inline(always)]
fn fr_from_be_checked(bytes: &[u8]) -> Option<Fr> {
    let b: &[u8; 32] = bytes.try_into().ok()?;
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[24 - 8 * i..32 - 8 * i]);
        *limb = u64::from_be_bytes(w);
    }
    Fr::from_bigint(BigInt::new(limbs))
}

// The same permutation was also run over the `helius-bn254` field backend from
// the bn254-decision worktree. It was slower on this host: 10,843 ns per arity-2
// hash against 8,683 ns for the arkworks no-alloc reference, and 10.1 ns per Fr
// multiplication against 8.99 ns. That backend is tuned for x86 AVX-512 IFMA in
// Fp, not for aarch64 Fr, so there is no field-layer headroom to borrow here.
// The dependency is left out so this crate builds from a clean checkout.

/// Cost per field element absorbed, `c(a)/(a-1)`, for a fold that reduces a
/// list to one digest. A hash chain built from arity-2 calls pays the arity-2
/// row for every element; a wider fold pays a cheaper row.
fn arity_economics() {
    println!("\n-- cost per element absorbed by a fold of arity a --");
    println!("Current tariff c(a)=61a^2+542 against a tariff proportional to the");
    println!("measured multiplication count, normalised so arity 2 stays at 786 CU.");
    println!(
        "{:>2} {:>8} {:>9} {:>8} {:>9}",
        "a", "tariff", "per_elem", "honest", "per_elem"
    );
    let scale = 786.0 / mul_count(3) as f64;
    for a in 2usize..=8 {
        let tariff = 61 * a * a + 542;
        let honest = mul_count(a + 1) as f64 * scale;
        println!(
            "{a:>2} {tariff:>8} {:>9.1} {honest:>8.0} {:>9.1}",
            tariff as f64 / (a - 1) as f64,
            honest / (a - 1) as f64
        );
    }
}

fn main() {
    let target = 15_000_000u128;

    println!("host: Apple M4 Max, aarch64 (NOT the x86 AVX-512 IFMA capture box)");
    println!("tariff assumption under test: 1 CU = {NS_PER_CU} ns\n");

    // Correctness gate: the no-alloc reference must agree with the shipped path.
    check_reference();

    println!("independent calls (out-of-order execution overlaps them) and chained");
    println!("calls (each hash feeds the next, the merkle-path shape).\n");
    println!(
        "{:>2} {:>9} {:>9} {:>9} {:>9} {:>8} {:>8} {:>8} {:>7}",
        "n", "cold_ns", "chain_ns", "warm_ns", "param_ns", "coldCU", "chainCU", "tariff", "tar/ch"
    );
    let mut rows = Vec::new();
    for n in 1usize..=12 {
        let vals = inputs_bytes(n);
        let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();

        // A: exactly what the syscall body calls, calls independent.
        let cold = bench(
            || {
                black_box(
                    solana_poseidon::hashv(
                        Parameters::Bn254X5,
                        Endianness::BigEndian,
                        black_box(&refs),
                    )
                    .unwrap(),
                );
            },
            target,
        );

        // A': same, but each hash consumes the previous digest.
        let tail: Vec<&[u8]> = refs[1..].to_vec();
        let chain = bench(
            || {
                let mut cur = vals[0];
                for _ in 0..8 {
                    let mut args: Vec<&[u8]> = Vec::with_capacity(n);
                    args.push(&cur);
                    args.extend_from_slice(&tail);
                    cur = solana_poseidon::hashv(Parameters::Bn254X5, Endianness::BigEndian, &args)
                        .unwrap()
                        .to_bytes();
                }
                black_box(cur);
            },
            target,
        ) / 8.0;

        // B: same permutation with the parameter set built once.
        let mut hasher = Poseidon::<Fr>::new_circom(n).unwrap();
        let warm = bench(
            || {
                black_box(hasher.hash_bytes_be(black_box(&refs)).unwrap());
            },
            target,
        );

        // C: parameter construction alone.
        let param = bench(
            || {
                black_box(Poseidon::<Fr>::new_circom(black_box(n)).unwrap());
            },
            target,
        );

        let tariff = 61 * (n as u64) * (n as u64) + 542;
        println!(
            "{n:>2} {cold:>9.0} {chain:>9.0} {warm:>9.0} {param:>9.0} {:>8.0} {:>8.0} {tariff:>8} {:>7.2}",
            cold / NS_PER_CU,
            chain / NS_PER_CU,
            tariff as f64 / (chain / NS_PER_CU)
        );
        rows.push((n, cold, warm, param, tariff));
    }

    println!("\n-- no-alloc reference, cached params, arity 2 (width 3) --");
    let fast3 = FastParams::<3>::build();
    let vals = inputs_bytes(2);
    let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
    let fast = bench(
        || {
            black_box(fast3.hash_bytes_be(black_box(&refs)).unwrap());
        },
        target,
    );
    let (_, cold2, warm2, _, _) = rows[1];
    println!("shipped cold      {cold2:>9.0} ns  {:>7.0} CU", cold2 / NS_PER_CU);
    println!("shipped warm      {warm2:>9.0} ns  {:>7.0} CU", warm2 / NS_PER_CU);
    println!("no-alloc ref      {fast:>9.0} ns  {:>7.0} CU", fast / NS_PER_CU);
    println!("speedup vs cold   {:>9.2}x", cold2 / fast);

    println!("\n-- no-alloc reference across widths --");
    println!(
        "{:>2} {:>9} {:>9} {:>8} {:>8} {:>7} {:>7} {:>8}",
        "n", "indep_ns", "chain_ns", "chainCU", "tariff", "tar/ch", "muls", "ns/mul"
    );
    bench_fast::<2>(target);
    bench_fast::<3>(target);
    bench_fast::<4>(target);
    bench_fast::<5>(target);
    bench_fast::<6>(target);
    bench_fast::<7>(target);
    bench_fast::<8>(target);
    bench_fast::<9>(target);
    bench_fast::<10>(target);
    bench_fast::<11>(target);
    bench_fast::<12>(target);
    bench_fast::<13>(target);

    println!("\n-- merkle path, depth 26, arity 2 --");
    let leaves = inputs_bytes(2);
    let a = leaves[0];
    let b = leaves[1];
    let path_cold = bench(
        || {
            let mut cur = a;
            for _ in 0..26 {
                cur = solana_poseidon::hashv(
                    Parameters::Bn254X5,
                    Endianness::BigEndian,
                    &[&cur, &b],
                )
                .unwrap()
                .to_bytes();
            }
            black_box(cur);
        },
        target,
    );
    let path_fast = bench(
        || {
            let mut cur = a;
            for _ in 0..26 {
                cur = fast3.hash_bytes_be(&[&cur, &b]).unwrap();
            }
            black_box(cur);
        },
        target,
    );
    println!(
        "26 separate syscalls, shipped code   {path_cold:>10.0} ns  {:>7.0} CU",
        path_cold / NS_PER_CU
    );
    println!("26 hashes charged at 786 CU each                        {:>7} CU", 26 * 786);
    println!(
        "one path syscall, shipped code       {path_cold:>10.0} ns  {:>7.0} CU",
        path_cold / NS_PER_CU
    );
    println!(
        "one path syscall, no-alloc ref       {path_fast:>10.0} ns  {:>7.0} CU",
        path_fast / NS_PER_CU
    );

    arity_economics();

    println!("\n-- k independent arity-2 hashes, no-alloc reference --");
    println!("Shows how much instruction-level parallelism a batch already has,");
    println!("which bounds what wide SIMD could add on top.");
    for k in [1usize, 2, 4, 8] {
        let seeds: Vec<[u8; 32]> = (0..k)
            .map(|i| {
                let mut b = inputs_bytes(1)[0];
                b[31] = i as u8;
                b
            })
            .collect();
        let t = bench(
            || {
                for s in &seeds {
                    black_box(fast3.hash_bytes_be(&[s, &b]).unwrap());
                }
            },
            target,
        ) / k as f64;
        println!("k={k:<2} {t:>9.0} ns per hash");
    }

    println!("\n-- field-op microbenchmarks --");
    let x = Fr::from(123456789u64);
    let y = Fr::from(987654321u64);
    let mul = bench(|| { black_box(black_box(x) * black_box(y)); }, target);
    let p5 = bench(|| { black_box(pow5(black_box(x))); }, target);
    let arkpow = bench(|| { black_box(black_box(x).pow([5u64])); }, target);
    let frombig = bench(
        || {
            black_box(Fr::from_bigint(black_box(BigInt::new([1, 2, 3, 4]))));
        },
        target,
    );
    let decode_lp = bench(
        || {
            black_box(light_poseidon::bytes_to_prime_field_element_be::<Fr>(black_box(
                &vals[0][..],
            )))
            .unwrap();
        },
        target,
    );
    let decode_direct = bench(
        || {
            black_box(fr_from_be_checked(black_box(&vals[0][..])));
        },
        target,
    );
    println!("Fr mul            {mul:>9.3} ns");
    println!("decode via num_bigint {decode_lp:>5.1} ns   (light-poseidon)");
    println!("decode direct     {decode_direct:>9.1} ns");
    println!("pow5 (3 mul)      {p5:>9.3} ns");
    println!("ark pow([5])      {arkpow:>9.3} ns");
    println!("Fr::from_bigint   {frombig:>9.3} ns   (one Montgomery mul + range check)");

    // Round/mul accounting for width 3.
    let p = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<Fr>(3).unwrap();
    let rounds = p.full_rounds + p.partial_rounds;
    let mds_muls = rounds * 9;
    let sbox_muls = p.full_rounds * 3 * 3 + p.partial_rounds * 3;
    println!(
        "\nwidth 3: {rounds} rounds, {mds_muls} MDS muls + {sbox_muls} sbox muls = {} muls",
        mds_muls + sbox_muls
    );
    println!(
        "predicted from Fr mul alone: {:.0} ns; measured no-alloc: {fast:.0} ns",
        (mds_muls + sbox_muls) as f64 * mul
    );
    println!(
        "params rebuilt per call at width 3: {} ark + 9 mds = {} Fr::from_bigint = {:.0} ns",
        rounds * 3,
        rounds * 3 + 9,
        (rounds * 3 + 9) as f64 * frombig
    );
}

fn bench_fast<const W: usize>(target: u128) {
    let n = W - 1;
    let p = FastParams::<W>::build();
    let vals = inputs_bytes(n);
    let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
    let t = bench(
        || {
            black_box(p.hash_bytes_be(black_box(&refs)).unwrap());
        },
        target,
    );
    let tail: Vec<&[u8]> = refs[1..].to_vec();
    let chain = bench(
        || {
            let mut cur = vals[0];
            for _ in 0..8 {
                let mut args: Vec<&[u8]> = Vec::with_capacity(W);
                args.push(&cur);
                args.extend_from_slice(&tail);
                cur = p.hash_bytes_be(&args).unwrap();
            }
            black_box(cur);
        },
        target,
    ) / 8.0;
    let tariff = 61 * (n as u64) * (n as u64) + 542;
    let muls = mul_count(W);
    println!(
        "{n:>2} {t:>9.0} {chain:>9.0} {:>8.0} {tariff:>8} {:>7.2} {muls:>7} {:>8.2}",
        chain / NS_PER_CU,
        tariff as f64 / (chain / NS_PER_CU),
        chain / muls as f64
    );
}

/// BN254 x^5 Poseidon field multiplications for state width `t`:
/// `rounds*t^2` for the MDS layer, `3` per S-box, S-boxes on every element in
/// the 8 full rounds and on one element in the partial rounds.
fn mul_count(t: usize) -> usize {
    const PARTIAL: [usize; 12] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65];
    let p = PARTIAL[t - 2];
    let rounds = 8 + p;
    rounds * t * t + 8 * t * 3 + p * 3
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// 32 big-endian bytes below 2^253, which is below the BN254 Fr modulus,
        /// so the value is always a canonical field element.
        fn field_bytes(&mut self) -> [u8; 32] {
            let mut b = [0u8; 32];
            for chunk in b.chunks_exact_mut(8) {
                chunk.copy_from_slice(&self.next().to_be_bytes());
            }
            b[0] &= 0x1f;
            b
        }
    }

    macro_rules! differential {
        ($name:ident, $w:literal) => {
            #[test]
            fn $name() {
                let ark_params = FastParams::<$w>::build();
                let mut rng = Rng(0x9e3779b97f4a7c15 ^ $w);
                for _ in 0..64 {
                    let vals: Vec<[u8; 32]> =
                        (0..$w - 1).map(|_| rng.field_bytes()).collect();
                    let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
                    let want = solana_poseidon::hashv(
                        Parameters::Bn254X5,
                        Endianness::BigEndian,
                        &refs,
                    )
                    .unwrap()
                    .to_bytes();
                    assert_eq!(ark_params.hash_bytes_be(&refs).unwrap(), want);
                }
            }
        };
    }

    differential!(width_2, 2);
    differential!(width_3, 3);
    differential!(width_4, 4);
    differential!(width_5, 5);
    differential!(width_6, 6);
    differential!(width_7, 7);
    differential!(width_8, 8);
    differential!(width_9, 9);
    differential!(width_10, 10);
    differential!(width_11, 11);
    differential!(width_12, 12);
    differential!(width_13, 13);

    /// The runtime tariff. Pinned so a change to it shows up as a test failure.
    fn tariff(arity: usize) -> usize {
        61 * arity * arity + 542
    }

    /// Arity 4 is the cheapest way to absorb a field element under the current
    /// tariff, arity 3 under a tariff proportional to the multiplication count.
    /// Arity 3 is therefore the choice that survives a tariff correction.
    #[test]
    fn fold_arity_optimum() {
        let per_elem = |a: usize| tariff(a) as f64 / (a - 1) as f64;
        let best = (2..=8).min_by(|a, b| per_elem(*a).total_cmp(&per_elem(*b)));
        assert_eq!(best, Some(4));

        let scale = tariff(2) as f64 / mul_count(3) as f64;
        let honest_per_elem = |a: usize| mul_count(a + 1) as f64 * scale / (a - 1) as f64;
        let best_honest = (2..=8).min_by(|a, b| honest_per_elem(*a).total_cmp(&honest_per_elem(*b)));
        assert_eq!(best_honest, Some(3));

        // Arity 3 beats arity 2 under both tariffs, by these margins.
        assert!((1.0 - per_elem(3) / per_elem(2) - 0.306).abs() < 0.005);
        assert!((1.0 - honest_per_elem(3) / honest_per_elem(2) - 0.222).abs() < 0.005);
    }

    /// Wide merkle trees lose. Halving the depth needs the arity squared, and
    /// the permutation cost grows faster than that.
    #[test]
    fn binary_trees_beat_wide_trees() {
        // Each tree holds at least 2^26 leaves.
        let shapes = [(2usize, 26usize), (4, 13), (8, 9)];
        let work: Vec<usize> = shapes
            .iter()
            .map(|(arity, depth)| depth * mul_count(arity + 1))
            .collect();
        assert_eq!(work.iter().min(), Some(&work[0]));
        // The current tariff makes the 4-ary tree look marginally cheaper than
        // it is: 3% better on paper, 21% more actual work.
        let charged: Vec<usize> = shapes.iter().map(|(a, d)| d * tariff(*a)).collect();
        assert!(charged[1] < charged[0]);
        assert!(work[1] > work[0]);
    }
}

fn check_reference() {
    macro_rules! check {
        ($w:literal) => {{
            let n = $w - 1;
            let vals = inputs_bytes(n);
            let refs: Vec<&[u8]> = vals.iter().map(|v| v.as_slice()).collect();
            let want = solana_poseidon::hashv(Parameters::Bn254X5, Endianness::BigEndian, &refs)
                .unwrap()
                .to_bytes();
            let got = FastParams::<$w>::build().hash_bytes_be(&refs).unwrap();
            assert_eq!(want, got, "width {} mismatch", $w);
        }};
    }
    check!(2);
    check!(3);
    check!(4);
    check!(5);
    check!(8);
    check!(13);
    println!("no-alloc reference matches solana_poseidon::hashv at widths 2,3,4,5,8,13\n");
}
