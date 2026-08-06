# Capture host requirements

A tariff capture is only as good as the host it ran on. Vast contract 46891192
was rejected on 2026-08-05 after run 1, and the reasons generalize.

## Reject a host that fails any of these

`scripts/verify-capture-host.sh` is the gate. Run it before building anything:
rejecting a host takes ten seconds, a wasted capture takes twenty minutes.

| Check | Threshold | Source | 46891192 |
|---|---|---|---|
| clock | >= 2,800 MHz | `docs/src/operations/requirements.md` | **1,500** |
| threads | >= 24 | `docs/src/operations/requirements.md` | 128 |
| `model name` | a retail part, not an engineering sample | non-final clocks and errata | **"AMD Eng Sample"** |
| `avx512ifma` | present | the B5 tariff basis | present |
| load average | below one per benchmark core | timing validity | **61** on 128 threads |

Read the clock from `cpufreq/cpuinfo_max_freq`, not `cpu MHz`. Under a powersave
governor an idle core reports about 600 MHz on a 5 GHz part, which rejects a
healthy host.

## Why 46891192 failed

Run 1 measured G1 MSM 1.9x to 2.4x slower than the accepted Threadripper 9970X
capture, uniformly across point counts:

| points | 9970X CU | 9970X us | 46891192 us | ratio |
|---:|---:|---:|---:|---:|
| 1 | 745 | 24.6 | 58.7 | 2.39x |
| 2 | 1,050 | 34.6 | 81.1 | 2.34x |
| 4 | 1,645 | 54.3 | 125.2 | 2.31x |
| 36 | 10,946 | 361.2 | 714.0 | 1.98x |
| 54 | 16,251 | 536.3 | 1,020.2 | 1.90x |

The near-constant ratio matches a clock difference, not a broken kernel: the
part runs at 1.5 GHz against the 9970X's boost clock. The IFMA kernel was
compiled in and used, so the numbers are internally consistent and still wrong
for pricing.

A load average of 61 is the second, independent disqualifier. `taskset` pins the
benchmark to a core but cannot stop other tenants from contending for shared L3
and memory bandwidth, and criterion's CI95 upper bound does not model that.

MSM at 6 points measured *faster* than at 5 (141.7 us against 148.1 us), which
is not a bucketing effect at that size. It is noise, and it is what a contended
host looks like.

## What a capture must record

The host manifest already carries `cpu_model`, `logical_cpus`, `avx512ifma`,
`rustflags`, `rustc`, `features`, `ns_per_cu`, `benchmark_cpu`, and the
benchmark binary sha256. Add `cpu_mhz` and the load average at start and end.
A capture that cannot show these must not reprice anything.

## Standing rule

Charged CU is a consensus price. A host slower than validator-class hardware
inflates every charge, and mixing hosts within one schedule reintroduces exactly
the cross-host splicing this campaign exists to remove. One host, fast, quiet,
retail silicon, or no capture.

## Measuring the residual (no special host needed)

The transaction table is `core + residual`. The core comes from the runtime
schedule and is host-independent. The residual is guest-side sBPF CU and needs
LiteSVM, but it is also a charge rather than a timing, so any host serves.

```bash
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd bn254-decision-bench/sbf/groth16 && cargo-build-sbf --sbf-out-dir /tmp/progs
cargo build -p solana-bn254-decision-collector
./target/debug/solana-bn254-decision-collector \
    --workspace-root . --program-dir /tmp/progs \
    --plonk-fixture-dir research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions \
    --runtime-revision "$(git rev-parse HEAD)" \
    < research/bn254-decision-table-v2-20260804/example-execution-request.json
```

One `ExecutionRequest` in, one `ResidualCell` out. Verified on
`groth16_n2_distinct_vk` / `current`: residual 3,769 CU, observed trace equal to
the contract. A stale guest binary fails with `invalid account data for
instruction`, so rebuild the four guests (`groth16`, `groth-recursion`,
`plonk-direct`, `plonk-recursion`) before a full run.

`run_campaign` with `ExecutorConfig::Command { argv }` already drives this
per cell, so the 30-cell sweep needs the campaign spec, not a new driver.

## The PLONK fixture set was replaced

The old set was sealed by an exporter manifest that no longer exists anywhere,
so its twelve residuals could not be measured. It was also measuring the wrong
shape: circomlib multipliers with 1, 2 and 3 public inputs, where every zolana
verifying key declares one. Public-input count drives the verifier's Lagrange
evaluation and its MSM width.

The replacement is `bn254-decision-bench/plonk-fixtures/zolana-shapes`: three
circuits mirroring transact, one public signal over a Poseidon chain, distinct
keys over one SRS. `generate.sh` regenerates them and
`export_rows --reseal` recomputes every pinned digest from the files on disk.

The seal discipline is unchanged. A reseal replaces the whole table in one
commit and the ordinary path must then reproduce it byte for byte.
