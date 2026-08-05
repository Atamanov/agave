# Capture host requirements

A tariff capture is only as good as the host it ran on. Vast contract 46891192
was rejected on 2026-08-05 after run 1, and the reasons generalize.

## Reject a host that fails any of these

| Check | Threshold | 46891192 |
|---|---|---|
| `cpu MHz` | at or near the part's rated clock | **1500** |
| `uptime` load average | below ~1 per benchmark core | **61** on 128 threads |
| `model name` | a retail part string | **"AMD Eng Sample"** |
| `avx512ifma` in `/proc/cpuinfo` | present | present |

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

## The PLONK residual is blocked on a lost artifact

18 of 30 residuals are measured: every Groth16 cell, plus both PLONK recursion
cells. The other 12 PLONK cells cannot be measured on this machine.

The collector reads `<plonk-fixture-dir>/manifest.json` and rejects anything
whose digest is not
`7a48e0a7631ae55da0502074b8ae9efad4bf305fad65ce51b63d8e9f26b8b38b`. That file
exists nowhere under `_OLD`, searched by content digest. Only the proof
directories (`mul1`, `mul2`, `mul3`) were preserved; the exporter manifest that
seals them was left in a session scratchpad and is gone.

The seal is doing its job. Reconstructing a `manifest.json` to satisfy the
digest is impossible, and writing a new one with a new digest would assert a
provenance no longer held. Either recover the original from the canonical
snarkjs exporter run, or regenerate the PLONK fixture set and re-seal it as a
new set with its own recorded provenance.

Until then the PLONK rows carry syscall core only, and must be labelled that
way rather than presented beside complete Groth16 rows.
