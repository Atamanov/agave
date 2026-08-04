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
