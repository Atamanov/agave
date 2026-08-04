# B5 charge schedule, fitted from the Threadripper 9970X capture

The runtime charge schedule is the source of truth for the decision table. This
file derives the B5 constants for `SVMTransactionExecutionCost` so the table is
a pure tariff, reproducible on any host.

## Source

`research/bn254-backend-range-vast-20260803/evidence/accepted-threadripper-9970x/backend-range/criterion/backend-b5-helius-ifma`,
AMD Ryzen Threadripper 9970X, Ubuntu 24.04, `-C target-cpu=native -C
target-feature=+avx512f,+avx512ifma`, benchmark CPU 4 via `taskset -c`, 100
criterion samples per shape, two independent process runs.

Selection rule, as recorded in that campaign's `analyzer.json`: maximum of the
two process mean CI95 upper bounds, then `ceil(ns / 33)`. Reproducing it against
the raw criterion trees returns the campaign's published tariffs to the CU.

## Measured, per pair count

| k | pairing check | pairing map |
|---:|---:|---:|
| 1 | 8,616 | 8,829 |
| 2 | 12,302 | 12,398 |
| 3 | 15,940 | 15,956 |
| 4 | 19,586 | 19,551 |
| 6 | 26,856 | 26,478 |
| 7 | 30,487 | 30,265 |
| 8 | **22,413** | **22,427** |
| 9 | 27,254 | 27,263 |
| 12 | 41,731 | 41,713 |
| 16 | **41,033** | **41,031** |

Eight pairs cost less than six. The 8-wide IFMA kernel takes any group of eight,
so cost follows lane count, not pair count. A schedule linear in `k` cannot
express this and would misprice every batch shape.

## Schedule

```
pairing(k) = base + (k / 8) * lane + (k % 8) * per_pair      // integer division
msm(n)     = msm_base + msm_per_point * n
```

| constant | value |
|---|---:|
| `alt_bn128_pairing_check_base_cost` | 4,641 |
| `alt_bn128_pairing_check_lane_cost` (new) | 20,338 |
| `alt_bn128_pairing_check_per_pair_cost` + `alt_bn128_g2_subgroup_check_cost` | 4,188 |
| `alt_bn128_g1_msm_base_cost` | 461 |
| `alt_bn128_g1_msm_per_point_cost` | 296 |

Fitted to never charge below measurement. Worst overcharge is 11.4% on pairing
and 1.6% on MSM. B1's shipped schedule charges 37% over its own measurement at
k=2, so B5 is the tighter of the two.

B5 MSM is linear over 1..54 points, so `ALT_BN128_G1_MSM_DISCOUNT_PER_THOUSAND`
must read 1000 for B5. The sublinear discount describes B1 Pippenger, not the
IFMA kernel.

## Splitting the 4,188

The charge sites read `base + (per_pair + subgroup) * k`, and a registered pair
skips the subgroup check. Only the sum is measured: the standalone G2 benchmark
runs the arkworks check in every build, so it is not a B5 tariff. Split on B1's
measured proportion (3,595 / 9,336 = 38.5%): `per_pair = 2,576`,
`g2_subgroup_check = 1,612`.

A registered pair then costs 2,576, and the saving falls out of the existing
charge site rather than a separate estimate. Registered pairs also skip line
preparation, which this does not credit, so the registered price stays
conservative.

## Not yet derived

`GtTargetMultiexp` at 2 and 3 targets has no x86 measurement. The published
table used a deliberately conservative research schedule, `50,000 + 20,000t`,
against an arm64 p50 calibration of 9.1k / 19.0k / 34.3k for t = 1 / 2 / 3.
It needs a decision before the table can claim this column.
