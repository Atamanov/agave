# B5 charge schedule, fitted from the Ryzen 9 9900X capture

The runtime charge schedule is the source of truth for the decision table. Every
constant below comes from one capture on one host, so the table is a pure tariff
and reproduces on any host.

## Source

`capture-zen5-20260805/`, AMD Ryzen 9 9900X, 5,250 MHz, 24 threads, `-C
target-cpu=native -C target-feature=+avx512f,+avx512ifma`, `taskset -c 2-9`, two
independent process runs. The host passed `scripts/verify-capture-host.sh`,
which gates on the thresholds in `docs/src/operations/requirements.md` plus the
`avx512ifma` the B5 basis requires.

Selection rule: maximum of the two process mean CI95 upper bounds, then
`ceil(ns / 33)`. Reproduce with:

```bash
python3 scripts/fit-bn254-schedule.py \
  research/bn254-decision-table-v2-20260804/capture-zen5-20260805
```

The fitter exits with an error if any constant would charge below measurement,
so a schedule that undercharges cannot be published by accident.

Cross-check: the same shapes on a Threadripper 9970X run 1.23x faster, flat
across every shape, with CI widths of 0.15%. A ratio that holds across shapes is
what a clock difference looks like; a ratio that varies by shape would mean the
two hosts were not running the same kernel path.

## Two pairing regimes

| k | measured | charged | over |
|---:|---:|---:|---:|
| 1 | 10,454 | 10,455 | 0.0% |
| 2 | 14,795 | 14,805 | 0.1% |
| 3 | 19,148 | 19,155 | 0.0% |
| 4 | 23,473 | 23,505 | 0.1% |
| 6 | 32,205 | 32,205 | 0.0% |
| 7 | 36,537 | 36,555 | 0.0% |
| 8 | **27,159** | 27,160 | 0.0% |
| 9 | 33,025 | 33,025 | 0.0% |
| 12 | 50,617 | 50,620 | 0.0% |
| 16 | **49,664** | 49,665 | 0.0% |

Eight pairs cost less than six. The 8-wide IFMA kernel takes any group of eight,
so cost follows lane count, not pair count.

A pair also costs differently in each regime: 4,350 CU in a call that never
fills a lane, 5,865 CU as the remainder after a full one. One per-pair term has
to cover the worse case, which is what the previous single-regime fit did, and
it overcharged the sub-lane shapes by 24.9%. Pricing the regimes apart brings
the worst overcharge to 0.1%.

## Schedule

```
pairing(k<8)  = base      + per_pair * k
pairing(k>=8) = lane_base + lane * (k / 8) + lane_rem * (k % 8)   // integer division
pairing       -= credit * registered_pairs                        // credit by the same regime
msm(n)        = msm_base + msm_per_point * n
gt(t)         = gt_base + gt_per_target * t
```

| constant | value |
|---|---:|
| `alt_bn128_pairing_check_base_cost` | 6,105 |
| `alt_bn128_pairing_check_per_pair_cost` | 4,350 |
| `alt_bn128_pairing_check_lane_base_cost` | 4,655 |
| `alt_bn128_pairing_check_lane_cost` | 22,505 |
| `alt_bn128_pairing_check_lane_rem_cost` | 5,865 |
| `alt_bn128_g1_msm_base_cost` | 583 |
| `alt_bn128_g1_msm_per_point_cost` | 364 |
| `alt_bn128_gt_multiexp_base_cost` | 3,534 |
| `alt_bn128_gt_multiexp_per_target_cost` | 2,148 |
| `alt_bn128_fr_lincomb_base_cost` | 1 |
| `alt_bn128_fr_lincomb_per_term_cost` | 1 |
| `alt_bn128_fr_batch_invert_base_cost` | 14 |
| `alt_bn128_fr_batch_invert_per_term_cost` | 2 |
| `alt_bn128_plonk_batch_reduce_base_cost` | 127 |
| `alt_bn128_plonk_batch_reduce_per_proof_cost` | 62 |
| `alt_bn128_plonk_batch_reduce_per_lagrange_cost` | 6 |
| `alt_bn128_registered_pair_scalar_credit_cost` | 2,819 |
| `alt_bn128_registered_pair_lane_credit_cost` | 1,142 |

Worst overcharge: pairing 0.1%, MSM 2.0%, GT 0.3%, PLONK reduce 7.2%. The two
scalar-field curves overcharge by up to 75.7% and 19.3%, set by integer CU
granularity rather than the fit: a lincomb term costs 0.62 CU and the schedule
cannot charge less than 1.

`SVMTransactionExecutionCost::alt_bn128_pairing_cost` is the single definition of
the pairing charge. The syscall charges through it and the decision table renders
from it, so a table cell cannot drift from what a validator would charge.

B5 MSM is linear over 1..54 points, so `ALT_BN128_G1_MSM_DISCOUNT_PER_THOUSAND`
reads 1000 for B5. The sublinear discount describes B1 Pippenger, not the IFMA
kernel.

PLONK reduce is fitted at one public input, which is what every zolana verifying
key declares, so the per-proof and per-Lagrange terms are not separable from this
capture. Their sum is fitted; the split holds the per-Lagrange marginal at its
prototype value for wider statements.

## GT multiexp, previously provisional

The published table carried `50,000 + 20,000t` against no x86 measurement.
Measured, it is `3,534 + 2,148t`: the placeholder charged about 11x too much,
roughly 82k and 100k CU of phantom charge on the fold-all cells of the two
multi-key Groth16 rows.

## The registered-pair credit

Measured, on the same host and under the same rule, by a registered-versus-full
differential at a fixed pair count. Requested from and built by the vk-registry
session; captured here as `prepared-run-1` and `prepared-run-2`.

| shape | measured | charged | over |
|---|---:|---:|---:|
| 3 total, 3 registered | 10,696 | 10,698 | 0.0% |
| 8 total, 8 registered | 18,020 | 18,024 | 0.0% |
| 3 total, 2 registered | 13,154 | 13,517 | 2.8% |
| 4 total, 3 registered | 14,766 | 15,048 | 1.9% |
| 8 total, 6 registered | 20,166 | 20,308 | 0.7% |
| 8 total, 3 registered | 23,426 | 23,734 | 1.3% |
| 16 total, 8 registered | 39,646 | 40,529 | 2.2% |

The credit splits on the same lane boundary as the price, for the same reason: a
registered pair still occupies a lane, so past a full lane it saves only its
preparation. Below one lane it saves 2,819 CU, at or above one lane 1,142.

The previous 1,612 was not a measurement. It came from splitting an older
per-pair term on a B1 proportion, and it was wrong in both directions: it
undercharged every lane-filling shape by about 40 percent per registered pair,
and threw away 43 percent of the real saving below one lane. Two charge sites
also added it on top of an all-in per-pair term, double-charging a subgroup
check the price already carried.

An earlier one-run reading of the prepared differential put the worst lane
saving at 552 CU. Two processes put it at 1,091 on the same shape. The
difference is process noise, which is exactly what the two-run selection rule
exists to absorb, and the single-run figure should not be quoted.
