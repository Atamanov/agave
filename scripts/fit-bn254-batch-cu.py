#!/usr/bin/env python3
"""Fit alt_bn128 batch-syscall CU constants from a criterion run.

Reads target/criterion/**/new/{benchmark.json,estimates.json} produced by
`cargo bench -p solana-syscalls --bench alt_bn128_batch` and refits every
constant of the documented pricing model (execution_budget.rs):

  CU(op, n) = ceil(mean 95%-CI upper bound ns / NS_PER_CU)

  g1_msm          base + per_point * n * discount[floor(log2 n)] / 1000
                  (per_point anchored at n = 1 plus 10% margin; the discount
                  table absorbs Pippenger sublinearity, one bucket per swept n)
  pairing_check   base + per_pair * n, fitted AFTER subtracting the standalone
                  G2 subgroup cost per pair, since the handler charges that
                  surcharge separately
  g2_subgroup     the standalone point benchmark
  fr_*            base fixed at the syscall floor; per_term = the smallest
                  integer slope that upper-bounds every measured grid point

Every fitted model is checked to upper-bound the measurement at every swept n;
violations are errors, not warnings. Output: a JSON report on stdout plus a
paste-ready Rust block for the execution_budget.rs Default impl and the MSM
discount table in syscalls/src/lib.rs. Pass --json for the report alone.
"""

import argparse
import json
import math
import sys
from pathlib import Path

NS_PER_CU = 33
BASE_FLOOR = 100  # syscall_base_cost: no syscall prices below the dispatch floor
MSM_MARGIN_PER_MILLE = 100  # 10% on the n = 1 anchor, per the model comment

GROUPS = {
    "BN254 G1 MSM": "g1_msm",
    "BN254 Pairing check": "pairing_check",
    "BN254 G2 subgroup check": "g2_subgroup",
    "BN254 Fr lincomb": "fr_lincomb",
    "BN254 Fr batch invert": "fr_batch_invert",
}


def collect(criterion_dir):
    """{op: {n: cu}} from every */new/ estimate under the criterion dir."""
    out = {op: {} for op in GROUPS.values()}
    for bench_json in criterion_dir.glob("**/new/benchmark.json"):
        meta = json.loads(bench_json.read_text())
        op = GROUPS.get(meta.get("group_id"))
        if op is None:
            continue
        estimates = json.loads((bench_json.parent / "estimates.json").read_text())
        upper_ns = estimates["mean"]["confidence_interval"]["upper_bound"]
        n = int(meta["value_str"]) if meta.get("value_str") else 1
        out[op][n] = math.ceil(upper_ns / NS_PER_CU)
    missing = [op for op, points in out.items() if not points]
    if missing:
        sys.exit(f"error: no criterion data for {missing} under {criterion_dir}")
    return out


def fit_linear_upper(points, subtract_per_n=0):
    """base + slope * n covering every (n, cu) grid point from above.

    Least-squares slope, ceiled; base then raised until no point pokes through.
    """
    xs = sorted(points)
    ys = [points[n] - subtract_per_n * n for n in xs]
    k = len(xs)
    mean_x, mean_y = sum(xs) / k, sum(ys) / k
    var = sum((x - mean_x) ** 2 for x in xs)
    slope = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / var
    slope = max(1, math.ceil(slope))
    base = max(BASE_FLOOR, max(math.ceil(y - slope * n) for n, y in zip(xs, ys)))
    return base, slope


def fit_msm(points):
    base = BASE_FLOOR
    anchor = points.get(1)
    if anchor is None:
        sys.exit("error: msm sweep must include n = 1 (the per-point anchor)")
    per_point = math.ceil((anchor - base) * (1000 + MSM_MARGIN_PER_MILLE) / 1000)
    discount = []
    for n in sorted(points):
        bucket = min(n.bit_length() - 1, 11)
        if bucket != len(discount):
            sys.exit(f"error: msm sweep must hold one size per log2 bucket, got n = {n}")
        if not discount:
            # the anchor bucket keeps the full 10% margin the per-point cost
            # carries; discounting it away here would cancel that headroom
            discount.append(1000)
            continue
        d = math.ceil(1000 * (points[n] - base) / (per_point * n))
        # buckets must not price a bigger batch above a smaller one per point
        discount.append(min(discount[-1], d))
    return base, per_point, discount


def check_upper(op, points, model):
    for n, cu in sorted(points.items()):
        priced = model(n)
        if priced < cu:
            sys.exit(f"error: {op} model prices n = {n} at {priced} CU, below measured {cu}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--criterion-dir", type=Path, default=Path("target/criterion"))
    parser.add_argument("--json", action="store_true", help="emit the JSON report only")
    args = parser.parse_args()

    cu = collect(args.criterion_dir)
    g2 = cu["g2_subgroup"][1]

    msm_base, msm_pp, discount = fit_msm(cu["g1_msm"])
    check_upper(
        "g1_msm",
        cu["g1_msm"],
        lambda n: msm_base + msm_pp * n * discount[min(n.bit_length() - 1, 11)] // 1000,
    )

    # the handler charges g2_subgroup_check_cost per pair on top of the fit
    pair_base, per_pair = fit_linear_upper(cu["pairing_check"], subtract_per_n=g2)
    check_upper("pairing_check", cu["pairing_check"], lambda n: pair_base + (per_pair + g2) * n)

    fr = {}
    for op in ("fr_lincomb", "fr_batch_invert"):
        per_term = max(
            1, max(math.ceil((v - BASE_FLOOR) / n) for n, v in cu[op].items())
        )
        check_upper(op, cu[op], lambda n, s=per_term: BASE_FLOOR + s * n)
        fr[op] = per_term

    fitted = {
        "alt_bn128_g1_msm_base_cost": msm_base,
        "alt_bn128_g1_msm_per_point_cost": msm_pp,
        "alt_bn128_pairing_check_base_cost": pair_base,
        "alt_bn128_pairing_check_per_pair_cost": per_pair,
        "alt_bn128_g2_subgroup_check_cost": g2,
        "alt_bn128_fr_lincomb_base_cost": BASE_FLOOR,
        "alt_bn128_fr_lincomb_per_term_cost": fr["fr_lincomb"],
        "alt_bn128_fr_batch_invert_base_cost": BASE_FLOOR,
        "alt_bn128_fr_batch_invert_per_term_cost": fr["fr_batch_invert"],
    }
    report = {
        "ns_per_cu": NS_PER_CU,
        "measured_cu": {op: dict(sorted(points.items())) for op, points in cu.items()},
        "fitted": fitted,
        "msm_discount_per_thousand": discount,
    }
    print(json.dumps(report, indent=2))
    if args.json:
        return

    print("\n// execution_budget.rs Default (paste over the alt_bn128 batch block):")
    for name, value in fitted.items():
        print(f"            {name}: {value:_},")
    table = ", ".join(str(d) for d in discount)
    print("\n// syscalls/src/lib.rs:")
    print(f"const ALT_BN128_G1_MSM_DISCOUNT_PER_THOUSAND: [u64; 12] =\n    [{table}];")


if __name__ == "__main__":
    main()
