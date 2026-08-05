#!/usr/bin/env python3
"""Fits the BN254 runtime charge schedule from a criterion capture.

Selection rule, unchanged from the accepted campaign: take the maximum of the
two process mean CI95 upper bounds per shape, then ceil(ns / 33). Two
independent processes are required, so a single run cannot produce a tariff.

The schedule must never charge below measurement. Overcharge is reported per
shape so the conservatism is visible rather than asserted.
"""

import argparse
import json
import math
import pathlib
import sys

NS_PER_CU = 33
LANE = 8  # pairs the AVX-512 IFMA kernel takes together

GROUPS = {
    "pairing": "BN254 Pairing check",
    "pairing_map": "BN254 Pairing map",
    "msm": "BN254 G1 MSM",
    "gt": "BN254 trusted GT multiexp",
}


def shape_cu(root: pathlib.Path, group: str) -> dict[int, int]:
    """Max of both runs' CI95 upper bounds per shape, converted to CU."""
    worst: dict[int, float] = {}
    for run in ("run-1", "run-2"):
        base = root / run / group
        if not base.is_dir():
            continue
        for estimates in base.glob("*/*/new/estimates.json"):
            shape = estimates.parent.parent.name
            if not shape.isdigit():
                continue
            upper = json.loads(estimates.read_text())["mean"]["confidence_interval"][
                "upper_bound"
            ]
            key = int(shape)
            worst[key] = max(worst.get(key, 0.0), upper)
    return {k: math.ceil(v / NS_PER_CU) for k, v in sorted(worst.items())}


def fit_linear(points: dict[int, int]) -> tuple[int, int]:
    """Smallest (base, per_unit) that covers every point."""
    best = None
    for base in range(0, 20_001):
        per = max(math.ceil((cu - base) / n) for n, cu in points.items() if n)
        over = max((base + per * n) / cu for n, cu in points.items())
        if best is None or over < best[0]:
            best = (over, base, per)
    return best[1], best[2]


def fit_pairing(points: dict[int, int]) -> tuple[int, int, int, int, int]:
    """Two-regime fit, because the kernel takes two paths.

        k < 8   ->  scalar_base + k * scalar_per
        k >= 8  ->  lane_base + (k div 8) * lane + (k mod 8) * lane_remainder

    The measured marginals differ by a third: a pair costs ~4.35k CU in a
    scalar-only call but ~5.86k as the remainder after a full lane. One
    per-pair term has to cover the worse case and overcharges the other by
    about a quarter, so the regimes are priced apart.
    """
    scalar = {k: cu for k, cu in points.items() if k < LANE}
    lane_pts = {k: cu for k, cu in points.items() if k >= LANE}

    scalar_base, scalar_per = fit_linear(scalar) if scalar else (0, 0)

    full = {k: cu for k, cu in lane_pts.items() if k % LANE == 0}
    rest = {k: cu for k, cu in lane_pts.items() if k % LANE}
    best = None
    for base in range(0, 12_001):
        lane = max(
            (math.ceil((cu - base) / (k // LANE)) for k, cu in full.items()), default=0
        )
        rem_cost = 0
        for k, cu in rest.items():
            over = cu - base - (k // LANE) * lane
            if over > 0:
                rem_cost = max(rem_cost, math.ceil(over / (k % LANE)))
        worst = max(
            (base + (k // LANE) * lane + (k % LANE) * rem_cost) / cu
            for k, cu in lane_pts.items()
        )
        if best is None or worst < best[0]:
            best = (worst, base, lane, rem_cost)
    return scalar_base, scalar_per, best[1], best[2], best[3]


def report(label: str, points: dict[int, int], charge) -> float:
    worst = 0.0
    print(f"\n{label}")
    print(f"  {'shape':>6} {'measured':>10} {'charged':>10} {'over':>7}")
    for n, cu in points.items():
        c = charge(n)
        if c < cu:
            sys.exit(f"FIT ERROR: {label} n={n} charges {c} below measured {cu}")
        worst = max(worst, c / cu - 1)
        print(f"  {n:>6} {cu:>10,} {c:>10,} {(c / cu - 1) * 100:>6.1f}%")
    return worst


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=pathlib.Path, help="dir holding run-1 and run-2")
    args = parser.parse_args()

    for run in ("run-1", "run-2"):
        if not (args.capture / run).is_dir():
            sys.exit(f"missing {run}: the selection rule needs two processes")

    # One pairing schedule covers check and map: they price the same work.
    pairing = shape_cu(args.capture, GROUPS["pairing"])
    for shape, cu in shape_cu(args.capture, GROUPS["pairing_map"]).items():
        pairing[shape] = max(pairing.get(shape, 0), cu)
    msm = shape_cu(args.capture, GROUPS["msm"])
    msm = {n: cu for n, cu in msm.items() if n <= 54}
    gt = shape_cu(args.capture, GROUPS["gt"])

    s_base, s_per, base, lane, lane_rem = fit_pairing(pairing)

    def pairing_charge(k: int) -> int:
        if k < LANE:
            return s_base + s_per * k
        return base + (k // LANE) * lane + (k % LANE) * lane_rem

    worst_pairing = report(
        f"pairing(k<8) = {s_base} + {s_per}k   "
        f"pairing(k>=8) = {base} + (k div 8)*{lane} + (k mod 8)*{lane_rem}",
        pairing,
        pairing_charge,
    )
    msm_base, msm_per = fit_linear(msm)
    worst_msm = report(
        f"msm(n) = {msm_base} + {msm_per} * n",
        msm,
        lambda n: msm_base + msm_per * n,
    )
    gt_base, gt_per = fit_linear(gt)
    worst_gt = report(
        f"gt(t) = {gt_base} + {gt_per} * t", gt, lambda t: gt_base + gt_per * t
    )

    print("\nexecution_budget.rs constants")
    print(f"  alt_bn128_pairing_check_base_cost:      {s_base}")
    print(f"  alt_bn128_pairing_check_per_pair_cost:  {s_per}")
    print(f"  alt_bn128_pairing_check_lane_base_cost: {base}")
    print(f"  alt_bn128_pairing_check_lane_cost:      {lane}")
    print(f"  alt_bn128_pairing_check_lane_rem_cost:  {lane_rem}")
    print(f"  alt_bn128_g1_msm_base_cost:            {msm_base}")
    print(f"  alt_bn128_g1_msm_per_point_cost:       {msm_per}")
    print(f"  alt_bn128_gt_multiexp_base_cost:       {gt_base}")
    print(f"  alt_bn128_gt_multiexp_per_target_cost: {gt_per}")
    print(
        f"\nworst overcharge: pairing {worst_pairing * 100:.1f}%, "
        f"msm {worst_msm * 100:.1f}%, gt {worst_gt * 100:.1f}%"
    )


if __name__ == "__main__":
    main()
