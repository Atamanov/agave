# Plan: re-base the decision table so every cell is independently reproducible

NOT STARTED. Recorded 2026-08-05 for a later decision. Nothing in this file has
been built, and the committed tables are unaffected by it.

It exists because two of the six published columns were found to name features
this session does not own and does not measure. Read the Context section before
quoting any recursion or VK-registry number from `TRANSACTION-TABLE.md`.

---


## Context

The table currently in `research/bn254-decision-table-v2-20260804/` is internally
consistent and fully reproducible by `bn254-decision-bench/run-pipeline.sh`, but
two of its six columns do not describe the features they are named after, and
the other four measure a quantity no other session can reproduce.

Verified read-only against the owning branches:

**Recursion over B5.** Session `e07cdf19` measures `aggregate_transact` (tag 18)
through `program-tests/shielded-pool/tests/aggregate/cu.rs`, reporting
whole-transaction CU: confidential batch 2 = 311,705, batch 3 = 388,411, against
solo 333,880 and 500,820. Our column reports 166,877 / 175,067 by verifying a
pre-baked 480–608 byte payload at fixed 6-pair arity in a synthetic guest that
performs no nullifier, merkle or state work. Different quantity entirely — which
is why `Groth16N3DistinctVk` and `PlonkN2DistinctVkSharedSrs` collapsed onto the
same 40,071 CU core.

**Batching + VK registry (B5).** Session `a4d074dd` builds a per-VK registry:
PDA seed `vk_registry`, digest domain `zolana:vk-registry:v1`, `g2_count` up to 5
(beta, gamma, delta, and the BSB22 pair), entry = 128-byte source + prepared
blob. Our guest models a keyset-scoped registry under seed
`bn254-b5-vk-registry-v3`. The blob size is also stale against an ABI the fork
pins with a test:

```
fork bn254-prepared-stateless: PREPARED_G2_WIRE_BYTES = 16_712  (assert_eq! in prepared_abi.rs)
our decision guest:            G2_PREPARED_BYTES      = 37_584
```

So `registry_len` is wrong and the registry residual over-measures blob
validation by 2.25x of entry size.

**The other four columns.** Sound arithmetic, but measured in
`new_litesvm_with_decision_syscalls` against synthetic guests at fabricated
program IDs. Nobody outside this session can reproduce them, because nothing
outside this session runs those guests.

Requirement: the final deliverable must be fully conforming and must match what
is measured independently. A number matches independently only if another
session, running its own test, arrives at the same value.

## The decision

Re-base every cell onto the basis both other sessions already use: **whole
transaction `compute_units_consumed` from `ZolanaProgramTest`, against real
zolana instructions, in zolana `program-tests`.** That harness runs the real SVM
and the real `alt_bn128` syscalls, and `last_transaction_trace()` is already the
shared accessor (`program-tests/shielded-pool/tests/cross_cutting/cu_budget.rs`).

Consequences, stated plainly because they are costs:

- The synthetic SBF guests stop being the headline measurement. They keep value
  as BN254-core microbenchmarks that explain *why* a column differs, and the
  agave charge schedule plus `scripts/fit-bn254-schedule.py` stay exactly as they
  are — that work is measured and stands.
- The grid changes shape. Rows become the rail and batch size both sessions
  already measure; the abstract "N proofs, distinct VKs" rows do not exist as
  runnable zolana transactions.

## Stage 0 — one agave schedule, or no table

Two agave branches carry conflicting schedules and a table cannot be built over
both:

| constant | `bn254-decision` | `bn254-prepared-stateless` |
|---|---:|---:|
| pairing regimes | two (lane base 4,655 / rem 5,865) | one |
| `alt_bn128_pairing_check_lane_cost` | 22,505 | 20,338 |
| `alt_bn128_g2_subgroup_check_cost` | removed | 1,612 |
| `alt_bn128_g2_prepare_base_cost` | 2,656 measured | 700 |
| credits | registered 2,819 / 1,142 | prepared 2,200 / 750 |

Their credits were fitted against the older single-regime price, so a naive
merge undercharges. Converge first: one branch, two-regime pairing, one
`alt_bn128_pairing_cost`, prepared and registered credits refitted against it
with `prepared_credit >= registered_credit` pinned as a test. The measurement
already exists in `capture-zen5-20260805/prepared-run-{1,2}`; only the fit moves.

This is a coordination step, not an edit of their branch.

## Stage 1 — grid that both sessions can run

Fix the rail to **confidential** (the shape `transact` settles) and use batch
sizes **2 and 3**, which both sessions already measure. That makes the aggregate
column directly comparable to `aggregate_reports_compute` rather than
approximately so.

| row | column | source of truth |
|---|---|---|
| confidential 2x3, batch 2 and 3 | solo | `aggregate/cu.rs` solo path |
| " | batching syscalls (B5) | new, this session |
| " | + VK registry | session `a4d074dd` |
| " | aggregate (recursion) | session `e07cdf19` |
| " | + Fp12 | this session |

Keep the ring eddsa and ring p256 rails as additional rows if the keys are
available; they are already measured on the recursion side and cost nothing
extra to include.

## Stage 2 — emit the table from zolana, not from agave

In a zolana worktree, add a CU-report test beside
`aggregate/cu.rs` that walks the grid and writes the two markdown tables. Reuse,
do not reimplement:

- `ZolanaProgramTest` and `last_transaction_trace()` for the CU;
- `shielded_pool_tests::support::fixtures::Pool` and
  `zolana_test_utils::transact::*` for witnesses, exactly as `aggregate/cu.rs`
  does;
- the existing observer for the operations table, so ML/SC/FE/MSM/GT counts come
  from the same run that produced the CU rather than from a hand-written model.

`bn254-decision-bench/run-pipeline.sh` keeps working as-is; it is relabelled as the BN254-core microbenchmark
runner once the zolana report supersedes it as the headline table. Until then
both stand, which is the point of separating the branches — the committed table
stays reproducible while its replacement is built.

## Stage 3 — prove the match, do not assert it

The deliverable is the cross-check, not the number. Add a test that runs the
owning session's own test and asserts equality with our cell:

- aggregate cells equal `aggregate_reports_compute` output for the same rail and
  batch;
- registry cells equal the vk-registry session's registered-transact CU test.

Import no numbers by hand. A hardcoded 311,705 is the failure mode this whole
change exists to remove.

## Stage 4 — fixtures (task #18)

Port `tools/bn254-decision-fixtures` from its original export branch into its
own worktree. Cherry-pick the single commit and let the build reveal which of
its base commits are load-bearing. It needs a live prover and three
locked proving keys and has no synthetic path by design, so if the keys are
unavailable, skip rather than substitute.

Lowest priority of the four. Once Stage 1 anchors the rows on real zolana
transactions, the Groth16 rows are built by the same witness helpers
`aggregate/cu.rs` already uses, so this generator may turn out to be unnecessary
for the table and worth keeping only as a standalone exporter. Decide after
Stage 2, not before.

## Verification

- Another session runs its own CU test; our corresponding cell equals it to the
  CU, asserted by Stage 3's test rather than by comparing documents.
- The current table branch still passes `run-pipeline.sh` unchanged, so the
  existing published table survives the transition.
- `PREPARED_G2_WIRE_BYTES` is referenced from the fork, never redeclared; the
  37,584 literal is gone.
- One agave branch, one `alt_bn128_pairing_cost`, credit ordering pinned.
- The zolana CU report regenerates both tables byte-identically.
- The BN254-core microbenchmarks still pass and are labelled as explanatory, not
  as the transaction table.

## Assumptions, flagged rather than asked

- The 5x6 grid is replaced, not preserved. Its rows are not runnable zolana
  transactions, so they cannot be independently reproduced by anyone. Keeping
  the old shape and the new requirement together is not possible.
- The confidential rail at batch 2 and 3 is the anchor because both sessions
  already measure exactly that. Other rails are additive.
- The agave charge-schedule work stands unchanged; only what consumes it moves.
