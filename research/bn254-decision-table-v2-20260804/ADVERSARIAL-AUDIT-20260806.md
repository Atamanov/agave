# Adversarial audit of the decompression-corrected BN254 decision tables

Date: 2026-08-06  
Audited HEAD: `a05db564400b0204bffdedc0f5e15b90ec516efa`  
Mode: analysis only. No implementation, table, fixture, or reconciliation source was changed.

## Verdict

The committed 5-by-6 grid is internally reproducible. The decompression counts and
charges are arithmetically correct, the current markdown matches its renderers, the
observed traces match the hard-coded trace contract, and the fitted syscall families
pass their tariff bounds.

The grid is **not sound enough to support the stated deployment recommendation**.
The designated reconciliation is stale, the real-program and synthetic recursion
implementations differ by more than the n=2 winning margin, the registry column
targets a divergent independently owned ABI, the PLONK conclusion is wrong on its own n=3
row, and the Table #3 comparison uses incompatible definitions of "syscall share."

The safe reading is:

* Within this synthetic model, recursion is the minimum on all three Groth16 rows
  and on PLONK n=3; registry is the minimum on PLONK n=2.
* That is a model result, not a validated recommendation for the named Zolana
  transaction implementations.
* No recommendation is established for ordinary Zolana `transact`, because the
  model cannot evaluate n=1.

## Blocking and high-severity findings

### A1. The reconciliation is stale and does not reconcile the published tables

`zolana-cu-b5/RECONCILIATION.md:14-16,57,109` and
`zolana-cu-b5/reconciliation.json` still use the pre-decompression cells:

| Groth16 n=2 cell | Reconciliation | Current Table #1 | Difference |
|---|---:|---:|---:|
| Batching B5 | 42,458 | 73,544 | 31,086 |
| Recursion B5 | 44,043 | 61,187 | 17,144 |

The current values are at `TRANSACTION-TABLE.md:9`. The reconciliation also still
says that no cell charges decompression (`RECONCILIATION.md:238-249`) and claims its
old cells reproduce the worktree exactly (`RECONCILIATION.md:188-199`). Both claims
are false after `contract.rs:386-393` added wire decompression.

The JSON ladders still sum to their targets:

* primary: 227,880, target 227,880, unattributed 0;
* recursion: 221,695, target 221,695, unattributed 0.

That closure does not validate the current cells. Each stale cell is removed in full
before the measured transaction is inserted, so an obsolete cell can close just as
well as a current one.

The advertised 5.4x budget warning is consequently obsolete:

* old comparison: `227,880 / 42,458 = 5.367x`;
* current comparison: `227,880 / 73,544 = 3.099x`;
* current batch cell plus the published two-solo bands:
  `73,544 + 50,104 + 97,650 = 221,298`, or `3.009x` the cell.

There is no test or pipeline check covering either reconciliation document.

### A2. The n=2 recursion win does not survive comparison with the real recursion verifier

The repository already warns that the Recursion and Registry columns do not measure
the named implementations (`README.md:3-8`; `CONFORMANCE-PLAN.md:15-49`). The new
decompression charge does not cure that mismatch.

The synthetic recursion trace uses one padded eight-pair check and models BSB22
reduction as a 16-CU `fr_lincomb` path (`contract.rs:445-452`). The real recursion
program instead makes two pairing calls and runs the BSB22 reduction in guest ark-ff
code. The real-program probe measures a 70,916-CU verification core and identifies
13,208 CU in that guest reduction (`RECONCILIATION.md:107-145`).

After removing only the known fixture-compression artifact described in A5:

| Groth16 n=2 verification candidate | CU |
|---|---:|
| Synthetic recursion | 61,187 - 706 = 60,481 |
| Synthetic registry | 67,561 - 892 = 66,669 |
| Real recursion verifier | 70,916 |

The real recursion verifier is 4,247 CU above the registry model. The published
6,374-CU recursion-over-registry margin is smaller than the model-to-real error.
The current n=2 row therefore cannot support a firm recursion recommendation.

The application mapping is also capable of flipping the narrow n=2 comparison.
Two solo legs carry 97,650 CU of application work; the measured two-leg aggregate
carries 100,675 CU. That 3,025-CU topology difference exceeds the 2,628-CU gap
between the real recursion core and the published batch model:

* batch + two-solo bands: `73,544 + 50,104 + 97,650 = 221,298`;
* batch + aggregate bands: `73,544 + 50,104 + 100,675 = 224,323`;
* measured recursion transaction: 221,695.

There is no real folded-batch Zolana transaction with which to choose between those
two application mappings. Zero closure cannot resolve that counterfactual.

### A3. The Table #3 ratio is not comparable with the cited real 34.7%

`STRUCTURE-TABLE.md:3-5` labels each cell as `syscall CU / sBPF CU`. The real 34.7%
number is instead **BN254 CU divided by the whole transaction**:

* BN254 decompression: 14,706;
* BN254 group operations: 24,786;
* `39,492 / 113,940 = 34.66%`.

The same real leg also contains 45,588 Poseidon CU, 874 hash CU, 740 memory CU,
7,881 CPI/runtime CU, 110 sysvar CU, and 150 ComputeBudget CU. Its measured sBPF is
only 19,105 CU. Named non-sBPF work is therefore:

`113,940 - 19,105 = 94,835`, or **83.23%** of the transaction.

Other useful, but different, ratios are:

* BN254 plus hash families: `(39,492 + 874) / 113,940 = 35.43%`;
* BN254 plus statement-compression Poseidon:
  `(39,492 + 18,078) / 113,940 = 50.53%`;
* current n=2 batch cell expanded with all named two-solo non-sBPF bands:
  `177,043 / 221,298 = 80.00%` on the committed classification.

Thus the prediction that Table #3 should move toward 34.7%, and the claim that its
current values are 2.5x away from a like-for-like real share, compare different
numerators. Table #3 is more accurately "selected modeled syscall core / cell
total"; it is not an all-syscall-versus-sBPF partition.

### A4. The prose ranking is wrong for PLONK n=3

The statement that batching wins the PLONK rows contradicts Table #1:

| PLONK row | Registry | Batch | Recursion | Winner |
|---|---:|---:|---:|---|
| n=2 | 52,492 | 57,595 | 61,887 | Registry |
| n=3 | 72,032 | 77,082 | 64,170 | Recursion |

Batching wins only PLONK n=2. Recursion wins PLONK n=3 by 7,862 CU over registry
and 12,912 CU over plain batching (`TRANSACTION-TABLE.md:11-12`).

The n=2 PLONK result is itself provisional. The multi-VK transcript term is not
measured (`B5-CHARGE-SCHEDULE.md:104-131`; `syscalls/src/lib.rs:3751-3773`). Its
13.5% "overcharge" only establishes headroom over equivalent hash syscalls:

| Shape | Transcript charge | Hash proxy | Known headroom |
|---|---:|---:|---:|
| n=2 | 5,302 | 4,670 | 632 |
| n=3 | 7,853 | 6,935 | 918 |

Native work around hashing is unmeasured, so the total reducer charge has not been
shown conservative. The ordinary n=2 batch margin over recursion is only 4,292 CU.
The registry result has the additional ABI problem in A8.

For PLONK, decompression is also an assumed future wire contract rather than an
observed Zolana transaction format. The exporter stores 64-byte affine G1 points
(`sbf/plonk-direct/src/lib.rs:2326-2339`); the guest then simulates a compressed
deployment with a compress/decompress round trip (`:896-908`). This can be a valid
design assumption, but it must be labeled as such.

### A5. Every residual contains a known fixture-only syscall artifact

The benchmark fixtures hold affine points. Each guest executes `compress ->
decompress` to simulate receipt of a compressed proof. The collector subtracts the
modeled decompression but deliberately leaves compression in
`non_core_transaction_cu` (`bn254-decision-collector/src/main.rs:780-823`;
`bn254-decision-litesvm/src/lib.rs:301-349`). No deployment receiving compressed
proof bytes pays this compression.

At the committed 100-CU syscall base, G1 compression costs 130 CU and G2
compression 186 CU. Known overstatement is:

| Row | Non-recursive columns | Recursion |
|---|---:|---:|
| Groth16 n=5 | 2,230 | 706 |
| Groth16 n=2 | 892 | 706 |
| Groth16 n=3 | 1,338 | 706 |
| PLONK n=2 | 2,340 | 706 |
| PLONK n=3 | 3,510 | 706 |

The fixture round trip and equality test also add unisolated sBPF, so these are
lower bounds. Removing the known charge does not change the synthetic winner in any
row, but it does invalidate both the totals and the Table #3 classification: a
syscall charge is currently labeled `sBPF`.

It also explains every syscall-bearing cell currently below 80%. Removing only the
known artifact changes the PLONK shares to:

| Row | Batch | Registry | Batch+Fp12 |
|---|---:|---:|---:|
| n=2 | 83.7% | 81.0% | 83.6% |
| n=3 | 83.1% | 81.0% | 83.0% |

### A6. The observed-trace source revision is false

All 30 cells in `observed-traces.json` claim runtime revision
`91ac8d4d983443fae079ac49dcc246bf3c2d4acf`. Git history shows that commit
`806637620` added the decompression guest, observer, collector, trace, and table
changes; `91ac8d4d` is its grandparent.

The decompression-corrected artifacts therefore cannot come from the clean source
revision they name. They were captured from a dirty descendant while HEAD still
pointed at 91ac. `collect-residuals.sh:61,87-90` records `git rev-parse HEAD` but has
no clean-tree gate or source-tree digest. Tests do not validate the revision or bind
`program_sha256` back to a reproducible source tree.

This does not by itself falsify the CU values, but it breaks the stated provenance
and prevents a clean checkout of the recorded revision from reproducing them.

### A7. The model cannot express the only ordinary Groth16 shape Zolana sends

`RowId` has no n=1 variant (`model.rs:72-125`). `groth_msm` is a per-row literal
matrix ending in `unreachable!()` (`contract.rs:361-382`). The real-program
reconciliation confirms that ordinary `transact` carries one proof
(`RECONCILIATION.md:23-49,310-314`).

Consequently the headline Groth16 recommendation cannot be tested against the
ordinary deployed path. The existing n=1 unit test only checks the charge of a
manually constructed decompression/G1-operation trace (`tests/contracts.rs:976-1007`);
it does not make any decision column evaluable at n=1.

### A8. Registry values do not target the independently owned registry ABI

The current branch uses 37,584-byte prepared-G2 records
(`bn254-batch-syscall/src/registry_abi.rs:7` and
`sbf/plonk-direct/src/lib.rs:90-99`). The independently owned prepared ABI pins
16,712 bytes. The divergence and resulting 2.25x entry-size overmeasurement are
already recorded in `CONFORMANCE-PLAN.md:31-44`.

The current registry column can be read as an internally consistent experiment for
this branch's v3 registry. It cannot be presented as the result for the independently
owned VK-registry target.

Groth16 `Current+Fp12` and `Batch+Fp12` also depend on an undisclosed preinitialized
registry containing cached GT targets. The collector initializes and excludes that
account before the hot measurement (`bn254-decision-collector/src/main.rs:338-364,
654-687`), and both handlers read it (`sbf/groth16/src/lib.rs:776-837,927-1000`).
The identically named PLONK Fp12 columns require no registry. Hot-path comparison is
reasonable only after setup cost, account lifecycle, and amortization are published.

### A9. Table #2 omits priced stock G1 work

The trace contains and Table #1 charges stock G1 additions and multiplications
(`contract.rs:405-409,535-540`; `pricing.rs:119-128`). The operations renderer never
emits them (`examples/render_ops_table.rs:53-119`).

Omitted charges are:

| Stock row | Omitted G1 CU |
|---|---:|
| Groth16 n=2 / n=3 / n=5 | 8,348 / 12,522 / 20,870 |
| PLONK n=2 | 165,624 |
| PLONK n=3 | 248,436 |

For PLONK Current, this is about 60% of the syscall numerator; for PLONK
Current+Fp12, about 66%. Table #1 includes the cost, but Table #2 does not explain
the operations producing its own totals.

## Medium-severity coverage and publication findings

### B1. There are four, not three, syscall-bearing cells below 80%

The committed cells are PLONK n=2 Registry 77.3%, PLONK n=3 Batch 79.3%, PLONK
n=3 Registry 77.0%, and PLONK n=3 Batch+Fp12 79.2%
(`STRUCTURE-TABLE.md:12-13`). `BatchFp12B5` is explicitly syscall-bearing
(`pricing.rs:230-234`).

No 80% floor is enforced. The implemented smell gate is 25% (`pricing.rs:220-225`),
and pipeline failure is optional unless `BN254_STRUCTURE_STRICT=1`
(`run-pipeline.sh:90-97`). As A5 shows, all four sub-80 results disappear after
removing the known fixture-only compression charge.

### B2. Golden tests establish reproducibility, not semantic approval

`run-pipeline.sh:50-83` renders to scratch, reports a changed golden only as a note,
copies it over the committed file, then re-renders and tests the new output. This
catches nondeterminism and later hand edits, but it does not reject a semantically
wrong renderer/model change.

The four guest crates are independent workspaces. The official pipeline runs the
decision-bench and tariff tests but not their host semantic/mutation suites
(`run-pipeline.sh:99-100`). The collector's one-byte negative case
(`bn254-decision-collector/src/main.rs:825-845`) is useful but is not a substitute
for component-by-component proof/VK/public-input/transcript binding tests.

### B3. The real-program captures are not fully source-sealed

The harness uses absolute external LiteSVM/Zolana paths and external prover/key
state (`zolana-cu-b5/Cargo.toml:20-21,42-51`; `zolana-cu-b5/run.sh:11,21-31`). The
reconciliation records a prose source description, not the external source-tree,
program, and proving-key digests required to recreate those raw captures from a
clean checkout.

This is a provenance limitation, not evidence that the committed raw numbers are
wrong.

## Checks that passed

* `cargo test -p solana-bn254-decision-bench`: 46/46 tests passed
  (3 unit, 24 contract, 4 observed-trace, 6 render, 9 seal).
* `cargo test -p solana-syscalls --test bn254_charge_schedule`: 11/11 passed.
* `cargo test --manifest-path zolana-cu-b5/Cargo.toml`: 2/2 passed.
* All 30 Table #1 totals recompute as the shared syscall price plus the committed
  residual; all Table #3 numerators match the same pricing path.
* The current decompression arithmetic is correct:
  * G1: `100 + 398 = 498`;
  * G2: `100 + 13,610 = 13,710`;
  * Groth16 n=5: `10*498 + 5*13,710 = 73,530`;
  * recursion: `4*498 + 13,710 = 15,702`;
  * PLONK n=2: `18*498 = 8,964`.
* Same-VK and distinct-VK pairing shapes, lane padding, registry reuse of the batch
  MSM shape, hash arithmetic, repeated-sample equality, and fixture digests pass
  their committed controls.
* Raw `probe-b5-2.txt` supports the measured 113,940/221,695 totals, 14,706 CU per
  ordinary Groth16 proof, 23,505 CU for a four-pair B5 check, and 379 CU for the
  BSB22 SHA-256 calls.
* Removing the known fixture-compression tariff artifact does not change the
  synthetic winner in any of the five rows.

## Limits of this audit

The full 30-cell collector and timing capture were not rerun. This audit used the
committed residuals, traces, fixtures, timing records, raw Zolana captures, runtime
source, renderers, and test suites. It validates accounting relationships and finds
decision/evidence failures; it is not an independent cryptographic proof of the
folding protocols, validator-fleet calibration, a B5 decompression tariff, or real
application bands for transaction shapes that Zolana does not implement.
