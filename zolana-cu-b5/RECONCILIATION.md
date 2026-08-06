# From a decision-table cell to a real zolana transaction

Every compute unit of two real transactions is on a named line below. Nothing is
rounded away and no line is an allowance. Both ladders close to zero.

Measured on this harness, LiteSVM over the unmodified shielded-pool program from
`dev/zolana/.worktrees/groth16-recursion`, agave runtime 4.1.2, B5 group op
installed by `src/kernel.rs`. Raw output in `artifacts/probe-b5-2.txt`.

| | measured |
|---|---:|
| solo `transact`, one leg, B5 | 113,940 |
| solo `transact`, one leg, stock | 166,940 |
| `aggregate_transact`, 2 legs, B5 | 221,695 |
| decision-table cell, Groth16 n=2 distinct VK, Batching B5 | 42,458 |
| decision-table cell, Groth16 n=2 distinct VK, Recursion over B5 | 44,043 |

## What each number counts, and the mapping between them

The two are not the same shape, and the reconciliation says so instead of
dividing one by the other and calling it normalised.

A decision-table row is **n proofs verified inside one transaction**. The
Batching column folds those n proofs into one pairing check. zolana sends no such
transaction. What zolana sends is either

* `transact`, **one leg carrying one Groth16 proof**, verified by the ordinary
  four-pair check, or
* `aggregate_transact`, **one recursive proof attesting n leg statements**, plus
  the full state machine of all n legs.

So the row and the transaction differ in three ways at once: the proof count per
transaction, whether the proofs are folded, and whether the application work of
n legs is present.

**The mapping chosen.** The Batching cell at n=2 is compared against **two solo
`transact` transactions**, 2 x 113,940 = 227,880. Both sides then carry two
Groth16 proofs over the same statements. Nothing is halved, so every line is an
integer and no line hides a division. The Recursion cell at n=2 is compared
against **one `aggregate_transact` over 2 legs**, which is the shape that column
actually names.

**The mapping refused.** Dividing the Batching cell by two gives 21,229 per
proof. That number is not a model evaluation. The fold's pairing charge is one
padded eight-pair call, not two things; and the same model cannot be evaluated at
n=1 at all, because `bn254-decision-bench/src/contract.rs::groth_msm` carries a
hard-coded point matrix per published row and reaches `unreachable!()` for any
other shape. The only Groth16 shape zolana runs today is therefore outside the
model's domain. That is a finding, not an inconvenience.

## Ladder 1: Batching syscalls (B5), n=2, to two real legs

### Stage 1, the verification model against the verification measured

| line | CU | class | source |
|---|---:|---|---|
| decision-table cell, Groth16 n=2 distinct VK, Batching B5 | 42,458 | — | derived |
| − fold pairing check, 1 call, 8 pairs | −27,160 | verification | derived |
| − fold MSM, 8 calls over 10 points | −8,304 | verification | derived |
| − fold scalar inner products, 4 calls of 1 term | −8 | verification | derived |
| − fold transcript hashing, 5 calls over 35 slices | −1,473 | verification | derived |
| − synthetic fold guest sBPF | −5,513 | verification | measured, other pipeline |
| **= nothing is left of the cell** | **0** | | |
| + pairing check, 2 x 4 pairs, B5 | +47,010 | verification | measured |
| + G2 decompression of proof B, 2 x 13,710 | +27,420 | verification | measured |
| + G1 decompression of proof A and C, 4 x 498 | +1,992 | verification | measured |
| + public-input commitment, 2 x (MSM 1 point + G1 add) | +2,562 | verification | measured |
| + Groth16 verifier guest sBPF, 2 x 571 | +1,142 | verification | measured |
| **= verification core of two real legs** | **80,126** | | |

Every line of the cell is removed, because every line describes the fold and
zolana does not fold. Only the pairing *family* survives the crossing, and the
cell charges 27,160 where two unfolded checks cost 47,010. That 19,850 is the
batching claim, and it is the only part of the cell that transfers.

### Stage 2, everything the cell does not carry

| line | CU | class | source |
|---|---:|---|---|
| carried from stage 1 | 80,126 | | |
| + statement compression, Poseidon, 2 x 23 calls at arity 2 | +36,156 | verification | measured |
| + statement compression, guest sBPF, 2 x 6,974 | +13,948 | verification | measured |
| + application Poseidon, 2 x 35 calls at arity 2 | +55,020 | application | measured |
| + application guest sBPF, 2 x 11,560 | +23,120 | application | measured |
| + keccak256 and sha256, 2 x 7 calls over 7 slices | +1,748 | application | measured |
| + memory operations, 2 x 74 calls | +1,480 | application | measured |
| + CPI invoke base, 6 x 946 | +5,676 | application | derived |
| + CPI callee builtin, 4 x system program at 150 | +600 | application | derived |
| + CPI account-data translation, 2 x 4,743 | +9,486 | application | derived |
| + clock sysvar read, 2 x 110 | +220 | application | measured |
| + ComputeBudget instruction, 2 x 150 | +300 | application | measured |
| **= two solo `transact` transactions, measured** | **227,880** | | |
| **unattributed** | **0** | | |

### The same leg under the stock schedule

The stock leg is 166,940. Only two lines move: the pairing check goes from 23,505
to 73,612 and the public-input multiplication from 947 to 3,840. Decompression is
14,706 in both, because the B5 schedule states no decompression tariff and the
harness charges the stock price for it in both configurations.

## Ladder 2: Recursion over B5, n=2, to `aggregate_transact`

This is the shape-correct comparison: one recursive proof over 2 legs on both
sides.

| line | CU | class | source |
|---|---:|---|---|
| decision-table cell, Groth16 n=2 distinct VK, Recursion over B5 | 44,043 | — | derived |
| − outer pairing check, 1 call, 6 real pairs padded to 8 | −27,160 | verification | derived |
| − outer MSM, 6 calls over 11 points | −7,502 | verification | derived |
| − BSB22 reduction as `fr_lincomb`, 7 calls | −16 | verification | derived |
| − outer transcript hashing, 7 calls over 34 slices | −1,625 | verification | derived |
| − synthetic recursion guest sBPF | −7,740 | verification | measured, other pipeline |
| **= nothing is left of the cell** | **0** | | |
| + outer pairing checks, 4 pairs and 2 pairs, B5 | +38,310 | verification | measured |
| + decompression, 1 G2 and 4 G1 | +15,702 | verification | measured |
| + public-input commitment, 2 MSM of 1 point and 3 G1 adds | +2,896 | verification | measured |
| + BSB22 hash-to-field, 3 `sol_sha256` calls | +379 | verification | measured |
| + recursive verifier guest sBPF | +13,629 | verification | measured |
| **= verification core of the aggregate** | **70,916** | | |
| + statement compression, Poseidon, 46 calls | +36,156 | verification | measured |
| + statement compression, guest sBPF | +13,948 | verification | measured |
| + application Poseidon, 73 calls | +57,378 | application | measured |
| + application guest sBPF | +23,997 | application | measured |
| + keccak256 and sha256, 14 calls | +1,748 | application | measured |
| + memory operations, 153 calls | +1,530 | application | measured |
| + CPI invoke base, 6 x 946 | +5,676 | application | derived |
| + CPI callee builtin, 4 x system program at 150 | +600 | application | derived |
| + CPI account-data translation, 2 x 4,743 | +9,486 | application | derived |
| + clock sysvar read | +110 | application | measured |
| + ComputeBudget instruction | +150 | application | measured |
| **= `aggregate_transact` over 2 legs, measured** | **221,695** | | |
| **unattributed** | **0** | | |

Three cell lines are wrong in kind here, not only in size.

* The cell models **one** padded eight-pair check. The real recursion verifier
  issues **two** checks, four pairs for the Groth16 equation and two for the
  BSB22 proof of knowledge. Padding both into one lane is available and unused,
  which is worth 11,150 CU.
* The cell charges 16 CU of `fr_lincomb` for the BSB22 hash-to-field reduction.
  The real program still runs the ark-ff loop, in the guest, for **13,208 CU**
  inside `Groth16Verifier::verify_common`. The syscall the cell prices is not
  called by the program the column names.
* The cell's transcript-hash model is nonetheless exact where the program agrees
  with it. `contract.rs::bsb22_hash_to_field()` prices three calls at 379 CU and
  the three measured `sol_sha256` calls cost 379 CU. That is an independent
  confirmation of the hash tariff and of the slice-length model behind it.

## How each line was obtained

**MEASURED** means a charge the runtime made during the transaction under
measurement, read either from the VM register trace with the argument registers
that fixed the price, or from the compute meter either side of the charge site.

* Every BN254 call: operation selector in r1 and input size in r3, from the
  register trace. `sol_alt_bn128_group_op` r1=3 r3=768 is four pairs; `pairing_be`
  is the only issuing frame.
* Decompression: `sol_alt_bn128_compression` r1=1 twice and r1=3 once, issued
  from `groth16_solana::decompression::decompress_g1` and `decompress_g2`.
* Poseidon: arity read from r4 at every call, always 2, so 786 CU each. The split
  between statement compression and the state machine comes from the
  stack-walking collector in `src/attribute.rs`, which credits a call to every
  frame beneath which it was issued. 23 of 58 sit under
  `TransactProof::public_input_hash` in the solo leg, 46 of 119 in the aggregate.
* Hash syscalls: the price-neutral `sol_sha256` and `sol_keccak256` shims in
  `src/kernel.rs`, which reproduce the runtime's schedule and additionally read
  the slice lengths that live in guest memory and never reach a register trace.
* CPI and sysvar: new price-neutral observers in `src/probe.rs`. They delegate to
  the stock `SyscallInvokeSignedC` and `SyscallGetSysvar` and read
  `ContextObject::get_remaining` either side. Measured windows are
  `[1096, 5838, 993]` per leg and 110 CU for the sysvar.
* sBPF: one compute unit per executed instruction, from the register trace.
  Per-frame figures are inclusive over nested calls.
* ComputeBudget instruction: the runtime log states the top-level program
  consumed 113,790 of a 113,940 transaction. The 150 is the difference.

**DERIVED** means computed from committed code rather than observed on its own
line.

* The three CPI sub-lines. The 7,927 CU per-leg window is measured; splitting it
  into 946 invoke base (`DEFAULT_INVOCATION_COST`), 150 system-program builtin
  and 4,743 account-data translation uses the runtime source. The translation
  term is confirmed independently: the pool tree account is 1,185,728 bytes, and
  `1,185,728 / 250` is 4,742, which is the whole of the 5,838 CU window once 946
  and 150 are removed. The remaining 1 CU is the event instruction's own data.
* Every cell figure. Recomputed here from `contract.rs` and the committed charge
  schedule, and it reproduces the published cells exactly, 42,458 and 44,043,
  including the family split 27,160 / 8,304 / 8 / 1,473 that `STRUCTURE-TABLE.md`
  publishes as 36,945.

**ESTIMATE** appears nowhere in the two ladders. No line is estimated.

Every cell figure was read from `bn254-decision-bench` as the worktree holds it
today, which another session is editing. The recomputation reproduces the
published `TRANSACTION-TABLE.md` and `STRUCTURE-TABLE.md` cells exactly, so the
two agree at the time of writing, but a later edit there moves the cell side of
both ladders and not the measured side.

## Where the synthetic guest is leaner, and what the real program does instead

The Batching cell carries 5,513 CU of guest sBPF for two proofs. Two real legs
execute 38,210. The difference is 32,697 CU, and it is not overhead.

Per leg, 19,105 instructions, inclusive by frame:

| frame | sBPF | what it is |
|---|---:|---|
| `TransactProof::verify` | 7,626 | statement plus verifier |
| ↳ `TransactProof::public_input_hash` | 6,974 | statement compression |
| ↳↳ `amount_field` | 5,235 | u64 amounts into Fr through ark-ff |
| ↳↳↳ `__multi3` | 4,184 | the 128-bit multiply that conversion compiles to |
| ↳ `verify_groth16` | 571 | the Groth16 verifier itself |
| `apply_output_tree` | 3,035 | batched Merkle append of 3 output leaves |
| `apply_input_tree` | 2,143 | nullifier queue insert and bloom check |
| `ExternalDataHash::hash` | 1,482 | binding the settlement instructions into the statement |
| `emit_general_event` | 1,220 | the event the indexer consumes |
| `TransactIxDataRef::from_bytes` | 917 | parsing 508 bytes of wincode instruction data |
| `fill_output_owner_pk_hashes` | 384 | output owner tags |
| `validate_and_parse` | 313 | account checks |

Only the 571 is the thing the cell's residual is trying to model, and the cell
charges 2,757 per proof for it. The synthetic guest is not leaner than the
verifier; it is a different guest, running a fold the real program never runs.

The recursion column inverts the error. Its residual is 7,740, and the real
recursive verifier's guest subtree is 13,629, of which 13,208 is the ark-ff
BSB22 reduction the column assumes has already been moved into a syscall.

Under the dynamic rule of `zolana-cu-split-core`, which marks every instruction
executed beneath an ark-ff, ark-ec or `groth16_solana` frame, the BN254-adjacent
sBPF of a solo leg is 2,511, not 571. The extra 1,940 is field arithmetic inside
statement compression, not inside the verifier.

## Findings

1. **Point decompression is charged by no cell and is 14,706 CU per proof.** A
   single G2 decompression is 13,710 of it, 12.0 percent of a real leg and 32.3
   percent of the whole n=2 Batching cell. A Groth16 proof arrives compressed; no
   column can avoid the cost and no column prices it. `contract.rs` emits no
   compression operation and the B5 schedule states no decompression constant.
   This is the single largest omission in the table and it is pure verification.

2. **The B5 run still pays the stock decompression price.** `Mode::bn254_cu`
   routes `sol_alt_bn128_compression` to `stock_compression_cu` in every
   configuration, because the B5 schedule has nothing to say about it. If the
   IFMA kernel decompresses faster, 13,710 CU per proof is an overcharge of
   unknown size. Unmeasured, and not closed here.

3. **The advertised saving does not survive the crossing.** The table reads
   157,064 for Current against 42,458 for Batching B5 at n=2, a 3.70x cut. On the
   real transaction the same schedule change moves 333,880 to 227,880, a 1.47x
   cut. The difference is not the batching claim, which holds. It is that 65
   percent of a real leg is work no column touches.

4. **The structural claim is off by a factor of two and a half.**
   `STRUCTURE-TABLE.md` puts the n=2 Batching cell at 87.0 percent syscall. On a
   real leg the BN254 syscalls are 39,492 of 113,940, 34.7 percent. The cell is
   not measuring its wrapper; it is measuring a transaction with no application
   in it.

5. **One application line is 4,743 CU and depends on nothing about the proof.**
   Every CPI that touches the 1,185,728-byte pool tree account pays
   `len / 250` for translating it. That is 11.2 percent of the whole n=2 cell,
   and it scales with the tree account, not with the proof or the column.

6. **Statement compression is 25,052 CU per leg, 22.0 percent of the leg, and
   invariant.** 18,078 is Poseidon and 6,974 is guest sBPF. It exists because
   every zolana verifying key declares exactly one public input, so the statement
   must be folded before the verifier can consume it. `OPERATIONS-TABLE.md`
   carries the Poseidon half in a footnote table and the sBPF half nowhere.

7. **The recursion column prices a syscall the recursion program does not call.**
   16 CU of `fr_lincomb` against 13,208 CU of ark-ff in the guest.

8. **The hash tariff is confirmed.** `bsb22_hash_to_field()` prices three calls at
   379 CU and the three measured calls cost 379 CU. The per-slice length model
   behind it is right.

9. **The pairing tariff is confirmed.** The schedule charges 23,505 for four pairs
   and the measured four-pair check costs 23,505. The syscall core of the table is
   sound. What is wrong is everything the core is embedded in.

## Stability

The solo leg is 113,940 in every run and every committed artifact.

The aggregate moves by up to 20 CU between runs, because `Pubkey::new_unique()`
hands the settlement recipients different bytes depending on how many were drawn
earlier in the process. Those bytes reach the leg statements, the leg statements
reach the outer proof's public inputs, and `from_le_bytes_mod_order` runs a
slightly different number of iterations on them. The drift is therefore confined
to one line, `verify_groth16`, and every other line of ladder 2 is bit-stable
across runs: statement compression is 13,948 and application sBPF is 23,997 in
every run observed. The drift is 0.009 percent. Ladder 2 uses the run committed
as `artifacts/probe-b5-2.txt` so that it closes on its own evidence.

## What would have to change in the pipeline

### Belongs inside a cell

**Decompression.** Add `G1Decompress` and `G2Decompress` to `OperationKind` and
to `OperationTrace`, count them from the proof encoding the fixture actually
carries, and fit a B5 tariff for them on the capture host. Without this every
Groth16 cell in the table is short by 14,706 CU per proof, and the B5 columns are
short by the largest relative margin because they shrank everything around it.
This is the one change that most improves every cell at once.

**A model that can be evaluated at n=1.** `groth_msm` is a hard-coded matrix keyed
by published row, and it panics on any other shape. Derive the MSM point counts
from the fixture's public-input width and key count instead. Until then the model
cannot price the only Groth16 transaction zolana sends today, which makes the
"real Zolana proofs" rows unfalsifiable against the real program.

**The guest residual.** 5,513 for the Batching cell against 571 of real verifier
sBPF, and 7,740 for the recursion cell against 13,629. The residual is 13.0 and
17.6 percent of its cell, so it is not a rounding term, and it currently
describes a guest that exists only in the bench. Measure it on the real program
where a real shape exists, and label it explicitly as modelled where none does.

**Two pairing calls, not one.** The recursion column assumes the outer verifier
folds the Groth16 equation and the BSB22 knowledge check into one padded call.
The real verifier does not. Either fix the model or fix the program, but the cell
should not silently claim the better of the two.

### Belongs beside a cell

**The application band.** 48,825 CU for a solo leg and 100,675 for the 2-leg
aggregate: Poseidon state machine, guest sBPF, hashing, memory operations,
CPI, sysvar and the ComputeBudget instruction. None of it moves with the column,
which is exactly why it should be published as a named constant next to the
table rather than folded into a cell. A reader who converts 42,458 into a
transaction budget today is out by a factor of five.

**Statement compression, 25,052 CU per leg.** Verification by the table's own
definition, invariant across all six columns. Publish it as its own band beside
the cells, with the sBPF half included, and state the convention it depends on:
one public input per verifying key. If that convention changes, the band moves
and the cells do not.

**The CPI account-data term.** 4,743 CU driven by a 1.19 MB account. It belongs in
the application band with its own line, because it is the one number a reader
would never guess and it will grow with the tree.

### Should the pipeline be rebuilt around the real program?

**Partly, and the evidence says exactly which part.**

For: three of the four largest lines found here, decompression, statement
compression and the CPI translation charge, were invisible to the pipeline and
appeared the moment the real program ran. The synthetic residuals do not describe
any real guest, in either direction. The harness that found all of this already
exists in this directory, reproduces the published zolana numbers exactly, and
now closes to zero unattributed CU on two transactions.

Against: the real program can only be run at the shapes it supports. That is
`transact` at n=1 and `aggregate_transact` at batch 1, 2 or 3, the latter capped
by `AggregateCircuitId::is_supported` and by the compiled verifying keys. It
cannot produce the 5-proof same-VK row, any distinct-VK Groth16 batch row, or any
PLONK row, because no such transaction exists to send. A real-program pipeline
would measure 2 of 30 cells. The batch and registry columns are counterfactuals
by construction and a counterfactual needs a model.

So: keep the syscall core as a tariff. It is confirmed twice over here, once on
the pairing charge and once on the hash charge, and it is the part of the pipeline
that is working. Change three things around it. Add the missing verification
operations to `contract.rs`, starting with decompression. Replace the
synthetic-guest residual with a real-program measurement wherever a real shape
exists and mark it modelled where none does. Publish the application and
statement-compression bands beside every cell, measured on the real program, so
that a cell plus its bands is a transaction budget rather than a fragment of one.

That keeps all 30 cells and stops the table from being wrong by 5x when someone
uses it to size a deployment.
