# helios-bn254: design

For a reviewer who is strong on systems and new to pairings. Each section
teaches the intuition first, then states the precise claim and where it is
enforced in the tree. Numbers are measured on two boxes: "Zen 4" (AMD, ADX
tier) and "Granite Rapids" (Intel, ADX tier); the sources are `build.rs`
comments and commit messages, both of which are updated with every measured
decision.

## 1. What this crate does, and the one constraint that shapes everything

The crate implements the BN254 (`alt_bn128` / mcl `BN_SNARK1`) operations a
Solana validator runs in consensus -- G1 multi-scalar multiplication, the
boolean pairing-product check, Fr linear combination and batch inversion --
behind an Agave-shaped byte facade (`src/batch.rs`). It does verification
only, and that single fact is the design constraint everything else follows
from: **all inputs are public, so every algorithm is variable-time by
design.**

The timing-leak trade, in the four sentences a security engineer needs: a
timing side channel is only a vulnerability when running time depends on data
the attacker does not already have. A verifier's inputs -- proof bytes,
public signals, verification key -- are public by definition, so an attacker
who times this code learns nothing they could not compute themselves.
Dropping the constant-time requirement legalizes exactly the tools that make
bignum arithmetic fast: conditional subtractions that branch on the borrow,
early exits, value-dependent windows (GLV + joint wNAF in the MSM), and
variable-time inversion (Kaliski Montgomery inverse; Bernstein-Yang divsteps,
ePrint 2019/266). The boundary is stated loudly rather than defended subtly:
the crate docs, README, and facade docs all say that feeding it a secret --
a key, a witness -- hands the attacker a side channel, and that use is
declared out of contract.

The facade is the checked boundary: canonical big-endian bytes only, values
`>= p` (or scalars `>= r`) rejected and never reduced, fixed
consensus-visible validation order, full r-subgroup check for G2. The typed
tower underneath (`Fp`, `Fp2`, ..., `Fp12`, curve types) is exported for
embedders and tests but performs no revalidation.

## 2. The arithmetic stack, bottom-up

### 2.1 Montgomery form

Reducing mod p after a multiply requires dividing by p, which is expensive;
dividing by a power of the word size is a shift, which is free. Montgomery
form trades one for the other: represent v as `v*R mod p` with `R = 2^256`,
and then the product of two representatives needs exactly one division by R,
done by adding a multiple of p that zeroes the low words. Pen-paper miniature
with p = 13, R = 10: represent 7 as `7*10 mod 13 = 5` and 2 as
`20 mod 13 = 7`; their plain product is 35, and the representative of `7*2`
should be `140 mod 13 = 10`. To divide 35 by 10 mod 13, add the multiple of
13 that makes the last digit zero -- `-13^-1 mod 10 = 3`, `m = 35*3 mod 10 =
5`, `35 + 5*13 = 100` -- and shift: `100/10 = 10`. Exactly that trick, one
64-bit word at a time, is the CIOS loop in every kernel here: per word,
compute `m = t0 * (-p^-1) mod 2^64`, add `m*p`, shift.

Cost anchor for everything below, in `mulx` (64x64->128 multiply) counts on
x86: a 4x4-limb product is 16 mulx; one Montgomery reduction is 20 mulx
(4 rounds x (1 for `m` + 4 for `m*p`)). One full Montgomery multiply = 36.

### 2.2 The sum-of-products kernel (Longa, ePrint 2022/367, Alg. 2)

The reduction does not care what 512-bit value it reduces. So when the
algorithm wants `a0*b0 + a1*b1 mod p` -- and tower arithmetic wants almost
nothing else -- sum the products first and reduce once. Cost algebra: T
separate Montgomery muls cost `36T` mulx; a T-term sum of products costs
`16T + 20`. At T = 2 that is 52 vs 72; at T = 6, 116 vs 216. Subtraction
enters as a product with `negp(x) = p - x`, so `a0*b0 - a1*b1` (the real part
of an Fp2 multiply) is the same two-product sum.

The slack that makes it sound: BN254's `p < 0.1891 * 2^256`. Between CIOS
rounds the accumulator stays below `(T+1)p`, so five limbs suffice through
T = 4 and six through T = 10; the final value is below `(1 + 0.1891T)p`,
canonicalized by one conditional subtraction for T <= 4 and two for T <= 10.
The whole argument is written in `src/fp/sos.rs` and re-checked as
debug-asserts in the portable kernels and as machine-checked claims in the
assembly schedules (section 3).

Two packaging decisions matter as much as the algebra. Dual-lane kernels
compute both Fp components of an Fp2 sum in one call with the two lanes' rows
interleaved: each lane alone is a serial carry chain longer than the
out-of-order window, so two sequential calls get no overlap, while
interleaving keeps both chains in flight (~2x ILP, same instruction count).
And on the ADX tier one rolled 540-byte kernel (`helios_sos_x86`, pointer
table, even T in {2, 4, 6, 8, 10}) serves every SoS shape in the tower, because the pairing
hot path is frontend-bound (see 2.4) and unrolled bodies do not fit.

### 2.3 The tower and its operation economics

`Fp2 = Fp[u]/(u^2+1)`, `Fp6 = Fp2[v]/(v^3 - (9+u))`,
`Fp12 = Fp6[w]/(w^2 - v)`. A pairing is a Miller loop (64 doubling and 23
addition steps over the NAF of `6x+2`, line formulas per ePrint 2013/722;
63 Fp12 squares and one sparse `mul_by_034` line update per step) followed by
a final exponentiation (Fuentes-Castaneda hard part, ePrint 2011/506: 60 full
Fp12 muls plus 192 cyclotomic squares sitting on the serial `pow_x` chain).

The published floor: with lazy reduction carried through the tower, one Fp12
multiply costs 54 Fp products + 12 reductions (Aranha-Karabina-Longa-Gebotys-
Lopez, ePrint 2010/526, Thm 1). mcl's kernels sit on that floor. The SoS
route composed from dual-lane kernels pays more raw products because SoS rows
cannot share sub-products across output coefficients -- sharing requires
parking double-width intermediates unreduced, which is exactly the
lazy-Karatsuba trick. Current counts (products + reductions per call):

| op                    | composed SoS | lazy shape (mcl) |
|-----------------------|--------------|------------------|
| Fp12 mul              | 108 + 18     | 54 + 12          |
| Fp12 square           | 72 + 12      | 36 + 12          |
| mul_by_034 (line)     | 72 + 12      | 39 + 12 (mcl's literal mul_403 pays 39 + 18) |
| cyclotomic square     | 36 + 12      | 18 + 12          |

So SoS wins where the computation is natively one sum -- Fp2 products, the
fused G2-step forms, the G2 subgroup check (El Housni-Guillevic-Piellard
one-`[x]` test, ePrint 2022/352) -- with canonical values at every seam, no
double-width temporaries, and one tiny resident kernel. It loses on the
full-width Fp12 ops, where the crate now ships lazy double-width leaves in
mcl's shape (section 4) and lets measurement pick per target.

### 2.4 The measured microarchitecture split

The same product-count cut behaves oppositely on the two vendors, and this
split drives every default in section 4.

Granite Rapids converts widening products to cycles nearly 1:1, so it is
product-count-bound: the lazy Fp12 square leaf (84 -> 36 products at the time
of measurement) is -6% on the Miller loop; adding the lazy Fp12 mul leaf
brings the final exponentiation to mcl parity (172.6 us vs 172.8) and the
full pairing to 330.3 us vs mcl's 314.2. The same reasoning routes the
G2-step Fp2 muls through 3-product Karatsuba there (2036 -> 1527 products per
Miller loop) under the `helios_x86_intel` tuning hint.

Zen 4 is scheduling- and frontend-bound: it hides the extra products, and
what hurts it is serialization and code mass. The identical Fp12 square leaf
is neutral there ("its excess is scheduling, not mass"), the Fp12 mul leaf is
+9% on the final exp (serial double-width staging on a latency chain), and
the `mul_by_034` leaf is +3% because Zen 4's store ports hide the composed
route's marshalling. The one lazy leaf that wins on both vendors is the
Granger-Scott cyclotomic square (ePrint 2009/565): 18 + 12 with a critical
path one phase shorter, -4.6% full pairing on Zen 4 and -10% final exp on
both -- it is the hottest serial chain in the whole computation, so cutting
its latency pays everywhere.

The frontend evidence, in case the "rolled kernels" theme looks like taste:
before outlining, one Miller iteration touched ~44 KB of code against a 32 KB
L1I (Fp12::square alone compiled to 15.4 KB); outlining the glue and rolling
the kernels took L1I misses to ~0 and the Miller loop -2.4% on Zen 4. The
kernel size budgets in `tests/kernelgen_verify.rs` pin that thesis as
assertions.

## 3. The kernel pipeline: why generated assembly is the auditable kind

Hand-written assembly optimizes review pain for run speed; compiler output
does the reverse (the founding gap: portable Rust 29.4 ns vs mcl 22.4 ns for
a dependent Montgomery mul on Zen 4). The pipeline here (ADR 0001,
`docs/adr-0001-schedule-dsl-generated-kernels.md`) refuses the trade by
making one readable artifact serve three consumers.

A schedule is an ordinary Rust function over a `Machine` trait
(`build/schedule.rs`); every call names the semantic value it computes.
The same function is run by:

1. the **emitter** (`build/emit.rs`) at build time -- GNU-as Intel-syntax
   text, one instruction per call, rendered in-memory and assembled in
   OUT_DIR; no `.s` file is a build input. The only checked-in `.s` files are
   the golden snapshots under `tests/golden/` (reviewed, regenerated with
   `HELIOS_BLESS=1`, diffed against this render by `tests/kernel_golden.rs`);
   `audit_source_surface.py` treats those as reviewed and fails closed on any
   other checked-in native source, and `HELIOS_DUMP_ASM=<dir>` writes the text
   for review;
2. the **interpreter** (`build/interp.rs`) in `tests/kernelgen_verify.rs` --
   bit-accurate executable semantics: u64 registers, CF and OF modeled
   exactly per instruction (adox touches only OF, adcx only CF, mulx
   neither), entry flags and callee-saved registers poisoned, sparse memory
   that panics on wild or uninitialized access, and `ret` verifying the
   System V callee-saved contract plus stack balance;
3. the human reader, who audits named values and bound comments instead of
   simulating an assembler.

Two claim primitives turn the bound comments into checked facts:
`claim_flags_clear(why)` and `claim_zero(reg, why)`. The emitter prints them
as comments; the interpreter asserts them. So the carry-bound argument in the
schedule header is not documentation -- it is a test that runs on any host,
no x86 required.

Worked example, the `mont4_mul` CIOS round. The schedule (excerpt,
`build/schedule.rs`):

```rust
for round in 1..4 {
    m.claim_flags_clear("previous round closed both chains under the 2^320 bound");
    let t: [Reg; 5] = core::array::from_fn(|k| acc(round, k));
    m.load(MULTIPLIER, Mem::new(Rsi, 8 * round as i32), &format!("b{round}"));
    for j in 0..4 {
        mul_into_columns(m, hi, A[j], t[j], t[j + 1], &format!("a{j}*b{round}"), j);
    }
    m.mov_zero(LO, "zero for the chain closes (flags preserved)");
    m.adox(t[4], LO, "close the value chain into t4");
    cancel_low_word(m, t, hi, round);
}
```

`mul_into_columns` is the dual-carry-chain idiom: each product's low half is
added into word j on the OF chain (`adox`), its high half into word j+1 on
the CF chain (`adcx`); mulx writes no flags, so the two chains interleave
without colliding. `cancel_low_word` is the Montgomery step: `m = t0 *
(-p^-1)`, add `m*p` (which zeroes t0), and the "shift" is free -- `acc(round,
k)` renames registers instead of moving data. What the interpreter checks: at
the `claim_flags_clear`, both CF and OF must actually be zero, which is true
iff every in-round peak stayed below `2^320` so the fifth word absorbed all
carries -- exactly the bound `t + a*b_i + m*p < 2^65 * 2^255` proven in the
module header for operands `< p`. Delete one chain-closing `adox` and the
claim panics; feed the schedule an operand `>= p` and it panics too, which is
how the strict `< p` operand contract (section 5) was discovered to be
load-bearing before hardware confirmed it. The emitted text (round 1,
excerpt):

```
    mov rdx, [rsi + 8]                 /* b1 */
    mulx rbx, rax, r8                  /* a0*b1 -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(a0*b1)   [value chain] */
    adcx r14, rbx                      /* t1 += hi(a0*b1)   [carry chain] */
    ...
    mov rdx, r13                       /* m1 multiplicand <- t0 */
    mulx rbx, rdx, qword ptr [rcx + 32] /* m1 = t0 * -p^-1 mod 2^64 */
    mulx rbx, rax, qword ptr [rcx]     /* m1*p0 -> (lo, hi) */
    adox r13, rax                      /* t0 += lo(m1*p0)   [value chain] */
    adcx r14, rbx                      /* t1 += hi(m1*p0)   [carry chain] */
```

The remaining trust gap -- does the printed text assemble to what the
interpreter ran? -- is closed from both sides. The emitter carries an exact
per-instruction byte-count model whose sums go into the provenance header;
every kernel commit re-verifies the model byte-exact under clang
cross-assembly on the box, and re-states that all pre-existing kernels emit
byte-identically (the review diff for "this commit adds one kernel" is
therefore trivially scoped). `kernelgen_verify` pins the rest as structure:
rendering twice must produce identical text (no timestamps, paths, or host
data), no `call` or `jmp` anywhere (kernels are leaves; the only control flow
is counted back edges, whose exact count per kernel is asserted), and the
per-kernel size budgets. Finally, silicon differentials (section 7) compare
the assembled kernels against the portable oracle on real hardware. The
AArch64 leaf took the strongest form of this argument: the schedule is an
instruction-for-instruction port of the previous hand-written M4 leaf, and
the assembled `.text` bytes were verified identical before the hand file was
deleted -- measured performance carried over by construction.

## 4. Dispatch policy: compile-time tiers, measured defaults

Tier selection is a compile-time property of the target. There is no runtime
dispatch and no silent fallback; what you compiled for is what you get.

| tier            | active when                                  | scope |
|-----------------|----------------------------------------------|-------|
| portable Rust   | any target; always under `force-portable`    | everything (also the correctness oracle) |
| AArch64 leaf    | `aarch64-apple-*`                            | Montgomery multiply leaf |
| x86-64 ADX      | x86-64 Linux with `bmi2`+`adx` features      | mont mul/sqr + all tower kernels |
| AVX-512 IFMA    | `avx512f`+`avx512ifma` features              | 8-wide MSM buckets + batch pairing |

`HELIOS_AVX512_IFMA=1` forces the IFMA tier and fails the build if the target
cannot honor it; `=0` denies it; unrecognized values panic rather than
silently building the scalar tier under a believed force. The Intel/AMD
split is a tuning hint, not a tier: `target_cpu_is_intel()` and
`target_cpu_is_amd()` each answer from an explicit `-C target-cpu` name, or
from `/proc/cpuinfo` when the name is `native`, and an unknown target gets
neither vendor default. Nothing links differently, only shape choices follow
the probes: the 034 and fp12 leaves default on for Intel, the sosd6 leaf for
AMD.

Every tower-leaf default is an A/B measured through the full pairing (or its
phase) with interleaved criterion on both boxes; kernel-level wins that do
not survive the pairing stay opt-in. The ledger, from `build.rs`:

| leaf (env toggle)          | shape: products + reductions | text bytes | Zen 4 verdict            | Granite Rapids verdict     | default |
|----------------------------|------------------------------|------------|--------------------------|----------------------------|---------|
| sosd2 (`HELIOS_SOSD2_ASM`) | 4 + 2 dual-lane              | 909 rolled | -13% latency in isolation, pairing-neutral | loses both levels | off (portable) |
| sosd6 (`HELIOS_SOSD6_ASM`) | 12 + 2 dual-lane, fused      | 1287       | Miller -3.8%, pairing 409-410 vs mcl 414.1 | no effect (vendor leaves own the sites) | follows vendor (AMD on) |
| fp6 mul (`HELIOS_FP6_ASM`) | 36 + 6, xi in-kernel         | 1415       | -1.3% pairing            | -0.5% pairing              | on everywhere |
| 034 v1 (`HELIOS_FP12_034_ASM`) | 72 + 12 W-walk           | 1750       | +3% (store ports hide composed) | -4% Miller           | follows vendor (Intel on) |
| fp12 sqr (`HELIOS_FP12_SQR_ASM`) | 36 + 12 dbl-width      | 3071       | neutral                  | -6% Miller                 | follows vendor |
| fp12 mul (`HELIOS_FP12_MUL_ASM`) | 54 + 12 dbl-width      | 2860       | +9% final exp            | final exp at mcl parity    | follows vendor |
| cyc sqr (`HELIOS_CYC_SQR_ASM`) | 18 + 12 dbl-width        | 2098       | -4.6% pairing, -10% FE   | -10% FE                    | on everywhere |

Every toggle is always assembled and interpreter-verified regardless of its
setting, so an A/B needs only a rebuild and test coverage never depends on
the dispatch choice. The lazy and Karatsuba 034 siblings (034L, 034K) lost
the pairing A/B on both microarchs and were removed.

## 5. The kernel contract chain

Canonicity flows down from the wire and is never re-established mid-tower:

1. The byte facade rejects any coordinate `>= p` and any scalar `>= r`
   (never reduces), in a fixed validation order, and subgroup-checks G2.
2. `Fp`'s invariant is canonical Montgomery limbs `< p`; `PartialEq`
   compares raw limbs, so a non-canonical residue would already break
   equality, not just kernel bounds. `from_raw` reduces below p before
   touching a kernel; `from_raw_unchecked` documents that the caller owns
   the invariant.
3. Every kernel returns canonical values, so composition needs no cleanup.

Inside the kernel layer there is one deliberate asymmetry. The mont4 leaves
require operands strictly `< p`: the dual-chain schedule's `2^320` bound
fails for larger inputs -- the interpreter caught the miscomputation and
hardware confirmed it, which is why `from_raw` reduces first. The SoS leaves
accept operands `<= p`, because subtraction enters as `negp(x) = p - x` and
`negp(0) = p`; the SoS bound argument (`u < (T+1)p` between rounds) only
needs `<= p`, and the extra multiple of p vanishes in the reduced output. So `p` is a legal
SoS *operand* while never being a legal `Fp` value or mont4 operand. Both
sides of the asymmetry are enforced: debug-asserts in every wrapper, and the
interpreter's edge palettes include `negp(0) = p` rows and all-`p-1`
operands.

Aliasing is part of each leaf's written contract, not folklore: mont4
operands may alias each other, outputs are wrapper-owned `MaybeUninit`
locals; the Fp12 leaves allow `z == f` (the in-place production shape) only
because the input is fully staged into the frame before the first store, and
`fp12_mul` additionally allows `z == a`, `z == b`, and `a == b` -- every
allowed shape is run in the interpreter, not just on hardware.

The lazy double-width leaves carry a bounds discipline stated as one
collapsible invariant: all staged operands stay `< 2p`, so every raw product
is `< 4p^2 < p*2^256` (legal because `p < 2^254` -- mcl's `isLtQuad`
argument made explicit); every linear double-width row is guarded mod
`p*2^256` (a borrow adds p to the high four limbs, a high half reaching p
sheds it); and every value entering a reduction satisfies `T < p*2^256`.
This is checked twice per kernel: interpreter flag claims on every path, and
a u512 reference in `kernelgen_verify` that mirrors the kernel row for row
and asserts the stage bounds (product caps, guard moduli, nine-fold operand
highs, reduction preconditions) on random and adversarial inputs.

ABI hygiene closes the chain: each leaf initializes every output byte,
saves the callee-saved registers it uses, keeps rsp alignment, and neither
calls Rust nor unwinds -- each item either interpreter-checked on `ret` or
pinned structurally (no `call` in the rendered text).

## 6. The batch tier: eight pairings on IFMA lanes

AVX-512 IFMA (`vpmadd52luq/huq`) multiplies eight independent 52x52-bit
pairs per instruction. The tier (`src/fp/avx512ifma.rs`, `src/batch8.rs`)
holds eight `Fp` values in structure-of-arrays form, five 52-bit limbs each,
in the radix-52 Montgomery domain `v * 2^260 mod p`. Conversion between the
4x64 and 5x52 domains costs one batched Montgomery multiply by a constant
each way.

That conversion is the whole story of what the tier can and cannot speed up.
Measured on Zen 4: the 8-wide sum-of-products MAC kernel is 2.37x faster than
scalar for the 6-term shape, but batching one lone `mul_by_034` -- convert 12
operand vectors in, compute, convert out -- lands 3.63x SLOWER than the
scalar call (3010 vs 830 ns). With operands already resident in the domain,
8-wide Fp2 multiply is 3.1x scalar (171.7 vs 530.5 ns per eight). So per-op
batching is dead on arrival; the shape that pays is eight *independent
pairings, one per lane*, converted once on entry, the entire Miller loop run
8-wide in lockstep, converted once at exit -- and no cross-lane movement
ever, because lanes never interact. The tower mirrors the scalar formulas
exactly; the fused sums ride `sos_mac(6)`, the lane-parallel analog of the
scalar `sosd6` lazy reduction. Frobenius endpoints and the one-time inversion
run scalar per lane; the batch entry point shares ONE scalar final
exponentiation over the product of all Miller values, which is what makes
the margin grow with the batch.

Dispatch: `pairing_product_is_one` routes to the 8-wide path at >= 8 pairs;
below that the scalar path keeps its common-Q bilinearity fold and pays no
conversion. Measured against mcl on the same silicon (mcl gates its IFMA
code to BLS12-381, so its BN254 runs scalar): per-pairing 137 us on Granite
Rapids, 178 on Zen 4, 354 on Ice Lake vs mcl's 311 / 413 / 617 -- 2.27x,
2.31x, 1.74x (Ice Lake has one IFMA port where the others have two; its
column was measured before the squaring-aware tower and understates helios).
The shared final exp amortizes from there: n = 8 is the amortization floor
over mcl, the margin rising toward 2.10x at n = 64 on Zen 4 (89.7 us/pair)
and Granite Rapids reaching 67 us/pair at n = 64.

## 7. Verification and measurement methodology

Each layer proves one specific thing; none is decoration.

- **Interpreter (`tests/kernelgen_verify.rs`)**: the schedule's operation
  sequence computes the intended function (vs an independent u128 CIOS
  reference, a u512 lazy-DAG reference, and the production portable oracle),
  every claimed carry/zero invariant holds, ABI discipline holds, rendering
  is deterministic, structure is pinned (leaf property, exact back-edge
  counts, size budgets). Runs on any host. Cannot prove: that assembler and
  CPU agree with the emitter's encoding and flag model.
- **Byte model vs clang + silicon differentials**: the emitter's byte counts
  are verified exact under clang cross-assembly; on ADX hardware the leaf
  wrappers are differential-tested against the portable oracle -- edge/carry
  corpus, 64k random cases always-on, million-case ignored stress gate, plus
  per-leaf 100k gates fed with *harvested* operands (a lockstep replay of the
  Miller recurrence pins the exact mid-loop accumulator/coefficient pairs the
  production path sees). Proves the assembled bytes behave like the oracle on
  real silicon. Cannot prove: inputs outside the corpora -- that residual is
  what the interpreter's bound proofs and edge palettes cover.
- **Arkworks conformance**: every compile-time constant is derived from the
  curve seed at build time and pinned against `ark-bn254` 0.5
  (`tests/ark_constants_match.rs`); differential tests and a ported arkworks
  test corpus cover the tower and curve ops; Agave fixture tests pin the
  facade's error taxonomy, caps, and validation order.
- **mcl vectors**: the `BN_SNARK1` golden pairing vector from mcl's own test
  suite pins cross-library pairing agreement (`src/lib.rs`).
- **Consensus fingerprint (`tests/fingerprint.rs`)**: the strongest in-repo
  behavioral gate. A fixed deterministic corpus over the byte facade -- edge
  scalars, infinity encodings, cap boundaries, every reachable `InputError`
  and its cross-variant precedence, non-canonical encodings, algebraic
  identities, and a seeded accept/reject frontier sweep -- has every outcome
  (output bytes or error discriminant) absorbed into one SHA-256 pinned as
  `GOLDEN`. Every tier must agree byte for byte (the corpus includes a
  >= 8-pair batch to force the IFMA dispatch), so any drift in decode,
  validation order, arithmetic, or encode breaks it on every target; re-pinning
  is deliberate and justified in-commit. The `ci_matrix.sh` golden leg runs it
  as a release gate.
- **Wire fingerprint**: the downstream Agave integration branches additionally
  pin a keccak fingerprint over 700 byte-level cases (including error-precedence
  pins); any intentional wire change must update it in-commit. That gate lives
  in the integration tree, not this repository.
- **What none of it proves**: this is differential testing, not adversarial
  cryptanalysis. Bugs are not adversaries; an external audit is planned and
  the crate says so.

Measurement protocol, because every default in section 4 is a measurement:
implementations are benchmarked *interleaved in a single criterion run*
(never library A's run compared with library B's run an hour later), on
pinned cores (`taskset`), against an mcl built on the same box from the
pinned source revision (`e107c70e`) with the same compiler family. Quick-mode
medians decide build defaults and are labeled diagnostic; release-grade
claims require the three-run interleaved gate in `PERFORMANCE.md` (ratio
below 1.00 in each of three clean runs). One-run phantom regressions are a
documented failure mode of the quick lane, which is why the defaults ledger
records the phase measured, not just a verdict.

## Citations

Longa, ePrint 2022/367 (sums-of-products Montgomery). Aranha, Karabina,
Longa, Gebotys, Lopez, ePrint 2010/526 (lazy-reduction pairing formulas; the
54-product Fp12 mul). Granger, Scott, ePrint 2009/565 (cyclotomic squaring).
Fuentes-Castaneda, Knapp, Rodriguez-Henriquez, ePrint 2011/506 (final exp).
Karabina, ePrint 2010/542 (compressed squarings, kept as an alternative).
El Housni, Guillevic, Piellard, ePrint 2022/352 (G2 membership). Bernstein,
Yang, ePrint 2019/266 (divsteps inversion). ePrint 2013/722 (Miller line
formulas). mcl: github.com/herumi/mcl, the hand-written competitor whose
operation counts the lazy leaves adopt and whose benchmarks gate the defaults.
