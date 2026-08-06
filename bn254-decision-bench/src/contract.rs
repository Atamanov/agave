use {
    crate::{Error, model::*},
    solana_program_runtime::execution_budget::{
        ALT_BN128_PAIRING_LANE_WIDTH, SVMTransactionExecutionCost,
    },
    std::collections::BTreeSet,
};

/// Pair limits of the pairing syscalls, from
/// `solana_bn254_batch_syscall::{PAIRING_MAX_PAIRS, PAIRING_MAP_MAX_PAIRS}`.
/// The bench does not link the syscall crate, which would drag a backend
/// selection into a host build that only prices shapes.
pub const PAIRING_CHECK_CAP: u32 = 256;
pub const PAIRING_MAP_CAP: u32 = 18;

/// Inert pairs the guests append so the call lands on the cheapest lane count.
///
/// Derived here from the charge itself, where the guests carry the residue
/// table it reduces to (`solana_bn254_groth16_batch::lane`). The two
/// derivations are independent and `tests/observed_traces` compares them.
///
/// Only a block of two or more pairs can be inert: `e(P, Q) = 1` forces an
/// infinity point, and the runtime drops an infinity pair before the kernel,
/// so it would buy a lane in the charge and not in the work. One added pair is
/// therefore out of reach.
pub fn lane_pad(full: u32, registered: u32, cap: u32) -> u32 {
    let cost = SVMTransactionExecutionCost::default();
    let charge = |pad: u32| {
        cost.alt_bn128_pairing_cost(u64::from(full.saturating_add(pad)), u64::from(registered))
    };
    let pairs = full.saturating_add(registered);
    (0..=ALT_BN128_PAIRING_LANE_WIDTH as u32)
        .filter(|pad| *pad != 1 && pairs.saturating_add(*pad) <= cap)
        .min_by_key(|pad| (charge(*pad), *pad))
        .unwrap_or_default()
}

/// One boolean pairing check over `pairs` fold terms and their lane pad.
fn padded_check(pairs: u32) -> PairingCall {
    PairingCall::full(
        pairs.saturating_add(lane_pad(pairs, 0, PAIRING_CHECK_CAP)),
        1,
    )
}

/// One pairing map over `pairs` fold terms and their lane pad.
fn padded_map(pairs: u32) -> PairingCall {
    PairingCall::full(pairs.saturating_add(lane_pad(pairs, 0, PAIRING_MAP_CAP)), 1)
}

fn msm(points: &[u32]) -> Vec<MsmCall> {
    points.iter().copied().map(MsmCall::one).collect()
}

fn trace(
    pairing_checks: Vec<PairingCall>,
    pairing_maps: Vec<PairingCall>,
    msm_calls: Vec<MsmCall>,
    gt_target_multiexp_calls: Vec<GtTargetMultiexpCall>,
) -> OperationTrace {
    let final_exponentiations = pairing_checks
        .iter()
        .chain(&pairing_maps)
        .map(|call| call.calls)
        .sum();
    let g2_subgroup_checks = pairing_checks
        .iter()
        .chain(&pairing_maps)
        .map(|call| call.full_pairs.saturating_mul(call.calls))
        .sum();
    OperationTrace {
        pairing_checks,
        pairing_maps,
        msm_calls,
        gt_target_multiexp_calls,
        final_exponentiations,
        g2_subgroup_checks,
        stock_g1_additions: 0,
        stock_g1_multiplications: 0,
        fr_lincomb_calls: Vec::new(),
        plonk_multi_vk_reduce_calls: Vec::new(),
        hash_syscalls: HashSyscallTotals::default(),
        g1_decompressions: 0,
        g2_decompressions: 0,
    }
}

/// Compressed points one proof carries on the wire, as `(G1, G2)`.
///
/// Groth16 sends `A` and `C` in G1 and `B` in G2. snarkjs PLONK sends nine G1
/// commitments and keeps its only G2 in the verifying key, which is not on the
/// wire. Recursion sends one committed outer Groth16 proof whatever the row
/// holds, so the BSB22 commitment and its proof of knowledge ride beside `A`
/// and `C` and the inner proofs never reach the chain.
const fn wire_decompressions(row: RowId, column: ColumnId) -> (u32, u32) {
    if matches!(column, ColumnId::RecursionB5) {
        return (4, 1);
    }
    let n = row.proof_count();
    if row.is_groth16() {
        (2u32.saturating_mul(n), n)
    } else {
        (9u32.saturating_mul(n), 0)
    }
}

/// Slice byte lengths of the operands a protocol step hashes.
type HashCall = Vec<u32>;

const FR: u32 = 32;
const G1: u32 = 64;
const G2: u32 = 128;
const GT: u32 = 384;
/// Big-endian `u64` counters and lengths the transcripts frame with.
const BE64: u32 = 8;

fn with_hash_syscalls(mut trace: OperationTrace, calls: Vec<HashCall>) -> OperationTrace {
    trace.hash_syscalls = HashSyscallTotals {
        calls: calls.len() as u32,
        slices: calls.iter().map(|call| call.len() as u32).sum(),
        byte_cu: calls
            .iter()
            .flatten()
            .map(|len| hash_slice_excess_cu(u64::from(*len)) as u32)
            .sum(),
    };
    trace
}

/// `vk::digest`: the committed-or-vanilla tag, alpha, the three fixed G2
/// points, the IC length, one G1 per IC entry, and the Pedersen pair.
fn groth16_vk_digest(ic_entries: u32, committed: bool) -> HashCall {
    let mut parts = vec![1, G1, G2, G2, G2, 2];
    parts.extend(core::iter::repeat_n(G1, ic_entries as usize));
    if committed {
        parts.extend([G2, G2]);
    }
    parts
}

/// `derive_seed`: the mode's domain tag, the key count and every key digest,
/// the proof count, then per proof its key index, A, B, C, the commitment pair
/// when the key is committed, and one slice per public input.
fn groth16_seed(keys: u32, proofs: u32, public_inputs: u32, committed: bool) -> HashCall {
    // b"solana-bn254-groth16-batch:v1:independent"
    const INDEPENDENT_DOMAIN: u32 = 41;
    let mut parts = vec![INDEPENDENT_DOMAIN, 2];
    parts.extend(core::iter::repeat_n(FR, keys as usize));
    parts.push(BE64);
    for _ in 0..proofs {
        parts.extend([2, G1, G2, G1]);
        if committed {
            parts.extend([G1, G1]);
        }
        parts.extend(core::iter::repeat_n(FR, public_inputs as usize));
    }
    parts
}

/// `draw_scalar`, once per verification equation. A committed proof carries two.
fn groth16_randomizer_draw() -> HashCall {
    vec![FR, BE64]
}

/// `same_vk_transcript_seed`, then one `tail_draw` per tail position.
fn same_vk_target_seed() -> HashCall {
    // b"solana-bn254-groth16-same-vk-target:v1:affine-sum-one"
    const TARGET_DOMAIN: u32 = 53;
    vec![TARGET_DOMAIN, FR, FR, GT]
}

fn same_vk_tail_draw() -> HashCall {
    // b"coef"
    const COEFFICIENT_DOMAIN: u32 = 4;
    vec![FR, COEFFICIENT_DOMAIN, BE64]
}

/// `authenticated_vk_digest` over the canonical PLONK verifying-key block.
fn plonk_vk_block_digest() -> HashCall {
    // layout::VK_BYTES = 8 + 4 + 5 * 64 + 3 * 64 + 2 * 32 + 2 * 128
    const VK_BLOCK: u32 = 844;
    vec![VK_BLOCK]
}

/// `keyset_digest`: the domain, the layout version, the group count and every
/// group's verifying-key digest.
fn plonk_keyset_digest(keys: u32) -> HashCall {
    // b"zolana:bn254:plonk:g2-registry-keyset:v1"
    const KEYSET_DOMAIN: u32 = 40;
    let mut parts = vec![KEYSET_DOMAIN, 1, BE64];
    parts.extend(core::iter::repeat_n(FR, keys as usize));
    parts
}

/// The snarkjs Fiat-Shamir rounds one direct PLONK proof runs: beta over the
/// eight selectors, the publics and the round-one commitments; gamma over
/// beta; alpha over beta, gamma and Z; xi over alpha and the quotient parts;
/// v1 over xi and the six evaluations; u over the two opening proofs.
fn plonk_challenges(public_inputs: u32) -> Vec<HashCall> {
    let mut beta = vec![G1; 8];
    beta.extend(core::iter::repeat_n(FR, public_inputs as usize));
    beta.extend([G1, G1, G1]);
    vec![
        beta,
        vec![FR],
        vec![FR, FR, G1],
        vec![FR, G1, G1, G1],
        vec![FR; 7],
        vec![G1, G1],
    ]
}

/// `expand_message_xmd_sha256_l48` for the BSB22 wire: b0 over a zero block,
/// the commitment, the output length, a zero byte and the length-tagged DST;
/// then b1 and b2 over a 32-byte block, a counter byte and the same tag.
/// These are `sol_sha256`, which the runtime prices exactly like `sol_keccak256`.
fn bsb22_hash_to_field() -> Vec<HashCall> {
    const DST: u32 = 16 + 1; // b"bsb22-commitment" plus its length byte
    const COMMITMENT: u32 = G1;
    const R_IN_BYTES: u32 = 64;
    const B_IN_BYTES: u32 = 32;
    vec![
        vec![R_IN_BYTES + COMMITMENT + 2 + 1 + DST],
        vec![B_IN_BYTES + 1 + DST],
        vec![B_IN_BYTES + 1 + DST],
    ]
}

/// Public inputs the outer recursive circuit declares, from the recursion
/// guests' `layout` constants. The verifier appends the BSB22 wire, so the
/// proof carries one more scalar than this and the key one more IC entry.
const fn recursion_public_inputs(row: RowId) -> u32 {
    match row {
        RowId::Groth16N2DistinctVk => 3,
        RowId::Groth16N3DistinctVk | RowId::PlonkN2DistinctVkSharedSrs => 4,
        RowId::Groth16N5SameVk => 6,
        RowId::PlonkN3DistinctVkSharedSrs => 7,
    }
}

/// One outer proof over a committed key, verified as a one-proof batch.
fn recursion_hash_calls(row: RowId) -> Vec<HashCall> {
    let declared = recursion_public_inputs(row);
    let mut calls = vec![
        groth16_vk_digest(declared.saturating_add(2), true),
        groth16_seed(1, 1, declared.saturating_add(1), true),
    ];
    // A committed proof has two verification equations, the Groth16 one and
    // the proof of knowledge, so the transcript draws two randomizers.
    calls.extend(core::iter::repeat_n(groth16_randomizer_draw(), 2));
    calls.extend(bsb22_hash_to_field());
    calls
}

/// Every zolana verifying key declares one public input, so its IC has two
/// entries.
const ZOLANA_PUBLIC_INPUTS: u32 = 1;
const ZOLANA_IC_ENTRIES: u32 = ZOLANA_PUBLIC_INPUTS + 1;

/// The batched Groth16 fold: one digest per key, the batch seed, one
/// randomizer draw per proof.
fn groth16_fold_hash_calls(proofs: u32, keys: u32) -> Vec<HashCall> {
    let mut calls: Vec<HashCall> = core::iter::repeat_n(keys, keys as usize)
        .map(|_| groth16_vk_digest(ZOLANA_IC_ENTRIES, false))
        .collect();
    calls.push(groth16_seed(keys, proofs, ZOLANA_PUBLIC_INPUTS, false));
    calls.extend(core::iter::repeat_n(
        groth16_randomizer_draw(),
        proofs as usize,
    ));
    calls
}

/// The batch columns hand the whole reduction to the runtime. One call per
/// transaction, one context and one proof per verifying key, one public input
/// each, which is what every zolana verifying key declares.
fn with_multi_vk_reduce(mut trace: OperationTrace, n: u32) -> OperationTrace {
    trace.plonk_multi_vk_reduce_calls = vec![PlonkMultiVkReduceCall {
        contexts: n,
        proofs: n,
        public_inputs: n,
        calls: 1,
    }];
    trace
}

/// The BSB22 hash-to-field reduction, one three-term inner product per outer
/// proof. It replaced an ark-ff byte-at-a-time loop that cost 75,000 CU.
///
/// The outer verification is itself a one-proof fold, so it also carries the
/// fold's own inner products: one negation plus one per public-input column,
/// and the outer statement width is the gamma MSM slot.
fn with_bsb22_reduction(mut trace: OperationTrace) -> OperationTrace {
    let gamma_width = trace
        .msm_calls
        .get(2)
        .map(|call| call.points)
        .unwrap_or_default();
    let mut calls = vec![FrLincombCall::one(3)];
    calls.extend(core::iter::repeat_n(
        FrLincombCall::one(1),
        gamma_width as usize,
    ));
    trace.fr_lincomb_calls = calls;
    trace
}

/// Inner products the batched fold hands to the runtime, per verifying key.
///
/// Each proof of a key needs its randomizer negated, one term each. A key with
/// several proofs then folds `-sum r` and each public-input column across them,
/// so those widen to the proof count; a key with a single proof reuses the
/// negation and its one column stays one term. Every zolana verifying key
/// declares one public input.
fn with_fp12_fold_lincombs(mut trace: OperationTrace, proofs: u32, keys: u32) -> OperationTrace {
    // A shared key runs the same_vk fold: one negation per proof, then a single
    // inner product across them per public-input column. Distinct keys run the
    // guest's own fp12 fold, where each key holds one proof, so its negation,
    // its column and its running sum are all one term.
    trace.fr_lincomb_calls = if keys == 1 {
        // Order matters: the derivation runs before the fold. It contributes the
        // affine coefficient and the sum-to-one check, and the fold re-checks
        // the invariant, so three n-term folds precede the per-proof negations.
        // A single proof needs none of them: the sum short-circuits and the
        // tail is empty.
        let mut calls = Vec::new();
        if proofs > 1 {
            calls.extend(core::iter::repeat_n(FrLincombCall::one(proofs), 3));
        }
        calls.extend(core::iter::repeat_n(FrLincombCall::one(1), proofs as usize));
        calls.push(FrLincombCall::one(proofs));
        calls
    } else {
        vec![FrLincombCall::one(1); (proofs as usize).saturating_mul(3)]
    };
    trace
}

fn with_fold_lincombs(mut trace: OperationTrace, proofs: u32, keys: u32) -> OperationTrace {
    const PUBLIC_INPUT_COLUMNS: u32 = 1;
    let per_key = proofs.checked_div(keys).unwrap_or_default();
    let mut calls = Vec::new();
    for _ in 0..keys {
        for _ in 0..per_key {
            calls.push(FrLincombCall::one(1));
        }
        if per_key > 1 {
            calls.push(FrLincombCall::one(per_key));
        }
        for _ in 0..PUBLIC_INPUT_COLUMNS {
            calls.push(FrLincombCall::one(per_key));
        }
    }
    trace.fr_lincomb_calls = calls;
    trace
}

/// The unbatched columns build their public-input commitment with stock G1
/// operations. Counts come from the observer, never from a guess: the
/// `observed_traces` test fails if the model and the guest disagree.
fn with_stock_g1(
    mut trace: OperationTrace,
    additions: u32,
    multiplications: u32,
) -> OperationTrace {
    trace.stock_g1_additions = additions;
    trace.stock_g1_multiplications = multiplications;
    trace
}

fn groth_msm(row: RowId, column: ColumnId) -> Vec<MsmCall> {
    // The registry variant reuses the exact B5 fold and replaces only the
    // fixed-G2 suffix at the pairing boundary. It must never grow a second,
    // registry-specific G1 fold.
    let column = if column == ColumnId::RegistryB5 {
        ColumnId::BatchB5
    } else {
        column
    };
    let points: &[u32] = match (row, column) {
        (RowId::Groth16N5SameVk, ColumnId::BatchB5) => &[1, 1, 1, 1, 1, 1, 2, 5],
        (RowId::Groth16N2DistinctVk, ColumnId::BatchB5) => &[1, 1, 1, 2, 1, 1, 2, 1],
        (RowId::Groth16N3DistinctVk, ColumnId::BatchB5) => &[1, 1, 1, 1, 2, 1, 1, 2, 1, 1, 2, 1],
        (RowId::Groth16N5SameVk, ColumnId::RecursionB5) => &[1, 1, 9, 1, 1, 1],
        (RowId::Groth16N2DistinctVk, ColumnId::RecursionB5) => &[1, 1, 6, 1, 1, 1],
        (RowId::Groth16N3DistinctVk, ColumnId::RecursionB5) => &[1, 1, 7, 1, 1, 1],
        (RowId::Groth16N5SameVk, ColumnId::BatchFp12B5) => &[1, 1, 1, 1, 1, 2, 5],
        (RowId::Groth16N2DistinctVk, ColumnId::BatchFp12B5) => &[1, 2, 1, 2, 1],
        (RowId::Groth16N3DistinctVk, ColumnId::BatchFp12B5) => &[1, 1, 2, 1, 2, 1, 2, 1],
        (_, ColumnId::Current | ColumnId::CurrentFp12) => &[],
        _ => unreachable!("Groth16 MSM matrix is exhaustive"),
    };
    msm(points)
}

pub fn expected_trace(row: RowId, column: ColumnId) -> OperationTrace {
    let mut trace = strategy_trace(row, column);
    // Applied here rather than inside each arm, so no cell can be published
    // without its wire cost.
    let (g1, g2) = wire_decompressions(row, column);
    trace.g1_decompressions = g1;
    trace.g2_decompressions = g2;
    trace
}

/// The work the verification strategy itself does, once the proof is a set of
/// affine points.
fn strategy_trace(row: RowId, column: ColumnId) -> OperationTrace {
    if row.is_groth16() {
        let n = row.proof_count();
        let k = row.vk_count();
        return match column {
            // The unbatched verifier binds nothing: no key digest, no batch
            // seed, no randomizer, so it hashes nothing.
            ColumnId::Current => with_stock_g1(
                trace(vec![PairingCall::full(4, n)], vec![], vec![], vec![]),
                n,
                n,
            ),
            ColumnId::BatchB5 => with_hash_syscalls(
                with_fold_lincombs(
                    trace(
                        vec![padded_check(n.saturating_add(3u32.saturating_mul(k)))],
                        vec![],
                        groth_msm(row, column),
                        vec![],
                    ),
                    n,
                    k,
                ),
                groth16_fold_hash_calls(n, k),
            ),
            // The registry replaces the fixed-G2 suffix at the pairing
            // boundary and leaves the transcript alone.
            ColumnId::RegistryB5 => with_hash_syscalls(
                with_fold_lincombs(
                    trace(
                        vec![PairingCall::registered(
                            n.saturating_add(lane_pad(
                                n,
                                3u32.saturating_mul(k),
                                PAIRING_CHECK_CAP,
                            )),
                            3u32.saturating_mul(k),
                        )],
                        vec![],
                        groth_msm(row, column),
                        vec![],
                    ),
                    n,
                    k,
                ),
                groth16_fold_hash_calls(n, k),
            ),
            ColumnId::RecursionB5 => with_hash_syscalls(
                with_bsb22_reduction(trace(
                    vec![padded_check(6)],
                    vec![],
                    groth_msm(row, column),
                    vec![],
                )),
                recursion_hash_calls(row),
            ),
            // This is deliberately n independent current-verifier maps. It is
            // not the batched FP12 fold and therefore has no MSM syscall. Each
            // target names its key by digest, so the keys are still hashed.
            ColumnId::CurrentFp12 => with_hash_syscalls(
                with_stock_g1(
                    trace(vec![], vec![PairingCall::full(3, n)], vec![], vec![]),
                    n,
                    n,
                ),
                core::iter::repeat_n(k, k as usize)
                    .map(|_| groth16_vk_digest(ZOLANA_IC_ENTRIES, false))
                    .collect(),
            ),
            ColumnId::BatchFp12B5 => {
                let gt_target_multiexp_calls = if k > 1 {
                    vec![GtTargetMultiexpCall {
                        targets: k,
                        nontrivial_exponents: k.saturating_sub(1),
                        calls: 1,
                    }]
                } else {
                    vec![]
                };
                // A shared key runs the same_vk fold, which binds the GT
                // target into its own seed and then draws one coefficient per
                // tail position instead of one randomizer per proof. Distinct
                // keys run the guest's fp12 fold over the ordinary transcript.
                let hash_calls = if k == 1 {
                    let mut calls = vec![
                        groth16_vk_digest(ZOLANA_IC_ENTRIES, false),
                        groth16_seed(k, n, ZOLANA_PUBLIC_INPUTS, false),
                        same_vk_target_seed(),
                    ];
                    calls.extend(core::iter::repeat_n(
                        same_vk_tail_draw(),
                        n.saturating_sub(1) as usize,
                    ));
                    calls
                } else {
                    groth16_fold_hash_calls(n, k)
                };
                with_hash_syscalls(
                    with_fp12_fold_lincombs(
                        trace(
                            vec![],
                            vec![padded_map(n.saturating_add(2u32.saturating_mul(k)))],
                            groth_msm(row, column),
                            gt_target_multiexp_calls,
                        ),
                        n,
                        k,
                    ),
                    hash_calls,
                )
            }
        };
    }

    let n = row.proof_count();
    let folded_msm = || msm(&[2u32.saturating_mul(n), 18u32.saturating_mul(n)]);
    // Every PLONK column authenticates each key by hashing its canonical block
    // and then binds the set. The batch columns stop there, because the
    // runtime replays the transcript for them.
    let key_binding = || {
        let mut calls: Vec<HashCall> = core::iter::repeat_n(n, n as usize)
            .map(|_| plonk_vk_block_digest())
            .collect();
        calls.push(plonk_keyset_digest(n));
        calls
    };
    // The unbatched column runs the whole snarkjs transcript per proof on top.
    let direct_transcript = || {
        let mut calls: Vec<HashCall> = Vec::new();
        for _ in 0..n {
            calls.push(plonk_vk_block_digest());
            calls.extend(plonk_challenges(ZOLANA_PUBLIC_INPUTS));
        }
        calls.push(plonk_keyset_digest(n));
        calls
    };
    match column {
        ColumnId::Current => with_hash_syscalls(
            with_stock_g1(
                trace(vec![PairingCall::full(2, n)], vec![], vec![], vec![]),
                18u32.saturating_mul(n),
                20u32.saturating_mul(n),
            ),
            direct_transcript(),
        ),
        ColumnId::BatchB5 => with_hash_syscalls(
            with_multi_vk_reduce(
                trace(vec![padded_check(2)], vec![], folded_msm(), vec![]),
                n,
            ),
            key_binding(),
        ),
        ColumnId::RegistryB5 => with_hash_syscalls(
            with_multi_vk_reduce(
                trace(
                    vec![PairingCall::registered(
                        lane_pad(0, 2, PAIRING_CHECK_CAP),
                        2,
                    )],
                    vec![],
                    folded_msm(),
                    vec![],
                ),
                n,
            ),
            key_binding(),
        ),
        ColumnId::RecursionB5 => {
            let outer_msm: &[u32] = match row {
                RowId::PlonkN2DistinctVkSharedSrs => &[1, 1, 7, 1, 1, 1],
                RowId::PlonkN3DistinctVkSharedSrs => &[1, 1, 10, 1, 1, 1],
                _ => unreachable!("PLONK recursion rows are exhaustive"),
            };
            with_hash_syscalls(
                with_bsb22_reduction(trace(vec![padded_check(6)], vec![], msm(outer_msm), vec![])),
                recursion_hash_calls(row),
            )
        }
        // As above, preserve one independent current-verifier map per proof.
        ColumnId::CurrentFp12 => with_hash_syscalls(
            with_stock_g1(
                trace(vec![], vec![PairingCall::full(2, n)], vec![], vec![]),
                18u32.saturating_mul(n),
                20u32.saturating_mul(n),
            ),
            direct_transcript(),
        ),
        ColumnId::BatchFp12B5 => with_hash_syscalls(
            with_multi_vk_reduce(trace(vec![], vec![padded_map(2)], folded_msm(), vec![]), n),
            key_binding(),
        ),
    }
}

pub fn builtin_expected_counts() -> ExpectedCountContract {
    ExpectedCountContract {
        schema: format!("{SCHEMA_PREFIX}.expected-counts.v1"),
        contract_id: "bn254-corrected-six-columns-counts-20260805".to_owned(),
        cells: RowId::ALL
            .into_iter()
            .flat_map(|row_id| {
                ColumnId::ALL
                    .into_iter()
                    .map(move |column_id| ExpectedCell {
                        row_id,
                        column_id,
                        trace: expected_trace(row_id, column_id),
                    })
            })
            .collect(),
    }
}

pub fn validate_trace_consistency(trace: &OperationTrace, label: &str) -> Result<(), Error> {
    for call in trace.pairing_checks.iter().chain(&trace.pairing_maps) {
        if call.calls == 0 || call.pairs == 0 {
            return Err(Error::Contract(format!(
                "{label}: pairing calls and pairs must be nonzero"
            )));
        }
        if call.pairs != call.full_pairs.saturating_add(call.registered_pairs) {
            return Err(Error::Contract(format!(
                "{label}: total pairs do not equal full plus registered pairs"
            )));
        }
    }
    if trace
        .pairing_maps
        .iter()
        .any(|call| call.registered_pairs != 0)
    {
        return Err(Error::Contract(format!(
            "{label}: pairing-map registry inputs are not part of this campaign"
        )));
    }
    if trace
        .msm_calls
        .iter()
        .any(|call| call.calls == 0 || call.points == 0)
    {
        return Err(Error::Contract(format!(
            "{label}: MSM calls and points must be nonzero"
        )));
    }
    if trace.gt_target_multiexp_calls.iter().any(|call| {
        call.calls == 0 || call.targets < 2 || call.nontrivial_exponents >= call.targets
    }) {
        return Err(Error::Contract(format!(
            "{label}: GT target multiexp shape is invalid"
        )));
    }
    let expected_final_exponentiations: u32 = trace
        .pairing_checks
        .iter()
        .chain(&trace.pairing_maps)
        .map(|call| call.calls)
        .sum();
    if trace.final_exponentiations != expected_final_exponentiations {
        return Err(Error::Contract(format!(
            "{label}: final-exponentiation count is {}, expected {expected_final_exponentiations}",
            trace.final_exponentiations
        )));
    }
    let expected_subgroup_checks: u32 = trace
        .pairing_checks
        .iter()
        .chain(&trace.pairing_maps)
        .map(|call| call.full_pairs.saturating_mul(call.calls))
        .sum();
    if trace.g2_subgroup_checks != expected_subgroup_checks {
        return Err(Error::Contract(format!(
            "{label}: subgroup-check count is {}, expected {expected_subgroup_checks}",
            trace.g2_subgroup_checks
        )));
    }
    Ok(())
}

pub fn validate_expected_counts(contract: &ExpectedCountContract) -> Result<(), Error> {
    let expected = builtin_expected_counts();
    if contract.schema != expected.schema {
        return Err(Error::Contract(format!(
            "expected-count schema must be {}",
            expected.schema
        )));
    }
    if contract.contract_id != expected.contract_id {
        return Err(Error::Contract(
            "expected-count contract id is not the corrected six-column contract".to_owned(),
        ));
    }
    if contract.cells.len() != RowId::ALL.len().saturating_mul(ColumnId::ALL.len()) {
        return Err(Error::Contract(
            "expected-count contract must contain exactly 5 x 6 cells".to_owned(),
        ));
    }
    let mut identities = BTreeSet::new();
    for cell in &contract.cells {
        if !identities.insert((cell.row_id, cell.column_id)) {
            return Err(Error::Contract(format!(
                "duplicate expected-count cell {:?}/{:?}",
                cell.row_id, cell.column_id
            )));
        }
        validate_trace_consistency(
            &cell.trace,
            &format!("expected {:?}/{:?}", cell.row_id, cell.column_id),
        )?;
    }
    if contract != &expected {
        return Err(Error::Contract(
            "expected-count contract differs from the built-in corrected matrix".to_owned(),
        ));
    }
    Ok(())
}

/// Rejects a document that names a retired B1 column or a derived, rather than
/// measured, value.
///
/// Matching is on whole identifiers. A substring match rejected every real
/// document: `fp12_b5` occurs inside the live column id `batch_fp12_b5`, and
/// `ratio` occurs inside `operation`, a key in every tariff entry. That made
/// the entire campaign entrypoint unreachable, and with it the fixture seal,
/// the tariff attestation and the observed-versus-expected trace comparison.
/// The published tables came from the renderer path instead, which performs
/// none of those checks.
pub fn reject_deprecated_or_derived_json(raw: &str, label: &str) -> Result<(), Error> {
    const FORBIDDEN: &[&str] = &[
        "batch_b1",
        "registry_b1",
        "fp12_b1",
        "fp12_b5",
        "ratio",
        "ratio_scaled",
        "substituted",
        "interpolated",
        "derived_cu",
    ];
    let lowered = raw.to_ascii_lowercase();
    let bytes = lowered.as_bytes();
    let boundary = |index: usize| {
        bytes
            .get(index)
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
    };
    for token in FORBIDDEN {
        for (start, _) in lowered.match_indices(token) {
            let before_ok = start.checked_sub(1).is_none_or(&boundary);
            let after_ok = start.checked_add(token.len()).is_none_or(&boundary);
            if before_ok && after_ok {
                return Err(Error::Contract(format!(
                    "{label} contains forbidden legacy/derived token `{token}`"
                )));
            }
        }
    }
    Ok(())
}
