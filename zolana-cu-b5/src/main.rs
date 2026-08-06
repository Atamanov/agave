//! What the B5 kernel buys on a real zolana transaction.
//!
//! Runs the confidential-rail `transact` and `aggregate_transact` of the
//! groth16-recursion worktree against three syscall configurations of the same
//! program binary, and reports the metered transaction CU of each with the
//! syscall charge split by family.
//!
//! * `raw` installs nothing. It must reproduce that worktree's published
//!   numbers, which is what makes the harness worth believing.
//! * `stock` adds the price-neutral hash observers. Its total must equal `raw`,
//!   which is what makes their per-slice charge worth believing.
//! * `b5` adds the B5 `sol_alt_bn128_group_op`. Only the price moves; the
//!   program, its instruction data, and its sBPF trace are the same bytes.
//!
//! Configurations are separate processes because the syscall set is installed
//! once per process, before the first program is loaded.
//!
//! Needs the recursion prover reachable, with the aggregate proving keys that
//! worktree generated.

mod attribute;
mod kernel;
mod probe;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use groth16_solana::groth16::negate_g1_be;
use num_bigint::BigUint;
use shielded_pool_tests::support::{fixtures::Pool, transact::tree_roots};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_program_runtime::solana_sbpf::program::BuiltinFunctionDefinition as _;
use solana_signer::Signer;
use zolana_client::{
    prover::{AggregateInputs, AggregateLeg},
    ProverClient, PublicInputs, PublicTransfers, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_cu_split_core::{
    is_bn254_name, poseidon_arity, poseidon_cu,
    report::{flat_profile, inclusive_profile},
    stock_compression_cu, FunctionMap, InvocationTrace, SyscallEvent, TraceCollector,
    MEM_OP_BASE_CU,
};
use zolana_hasher::{primitives::hash_bytes, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::{
            aggregate_transact::{AggregateTransactIxData, EMPTY_LEG_PROOF},
            transact::{
                CircuitId, ExternalDataHash, InterfaceTransfer, ResolvedInterfaceTransfer,
                TransactIxData,
            },
        },
        AggregateTransact, Transact, TransactInterfaceTransferAccounts,
        TransactSolTransferAccounts,
    },
    verifying_keys::{AggregateCircuitId, InnerCircuitKind},
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::test_blinding;
use zolana_test_utils::transact::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo, fe,
    inline_outputs, new_transact_ix_data, nullifier_tree, output_owner_pk_hashes,
    prove_and_verify_rail_raw, public_sol_field, resolve_outputs, set_output_owner_tags,
    sol_public_slots, spend_input, SpendInputArgs, TransferProverInputsArgs,
};
use zolana_transaction::{instructions::transact::PrivateTxHash, Data, Utxo, SOL_MINT};

const SLOTS: u8 = N_PUBLIC_SLOTS as u8;
const WITHDRAW_LAMPORTS: u64 = 1_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Raw,
    Stock,
    B5,
}

impl Mode {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "raw" => Mode::Raw,
            "stock" => Mode::Stock,
            "b5" => Mode::B5,
            other => bail!("MODE must be raw, stock or b5, not {other}"),
        })
    }

    fn label(self) -> &'static str {
        match self {
            Mode::Raw => "raw",
            Mode::Stock => "stock",
            Mode::B5 => "b5",
        }
    }

    /// Group-op and compression charge for one syscall event, from the argument
    /// registers alone. Mirrors what the installed syscall set charges, so the
    /// per-family split and the metered total are two views of one run.
    fn bn254_cu(self, event: &SyscallEvent) -> Option<u64> {
        const LE_FLAG: u64 = 0x80;
        match event.name.as_str() {
            "sol_alt_bn128_compression" => Some(stock_compression_cu(event.args[0])),
            "sol_alt_bn128_group_op" => Some(match self {
                Mode::Raw | Mode::Stock => kernel::stock_group_op_cu(event.args[0], event.args[2]),
                Mode::B5 => match event.args[0] & !LE_FLAG {
                    0 | 1 => kernel::STOCK_G1_ADD_CU,
                    2 => kernel::b5_msm_cu(1),
                    3 => kernel::b5_pairing_cu(event.args[2] / 192),
                    other => panic!("group op {other} has no B5 mapping"),
                },
            }),
            _ => None,
        }
    }

    fn is_pairing(event: &SyscallEvent) -> bool {
        event.name == "sol_alt_bn128_group_op" && event.args[0] & !0x80 == 3
    }
}

fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("zolana-cu-split")
        .join("artifacts")
}

// ---------------------------------------------------------------------------
// Leg and batch construction, the confidential-rail path of the recursion
// worktree's `aggregate/cu.rs`, reproduced so that worktree stays untouched.
// ---------------------------------------------------------------------------

struct Leg {
    data: TransactIxData,
    proof: zolana_client::Proof,
    public_input_hash: [u8; 32],
    settlement: Pubkey,
}

struct LegInputs {
    utxo_hash: [u8; 32],
    nullifier: [u8; 32],
    nullifier_key: NullifierKey,
    owner_field: [u8; 32],
    utxo: Utxo,
}

fn leg_inputs(env: &mut Pool, index: u8) -> Result<LegInputs> {
    let payer = env.rpc.payer.insecure_clone();
    let owner_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    let blinding = test_blinding(7 + index);
    let nullifier_key = NullifierKey::from_secret([9 + index; 31]);
    let nullifier_pk = nullifier_key.pubkey()?;
    let owner_public_key = PublicKey::from_ed25519(&owner_bytes);
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk)?;
    let utxo = Utxo {
        owner: owner_public_key,
        asset: SOL_MINT,
        amount: WITHDRAW_LAMPORTS,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };
    env.rpc
        .deposit_sol(
            &env.tree.pubkey(),
            &payer,
            WITHDRAW_LAMPORTS,
            owner_field,
            blinding,
        )
        .map_err(|error| anyhow::anyhow!("proofless deposit: {error}"))?;

    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero)?;
    let nullifier = nullifier_key.nullifier(&utxo_hash, &blinding)?;
    Ok(LegInputs {
        utxo_hash,
        nullifier,
        nullifier_key,
        owner_field,
        utxo,
    })
}

fn build_leg(
    env: &Pool,
    index: usize,
    inputs: &LegInputs,
    state_tree: &MerkleTree<Poseidon>,
    roots: ([u8; 32], [u8; 32]),
    root_index: u16,
) -> Result<Leg> {
    let payer_bytes = env.rpc.payer.pubkey().to_bytes();
    let zero = [0u8; 32];
    let owner_public_key = PublicKey::from_ed25519(&payer_bytes);
    let owner_pk_hash = owner_public_key.owner_proof_input_hash()?;

    let state_path: Vec<[u8; 32]> = state_tree.get_proof_of_leaf(index, true)?.to_vec();
    let nf_tree = nullifier_tree()?;
    let non_inclusion =
        nf_tree.get_non_inclusion_proof(&BigUint::from_bytes_be(&inputs.nullifier))?;
    let (dummy_input_1, dummy_nullifier) = dummy_input(&[2 + index as u8; 31], &nf_tree, roots)?;

    let real_input = spend_input(SpendInputArgs {
        utxo: &inputs.utxo,
        owner_field: &inputs.owner_field,
        state_path: &state_path,
        state_path_index: index as u64,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &inputs.nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &inputs.nullifier_key,
    })?;

    let base = 1 + 3 * index as u8;
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [base, base + 1, base + 2]
        .iter()
        .map(|seed| dummy_transfer_output(&[*seed; 31]))
        .collect::<Result<_>>()?;
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    let recipient = Pubkey::new_unique();
    let mut data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(inputs.nullifier, root_index),
            eddsa_input_utxo(dummy_nullifier, root_index),
        ],
        vec![InterfaceTransfer::SolWithdrawal {
            amount: WITHDRAW_LAMPORTS,
        }],
        inline_outputs(&output_hashes, &[payer_bytes; 3]),
    );
    data.circuit = CircuitId::ConfidentialEddsa(2, 3, SLOTS);

    let owner_pk_hashes = output_owner_pk_hashes(&data.outputs)?;
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);

    let resolved_transfers = [ResolvedInterfaceTransfer::SolWithdrawal {
        amount: WITHDRAW_LAMPORTS,
        recipient: recipient.to_bytes(),
    }];
    let resolved_outputs = resolve_outputs(&data)?;
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: InnerCircuitKind::ConfidentialEddsa.solo_tag(),
        expiry_unix_ts: data.expiry_unix_ts,
        interface_transfers: &resolved_transfers,
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: &data.tx_viewing_pk,
        salt: &data.salt,
        outputs: &resolved_outputs,
        messages: &data.messages,
    }
    .hash()?;

    let private_tx = PrivateTxHash::new(
        &[inputs.utxo_hash, zero],
        &[zero, zero, zero],
        &external_data_hash,
    )
    .hash()?;

    let payer_hash = hash_bytes(&payer_bytes)?;
    let signer_hashes = [payer_hash, zero, zero];
    let (public_slot_assets, public_slot_amounts) =
        sol_public_slots(public_sol_field(Some(-(WITHDRAW_LAMPORTS as i64))));
    let public_inputs = PublicInputs {
        nullifiers: &[inputs.nullifier, dummy_nullifier],
        output_hashes: &output_hashes,
        utxo_roots: &[roots.0, roots.0],
        nullifier_tree_roots: &[roots.1, roots.1],
        private_tx: &private_tx,
        external_data_hash: &external_data_hash,
        public_transfers: &PublicTransfers {
            assets: public_slot_assets,
            amounts: public_slot_amounts,
        },
        ring_program_id: &zero,
        allow_dummy_inputs: &fe(1),
        signer_pk_hashes: &signer_hashes,
        output_owner_pk_hashes: Some(&owner_pk_hashes),
    };
    let public_input_hash = public_inputs.hash()?;

    let mut prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![real_input, dummy_input_1],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        signer_pk_hashes: signer_hashes.to_vec(),
        public_input_hash,
    });
    prover_inputs.ring_program_id = BigUint::from_bytes_be(&zero);

    let (packed, raw) = prove_and_verify_rail_raw(&prover_inputs, public_input_hash, "leg", false)?;
    data.private_tx_hash = private_tx;
    data.proof = packed;

    Ok(Leg {
        data,
        proof: raw,
        public_input_hash,
        settlement: recipient,
    })
}

fn sol_settlement(leg: &Leg) -> Vec<TransactInterfaceTransferAccounts> {
    vec![TransactInterfaceTransferAccounts::Sol(
        TransactSolTransferAccounts {
            recipient: leg.settlement,
        },
    )]
}

fn solo_cu(env: &mut Pool, leg: &Leg) -> Result<u64> {
    Ok(solo_run(env, leg)?.0)
}

fn solo_run(env: &mut Pool, leg: &Leg) -> Result<(u64, Vec<String>)> {
    let ix = Transact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: sol_settlement(leg),
        data: leg.data.clone(),
    }
    .instruction();
    println!("  solo instruction data {} bytes", ix.data.len());
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    kernel::reset_observations();
    probe::reset();
    env.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .map_err(|error| anyhow::anyhow!("solo transact: {error}"))?;
    let trace = env.rpc.last_transaction_trace().context("solo trace")?;
    Ok((trace.compute_units_consumed, trace.logs.clone()))
}

fn batch_cu(env: &mut Pool, legs: &[Leg]) -> Result<u64> {
    let outer = ProverClient::local().prove_aggregate(&AggregateInputs {
        inner: InnerCircuitKind::ConfidentialEddsa,
        num_inputs: 2,
        num_outputs: 3,
        legs: legs
            .iter()
            .map(|leg| AggregateLeg {
                proof: zolana_client::Proof {
                    a: negate_g1_be(&leg.proof.a),
                    ..leg.proof
                },
                public_input_hash: leg.public_input_hash,
            })
            .collect(),
    })?;
    let outer = zolana_client::ProofCompressed::try_from(outer)?;
    let (proof, bsb22_commitment) = outer.into_ring_p256_transact_parts()?;

    let data = AggregateTransactIxData {
        circuit: AggregateCircuitId {
            kind: InnerCircuitKind::ConfidentialEddsa,
            num_inputs: 2,
            num_outputs: 3,
            num_public_asset_slots: SLOTS,
            batch: legs.len() as u8,
        },
        proof,
        bsb22_commitment,
        legs: legs
            .iter()
            .map(|leg| TransactIxData {
                proof: EMPTY_LEG_PROOF,
                ..leg.data.clone()
            })
            .collect(),
        leg_account_counts: Vec::new(),
    };
    let instruction = AggregateTransact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        ring_program_ids: vec![
            Pubkey::new_from_array(zolana_program_test::RING_TEST_PROGRAM_ID);
            legs.len()
        ],
        owner_signers: vec![Vec::new(); legs.len()],
        interface_transfer_accounts: legs.iter().map(sol_settlement).collect(),
        data,
    }
    .instruction();
    println!(
        "  batch-{} instruction data {} bytes over {} accounts",
        legs.len(),
        instruction.data.len(),
        instruction.accounts.len()
    );

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    kernel::reset_observations();
    probe::reset();
    env.rpc
        .create_and_send_default_payer_transaction(&[budget, instruction], &[])
        .map_err(|error| anyhow::anyhow!("aggregate transact: {error}"))?;
    Ok(env
        .rpc
        .last_transaction_trace()
        .context("aggregate trace")?
        .compute_units_consumed)
}

/// Deposit `legs` UTXOs, prove one leg each, and hand back the pool with the
/// state root every leg proved against.
fn prepared_pool(
    legs: usize,
    install: &dyn Fn(&mut litesvm::LiteSVM),
) -> Result<(Pool, Vec<Leg>)> {
    let mut env = Pool::initialized();
    install(&mut env.rpc.svm);

    let mut inputs = Vec::with_capacity(legs);
    for index in 0..legs {
        inputs.push(leg_inputs(&mut env, index as u8)?);
    }
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for leg in &inputs {
        state_tree.append(&leg.utxo_hash)?;
    }
    let root_index = legs as u16;
    let roots = tree_roots(&env.rpc, &env.tree.pubkey(), root_index);
    if state_tree.root() != roots.0 {
        bail!("state root gate");
    }
    let built = inputs
        .iter()
        .enumerate()
        .map(|(index, leg)| build_leg(&env, index, leg, &state_tree, roots, root_index))
        .collect::<Result<Vec<_>>>()?;
    Ok((env, built))
}

// ---------------------------------------------------------------------------
// Reporting.
// ---------------------------------------------------------------------------

struct Split {
    transaction_cu: u64,
    sbpf_cu: u64,
    pairing_cu: u64,
    pairing_calls: u64,
    pairing_pairs: u64,
    bn254_other_cu: u64,
    bn254_other_calls: u64,
    poseidon_cu: u64,
    poseidon_calls: u64,
    hash_cu: Option<u64>,
    hash_calls: u64,
    hash_slices: u64,
    mem_op_cu: u64,
    mem_op_calls: u64,
    cpi_calls: u64,
}

impl Split {
    /// Whatever the four priced families and the sBPF trace do not account for:
    /// CPI, the sysvar read, and the runtime's fixed per-invocation cost.
    fn residual_cu(&self) -> i64 {
        self.transaction_cu as i64
            - self.sbpf_cu as i64
            - self.pairing_cu as i64
            - self.bn254_other_cu as i64
            - self.poseidon_cu as i64
            - self.hash_cu.unwrap_or(0) as i64
            - self.mem_op_cu as i64
    }
}

fn split(mode: Mode, transaction_cu: u64, traces: &[InvocationTrace]) -> Split {
    let events = || traces.iter().flat_map(|trace| trace.syscalls.iter());
    let observed = kernel::observations();

    let mut split = Split {
        transaction_cu,
        sbpf_cu: traces.iter().map(|trace| trace.instructions).sum(),
        pairing_cu: 0,
        pairing_calls: 0,
        pairing_pairs: 0,
        bn254_other_cu: 0,
        bn254_other_calls: 0,
        poseidon_cu: 0,
        poseidon_calls: 0,
        hash_cu: (mode != Mode::Raw).then_some(observed.hash_cu),
        hash_calls: 0,
        hash_slices: observed.hash_slices,
        mem_op_cu: 0,
        mem_op_calls: 0,
        cpi_calls: 0,
    };

    for event in events() {
        if let Some(cu) = mode.bn254_cu(event) {
            if Mode::is_pairing(event) {
                split.pairing_calls += 1;
                split.pairing_pairs += event.args[2] / 192;
                split.pairing_cu += cu;
            } else {
                split.bn254_other_calls += 1;
                split.bn254_other_cu += cu;
            }
            continue;
        }
        match event.name.as_str() {
            "sol_poseidon" => {
                split.poseidon_calls += 1;
                split.poseidon_cu += poseidon_cu(poseidon_arity(event).unwrap_or(0));
            }
            "sol_sha256" | "sol_keccak256" => split.hash_calls += 1,
            "sol_memcpy_" | "sol_memmove_" | "sol_memset_" | "sol_memcmp_" => {
                split.mem_op_calls += 1;
                split.mem_op_cu += MEM_OP_BASE_CU.max(event.args[2] / 250);
            }
            "sol_invoke_signed_c" | "sol_invoke_signed_rust" => split.cpi_calls += 1,
            _ => {}
        }
    }

    // The shim sees every hash call the program makes, including any inside a
    // CPI the register trace does not cover, so a disagreement here is a fact
    // about the trace rather than a rounding error.
    if mode != Mode::Raw && observed.hash_calls != split.hash_calls {
        eprintln!(
            "note: {} hash calls charged, {} seen in the register trace",
            observed.hash_calls, split.hash_calls
        );
    }
    if mode == Mode::B5 && observed.pairing_cu != split.pairing_cu {
        eprintln!(
            "note: {} pairing CU charged, {} re-derived from registers",
            observed.pairing_cu, split.pairing_cu
        );
    }
    split
}

fn render(title: &str, mode: Mode, split: &Split) -> String {
    let pct = |value: u64| 100.0 * value as f64 / split.transaction_cu as f64;
    let hash = split
        .hash_cu
        .map_or_else(|| "        ?".to_owned(), |cu| format!("{cu:9}"));
    let mut out = format!("\n=== {title} [{}] ===\n", mode.label());
    out.push_str(&format!(
        "  transaction CU            {:9}\n",
        split.transaction_cu
    ));
    out.push_str(&format!(
        "  executed sBPF CU          {:9}  {:5.1}%\n",
        split.sbpf_cu,
        pct(split.sbpf_cu)
    ));
    out.push_str(&format!(
        "  BN254 pairing             {:9}  {:5.1}%   x{} over {} pairs\n",
        split.pairing_cu,
        pct(split.pairing_cu),
        split.pairing_calls,
        split.pairing_pairs
    ));
    out.push_str(&format!(
        "  BN254 MSM / other         {:9}  {:5.1}%   x{}\n",
        split.bn254_other_cu,
        pct(split.bn254_other_cu),
        split.bn254_other_calls
    ));
    out.push_str(&format!(
        "  Poseidon                  {:9}  {:5.1}%   x{}\n",
        split.poseidon_cu,
        pct(split.poseidon_cu),
        split.poseidon_calls
    ));
    out.push_str(&format!(
        "  keccak256 / sha256        {hash}  {:5.1}%   x{} over {} slices\n",
        pct(split.hash_cu.unwrap_or(0)),
        split.hash_calls,
        split.hash_slices
    ));
    out.push_str(&format!(
        "  mem ops                   {:9}  {:5.1}%   x{}\n",
        split.mem_op_cu,
        pct(split.mem_op_cu),
        split.mem_op_calls
    ));
    out.push_str(&format!(
        "  everything else           {:9}  {:5.1}%   {} CPI\n",
        split.residual_cu(),
        100.0 * split.residual_cu() as f64 / split.transaction_cu as f64,
        split.cpi_calls
    ));
    out
}

fn measure(
    mode: Mode,
    title: &str,
    legs: usize,
    map: &FunctionMap,
    batch: bool,
) -> Result<(u64, String)> {
    let collector = TraceCollector::with_symbols(map.clone());
    let (mut env, built) = prepared_pool(legs, &|svm| collector.install(svm))?;
    let total = if batch {
        batch_cu(&mut env, &built)?
    } else {
        solo_cu(&mut env, &built[0])?
    };
    let traces = collector.last().context("no trace")?;
    let split = split(mode, total, &traces);
    Ok((total, render(title, mode, &split)))
}

/// Second pass over the same transaction with a stack-walking collector, which
/// is a separate run because LiteSVM holds one inspect callback at a time.
fn attribute(title: &str, legs: usize, map: &FunctionMap, batch: bool) -> Result<String> {
    let collector = attribute::StackCollector::new(map.clone());
    let (mut env, built) = prepared_pool(legs, &|svm| collector.install(svm))?;
    if batch {
        batch_cu(&mut env, &built)?;
    } else {
        solo_cu(&mut env, &built[0])?;
    }
    let found = collector.last().context("no attribution")?;
    Ok(format!("\n=== {title} Poseidon attribution ===\n{}", attribute::render(&found)))
}

/// Everything the reconciliation needs from one solo leg, printed once.
///
/// Runs under the B5 group op and the observing hash, CPI and sysvar shims, so
/// every line below is a charge read at the point the runtime makes it.
fn probe_solo(map: &FunctionMap, legs: usize, batch: bool) -> Result<String> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let collector = TraceCollector::with_symbols(map.clone());
    let (mut env, built) = prepared_pool(legs, &|svm| collector.install(svm))?;
    let tree_bytes = env
        .rpc
        .account_data(&env.tree.pubkey())
        .map_or(0, |data| data.len());
    let (total, logs) = if batch {
        let cu = batch_cu(&mut env, &built)?;
        let logs = env
            .rpc
            .last_transaction_trace()
            .context("batch trace")?
            .logs
            .clone();
        (cu, logs)
    } else {
        solo_run(&mut env, &built[0])?
    };
    let traces = collector.last().context("no trace")?;
    let observed = probe::observations();
    let hashes = kernel::observations();
    let split = split(Mode::B5, total, &traces);

    let mut out = format!(
        "\n=== probe, {} [b5] ===\ntransaction CU {total}   pool tree account {tree_bytes} bytes\n",
        if batch {
            format!("aggregate transact, {legs} legs")
        } else {
            "solo transact".to_owned()
        }
    );

    out.push_str("\n-- runtime invocation log --\n");
    for line in &logs {
        let _ = writeln!(out, "  {line}");
    }

    out.push_str("\n-- sBPF invocations --\n");
    let mut callee_sbpf = 0u64;
    for (index, trace) in traces.iter().enumerate() {
        let _ = writeln!(
            out,
            "  #{index}  sbpf {:>8}  syscalls {:>4}  bn254 subtree {:>6}  depth {}",
            trace.instructions,
            trace.syscalls.len(),
            trace.bn254_subtree_instructions,
            trace.max_stack_depth
        );
    }
    // Every invocation but the top-level one is a self-CPI the event path
    // makes. Its sBPF sits inside a measured CPI window and inside the sBPF
    // total at once, so one of the two has to give it back.
    if traces.len() > 1 {
        let top = traces
            .iter()
            .map(|trace| trace.instructions)
            .max()
            .unwrap_or(0);
        callee_sbpf = split.sbpf_cu.saturating_sub(top);
    }

    let mut bn254_static = 0u64;
    for trace in &traces {
        for (pc, count) in &trace.pc_counts {
            if map.lookup(*pc).is_some_and(|s| is_bn254_name(&s.name)) {
                bn254_static += count;
            }
        }
    }
    let bn254_dynamic: u64 = traces
        .iter()
        .map(|trace| trace.bn254_subtree_instructions)
        .sum();
    let _ = writeln!(
        out,
        "  total {}  bn254 dynamic {bn254_dynamic}  bn254 static {bn254_static}  callee sbpf {callee_sbpf}",
        split.sbpf_cu
    );

    out.push_str("\n-- every syscall, with the frame that issued it --\n");
    let mut by_name: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        let cu = Mode::B5.bn254_cu(event).or_else(|| match event.name.as_str() {
            "sol_poseidon" => Some(poseidon_cu(poseidon_arity(event).unwrap_or(0))),
            "sol_memcpy_" | "sol_memmove_" | "sol_memset_" | "sol_memcmp_" => {
                Some(MEM_OP_BASE_CU.max(event.args[2] / 250))
            }
            _ => None,
        });
        let slot = by_name.entry(event.name.clone()).or_insert((0, 0));
        slot.0 += 1;
        slot.1 += cu.unwrap_or(0);
    }
    for (name, (calls, cu)) in &by_name {
        let _ = writeln!(out, "  {name:<28} x{calls:<4} {cu:>8} CU from registers");
    }

    out.push_str("\n-- BN254 and hash calls, one line each --\n");
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        let interesting = matches!(
            event.name.as_str(),
            "sol_alt_bn128_group_op"
                | "sol_alt_bn128_compression"
                | "sol_keccak256"
                | "sol_sha256"
        );
        if !interesting {
            continue;
        }
        let _ = writeln!(
            out,
            "  {:<26} r1={:<4} r2={:<3} r3={:<6} {:>8} CU  {}",
            event.name,
            event.args[0],
            event.args[1],
            event.args[2],
            Mode::B5.bn254_cu(event).unwrap_or(0),
            short(&map.name(event.caller_entry_pc))
        );
    }

    out.push_str("\n-- Poseidon by issuing frame --\n");
    let mut poseidon_by_caller: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        let Some(arity) = poseidon_arity(event) else {
            continue;
        };
        let slot = poseidon_by_caller
            .entry(short(&map.name(event.caller_entry_pc)))
            .or_insert((0, 0));
        slot.0 += 1;
        slot.1 += poseidon_cu(arity);
    }
    for (name, (calls, cu)) in &poseidon_by_caller {
        let _ = writeln!(out, "  x{calls:<4} {cu:>8} CU  {name}");
    }

    out.push_str("\n-- mem ops by issuing frame --\n");
    let mut mem_by_caller: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        if !matches!(
            event.name.as_str(),
            "sol_memcpy_" | "sol_memmove_" | "sol_memset_" | "sol_memcmp_"
        ) {
            continue;
        }
        let slot = mem_by_caller
            .entry(short(&map.name(event.caller_entry_pc)))
            .or_insert((0, 0));
        slot.0 += 1;
        slot.1 += MEM_OP_BASE_CU.max(event.args[2] / 250);
    }
    let mut mem_rows: Vec<(String, (u64, u64))> = mem_by_caller.into_iter().collect();
    mem_rows.sort_by(|left, right| right.1 .1.cmp(&left.1 .1));
    for (name, (calls, cu)) in mem_rows.iter().take(12) {
        let _ = writeln!(out, "  x{calls:<4} {cu:>8} CU  {name}");
    }

    let _ = writeln!(
        out,
        "\n-- measured at the charge site --\n  CPI windows       x{}  {:>8} CU  {:?}\n  sysvar reads      x{}  {:>8} CU\n  hash syscalls     x{}  {:>8} CU over {} slices",
        observed.cpi_calls,
        observed.cpi_window_cu,
        observed.cpi_windows,
        observed.sysvar_calls,
        observed.sysvar_cu,
        hashes.hash_calls,
        hashes.hash_cu,
        hashes.hash_slices
    );

    let priced = split.sbpf_cu
        + split.pairing_cu
        + split.bn254_other_cu
        + split.poseidon_cu
        + split.hash_cu.unwrap_or(0)
        + split.mem_op_cu;
    // A CPI window holds the callee, whose sBPF the register trace has already
    // counted, so the window gives it back before the two lines are added.
    let cpi_caller_cu = observed.cpi_window_cu.saturating_sub(callee_sbpf);
    let _ = writeln!(
        out,
        "\n-- what is left --\n  transaction                 {total:>9}\n  priced from the trace       {priced:>9}\n  residual                    {:>9}\n  CPI window minus callee     {cpi_caller_cu:>9}\n  sysvar                      {:>9}\n  still unattributed          {:>9}",
        total as i64 - priced as i64,
        observed.sysvar_cu,
        total as i64 - priced as i64 - cpi_caller_cu as i64 - observed.sysvar_cu as i64
    );

    out.push_str("\n-- top frames, inclusive sBPF --\n");
    for (name, count) in inclusive_profile(&traces, map).into_iter().take(30) {
        let _ = writeln!(out, "  {count:>8}  {}", short(&name));
    }
    out.push_str("\n-- top functions, exclusive sBPF --\n");
    for (name, count, bn254) in flat_profile(&traces, map).into_iter().take(30) {
        let _ = writeln!(
            out,
            "  {count:>8}  {}  {}",
            if bn254 { "BN254" } else { "     " },
            short(&name)
        );
    }
    Ok(out)
}

fn short(name: &str) -> String {
    name.rsplit_once("::h")
        .map_or(name, |(head, _)| head)
        .to_owned()
}

fn main() -> Result<()> {
    let mode = Mode::parse(&std::env::var("MODE").unwrap_or_else(|_| "raw".to_owned()))?;
    let legs: usize = std::env::var("BATCH_LEGS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2);

    // Installed before the first `LiteSVM` exists. `Pool::initialized()` builds
    // one internally, and a program cache entry binds its runtime environment
    // at load time, so this cannot be deferred.
    let mut syscalls: Vec<(String, _)> = Vec::new();
    if mode != Mode::Raw {
        syscalls.push(("sol_sha256".to_owned(), kernel::ObservedSha256::register as _));
        syscalls.push((
            "sol_keccak256".to_owned(),
            kernel::ObservedKeccak256::register as _,
        ));
    }
    if mode == Mode::B5 {
        syscalls.push((
            "sol_alt_bn128_group_op".to_owned(),
            kernel::B5GroupOp::register as _,
        ));
    }
    let probing = std::env::var("PROBE").is_ok();
    if probing {
        syscalls.push((
            "sol_invoke_signed_c".to_owned(),
            probe::ObservedInvokeSignedC::register as _,
        ));
        syscalls.push((
            "sol_get_sysvar".to_owned(),
            probe::ObservedGetSysvar::register as _,
        ));
    }
    litesvm::set_global_custom_syscalls(syscalls).map_err(|_| anyhow::anyhow!("syscalls set"))?;

    std::env::var("SBF_TRACE_DIR")
        .context("set SBF_TRACE_DIR; LiteSVM reads it to enable register tracing")?;
    zolana_test_utils::prover::spawn_workspace_prover();

    let map = FunctionMap::from_paths(
        &artifacts().join("recursion_shielded_pool_program.so"),
        &artifacts().join("recursion_shielded_pool_program.symbols.so"),
    )?;
    println!(
        "mode {}  legs {legs}  symbols {}",
        mode.label(),
        map.len()
    );

    if probing {
        print!("{}", probe_solo(&map, 1, false)?);
        print!("{}", probe_solo(&map, legs, true)?);
        return Ok(());
    }

    if std::env::var("ATTRIBUTE").is_ok() {
        print!("{}", attribute("solo transact", 1, &map, false)?);
        print!(
            "{}",
            attribute(&format!("aggregate transact, {legs} legs"), legs, &map, true)?
        );
        return Ok(());
    }

    let (solo, solo_report) = measure(mode, "solo transact", 1, &map, false)?;
    print!("{solo_report}");
    let (batch, batch_report) = measure(
        mode,
        &format!("aggregate transact, {legs} legs"),
        legs,
        &map,
        true,
    )?;
    print!("{batch_report}");

    println!(
        "\nsummary [{}] legs {legs}: aggregate {batch}, solo x{legs} {}, per solo {solo}",
        mode.label(),
        solo * legs as u64
    );
    Ok(())
}
