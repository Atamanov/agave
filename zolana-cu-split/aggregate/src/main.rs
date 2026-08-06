//! Four-bucket CU split of a real `aggregate_transact` batch and of the solo
//! `transact` it replaces, on the groth16-recursion program.
//!
//! The leg and batch construction is the confidential-rail path of that
//! worktree's `aggregate/cu.rs`, reproduced here so the worktree stays
//! untouched. Register tracing is switched on through `SBF_TRACE_DIR`, which
//! LiteSVM reads when it builds its default environment, and the file-writing
//! callback is then replaced with an in-memory collector.
//!
//! Needs the recursion prover reachable on the usual port, with the aggregate
//! proving keys the worktree generated.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use groth16_solana::groth16::negate_g1_be;
use num_bigint::BigUint;
use shielded_pool_tests::support::{fixtures::Pool, transact::tree_roots};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::{AggregateInputs, AggregateLeg},
    ProverClient, PublicInputs, PublicTransfers, TransferOutput, STATE_TREE_HEIGHT,
};
use zolana_cu_split_core::{report, stock_bn254_pricer, FunctionMap, TraceCollector};
use zolana_hasher::{primitives::hash_bytes, Poseidon};
use zolana_interface::{
    instruction::{
        instruction_data::{
            aggregate_transact::{AggregateTransactIxData, EMPTY_LEG_PROOF},
            transact::{CircuitId, ExternalDataHash, InterfaceTransfer, ResolvedInterfaceTransfer,
                       TransactIxData},
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

fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("artifacts")
}

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
    let non_inclusion = nf_tree.get_non_inclusion_proof(&BigUint::from_bytes_be(&inputs.nullifier))?;
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
    let ix = Transact {
        payer: env.rpc.payer.pubkey(),
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        owner_signers: Vec::new(),
        interface_transfer_accounts: sol_settlement(leg),
        data: leg.data.clone(),
    }
    .instruction();
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    env.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .map_err(|error| anyhow::anyhow!("solo transact: {error}"))?;
    Ok(env
        .rpc
        .last_transaction_trace()
        .context("solo trace")?
        .compute_units_consumed)
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

    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
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
fn prepared_pool(legs: usize, collector: Option<&TraceCollector>) -> Result<(Pool, Vec<Leg>)> {
    let mut env = Pool::initialized();
    if let Some(collector) = collector {
        collector.install(&mut env.rpc.svm);
    }

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

fn main() -> Result<()> {
    let trace_dir = std::env::var("SBF_TRACE_DIR")
        .context("set SBF_TRACE_DIR; LiteSVM reads it to enable register tracing")?;
    // Cleared for the untraced control, restored for the measured run.
    std::env::remove_var("SBF_TRACE_DIR");

    zolana_test_utils::prover::spawn_workspace_prover();

    let map = FunctionMap::from_paths(
        &artifacts().join("recursion_shielded_pool_program.so"),
        &artifacts().join("recursion_shielded_pool_program.symbols.so"),
    )?;
    println!("symbols resolved: {}", map.len());

    let legs = std::env::var("BATCH_LEGS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2usize);

    let (mut control_env, control_legs) = prepared_pool(legs, None)?;
    let control_batch = batch_cu(&mut control_env, &control_legs)?;
    let (mut control_solo_env, control_solo_legs) = prepared_pool(1, None)?;
    let control_solo = solo_cu(&mut control_solo_env, &control_solo_legs[0])?;
    println!("untraced CU: batch-{legs} {control_batch}, solo {control_solo}");

    std::env::set_var("SBF_TRACE_DIR", &trace_dir);

    let solo_collector = TraceCollector::with_symbols(map.clone());
    let (mut solo_env, solo_legs) = prepared_pool(1, Some(&solo_collector))?;
    let solo = solo_cu(&mut solo_env, &solo_legs[0])?;
    let solo_traces = solo_collector.last().context("no solo trace")?;
    println!("\n[solo transact] untraced {control_solo}, traced {solo}");
    print!(
        "{}",
        report::render("solo transact", solo, &solo_traces, &map, stock_bn254_pricer)
    );

    let batch_collector = TraceCollector::with_symbols(map.clone());
    let (mut batch_env, batch_legs) = prepared_pool(legs, Some(&batch_collector))?;
    let batch = batch_cu(&mut batch_env, &batch_legs)?;
    let batch_traces = batch_collector.last().context("no batch trace")?;
    println!("\n[aggregate transact, {legs} legs] untraced {control_batch}, traced {batch}");
    print!(
        "{}",
        report::render(
            &format!("aggregate transact, {legs} legs"),
            batch,
            &batch_traces,
            &map,
            stock_bn254_pricer
        )
    );

    Ok(())
}
