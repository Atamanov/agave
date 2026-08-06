//! Three-bucket CU split of a real registry-enabled `transact`.
//!
//! Boots the same LiteSVM harness the vk-registry session uses, with register
//! tracing on and a trace collector in place of the file-writing default.
//! Neither the program nor the harness is modified; the SVM is prepared here
//! and handed to `ZolanaProgramTest::with_svm_and_program_path`.
//!
//! Needs the prover reachable on the usual port. The program binaries are the
//! copies under `../artifacts/`, taken from the vk-registry worktree.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use litesvm::LiteSVM;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use vk_registry_test::with_prepared_syscalls;
use zolana_cu_split_core::{report, stock_bn254_pricer, FunctionMap, SyscallEvent, TraceCollector};
use zolana_interface::{
    instruction::{
        builders::{append_vk_registry, InitVkRegistry},
        tag, Transact,
    },
    verifying_keys::{catalog::VK_CATALOG, registry::VK_REGISTRY_SPECS},
};
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::{
    backend::LiteSvmPoolBackend, transact::build_valid_confidential_transact_ix,
};

/// The prices the harness shim charges, read from the shim itself.
fn pricer(event: &SyscallEvent) -> Option<u64> {
    use vk_registry_test::{prepared_pairing_cu, RUNTIME_G2_PREPARE_CU};

    match event.name.as_str() {
        "sol_alt_bn128_g2_prepare" => Some(RUNTIME_G2_PREPARE_CU),
        "sol_alt_bn128_pairing_check_prepared" | "sol_alt_bn128_pairing_map_prepared" => {
            let (full, prepared) =
                solana_bn254_batch_syscall::unpack_prepared_pairing_shape(event.args[0])
                    .unwrap_or((0, 0));
            Some(prepared_pairing_cu(u64::from(full), u64::from(prepared)))
        }
        "sol_alt_bn128_pairing_map" => Some(prepared_pairing_cu(event.args[0], 0)),
        _ => stock_bn254_pricer(event),
    }
}

fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("artifacts")
}

fn program_path() -> PathBuf {
    artifacts().join("registry_shielded_pool_program.so")
}

fn symbol_path() -> PathBuf {
    artifacts().join("registry_shielded_pool_program.symbols.so")
}

/// Fresh pool over the registry-enabled program. One backend per transaction:
/// the fixture's deterministic blindings mean a second send replays the same
/// nullifiers.
fn boot(collector: Option<&TraceCollector>) -> Result<LiteSvmPoolBackend> {
    let path = program_path();
    if !path.exists() {
        bail!("missing {}", path.display());
    }
    let mut svm = with_prepared_syscalls(match collector {
        Some(_) => LiteSVM::new_debuggable(true),
        None => LiteSVM::new(),
    });
    if let Some(collector) = collector {
        collector.install(&mut svm);
    }
    let rpc = ZolanaProgramTest::with_svm_and_program_path(svm, &path)
        .map_err(|error| anyhow::anyhow!("boot registry-enabled program: {error}"))?;
    LiteSvmPoolBackend::with_rpc(rpc).map_err(|error| anyhow::anyhow!("boot pool state: {error}"))
}

fn transact_cu(env: &mut LiteSvmPoolBackend, with_registry: bool) -> Result<u64> {
    let payer = env.rpc.payer.pubkey();
    let tree = env.tree.pubkey();
    let data = build_valid_confidential_transact_ix(env, payer, tag::TRANSACT)
        .context("build confidential transact")?;
    let mut ix = Transact {
        payer,
        input_tree: tree,
        output_tree: tree,
        owner_signers: Vec::new(),
        interface_transfer_accounts: Vec::new(),
        data,
    }
    .instruction();

    if with_registry {
        let vk_index = VK_CATALOG
            .iter()
            .position(|(name, _)| *name == "transfer_confidential_2_3")
            .context("catalog entry")?;
        let builder = InitVkRegistry {
            payer,
            vk_index: vk_index as u8,
        };
        for _ in 0..builder.transaction_count() {
            env.rpc
                .create_and_send_default_payer_transaction(&[builder.instruction()], &[])
                .map_err(|error| anyhow::anyhow!("registry init step: {error}"))?;
        }
        append_vk_registry(
            &mut ix,
            Pubkey::new_from_array(VK_REGISTRY_SPECS[vk_index].address),
        );
    }

    env.rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .map_err(|error| anyhow::anyhow!("transact: {error}"))?;
    Ok(env
        .rpc
        .last_transaction_trace()
        .context("transaction trace")?
        .compute_units_consumed)
}

fn main() -> Result<()> {
    zolana_client::spawn_prover().map_err(|error| anyhow::anyhow!("prover unreachable: {error}"))?;

    let map = FunctionMap::from_paths(&program_path(), &symbol_path())?;
    println!("symbols resolved: {}", map.len());

    // Control: the untraced CU must equal the traced CU, or tracing perturbs
    // the very number the split divides up.
    let control_plain = transact_cu(&mut boot(None)?, false)?;
    let control_registered = transact_cu(&mut boot(None)?, true)?;
    println!("untraced CU: plain {control_plain}, registered {control_registered}");

    for (label, with_registry, control) in [
        ("plain transact (full-pair path)", false, control_plain),
        ("registered transact", true, control_registered),
    ] {
        let collector = TraceCollector::with_symbols(map.clone());
        let mut env = boot(Some(&collector))?;
        let cu = transact_cu(&mut env, with_registry)?;
        // The fixture draws a fresh payer keypair per boot, so the proof and a
        // few data-dependent branches move by a unit or two between runs. A
        // wider gap would mean tracing itself changed what is being measured.
        let drift = cu as i64 - control as i64;
        if drift.abs() > 16 {
            bail!("tracing changed CU for {label}: {control} -> {cu}");
        }
        println!("\n[{label}] untraced {control}, traced {cu} (drift {drift})");
        let traces = collector.last().context("no trace captured")?;
        print!("{}", report::render(label, cu, &traces, &map, pricer));
    }

    Ok(())
}
