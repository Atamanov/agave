use {
    litesvm::{LiteSVM, types::TransactionMetadata},
    serde::Deserialize,
    sha2::{Digest, Sha256},
    solana_account_v3::Account,
    solana_address_v2::Address,
    solana_bn254_decision_bench::{
        ColumnId, ExecutionRequest, FixtureManifest, FrLincombCall, GtTargetMultiexpCall,
        HashSyscallTotals, MsmCall, OperationTrace, PairingCall, PlonkMultiVkReduceCall,
        ResidualCell, RowId,
    },
    solana_bn254_decision_litesvm::{
        DEFAULT_HASH_BYTE_COST, GroupOpKind, ObserverSnapshot, current_embedded_hot_core_cu,
        new_litesvm_charging_hash_bytes, observer_snapshot, registry_account_len, reset_observers,
    },
    solana_compute_budget_interface_v3::ComputeBudgetInstruction,
    solana_instruction_v3::{Instruction, account_meta::AccountMeta},
    solana_keypair_v3::Keypair,
    solana_message_v3::Message,
    solana_signer_v3::Signer,
    solana_transaction_v3::Transaction,
    std::{
        collections::BTreeMap,
        env, fs,
        io::{self, Read},
        path::{Path, PathBuf},
    },
};

const SAMPLE_COUNT: u64 = 2;
const INPUT_PDA_SEED: &[u8] = b"plonk-input-v1";
const REGISTRY_PDA_SEED: &[u8] = b"bn254-b5-vk-registry-v3";
const REGISTRY_HEADER_BYTES: usize = 80;
const REGISTRY_ENTRY_BYTES: usize = 32 + 128 + 37_584;
const GROTH_KEYSET_DOMAIN: &[u8] = b"agave:bn254:b5:keyset:v3";
const GROTH_REGISTRY_VERSION: u8 = 3;

#[derive(Debug)]
struct Cli {
    workspace_root: PathBuf,
    program_dir: PathBuf,
    plonk_fixture_dir: PathBuf,
    runtime_revision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlonkFixtureMetadata {
    schema: String,
    semantics: String,
    source_set_sha256: String,
    rows: BTreeMap<String, PlonkRowMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlonkRowMetadata {
    path: String,
    length: usize,
    sha256: String,
    input_digest: String,
    registry_keyset_digest_v3: String,
    registry_len: usize,
}

struct PlonkMaterial {
    fixture_data: Vec<u8>,
    input_digest: [u8; 32],
    registry_digest: [u8; 32],
    registry_len: usize,
}

#[derive(Clone)]
struct Case {
    program_id: Address,
    program_path: PathBuf,
    fixture_address: Address,
    fixture_data: Vec<u8>,
    tag: u8,
    registry: Option<(Address, usize)>,
    setup_tag: Option<u8>,
    /// The PLONK guest takes the two registry entry IDs in the hot instruction,
    /// ordered tau then generator. They exist only after initialization, so the
    /// setup transaction reads them back out of the account.
    hot_registry_ids: bool,
}

fn parse_cli() -> Result<Cli, String> {
    let mut workspace_root = None;
    let mut program_dir = None;
    let mut plonk_fixture_dir = None;
    let mut runtime_revision = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let target = match arg.as_str() {
            "--workspace-root" => &mut workspace_root,
            "--program-dir" => &mut program_dir,
            "--plonk-fixture-dir" => &mut plonk_fixture_dir,
            "--runtime-revision" => &mut runtime_revision,
            _ => return Err(format!("unknown collector argument {arg}")),
        };
        if target
            .replace(
                args.next()
                    .ok_or_else(|| format!("{arg} requires a value"))?,
            )
            .is_some()
        {
            return Err(format!("{arg} repeated"));
        }
    }
    Ok(Cli {
        workspace_root: PathBuf::from(workspace_root.ok_or("missing --workspace-root")?),
        program_dir: PathBuf::from(program_dir.ok_or("missing --program-dir")?),
        plonk_fixture_dir: PathBuf::from(plonk_fixture_dir.ok_or("missing --plonk-fixture-dir")?),
        runtime_revision: runtime_revision.ok_or("missing --runtime-revision")?,
    })
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|error| format!("{label}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} is not 32 bytes"))
}

fn fixture_root(request: &ExecutionRequest) -> Result<PathBuf, String> {
    let manifest_path = Path::new(&request.fixture_manifest_path);
    let bytes = read(manifest_path)?;
    let manifest: FixtureManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("fixture manifest JSON: {error}"))?;
    let parent = manifest_path
        .parent()
        .ok_or("fixture manifest has no parent")?;
    let root = parent.join(manifest.artifact_root);
    fs::canonicalize(&root).map_err(|error| format!("fixture root {}: {error}", root.display()))
}

fn groth_fixture_path(request: &ExecutionRequest, root: &Path) -> Result<PathBuf, String> {
    let suffix = match request.row_id {
        RowId::Groth16N5SameVk => "rows/G5.bin",
        RowId::Groth16N2DistinctVk => "rows/G2.bin",
        RowId::Groth16N3DistinctVk => "rows/G3.bin",
        _ => return Err("PLONK row requested a Groth fixture".into()),
    };
    let pinned = request
        .fixture
        .files
        .iter()
        .find(|file| file.path == suffix)
        .ok_or_else(|| format!("row does not pin {suffix}"))?;
    let path = root.join(suffix);
    let bytes = read(&path)?;
    if bytes.len() as u64 != pinned.size_bytes || digest(&bytes) != pinned.sha256 {
        return Err(format!("sealed Groth fixture {suffix} changed"));
    }
    Ok(path)
}

fn groth_registry_material(data: &[u8]) -> Result<([u8; 32], usize), String> {
    let n = usize::from(*data.first().ok_or("empty Groth fixture")?);
    let k = usize::from(*data.get(1).ok_or("short Groth fixture")?);
    let vk_region_len = k
        .checked_mul(576)
        .ok_or("Groth VK region length overflow")?;
    let vk_base = 2usize.checked_add(n).ok_or("Groth VK base overflow")?;
    let minimum = vk_base
        .checked_add(vk_region_len)
        .ok_or("Groth fixture minimum length overflow")?;
    if n == 0 || k == 0 || k > n || data.len() < minimum {
        return Err("invalid Groth fixture header".into());
    }
    let mut sources = Vec::with_capacity(vk_region_len);
    let vk_region = data
        .get(vk_base..minimum)
        .ok_or("Groth VK region is out of bounds")?;
    let vks: Vec<&[u8]> = vk_region.chunks_exact(576).collect();
    if vks.len() != k {
        return Err("Groth VK chunk count changed".into());
    }
    for vk in &vks {
        sources.extend_from_slice(&vk[64..192]);
        sources.extend_from_slice(&vk[192..320]);
        sources.extend_from_slice(&vk[320..448]);
    }
    for vk in &vks {
        sources.extend_from_slice(&vk[..64]);
        sources.extend_from_slice(&vk[64..192]);
    }
    let g2_count = u16::try_from(k)
        .ok()
        .and_then(|count| count.checked_mul(3))
        .ok_or("Groth registry G2 count overflow")?;
    let gt_count = u16::try_from(k).map_err(|_| "Groth registry GT count overflow")?;
    let digest = solana_keccak_hasher::hashv(&[
        GROTH_KEYSET_DOMAIN,
        &[GROTH_REGISTRY_VERSION],
        &g2_count.to_le_bytes(),
        &gt_count.to_le_bytes(),
        &sources,
    ])
    .to_bytes();
    Ok((digest, registry_account_len(3 * k, k)))
}

fn plonk_metadata(dir: &Path, proof_count: u32) -> Result<PlonkMaterial, String> {
    let metadata_path = dir.join("manifest.json");
    let metadata_bytes = read(&metadata_path)?;
    if digest(&metadata_bytes) != "e0029065e7450f1987fab16163584381970cb57af60712a08280cac4c0012fc8"
    {
        return Err("canonical PLONK exporter manifest digest changed".into());
    }
    let metadata: PlonkFixtureMetadata = serde_json::from_slice(&metadata_bytes)
        .map_err(|error| format!("PLONK exporter manifest JSON: {error}"))?;
    if metadata.schema != "helius.bn254-decision.plonk-direct-test-exceptions.v1"
        || metadata.semantics
            != "committed snarkjs PLONK fixtures shaped like zolana transact: one public \
signal, Poseidon chain over (nIn, nOut) at 1_1, 2_2, 2_3, distinct keys over one SRS; \
not production proofs"
        || metadata.source_set_sha256
            != "be0d2d01245e8ef0bac319a60033ce96d64dddb39a6431d9ed4e4e2c7042dd73"
    {
        return Err("PLONK exporter manifest schema changed".into());
    }
    let row = metadata
        .rows
        .get(&format!("n{proof_count}"))
        .ok_or("PLONK exporter omitted requested row")?;
    let (expected_length, expected_sha256) = match proof_count {
        2 => (
            3_308,
            "0596581e68c6f23f422ff2932f6d66c8bea7b92d2b21ce937507ee1df9bfb88c",
        ),
        3 => (
            4_956,
            "c2a0a59915ef6de40645737c61f98b5e82856638150d5d073d5909510ec71b9a",
        ),
        _ => return Err("canonical PLONK row proof count changed".into()),
    };
    let bytes = read(&dir.join(&row.path))?;
    if row.length != expected_length
        || row.sha256 != expected_sha256
        || bytes.len() != expected_length
        || digest(&bytes) != expected_sha256
    {
        return Err("PLONK exported account digest changed".into());
    }
    Ok(PlonkMaterial {
        fixture_data: bytes,
        input_digest: decode_digest(&row.input_digest, "PLONK input digest")?,
        registry_digest: decode_digest(&row.registry_keyset_digest_v3, "PLONK registry digest")?,
        registry_len: row.registry_len,
    })
}

fn recursion_payload(cli: &Cli, row: RowId) -> Result<Vec<u8>, String> {
    let (relative, length, sha256) = match row {
        RowId::Groth16N5SameVk => (
            "research/bn254-decision-table-v2-20260804/recursion-v2/n5-same/payload_unnegated_a.bin",
            576,
            "4e949e0ec63f00197ce059a7be6b7a9aaac8fe8be08907f37f86e7c5aeb1dc86",
        ),
        RowId::Groth16N2DistinctVk => (
            "research/bn254-decision-table-v2-20260804/recursion-v2/n2-distinct/payload_unnegated_a.bin",
            480,
            "6901c6d6d4575d24ad987caf3defa82113cbccf36794a9a4d69d02810ee15278",
        ),
        RowId::Groth16N3DistinctVk => (
            "research/bn254-decision-table-v2-20260804/recursion-v2/n3-distinct/payload_unnegated_a.bin",
            512,
            "58d8db8c9f035386f1419b35c230c3589a62f47e89bf370cc734880f2487c79f",
        ),
        RowId::PlonkN2DistinctVkSharedSrs => (
            "bn254-decision-bench/sbf/plonk-recursion/fixtures/fixed-statement-v3/n2-secure/payload_unnegated_a.bin",
            512,
            "5a381a6ae9c930e49b0a758324331c87594abefbb496fe159f1a176f3327f4f3",
        ),
        RowId::PlonkN3DistinctVkSharedSrs => (
            "bn254-decision-bench/sbf/plonk-recursion/fixtures/fixed-statement-v3/n3-secure/payload_unnegated_a.bin",
            608,
            "58e22abcfc95483ae180e081f44d32cd5b6b898d092571b14a1c5f5caa9cf4ca",
        ),
    };
    let bytes = read(&cli.workspace_root.join(relative))?;
    if bytes.len() != length || digest(&bytes) != sha256 {
        return Err(format!("sealed recursion payload {relative} changed"));
    }
    Ok(bytes)
}

fn program_id(row: RowId, recursion: bool) -> Address {
    let discriminator = match (row.is_groth16(), recursion) {
        (true, false) => 41,
        (false, false) => 42,
        (true, true) => 43,
        (false, true) => 44,
    };
    Address::new_from_array([discriminator; 32])
}

fn program_filename(row: RowId, recursion: bool) -> &'static str {
    match (row.is_groth16(), recursion) {
        (true, false) => "bn254_decision_groth16_guest.so",
        (false, false) => "bn254_decision_plonk_direct_guest.so",
        (true, true) => "bn254_decision_groth_recursion_guest.so",
        (false, true) => "bn254_decision_plonk_recursion_guest.so",
    }
}

fn build_case(cli: &Cli, request: &ExecutionRequest) -> Result<Case, String> {
    let recursion = request.column_id == ColumnId::RecursionB5;
    let program_id = program_id(request.row_id, recursion);
    let program_path = cli
        .program_dir
        .join(program_filename(request.row_id, recursion));
    if recursion {
        return Ok(Case {
            program_id,
            program_path,
            fixture_address: Address::new_from_array([61; 32]),
            fixture_data: recursion_payload(cli, request.row_id)?,
            tag: 0,
            registry: None,
            setup_tag: None,
            hot_registry_ids: false,
        });
    }

    if request.row_id.is_groth16() {
        let root = fixture_root(request)?;
        let fixture_data = read(&groth_fixture_path(request, &root)?)?;
        let (keyset_digest, registry_len) = groth_registry_material(&fixture_data)?;
        let (registry_address, _) =
            Address::find_program_address(&[REGISTRY_PDA_SEED, &keyset_digest], &program_id);
        let registry_needed = matches!(
            request.column_id,
            ColumnId::RegistryB5 | ColumnId::CurrentFp12 | ColumnId::BatchFp12B5
        );
        return Ok(Case {
            program_id,
            program_path,
            fixture_address: Address::new_from_array([62; 32]),
            fixture_data,
            tag: match request.column_id {
                ColumnId::Current => 0,
                ColumnId::BatchB5 => 2,
                ColumnId::RegistryB5 => 3,
                ColumnId::CurrentFp12 => 9,
                ColumnId::BatchFp12B5 => 4,
                ColumnId::RecursionB5 => unreachable!(),
            },
            registry: registry_needed.then_some((registry_address, registry_len)),
            setup_tag: registry_needed.then_some(5),
            hot_registry_ids: false,
        });
    }

    let PlonkMaterial {
        fixture_data,
        input_digest,
        registry_digest,
        registry_len,
    } = plonk_metadata(&cli.plonk_fixture_dir, request.row_id.proof_count())?;
    let (fixture_address, _) =
        Address::find_program_address(&[INPUT_PDA_SEED, &input_digest], &program_id);
    let (registry_address, _) =
        Address::find_program_address(&[REGISTRY_PDA_SEED, &registry_digest], &program_id);
    let registry_needed = request.column_id == ColumnId::RegistryB5;
    Ok(Case {
        program_id,
        program_path,
        fixture_address,
        fixture_data,
        tag: match request.column_id {
            ColumnId::Current => 0,
            ColumnId::BatchB5 => 2,
            ColumnId::RegistryB5 => 3,
            ColumnId::CurrentFp12 => 9,
            ColumnId::BatchFp12B5 => 4,
            ColumnId::RecursionB5 => unreachable!(),
        },
        registry: registry_needed.then_some((registry_address, registry_len)),
        setup_tag: registry_needed.then_some(5),
        hot_registry_ids: registry_needed,
    })
}

fn account(data: Vec<u8>, owner: Address) -> Account {
    Account {
        lamports: 10_000_000_000,
        data,
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn instruction(
    case: &Case,
    tag: u8,
    registry_writable: bool,
    registry_ids: &[[u8; 32]],
) -> Instruction {
    let mut accounts = Vec::new();
    if let Some((registry, _)) = case.registry {
        accounts.push(AccountMeta {
            pubkey: registry,
            is_signer: false,
            is_writable: registry_writable,
        });
    }
    accounts.push(AccountMeta {
        pubkey: case.fixture_address,
        is_signer: false,
        is_writable: false,
    });
    let mut data = vec![tag];
    for id in registry_ids {
        data.extend_from_slice(id);
    }
    Instruction {
        program_id: case.program_id,
        accounts,
        data,
    }
}

fn send(svm: &mut LiteSVM, ix: Instruction) -> Result<TransactionMetadata, String> {
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000)
        .map_err(|error| format!("payer airdrop failed: {error:?}"))?;
    let blockhash = svm.latest_blockhash();
    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        ix,
    ];
    let message = Message::new_with_blockhash(&instructions, Some(&payer.pubkey()), &blockhash);
    let tx = Transaction::new(&[&payer], message, blockhash);
    svm.send_transaction(tx).map_err(|error| {
        format!(
            "transaction failed: {:?}; logs={:?}",
            error.err, error.meta.logs
        )
    })
}

fn append_pairing(calls: &mut Vec<PairingCall>, full: u32, registered: u32) {
    let pairs = full.saturating_add(registered);
    if let Some(last) = calls.last_mut() {
        if last.pairs == pairs && last.full_pairs == full && last.registered_pairs == registered {
            last.calls = last.calls.saturating_add(1);
            return;
        }
    }
    calls.push(PairingCall {
        pairs,
        full_pairs: full,
        registered_pairs: registered,
        calls: 1,
    });
}

fn trace(snapshot: &ObserverSnapshot) -> Result<OperationTrace, String> {
    snapshot.stock_group_ops.require_valid_count(1)?;
    if snapshot.registry_init.g2_entries != 0
        || snapshot.registry_init.gt_entries != 0
        || snapshot.standalone_subgroup_checks != 0
        || snapshot.standalone_final_exponentiations != 0
    {
        return Err("hot transaction contains setup/probe-only observer events".into());
    }
    let mut pairing_checks = Vec::new();
    for event in &snapshot.pairing_checks {
        append_pairing(&mut pairing_checks, event.pairs as u32, 0);
    }
    for event in &snapshot.registered_pairing_checks {
        append_pairing(
            &mut pairing_checks,
            event.full_pairs as u32,
            event.registered_pairs as u32,
        );
    }
    for event in &snapshot.stock_group_ops.events {
        if event.kind == GroupOpKind::Pairing {
            append_pairing(
                &mut pairing_checks,
                event
                    .pairing_elements
                    .ok_or("stock pairing has no element count")? as u32,
                0,
            );
        }
    }
    let mut pairing_maps = Vec::new();
    for event in &snapshot.pairing_maps {
        append_pairing(&mut pairing_maps, event.pairs as u32, 0);
    }
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
    let mut stock_g1_additions = 0u32;
    let mut stock_g1_multiplications = 0u32;
    for event in &snapshot.stock_group_ops.events {
        match event.kind {
            GroupOpKind::G1Add => stock_g1_additions = stock_g1_additions.saturating_add(1),
            GroupOpKind::G1Mul => {
                stock_g1_multiplications = stock_g1_multiplications.saturating_add(1)
            }
            GroupOpKind::Pairing => {}
        }
    }
    let fr_lincomb_calls = snapshot
        .fr_lincombs
        .iter()
        .map(|event| {
            u32::try_from(event.terms)
                .map(FrLincombCall::one)
                .map_err(|_| "fr_lincomb term count overflows u32".to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let plonk_multi_vk_reduce_calls = snapshot
        .plonk_multi_vk_reduces
        .iter()
        .map(|event| {
            Ok(PlonkMultiVkReduceCall {
                contexts: u32::try_from(event.contexts).map_err(|_| "contexts overflow")?,
                proofs: u32::try_from(event.proofs).map_err(|_| "proofs overflow")?,
                public_inputs: u32::try_from(event.public_inputs)
                    .map_err(|_| "public inputs overflow")?,
                calls: 1,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let hash_syscalls = HashSyscallTotals {
        calls: u32::try_from(snapshot.hash_syscalls.calls)
            .map_err(|_| "hash syscall count overflow")?,
        slices: u32::try_from(snapshot.hash_syscalls.slices)
            .map_err(|_| "hash syscall slice overflow")?,
        byte_cu: u32::try_from(snapshot.hash_syscalls.byte_cu)
            .map_err(|_| "hash syscall byte CU overflow")?,
    };
    Ok(OperationTrace {
        hash_syscalls,
        plonk_multi_vk_reduce_calls,
        fr_lincomb_calls,
        stock_g1_additions,
        stock_g1_multiplications,
        pairing_checks,
        pairing_maps,
        msm_calls: snapshot
            .msm_calls
            .iter()
            .map(|event| MsmCall {
                points: event.points as u32,
                calls: 1,
            })
            .collect(),
        gt_target_multiexp_calls: snapshot
            .trusted_gt_multiexps
            .iter()
            .map(|event| GtTargetMultiexpCall {
                targets: event.targets as u32,
                nontrivial_exponents: event.nontrivial_exponents as u32,
                calls: 1,
            })
            .collect(),
        final_exponentiations,
        g2_subgroup_checks,
    })
}

fn require_b5_dispatch_attestation(snapshot: &ObserverSnapshot) -> Result<(), String> {
    #[cfg(not(feature = "backend-b5-helius-ifma"))]
    let _ = snapshot;
    #[cfg(feature = "backend-b5-helius-ifma")]
    {
        let ordinary_eight = snapshot
            .pairing_checks
            .iter()
            .chain(&snapshot.pairing_maps)
            .any(|event| event.pairs >= 8);
        let mixed_eight = snapshot
            .registered_pairing_checks
            .iter()
            .any(|event| event.full_pairs.saturating_add(event.registered_pairs) >= 8);
        // The lane kernel only exists under compile-time IFMA. Without it the
        // portable path runs and dispatches nothing, which is expected, not a
        // fault: charges and the guest residual are identical either way.
        let lane_kernel_present =
            solana_bn254_decision_litesvm::selected_backend_compiled_with_avx512_ifma();
        if lane_kernel_present && ordinary_eight && snapshot.ifma_batch8_dispatches == 0 {
            return Err(
                "B5 transaction reached an 8-pair shape without ordinary IFMA dispatch".into(),
            );
        }
        if lane_kernel_present && mixed_eight && snapshot.ifma_mixed_batch8_dispatches == 0 {
            return Err(
                "B5 transaction reached an 8-pair registered shape without mixed IFMA dispatch"
                    .into(),
            );
        }
    }
    Ok(())
}

/// Returns the SVM plus the registry entry IDs the hot instruction needs, in
/// the order the guest reads them.
fn setup_svm(case: &Case) -> Result<(LiteSVM, Vec<[u8; 32]>), String> {
    setup_svm_charging_hash_bytes(case, DEFAULT_HASH_BYTE_COST)
}

fn setup_svm_charging_hash_bytes(
    case: &Case,
    hash_byte_cost: u64,
) -> Result<(LiteSVM, Vec<[u8; 32]>), String> {
    let mut svm = new_litesvm_charging_hash_bytes(hash_byte_cost);
    let program = read(&case.program_path)?;
    svm.add_program(case.program_id, &program)
        .map_err(|error| format!("load {}: {error}", case.program_path.display()))?;
    svm.set_account(
        case.fixture_address,
        account(case.fixture_data.clone(), case.program_id),
    )
    .map_err(|error| format!("install fixture account: {error}"))?;
    if let Some((address, len)) = case.registry {
        svm.set_account(address, account(vec![0; len], case.program_id))
            .map_err(|error| format!("install registry account: {error}"))?;
        reset_observers();
        send(
            &mut svm,
            instruction(
                case,
                case.setup_tag.ok_or("registry has no setup tag")?,
                true,
                &[],
            ),
        )?;
        let setup = observer_snapshot();
        if setup.registry_init.g2_entries == 0 {
            return Err("registry setup did not cross the initialization syscall".into());
        }
        if env::var_os("BN254_DUMP_GROTH_SEALS").is_some() && case.program_id == program_id(RowId::Groth16N5SameVk, false) {
            let registry = svm
                .get_account(&address)
                .ok_or("initialized registry account disappeared")?;
            let n = usize::from(case.fixture_data[0]);
            let k = usize::from(case.fixture_data[1]);
            let vk_base = 2 + n;
            let mut vk_digests = Vec::with_capacity(k);
            for key in 0..k {
                let vk = &case.fixture_data[vk_base + key * 576..vk_base + (key + 1) * 576];
                vk_digests.push(solana_keccak_hasher::hashv(&[
                    &[0],
                    &vk[..64],
                    &vk[64..192],
                    &vk[192..320],
                    &vk[320..448],
                    &2u16.to_be_bytes(),
                    &vk[448..512],
                    &vk[512..576],
                ]).to_bytes());
            }
            let ids: Vec<[u8; 32]> = (0..3 * k)
                .map(|index| {
                    let start = 80 + index * 37_744;
                    registry.data[start..start + 32].try_into().unwrap()
                })
                .collect();
            eprintln!("GROTH_SEAL n={n} k={k} address={} digest={} vk={} ids={}", hex::encode(address.as_array()), hex::encode(&registry.data[48..80]), hex::encode(vk_digests.concat()), hex::encode(ids.concat()));
        }
    }
    let hot_ids = match case.registry {
        Some((address, _)) if case.hot_registry_ids => {
            let registry = svm
                .get_account(&address)
                .ok_or("initialized registry account disappeared")?;
            // Entry 1 is tau and entry 0 the generator, and the guest reads them
            // in that order. Anything else fails its index-prefix check rather
            // than verifying against the wrong source.
            [1usize, 0]
                .iter()
                .map(|index| {
                    let start = REGISTRY_HEADER_BYTES + index * REGISTRY_ENTRY_BYTES;
                    registry
                        .data
                        .get(start..start + 32)
                        .and_then(|id| <[u8; 32]>::try_from(id).ok())
                        .ok_or("registry account is shorter than its entry table")
                })
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => Vec::new(),
    };
    Ok((svm, hot_ids))
}

/// The byte half of the cell's hash-syscall charge, by difference.
///
/// `sha256_byte_cost` scales the per-slice term of every `SyscallHash` charge
/// and touches nothing else, so running the same transaction at cost 1 and at
/// cost 0 isolates it. At 0 each slice falls to the `mem_op_base_cost` floor,
/// which the register trace already accounts for. The two runs must agree on
/// the call shapes, or the difference is measuring two different executions.
fn measure_hash_byte_cu(case: &Case) -> Result<u64, String> {
    let mut charged = Vec::new();
    for hash_byte_cost in [DEFAULT_HASH_BYTE_COST, 0] {
        let (mut svm, registry_ids) = setup_svm_charging_hash_bytes(case, hash_byte_cost)?;
        reset_observers();
        let metadata = send(&mut svm, instruction(case, case.tag, false, &registry_ids))?;
        let snapshot = observer_snapshot();
        charged.push((
            metadata.compute_units_consumed,
            snapshot.hash_syscalls.calls,
            snapshot.hash_syscalls.slices,
        ));
    }
    let (metered, calls, slices) = charged[0];
    let (floored, free_calls, free_slices) = charged[1];
    if (calls, slices) != (free_calls, free_slices) {
        return Err(format!(
            "hash-syscall shape moved with the byte cost: {calls}/{slices} against \
             {free_calls}/{free_slices}"
        ));
    }
    metered.checked_sub(floored).ok_or_else(|| {
        format!("free-byte run charged {floored}, more than the metered run's {metered}")
    })
}

fn execute(cli: &Cli, request: &ExecutionRequest) -> Result<ResidualCell, String> {
    let case = build_case(cli, request)?;
    let program_bytes = read(&case.program_path)?;
    let hash_byte_cu = measure_hash_byte_cu(&case)?;
    let (mut svm, registry_ids) = setup_svm(&case)?;
    let mut observations = Vec::new();
    for _ in 0..SAMPLE_COUNT {
        reset_observers();
        let metadata = send(&mut svm, instruction(&case, case.tag, false, &registry_ids))?;
        let mut snapshot = observer_snapshot();
        snapshot.hash_syscalls.byte_cu = hash_byte_cu;
        require_b5_dispatch_attestation(&snapshot)?;
        let observed_trace = trace(&snapshot)?;
        let embedded = current_embedded_hot_core_cu(&snapshot);
        let non_core = metadata
            .compute_units_consumed
            .checked_sub(embedded)
            .ok_or_else(|| {
                format!(
                    "embedded current core {embedded} exceeds transaction CU {}",
                    metadata.compute_units_consumed
                )
            })?;
        observations.push((metadata, observed_trace, non_core));
    }
    if observations[0].1 != observations[1].1 || observations[0].2 != observations[1].2 {
        return Err("repeated hot transactions produced different trace/residual".into());
    }

    // Every guest/case also proves a corrupted account is rejected. This is
    // deliberately outside both setup and the measured samples.
    let mut negative_case = case.clone();
    let index = negative_case.fixture_data.len() / 2;
    negative_case.fixture_data[index] ^= 1;
    let (mut negative_svm, negative_ids) = setup_svm(&case)?;
    negative_svm
        .set_account(
            negative_case.fixture_address,
            account(negative_case.fixture_data.clone(), negative_case.program_id),
        )
        .map_err(|error| format!("install corrupted fixture account: {error}"))?;
    reset_observers();
    if send(
        &mut negative_svm,
        instruction(&negative_case, negative_case.tag, false, &negative_ids),
    )
    .is_ok()
    {
        return Err("corrupted fixture unexpectedly verified".into());
    }

    let log_bytes = serde_json::to_vec(&observations[0].0.logs)
        .map_err(|error| format!("serialize transaction logs: {error}"))?;
    Ok(ResidualCell {
        row_id: request.row_id,
        column_id: request.column_id,
        observed_trace: observations[0].1.clone(),
        non_core_transaction_cu: observations[0].2,
        transaction_cu: observations[0].0.compute_units_consumed,
        source: "observed_in_tree_host_non_core".into(),
        sample_count: SAMPLE_COUNT,
        program_sha256: digest(&program_bytes),
        runtime_revision: cli.runtime_revision.clone(),
        transaction_log_sha256: digest(&log_bytes),
    })
}

fn main() {
    let result = (|| {
        let cli = parse_cli()?;
        // The collector reports charged CU, which the runtime schedule fixes
        // for a given syscall shape, so it does not depend on the host. A build
        // without IFMA runs the portable path and charges the same. Only a
        // timing capture needs the kernel itself: that is what `require-ifma`
        // is for, and it fails the build rather than the run.
        #[cfg(feature = "backend-b5-helius-ifma")]
        if !solana_bn254_decision_litesvm::selected_backend_compiled_with_avx512_ifma() {
            eprintln!(
                "note: B5 without compile-time AVX-512 IFMA. Charges are unaffected; wall time is not representative."
            );
        }
        let mut stdin = Vec::new();
        io::stdin()
            .read_to_end(&mut stdin)
            .map_err(|error| format!("read execution request: {error}"))?;
        let request: ExecutionRequest = serde_json::from_slice(&stdin)
            .map_err(|error| format!("strict execution request JSON: {error}"))?;
        execute(&cli, &request)
    })();
    match result {
        Ok(residual) => {
            serde_json::to_writer(io::stdout(), &residual).expect("serialize residual cell");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
