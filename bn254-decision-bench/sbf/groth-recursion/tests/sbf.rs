use {
    solana_account::Account,
    solana_bn254_decision_litesvm::{
        new_litesvm_with_decision_syscalls, observer_snapshot, reset_observers,
    },
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_message::Message,
    solana_pubkey::Pubkey,
    solana_signer::Signer,
    solana_transaction::Transaction,
    std::path::{Path, PathBuf},
};

fn fixture_root() -> PathBuf {
    std::env::var_os("HELIUS_GROTH_RECURSION_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../research/bn254-decision-table-v2-20260804/recursion-v2")
        })
}

fn fixture(selector: u8) -> Vec<u8> {
    let directory = match selector {
        2 => "n2-distinct",
        3 => "n3-distinct",
        5 => "n5-same",
        _ => panic!("unknown fixture selector"),
    };
    std::fs::read(
        fixture_root()
            .join(directory)
            .join("payload_unnegated_a.bin"),
    )
    .expect("read real-Zolana recursion payload")
}

fn execute(so: &[u8], data: Vec<u8>) -> Result<u64, String> {
    let mut svm = new_litesvm_with_decision_syscalls();
    let program_id = Pubkey::new_from_array([0x92; 32]);
    svm.add_program(program_id, so)
        .map_err(|error| format!("add program: {error:?}"))?;
    let input = Pubkey::new_unique();
    svm.set_account(
        input,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: Pubkey::new_unique(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .map_err(|error| format!("set fixture account: {error:?}"))?;
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000)
        .map_err(|error| format!("airdrop: {error:?}"))?;
    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
        Instruction {
            program_id,
            accounts: vec![AccountMeta::new_readonly(input, false)],
            data: vec![0],
        },
    ];
    let message = Message::new(&instructions, Some(&payer.pubkey()));
    let transaction = Transaction::new(&[&payer], message, svm.latest_blockhash());
    svm.send_transaction(transaction)
        .map(|metadata| metadata.compute_units_consumed)
        .map_err(|failure| format!("{:?}; logs={:#?}", failure.err, failure.meta.logs))
}

#[test]
#[ignore = "set HELIUS_GROTH_RECURSION_SBF_PATH to the freshly built deploy .so"]
fn sbf_accepts_real_zolana_outer_proofs_and_rejects_mutations() {
    let so_path = PathBuf::from(
        std::env::var_os("HELIUS_GROTH_RECURSION_SBF_PATH")
            .expect("HELIUS_GROTH_RECURSION_SBF_PATH"),
    );
    let so = std::fs::read(&so_path).expect("read fresh Groth recursion SBF");

    for (selector, expected_gamma_msm) in [(2u8, 6u64), (3, 7), (5, 9)] {
        let payload = fixture(selector);
        reset_observers();
        execute(&so, payload.clone())
            .unwrap_or_else(|error| panic!("selector={selector}: {error}"));
        let observed = observer_snapshot();
        assert_eq!(observed.pairing_checks.len(), 1);
        assert_eq!(observed.pairing_checks[0].pairs, 6);
        assert_eq!(observed.pairing_checks[0].nonidentity_pairs, 6);
        assert_eq!(
            observed
                .msm_calls
                .iter()
                .map(|call| call.points)
                .collect::<Vec<_>>(),
            vec![1, 1, expected_gamma_msm, 1, 1, 1]
        );

        let mut changed_proof = payload.clone();
        changed_proof[0] ^= 1;
        assert!(execute(&so, changed_proof).is_err());

        let mut changed_public = payload.clone();
        changed_public[384] ^= 1;
        assert!(execute(&so, changed_public).is_err());

        let mut changed_statement = payload;
        let last = changed_statement.len() - 32;
        changed_statement[last] ^= 1;
        assert!(execute(&so, changed_statement).is_err());
    }
}
