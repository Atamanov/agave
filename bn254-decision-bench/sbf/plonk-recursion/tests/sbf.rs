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
    std::env::var_os("HELIOS_PLONK_RECURSION_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/fixed-statement-v3")
        })
}

fn fixture(selector: u8) -> Vec<u8> {
    let directory = match selector {
        2 => "n2-secure",
        3 => "n3-secure",
        _ => panic!("unknown fixture selector"),
    };
    std::fs::read(
        fixture_root()
            .join(directory)
            .join("payload_unnegated_a.bin"),
    )
    .expect("read fixed-statement-v3 payload")
}

fn execute(so: &[u8], data: Vec<u8>) -> Result<u64, String> {
    let mut svm = new_litesvm_with_decision_syscalls();
    let program_id = Pubkey::new_from_array([0x93; 32]);
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
#[ignore = "set HELIOS_PLONK_RECURSION_SBF_PATH to the freshly built deploy .so"]
fn sbf_accepts_exact_v3_and_rejects_commitment_mutation() {
    let so_path = PathBuf::from(
        std::env::var_os("HELIOS_PLONK_RECURSION_SBF_PATH")
            .expect("HELIOS_PLONK_RECURSION_SBF_PATH"),
    );
    let so = std::fs::read(&so_path).expect("read fresh PLONK recursion SBF");

    for (selector, expected_gamma_msm) in [(2u8, 7u64), (3, 10)] {
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

        let mut changed_commitment = payload;
        changed_commitment[256] ^= 1;
        assert!(
            execute(&so, changed_commitment).is_err(),
            "SBF accepted changed BSB22 commitment for selector={selector}"
        );
    }
}
