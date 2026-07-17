use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{read_keypair_file, Signer},
    transaction::Transaction,
};
use std::str::FromStr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = Pubkey::from_str(&args[1]).unwrap();
    let payer = read_keypair_file(&args[2]).unwrap();
    let rpc = RpcClient::new_with_commitment(
        "http://localhost:8899".to_string(),
        CommitmentConfig::confirmed(),
    );
    // the program takes no accounts and empty data; its entrypoint runs both
    // batch syscalls with baked vectors and asserts the verdicts
    let ix = Instruction::new_with_bytes(program, &[], vec![]);
    let bh = rpc.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], bh);
    match rpc.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("OK syscalls executed on-chain, sig {sig}"),
        Err(e) => {
            eprintln!("FAIL {e}");
            std::process::exit(1);
        }
    }
}
