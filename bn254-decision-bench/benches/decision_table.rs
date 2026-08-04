use {
    solana_bn254_decision_bench::{Cli, run_cli},
    std::process::ExitCode,
};

fn main() -> ExitCode {
    match Cli::parse(std::env::args_os().skip(1)).and_then(run_cli) {
        Ok(paths) => {
            println!("result_json={}", paths.result_json.display());
            println!("report_markdown={}", paths.report_markdown.display());
            println!(
                "exact_shape_tariff_json={}",
                paths.exact_shape_tariff_json.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("bn254 decision campaign failed: {error}");
            ExitCode::FAILURE
        }
    }
}
