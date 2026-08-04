mod contract;
mod io;
mod model;
mod report;
mod runner;
mod tariff;

pub use {
    contract::{builtin_expected_counts, expected_trace, validate_expected_counts},
    model::*,
    report::render_report,
    runner::{Cli, OutputPaths, TransactionExecutor, run_campaign, run_cli},
    tariff::HostCapabilities,
};

use {std::path::PathBuf, thiserror::Error};

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid command line: {0}")]
    Cli(String),
    #[error("campaign contract violation: {0}")]
    Contract(String),
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("executor failed for {row}/{column}: {message}")]
    Executor {
        row: String,
        column: String,
        message: String,
    },
}
