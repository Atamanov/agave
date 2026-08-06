mod contract;
mod pricing;
mod io;
mod model;
mod report;
mod runner;
mod tariff;

pub use {
    contract::{
        PAIRING_CHECK_CAP, PAIRING_MAP_CAP, builtin_expected_counts, expected_trace, lane_pad,
        reject_deprecated_or_derived_json, validate_expected_counts,
    },
    model::*,
    pricing::{
        CostSplit, MIN_SYSCALL_SHARE_PER_MILLE, SYSCALL_BEARING_COLUMNS, SyscallFamilies,
        cost_split, syscall_cu, syscall_families,
    },
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
