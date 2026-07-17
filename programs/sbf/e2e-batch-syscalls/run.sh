#!/usr/bin/env bash
#
# End-to-end check that the two BN254 batch syscalls
# (sol_alt_bn128_g1_msm, sol_alt_bn128_pairing_check) execute on a local
# solana-test-validator built from this fork, with the
# enable_alt_bn128_batch_syscalls feature active at genesis.
#
# It boots the fork validator with the alt_bn128_batch SBF program loaded at
# genesis (the fork loader resolves the new syscall symbols; the stock CLI does
# not, so program deploy over RPC would reject the ELF), then invokes the
# program once. The program runs both syscalls with baked vectors and asserts
# their verdicts, so a successful transaction means the syscalls executed
# correctly on-chain.
#
# Prerequisites, built from this repo:
#   cargo build --release -p agave-validator --bin solana-test-validator
#   ( cd programs/sbf/rust/alt_bn128_batch && cargo-build-sbf --tools-version v1.54 )
# and a stock `solana` CLI plus `solana-keygen` on PATH for keypairs/airdrop.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
validator="$repo/target/release/solana-test-validator"
program_so="$repo/programs/sbf/target/deploy/solana_sbf_rust_alt_bn128_batch.so"
work="$(mktemp -d)"
trap 'kill "${vpid:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

[ -x "$validator" ] || { echo "missing $validator (build it first)"; exit 1; }
[ -f "$program_so" ] || { echo "missing $program_so (cargo-build-sbf it first)"; exit 1; }

solana-keygen new --no-bip39-passphrase -s -o "$work/payer.json" >/dev/null
solana-keygen new --no-bip39-passphrase -s -o "$work/prog.json" >/dev/null
prog="$(solana-keygen pubkey "$work/prog.json")"

"$validator" --reset --ledger "$work/ledger" --rpc-port 8899 \
  --bpf-program "$prog" "$program_so" >"$work/validator.log" 2>&1 &
vpid=$!

for _ in $(seq 1 30); do
  solana -u http://localhost:8899 cluster-version >/dev/null 2>&1 && break
  sleep 1
done

solana -u http://localhost:8899 -k "$work/payer.json" airdrop 100 >/dev/null
cargo run --quiet --manifest-path "$here/invoker/Cargo.toml" -- "$prog" "$work/payer.json"
echo "e2e ok: batch syscalls executed on the fork validator"
