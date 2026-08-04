#!/usr/bin/env bash
# The validator must provide the fork syscall symbols that the SBF program uses.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
validator="$repo/target/release/solana-test-validator"
program_so="$repo/programs/sbf/target/deploy/solana_sbf_rust_alt_bn128_batch.so"
backend="${BN254_BACKEND:-backend-b1-arkworks}"
work="$(mktemp -d)"
trap 'kill "${vpid:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

case "$backend" in
  backend-b1-arkworks | backend-b2-arkworks-optimized | backend-b3-mcl | backend-b4-helius | backend-b5-helius-ifma) ;;
  *) echo "unsupported BN254_BACKEND: $backend" >&2; exit 2 ;;
esac

if [[ "$backend" == backend-b5-helius-ifma ]]; then
  if [[ "$(uname -m)" != x86_64 ]] || ! {
    { [[ -r /proc/cpuinfo ]] && grep -qiw avx512ifma /proc/cpuinfo; } ||
      { command -v sysctl >/dev/null 2>&1 && sysctl -a 2>/dev/null | grep -iw avx512ifma >/dev/null; }
  }; then
    echo "B5 requires an x86_64 host with AVX-512 IFMA" >&2
    exit 2
  fi
  RUSTFLAGS="${RUSTFLAGS:-} -C target-feature=+avx512f,+avx512ifma" \
    cargo +1.95.0 build --release -p agave-validator --bin solana-test-validator \
      --no-default-features --features "$backend"
else
  cargo +1.95.0 build --release -p agave-validator --bin solana-test-validator \
    --no-default-features --features "$backend"
fi
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
echo "e2e ok: batch syscalls executed with $backend"
