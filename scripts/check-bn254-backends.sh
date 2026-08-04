#!/usr/bin/env bash
# Check the BN254 wire contract and backend feature gates.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

backends=(
    backend-b1-arkworks
    backend-b2-arkworks-optimized
    backend-b3-mcl
    backend-b4-helios
)
b5_compile_only=false

case "$#:${1:-}" in
    0:) ;;
    1:--include-b5) backends+=(backend-b5-helios-ifma) ;;
    *)
        echo "usage: $0 [--include-b5]" >&2
        exit 2
        ;;
esac

for backend in "${backends[@]}"; do
    echo "checking $backend"
    if [[ "$backend" == backend-b5-helios-ifma ]]; then
        if [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] && \
            grep -qiw avx512ifma /proc/cpuinfo
        then
            RUSTFLAGS="-C target-feature=+avx512f,+avx512ifma" cargo test \
                -p solana-bn254-batch-syscall \
                --test fingerprint \
                --target x86_64-unknown-linux-gnu \
                --no-default-features \
                --features "agave-unstable-api,$backend"
        else
            echo "B5 is compile-only on this host"
            b5_compile_only=true
            RUSTFLAGS="-C target-feature=+avx512f,+avx512ifma" cargo check \
                -p solana-bn254-batch-syscall \
                --test fingerprint \
                --target x86_64-unknown-linux-gnu \
                --no-default-features \
                --features "agave-unstable-api,$backend"
        fi
    else
        cargo test \
            -p solana-bn254-batch-syscall \
            --test fingerprint \
            --no-default-features \
            --features "agave-unstable-api,$backend"
    fi
done

echo "checking the zero-feature B1 fallback"
cargo test \
    -p solana-bn254-batch-syscall \
    --test fingerprint \
    --no-default-features \
    --features agave-unstable-api

conflicts=(
    "backend-b1-arkworks,backend-b2-arkworks-optimized"
    "backend-b1-arkworks,backend-b3-mcl"
    "backend-b1-arkworks,backend-b4-helios"
    "backend-b1-arkworks,backend-b5-helios-ifma"
    "backend-b2-arkworks-optimized,backend-b3-mcl"
    "backend-b2-arkworks-optimized,backend-b4-helios"
    "backend-b2-arkworks-optimized,backend-b5-helios-ifma"
    "backend-b3-mcl,backend-b4-helios"
    "backend-b3-mcl,backend-b5-helios-ifma"
    "backend-b4-helios,backend-b5-helios-ifma"
)

conflict_log="$(mktemp)"
conflict_dir="$(mktemp -d)"
trap 'rm -f "$conflict_log"; rm -rf "$conflict_dir"' EXIT
for conflict in "${conflicts[@]}"; do
    echo "checking conflict $conflict"
    IFS=, read -r left right <<<"$conflict"
    if rustc \
        --crate-name bn254_backend_selection \
        --crate-type lib \
        --edition 2021 \
        --out-dir "$conflict_dir" \
        --cfg "feature=\"$left\"" \
        --cfg "feature=\"$right\"" \
        bn254-batch-syscall/src/backend_selection.rs \
        >"$conflict_log" 2>&1
    then
        echo "backend conflict succeeded unexpectedly: $conflict" >&2
        exit 1
    fi
    if ! grep -q "select exactly one BN254 native backend" "$conflict_log"; then
        cat "$conflict_log" >&2
        exit 1
    fi
done

if [[ "$b5_compile_only" == true ]]; then
    echo "B1-B4 wire checks and the B5 compile check passed"
else
    echo "BN254 backend checks passed"
fi
