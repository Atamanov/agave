# Real-Zolana Groth16 recursion guest

This guest verifies the three genuine OS-random gnark Groth16/BSB22 recursive
outer proofs generated over exact authenticated Zolana production-prover
Groth16 statements. Build-time checks hard-seal the compact recursion manifest
and every source row, generation record, statement scalar, payload, and outer
VK used by the guest.

The instruction interface is exactly `[0]` with one read-only payload account:

- 480 bytes selects G2 (`n2-distinct`), with three explicit outer publics;
- 512 bytes selects G3 (`n3-distinct`), with four explicit outer publics;
- 576 bytes selects G5 (`n5-same`), with six explicit outer publics.

Payload layout is `A(64) | B(128) | C(64) | commitment(64) | PoK(64) |
explicit publics`. The guest recomputes gnark's trailing BSB22 hash wire and
runs exactly one B5 six-pair check. The G1 MSM sequences are respectively
`[1,1,6,1,1,1]`, `[1,1,7,1,1,1]`, and `[1,1,9,1,1,1]`.

```sh
cargo test --manifest-path bn254-decision-bench/sbf/groth-recursion/Cargo.toml \
  --features research-observer --lib

RUSTFLAGS='-C target-cpu=native' cargo test \
  --manifest-path bn254-decision-bench/sbf/groth-recursion/Cargo.toml \
  --no-default-features --features backend-b5-helios-ifma,research-observer --lib

cargo build-sbf \
  --manifest-path bn254-decision-bench/sbf/groth-recursion/Cargo.toml \
  --no-default-features --features bpf-entrypoint,backend-b5-helios-ifma

RUSTFLAGS='-C target-cpu=native' \
  HELIOS_GROTH_RECURSION_SBF_PATH="$PWD/bn254-decision-bench/sbf/groth-recursion/target/deploy/bn254_decision_groth_recursion_guest.so" \
  cargo test --manifest-path bn254-decision-bench/sbf/groth-recursion/Cargo.toml \
  --no-default-features --features backend-b5-helios-ifma,research-observer \
  --test sbf -- --ignored --exact sbf_accepts_real_zolana_outer_proofs_and_rejects_mutations
```

An independently copied identical compact bundle may be selected with
`HELIOS_GROTH_RECURSION_FIXTURE_ROOT=/absolute/path`; the hardcoded seals still
have to match.
