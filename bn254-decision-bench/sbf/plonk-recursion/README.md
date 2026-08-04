# Fixed-statement-v3 PLONK recursion guest

This guest verifies the freshly generated OS-random gnark Groth16/BSB22 outer
proofs for the campaign's canonical snarkjs PLONK `n=2` and `n=3` test rows.
The verifying keys are parsed from sealed `vk.bin` files at build time and
compiled into the SBF program.

The account payload is:

`A(64) | B(128) | C(64) | commitment(64) | PoK(64) | explicit publics`

The sole instruction tag is `[0]`; account 0 is the read-only payload. An exact
512-byte account selects the sealed n=2 VK and an exact 608-byte account selects
the sealed n=3 VK. The two payloads respectively contain four and seven
explicit outer public inputs. The guest recomputes and appends gnark's BSB22
commitment-hash wire. The final verification is one B5 six-pair check, hence one
final exponentiation and six G2 subgroup checks. Its G1 MSM shapes are
`[1,1,7,1,1,1]` for n=2 and `[1,1,10,1,1,1]` for n=3.

Host verification, including mutation negatives and exact observer shapes:

```sh
cargo test --manifest-path bn254-decision-bench/sbf/plonk-recursion/Cargo.toml \
  --features research-observer
```

Pinned-x86 B5 verification:

```sh
RUSTFLAGS='-C target-cpu=native' cargo test \
  --manifest-path bn254-decision-bench/sbf/plonk-recursion/Cargo.toml \
  --no-default-features --features backend-b5-helius-ifma,research-observer
```

Build the campaign SBF with the B5 strategy selected explicitly:

```sh
cargo build-sbf \
  --manifest-path bn254-decision-bench/sbf/plonk-recursion/Cargo.toml \
  --no-default-features --features bpf-entrypoint,backend-b5-helius-ifma
```

The fixture root can be overridden for an independently fetched sealed export
with `HELIUS_PLONK_RECURSION_FIXTURE_ROOT=/absolute/path`.

To execute the fresh SBF under the campaign's embedded LiteSVM runtime and
check both valid payloads plus a commitment mutation:

```sh
RUSTFLAGS='-C target-cpu=native' \
  HELIUS_PLONK_RECURSION_SBF_PATH="$PWD/bn254-decision-bench/sbf/plonk-recursion/target/deploy/bn254_decision_plonk_recursion_guest.so" \
  cargo test --manifest-path bn254-decision-bench/sbf/plonk-recursion/Cargo.toml \
  --no-default-features --features backend-b5-helius-ifma,research-observer \
  --test sbf -- --ignored --exact sbf_accepts_exact_v3_and_rejects_commitment_mutation
```
