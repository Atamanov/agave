# Helius BN254 design

This document states the invariants that are not clear from the public API.

## Checked boundary

The byte facade accepts the Agave BN254 wire format. It rejects a field value
that is at least the field modulus. It does not reduce external values. It also
checks curve membership, G2 subgroup membership, empty inputs, and operation
limits in the Agave error order.

The limits are:

| Operation | Limit |
|---|---:|
| G1 MSM | 2,048 points |
| Pairing check | 256 pairs |
| Pairing map | 16 pairs |
| Fr linear combination | 2,048 elements |
| Fr batch inversion | 2,048 elements |

An all-zero G1 or G2 encoding is the point at infinity. A pair with an
infinity member contributes the target-group identity. The facade still
validates both declared points before it skips that factor.

All algorithms are variable-time. All inputs must be public verifier data.

## Arithmetic invariants

`Fp` and `Fr` values use canonical Montgomery limbs. Public constructors
restore this invariant before they call a native kernel. Native Montgomery
kernels require operands below the modulus.

Sum-of-products kernels can use the modulus as an internal subtraction
operand. The modulus is not a valid stored field value. Each kernel returns a
canonical value, so tower operations do not need a later cleanup step.

Unchecked curve constructors are private implementation seams. The checked
byte facade owns all external validation.

## Pairing result

The pairing paths combine all Miller-loop terms and perform one final
exponentiation. The IFMA path handles complete groups of eight and sends the
remainder to the scalar path before the same final exponentiation.

`pairing_map` returns the canonical post-final-exponentiation target-group
value. It never returns a Miller-loop value, Montgomery limbs, prepared lines,
or another backend-specific representation.

`TrustedGt` can decode a canonical target-group value and checks its nonzero
and subgroup properties. These checks do not prove source or ownership. A
runtime registry must authenticate the owner, source, and identifier before it
uses stored target-group bytes.

## Build selection

Selection occurs at build time.

| Selection | Result |
|---|---|
| `force-portable` | Portable Rust |
| AArch64 target | AArch64 Montgomery kernel when supported |
| x86-64 with `bmi2` and `adx` | ADX field and tower kernels |
| x86-64 with `avx512f` and `avx512ifma` | IFMA batch kernels when allowed |
| `deny-ifma` | IFMA cannot be selected |
| `force-ifma` | Build fails unless both IFMA target features exist |

`force-ifma` cannot be combined with `deny-ifma` or `force-portable`. Invalid
environment toggle values stop the build. `HELIUS_DUMP_ASM` must name an
absolute output directory.

## Generated kernels

One semantic schedule drives the assembly emitter and the bit-accurate test
interpreter. The interpreter checks flags, register preservation, stack
balance, memory access, and declared carry bounds. Golden tests compare the
rendered assembly with the checked-in snapshots. The ASCII source test rejects
native source outside this pipeline.

The relevant files are `build/schedule.rs`, `build/interp.rs`,
`tests/kernelgen_verify.rs`, and `tests/kernel_golden.rs`. AArch64 uses the
equivalent files under `build/a64/`.

## Verification

The conformance tests compare the byte facade with Arkworks 0.5. Differential
tests cover field, curve, MSM, pairing, target-group encoding, and dispatch
boundaries.

```text
cargo test -p helius-bn254 --features std,deny-ifma
cargo clippy -p helius-bn254 --all-targets --features std,deny-ifma -- -D warnings
cargo clippy -p helius-bn254 --all-targets --features std,force-portable,deny-ifma -- -D warnings
```
