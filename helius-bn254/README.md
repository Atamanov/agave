# helius-bn254

`helius-bn254` provides variable-time BN254 arithmetic for proof verification. Its byte API matches the Agave `alt_bn128` ABI.

The public operations are:

- G1 multi-scalar multiplication
- pairing-product check
- post-final-exponentiation GT map
- Fr linear combination
- Fr batch inversion

Inputs use canonical big-endian bytes. G1 uses `x | y`. G2 uses `x1 | x0 | y1 | y0`. An all-zero point is the identity. The API rejects non-canonical fields, invalid curve points, and G2 points outside the scalar subgroup.

The Agave limits are 2,048 MSM points, 256 pairing-check pairs, 16 pairing-map pairs, and 2,048 Fr elements.

## Build tiers

| Tier | Selection | Scope |
|---|---|---|
| Portable Rust | Default on targets without a supported assembly tier | All operations |
| AArch64 | Apple AArch64 | Montgomery multiplication |
| x86-64 ADX | `bmi2` and `adx` target features | Field and extension-field kernels |
| AVX-512 IFMA | `avx512f` and `avx512ifma` target features | Eight-lane MSM and pairing batches |

Tier selection occurs at build time. `force-portable` selects portable Rust. `deny-ifma` prevents IFMA selection. `force-ifma` requires the IFMA target features and stops the build if they are absent.

The IFMA pairing path processes complete groups of eight and uses the scalar path for the remainder. All terms share one final exponentiation.

## Security

All algorithms are variable-time. Use this crate only with public verifier data. Do not use it with secret scalars, witnesses, or keys.

The GT map returns a canonical post-final-exponentiation subgroup element. It does not expose a Miller-loop intermediate or native Montgomery limbs.

## Validation

The test suite compares the byte API and arithmetic with Arkworks 0.5. Kernel tests also verify generated assembly with a bit-accurate interpreter.

```text
cargo test -p helius-bn254 --features std,deny-ifma
cargo clippy -p helius-bn254 --all-targets --features std,deny-ifma -- -D warnings
```

The crate uses Rust 1.95.0 and edition 2024. The default build is `no_std` with `alloc`.

## License

MIT OR Apache-2.0
