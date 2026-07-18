# solana-bn254-batch-syscall

Solana alt_bn128 G1 MSM, boolean multi-pairing check, and Fr batch ops.

On this branch the arithmetic backend is the pure-Rust `helios-bn254` crate,
consumed as a path dependency. The wire contract (encodings, caps, validation
order, error taxonomy) is unchanged; `tests/fingerprint.rs` pins it.

## Required checkout layout

This branch is deliberately non-portable: the manifest references
`../../helios-bn254-2/crates/helios-bn254`, which resolves only when the two
repositories are sibling checkouts under one root:

```
<root>/agave            this repository
<root>/helios-bn254-2   the helios-bn254 workspace
```

The benchmark box uses the same layout under `/root/helios`. Any other layout
needs a symlink at `<root>/helios-bn254-2` pointing at the real checkout.
