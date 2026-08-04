# PLONK direct decision guest

This isolated SBF program uses only the byte-exact committed Zolana snarkjs
`mul1`, `mul2`, and `mul3` test exceptions under
`research/bn254-decision-table-v2-20260804/fixtures-v3/plonk-test-exceptions`.
They are canonical test exceptions, not fresh or production proofs.

Generate the P2/P3 account bytes without linking the guest into another
workspace:

```sh
cargo run \
  --manifest-path bn254-decision-bench/sbf/plonk-direct/Cargo.toml \
  --example export_rows -- \
  --fixtures-root /absolute/path/to/plonk-test-exceptions \
  --output /absolute/path/to/an-empty-directory
```

The create-new exporter writes `n2.bin`, `n3.bin`, and `manifest.json`. The
manifest seals each account's SHA-256, length, input-PDA digest, v3 registry-PDA
digest, and registry length. The collector derives both PDAs with its chosen
program ID. Both accounts use the authenticated layout inherited from the
canonical Zolana exporter:

`PLKFP12\0 | version | group count | reserved | repeated(group proof count | reserved | VK | proofs)`.

Build the single guest:

```sh
cargo build-sbf --tools-version v1.54 \
  --manifest-path bn254-decision-bench/sbf/plonk-direct/Cargo.toml -- --locked
```

Instruction tags and account order:

| Tag | Strategy | Accounts | Exact core trace |
|---:|---|---|---|
| 0 | Current | fixture | `n` independent stock 2-pair checks; no MSM |
| 2 | Batching syscalls (B5) | fixture | MSM `[2n,18n]`; one 2-pair check |
| 3 | Batching + VK registry (B5) | registry, fixture | same MSM; one `0 full + 2 registered` check |
| 4 | Batching + Fp12 (B5) | fixture | MSM `[2n,18n]`; one 2-pair map |
| 5 | Registry initialization (excluded) | writable registry, fixture | install `[1]_2,[tau]_2` |
| 9 | Current + Fp12 | fixture | `n` independent 2-pair maps; no MSM |

The registry account is a program-owned Agave v3 registry PDA, is 75,568
bytes, and is used only by registry tag 3 and excluded initialization tag 5.
Both Fp12 strategies are fixture-only and carry no registry account. The
fixture is a readonly, program-owned input PDA. Host tests accept P2/P3,
assert the exact optimized MSM/finalizer traces, and reject a code-owned proof
mutation through every direct finalizer.

Tag 3 has one additional instruction-data contract: exactly
`3 | tau opaque ID (slot 1, 32 bytes) | generator opaque ID (slot 0, 32 bytes)`.
The guest derives the registry PDA from the sealed allowlisted SRS digest and
checks its program owner, readonly state, and exact v3 length without borrowing
or scanning the 75,568-byte account. Agave's registered-pairing syscall then
authenticates the registry header, consumer, keyset digest, and both complete
opaque IDs before using the prepared points. The excluded tag-5 transaction is
where the collector obtains these runtime-issued IDs.
