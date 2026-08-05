//! Stateless prepared-operand BN254 operations.
//!
//! No account access anywhere in this module. Callers own storage and
//! authentication of prepared blobs; a caller that supplies bytes it never
//! authenticated weakens only its own verification. The runtime still
//! validates every encoding so results are deterministic on every host.

use solana_bn254_batch_syscall::{
    AltBn128BatchError, PodG1G2Pair, PodG1Point, PodGtElement, PreparedG2, prepared_g2_from_wire,
};

pub use solana_bn254_batch_syscall::{
    MAX_PREPARED_PAIRS, PAIRING_MAP_MAX_PAIRS, PAIRING_MAX_PAIRS, PREPARED_ABI_VERSION,
    PREPARED_G2_WIRE_BYTES, g2_prepare, pack_g2_prepare_shape, pack_prepared_pairing_shape,
    prepared_blob_header, unpack_g2_prepare_shape, unpack_prepared_pairing_shape,
};

/// Fully validate one canonical G2 source and return its wire blob.
pub fn g2_prepare_wire(
    source: &solana_bn254_batch_syscall::PodG2Point,
) -> Result<Vec<u8>, AltBn128BatchError> {
    Ok(g2_prepare(source)?.to_wire_bytes())
}

/// Mixed pairing verdict over full pairs and translated prepared wire blobs.
/// `target` of `None` compares against the GT identity; `Some` compares the
/// final-exponentiated product against the caller's canonical encoding.
pub fn pairing_check_prepared_blobs(
    full: &[PodG1G2Pair],
    prepared: &[(PodG1Point, &[u8])],
    target: Option<&PodGtElement>,
) -> Result<bool, AltBn128BatchError> {
    let handles = restore_blobs(prepared)?;
    let refs = prepared_refs(prepared, &handles);
    match target {
        Some(target) => solana_bn254_batch_syscall::pairing_check_prepared_vs_target(
            full, &refs, target,
        ),
        None => solana_bn254_batch_syscall::pairing_check_prepared(full, &refs),
    }
}

/// Mixed product mapped to its canonical post-final-exponentiation encoding.
pub fn pairing_map_prepared_blobs(
    full: &[PodG1G2Pair],
    prepared: &[(PodG1Point, &[u8])],
) -> Result<PodGtElement, AltBn128BatchError> {
    let handles = restore_blobs(prepared)?;
    let refs = prepared_refs(prepared, &handles);
    solana_bn254_batch_syscall::pairing_map_prepared(full, &refs)
}

fn restore_blobs(
    prepared: &[(PodG1Point, &[u8])],
) -> Result<Vec<PreparedG2>, AltBn128BatchError> {
    prepared
        .iter()
        .map(|(_, blob)| prepared_g2_from_wire(blob))
        .collect()
}

fn prepared_refs<'a>(
    prepared: &[(PodG1Point, &[u8])],
    handles: &'a [PreparedG2],
) -> Vec<(PodG1Point, &'a PreparedG2)> {
    prepared
        .iter()
        .zip(handles)
        .map(|((g1, _), handle)| (*g1, handle))
        .collect()
}
