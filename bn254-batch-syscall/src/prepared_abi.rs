//! Wire ABI for the stateless prepared-operand syscalls.
//!
//! Nothing here names an account. The caller owns storage and authentication
//! of prepared blobs; the syscalls validate encodings only, because a caller
//! that lies about its own prepared bytes weakens only its own verification.
//!
//! A prepared-G2 blob is self-describing: an 8-byte header pins the format,
//! curve, and backend limb domain, followed by the scalar-Montgomery line
//! schedule. The radix-52 IFMA form is never on the wire; the runtime derives
//! it on restore so the two limb domains can never disagree across a fleet
//! with mixed IFMA support.

pub const PREPARED_ABI_VERSION: u16 = 1;

pub const PREPARED_BLOB_MAGIC: [u8; 4] = *b"BPG2";
pub const PREPARED_BLOB_FORMAT_VERSION: u8 = 1;
pub const PREPARED_BLOB_CURVE_BN254: u8 = 1;
/// B5 scalar-Montgomery limb domain. A backend that changes the limb domain
/// bumps this byte, and every stored blob cleanly fails restore until its
/// owner re-runs prepare against the canonical G2 source stored next to it.
pub const PREPARED_BLOB_BACKEND_B5: u8 = 5;
pub const PREPARED_BLOB_HEADER_BYTES: usize = 8;
/// 87 line triples x 3 Fp2 x 2 Fp x 4 u64 little-endian Montgomery limbs.
pub const PREPARED_G2_SCALAR_BLOCK_BYTES: usize = 87 * 3 * 2 * 4 * 8;
pub const PREPARED_G2_WIRE_BYTES: usize =
    PREPARED_BLOB_HEADER_BYTES + PREPARED_G2_SCALAR_BLOCK_BYTES;

/// Per-call cap on prepared operands; bounds VM region translations.
pub const MAX_PREPARED_PAIRS: usize = 16;

pub const fn prepared_blob_header() -> [u8; PREPARED_BLOB_HEADER_BYTES] {
    [
        PREPARED_BLOB_MAGIC[0],
        PREPARED_BLOB_MAGIC[1],
        PREPARED_BLOB_MAGIC[2],
        PREPARED_BLOB_MAGIC[3],
        PREPARED_BLOB_FORMAT_VERSION,
        PREPARED_BLOB_CURVE_BN254,
        PREPARED_BLOB_BACKEND_B5,
        0,
    ]
}

/// The scalar block of a well-framed wire blob, or `None` when the length or
/// any header byte (including the reserved byte) does not match exactly.
pub fn prepared_blob_scalar_block(blob: &[u8]) -> Option<&[u8]> {
    if blob.len() != PREPARED_G2_WIRE_BYTES {
        return None;
    }
    let (header, block) = blob.split_at(PREPARED_BLOB_HEADER_BYTES);
    (header == prepared_blob_header()).then_some(block)
}

pub const fn pack_g2_prepare_shape() -> u64 {
    (PREPARED_ABI_VERSION as u64) << 48
}

/// Bits 0..16 full count, 16..32 prepared count, 32..48 reserved zero,
/// 48..64 ABI version.
pub const fn pack_prepared_pairing_shape(full_count: u16, prepared_count: u16) -> u64 {
    full_count as u64 | ((prepared_count as u64) << 16) | ((PREPARED_ABI_VERSION as u64) << 48)
}

/// `(full_count, prepared_count)`, or `None` on a version mismatch or any
/// set reserved bit.
pub const fn unpack_prepared_pairing_shape(shape: u64) -> Option<(u16, u16)> {
    if (shape >> 48) as u16 != PREPARED_ABI_VERSION {
        return None;
    }
    if (shape >> 32) as u16 != 0 {
        return None;
    }
    Some((shape as u16, (shape >> 16) as u16))
}

pub const fn unpack_g2_prepare_shape(shape: u64) -> bool {
    shape == pack_g2_prepare_shape()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_wire_sizes_and_shapes_are_pinned() {
        assert_eq!(PREPARED_G2_SCALAR_BLOCK_BYTES, 16_704);
        assert_eq!(PREPARED_G2_WIRE_BYTES, 16_712);
        assert_eq!(prepared_blob_header(), *b"BPG2\x01\x01\x05\x00");

        assert_eq!(pack_g2_prepare_shape(), 1 << 48);
        let shape = pack_prepared_pairing_shape(5, 3);
        assert_eq!(shape, 5 | (3 << 16) | (1 << 48));
        assert_eq!(unpack_prepared_pairing_shape(shape), Some((5, 3)));
        assert_eq!(unpack_prepared_pairing_shape(shape | (1 << 32)), None);
        assert_eq!(unpack_prepared_pairing_shape(shape | (1 << 49)), None);
        assert!(unpack_g2_prepare_shape(pack_g2_prepare_shape()));
        assert!(!unpack_g2_prepare_shape(pack_g2_prepare_shape() | 1));
    }

    #[test]
    fn blob_framing_requires_the_exact_header() {
        let mut blob = vec![0u8; PREPARED_G2_WIRE_BYTES];
        blob[..PREPARED_BLOB_HEADER_BYTES].copy_from_slice(&prepared_blob_header());
        assert!(prepared_blob_scalar_block(&blob).is_some());
        assert_eq!(
            prepared_blob_scalar_block(&blob).unwrap().len(),
            PREPARED_G2_SCALAR_BLOCK_BYTES
        );

        assert!(prepared_blob_scalar_block(&blob[..blob.len() - 1]).is_none());
        for byte in 0..PREPARED_BLOB_HEADER_BYTES {
            let mut corrupted = blob.clone();
            corrupted[byte] ^= 1;
            assert!(prepared_blob_scalar_block(&corrupted).is_none());
        }
    }
}
