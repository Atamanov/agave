//! Allocation-free BSB22 hash-to-field, byte-exact with gnark-crypto's
//! `fr.Hash(commitment, "bsb22-commitment", 1)`.

use ark_bn254::Fr;
use ark_ff::PrimeField;

#[cfg(target_os = "solana")]
fn sha256(input: &[u8]) -> [u8; 32] {
    use pinocchio::syscalls::sol_sha256;
    let slices: [&[u8]; 1] = [input];
    let mut out = [0u8; 32];
    // SAFETY: both the slice descriptor and the 32-byte output remain valid
    // for the synchronous syscall invocation.
    unsafe {
        sol_sha256(
            slices.as_ptr() as *const u8,
            slices.len() as u64,
            out.as_mut_ptr(),
        );
    }
    out
}

#[cfg(not(target_os = "solana"))]
fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(input).into()
}

const B_IN_BYTES: usize = 32;
const R_IN_BYTES: usize = 64;
const L: usize = 48;
const MAX_SCRATCH: usize = 256;

fn expand_message_xmd_sha256_l48<const MSG_LEN: usize, const DST_LEN: usize>(
    msg: &[u8; MSG_LEN],
    dst: &[u8; DST_LEN],
) -> [u8; L] {
    const { assert!(DST_LEN <= 255) };
    const {
        let b0_len = R_IN_BYTES + MSG_LEN + 2 + 1 + (DST_LEN + 1);
        assert!(b0_len <= MAX_SCRATCH)
    };

    let mut scratch = [0u8; MAX_SCRATCH];
    let append_dst_prime = |scratch: &mut [u8; MAX_SCRATCH], offset: usize| -> usize {
        scratch[offset..offset + DST_LEN].copy_from_slice(dst);
        scratch[offset + DST_LEN] = DST_LEN as u8;
        offset + DST_LEN + 1
    };

    let mut offset = R_IN_BYTES;
    scratch[offset..offset + MSG_LEN].copy_from_slice(msg);
    offset += MSG_LEN;
    scratch[offset..offset + 2].copy_from_slice(&(L as u16).to_be_bytes());
    offset += 2;
    scratch[offset] = 0;
    offset += 1;
    offset = append_dst_prime(&mut scratch, offset);
    let b0 = sha256(&scratch[..offset]);

    let mut offset = 0;
    scratch[..B_IN_BYTES].copy_from_slice(&b0);
    offset += B_IN_BYTES;
    scratch[offset] = 1;
    offset += 1;
    offset = append_dst_prime(&mut scratch, offset);
    let b1 = sha256(&scratch[..offset]);

    for (out, (x, y)) in scratch.iter_mut().zip(b0.iter().zip(&b1)) {
        *out = x ^ y;
    }
    let mut offset = B_IN_BYTES;
    scratch[offset] = 2;
    offset += 1;
    offset = append_dst_prime(&mut scratch, offset);
    let b2 = sha256(&scratch[..offset]);

    let mut out = [0u8; L];
    out[..B_IN_BYTES].copy_from_slice(&b1);
    out[B_IN_BYTES..].copy_from_slice(&b2[..L - B_IN_BYTES]);
    out
}

pub fn hash_to_field_bn254_fr<const MSG_LEN: usize, const DST_LEN: usize>(
    msg: &[u8; MSG_LEN],
    dst: &[u8; DST_LEN],
) -> [u8; 32] {
    let mut raw = expand_message_xmd_sha256_l48(msg, dst);
    raw.reverse();
    let limbs = Fr::from_le_bytes_mod_order(&raw).into_bigint().0;
    let mut out = [0u8; 32];
    for (chunk, limb) in out.chunks_exact_mut(8).zip(limbs.iter().rev()) {
        chunk.copy_from_slice(&limb.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gnark_golden_vector_for_zero_g1() {
        assert_eq!(
            hash_to_field_bn254_fr(&[0u8; 64], b"bsb22-commitment"),
            [
                0x1f, 0x14, 0x07, 0xef, 0x74, 0x5a, 0x0b, 0x1e, 0xae, 0x05, 0x67, 0x30, 0x6b, 0x45,
                0x60, 0x47, 0x9d, 0x99, 0xb9, 0x43, 0xb3, 0x40, 0x72, 0xd9, 0x83, 0xad, 0x2e, 0xc6,
                0xd3, 0x7a, 0x13, 0x60,
            ]
        );
    }
}
