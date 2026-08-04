use crate::errors::PlonkError;

#[cfg(target_os = "solana")]
mod inner {
    use super::PlonkError;
    use pinocchio::syscalls::{sol_alt_bn128_compression, sol_alt_bn128_group_op};

    const G1_ADD_BE: u64 = 0;
    const G1_MUL_BE: u64 = 2;
    const PAIRING_BE: u64 = 3;
    const G1_COMPRESS_BE: u64 = 0;
    const G1_DECOMPRESS_BE: u64 = 1;

    pub fn g1_addition_be(input: &[u8; 128]) -> Result<[u8; 64], PlonkError> {
        let mut result = [0u8; 64];
        let rc = unsafe {
            sol_alt_bn128_group_op(
                G1_ADD_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(PlonkError::G1AdditionFailed);
        }
        Ok(result)
    }

    pub fn g1_multiplication_be(input: &[u8; 96]) -> Result<[u8; 64], PlonkError> {
        let mut result = [0u8; 64];
        let rc = unsafe {
            sol_alt_bn128_group_op(
                G1_MUL_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(PlonkError::G1MulFailed);
        }
        Ok(result)
    }

    pub fn pairing_be(input: &[u8]) -> Result<[u8; 32], PlonkError> {
        let mut result = [0u8; 32];
        let rc = unsafe {
            sol_alt_bn128_group_op(
                PAIRING_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(PlonkError::PairingFailed);
        }
        Ok(result)
    }

    pub fn g1_compress_be(input: &[u8; 64]) -> Result<[u8; 32], PlonkError> {
        let mut result = [0u8; 32];
        let rc = unsafe {
            sol_alt_bn128_compression(
                G1_COMPRESS_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(PlonkError::G1CompressionFailed);
        }
        Ok(result)
    }

    pub fn g1_decompress_be(input: &[u8; 32]) -> Result<[u8; 64], PlonkError> {
        let mut result = [0u8; 64];
        let rc = unsafe {
            sol_alt_bn128_compression(
                G1_DECOMPRESS_BE,
                input.as_ptr(),
                input.len() as u64,
                result.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(PlonkError::G1DecompressionFailed);
        }
        Ok(result)
    }
}

#[cfg(not(target_os = "solana"))]
mod inner {
    use super::PlonkError;
    extern crate alloc;
    use alloc::vec::Vec;
    use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_ec::AffineRepr;
    use ark_ff::{BigInt, One};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

    /// Reverse each CHUNK_SIZE-byte chunk in a ARRAY_SIZE-byte array.
    /// This converts between big-endian (EIP-197) and little-endian (arkworks) formats.
    fn convert_endianness<const CHUNK: usize, const SIZE: usize>(bytes: &[u8; SIZE]) -> [u8; SIZE] {
        let mut out = [0u8; SIZE];
        for (i, chunk) in bytes.chunks_exact(CHUNK).enumerate() {
            let offset = i * CHUNK;
            for (j, &b) in chunk.iter().rev().enumerate() {
                out[offset + j] = b;
            }
        }
        out
    }

    fn fq_from_le_bytes(bytes: &[u8; 32]) -> Result<Fq, PlonkError> {
        Fq::deserialize_with_mode(bytes.as_slice(), Compress::No, Validate::No)
            .map_err(|_| PlonkError::G1AdditionFailed)
    }

    fn g1_from_be_bytes(input: &[u8]) -> Result<G1Affine, PlonkError> {
        if input.iter().all(|&b| b == 0) {
            return Ok(G1Affine::identity());
        }
        let le: [u8; 64] = convert_endianness::<32, 64>(
            input.try_into().map_err(|_| PlonkError::G1AdditionFailed)?,
        );
        G1Affine::deserialize_with_mode(le.as_slice(), Compress::No, Validate::Yes)
            .map_err(|_| PlonkError::G1AdditionFailed)
    }

    fn g1_to_be_bytes(p: &G1Affine) -> Result<[u8; 64], PlonkError> {
        if p.is_zero() {
            return Ok([0u8; 64]);
        }
        let mut le = [0u8; 64];
        p.x.serialize_with_mode(&mut le[..32], Compress::No)
            .map_err(|_| PlonkError::G1AdditionFailed)?;
        p.y.serialize_with_mode(&mut le[32..], Compress::No)
            .map_err(|_| PlonkError::G1AdditionFailed)?;
        Ok(convert_endianness::<32, 64>(&le))
    }

    fn g2_from_be_bytes(input: &[u8]) -> Result<G2Affine, PlonkError> {
        if input.iter().all(|&b| b == 0) {
            return Ok(G2Affine::identity());
        }
        // EIP-197 BE format: x1 || x0 || y1 || y0 (each 32 bytes)
        // arkworks LE format: x0_le || x1_le || y0_le || y1_le
        let input: &[u8; 128] = input.try_into().map_err(|_| PlonkError::PairingFailed)?;
        let be_x1 = &input[0..32];
        let be_x0 = &input[32..64];
        let be_y1 = &input[64..96];
        let be_y0 = &input[96..128];

        let le_x0 = convert_endianness::<32, 32>(be_x0.try_into().unwrap());
        let le_x1 = convert_endianness::<32, 32>(be_x1.try_into().unwrap());
        let le_y0 = convert_endianness::<32, 32>(be_y0.try_into().unwrap());
        let le_y1 = convert_endianness::<32, 32>(be_y1.try_into().unwrap());

        let x0 = fq_from_le_bytes(&le_x0).map_err(|_| PlonkError::PairingFailed)?;
        let x1 = fq_from_le_bytes(&le_x1).map_err(|_| PlonkError::PairingFailed)?;
        let y0 = fq_from_le_bytes(&le_y0).map_err(|_| PlonkError::PairingFailed)?;
        let y1 = fq_from_le_bytes(&le_y1).map_err(|_| PlonkError::PairingFailed)?;

        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);

        let p = G2Affine::new(x, y);
        if !p.is_on_curve() {
            return Err(PlonkError::PairingFailed);
        }
        Ok(p)
    }

    pub fn g1_addition_be(input: &[u8; 128]) -> Result<[u8; 64], PlonkError> {
        let p = g1_from_be_bytes(&input[..64])?;
        let q = g1_from_be_bytes(&input[64..])?;
        let result: G1Affine = (p + q).into();
        g1_to_be_bytes(&result)
    }

    pub fn g1_multiplication_be(input: &[u8; 96]) -> Result<[u8; 64], PlonkError> {
        let p = g1_from_be_bytes(&input[..64]).map_err(|_| PlonkError::G1MulFailed)?;
        // Scalar: 32 BE bytes -> LE bytes -> BigInt<4>
        let scalar_be: &[u8; 32] = input[64..96].try_into().unwrap();
        let scalar_le = convert_endianness::<32, 32>(scalar_be);
        let scalar = BigInt::<4>::deserialize_uncompressed_unchecked(scalar_le.as_slice())
            .map_err(|_| PlonkError::G1MulFailed)?;
        use ark_ec::CurveGroup;
        let result: G1Affine = p.mul_bigint(scalar).into_affine();
        g1_to_be_bytes(&result).map_err(|_| PlonkError::G1MulFailed)
    }

    pub fn pairing_be(input: &[u8]) -> Result<[u8; 32], PlonkError> {
        let n_pairs = input.len() / 192;
        let mut g1s = Vec::with_capacity(n_pairs);
        let mut g2s = Vec::with_capacity(n_pairs);
        for i in 0..n_pairs {
            let offset = i * 192;
            let g1 = g1_from_be_bytes(&input[offset..offset + 64])
                .map_err(|_| PlonkError::PairingFailed)?;
            let g2 = g2_from_be_bytes(&input[offset + 64..offset + 192])?;
            g1s.push(g1);
            g2s.push(g2);
        }

        let res = Bn254::multi_pairing(&g1s, &g2s);
        let mut result = [0u8; 32];
        if res.0 == ark_bn254::Fq12::one() {
            result[31] = 1;
        }
        Ok(result)
    }

    pub fn g1_compress_be(input: &[u8; 64]) -> Result<[u8; 32], PlonkError> {
        if *input == [0u8; 64] {
            return Ok([0u8; 32]);
        }
        let le = convert_endianness::<32, 64>(input);
        let p = G1Affine::deserialize_with_mode(le.as_slice(), Compress::No, Validate::No)
            .map_err(|_| PlonkError::G1CompressionFailed)?;
        let mut compressed_le = [0u8; 32];
        G1Affine::serialize_compressed(&p, compressed_le.as_mut_slice())
            .map_err(|_| PlonkError::G1CompressionFailed)?;
        Ok(convert_endianness::<32, 32>(&compressed_le))
    }

    pub fn g1_decompress_be(input: &[u8; 32]) -> Result<[u8; 64], PlonkError> {
        if *input == [0u8; 32] {
            return Ok([0u8; 64]);
        }
        let le = convert_endianness::<32, 32>(input);
        let p = G1Affine::deserialize_with_mode(le.as_slice(), Compress::Yes, Validate::No)
            .map_err(|_| PlonkError::G1DecompressionFailed)?;
        let mut uncompressed_le = [0u8; 64];
        p.x.serialize_with_mode(&mut uncompressed_le[..32], Compress::No)
            .map_err(|_| PlonkError::G1DecompressionFailed)?;
        p.y.serialize_with_mode(&mut uncompressed_le[32..], Compress::No)
            .map_err(|_| PlonkError::G1DecompressionFailed)?;
        Ok(convert_endianness::<32, 64>(&uncompressed_le))
    }
}

pub use inner::*;

