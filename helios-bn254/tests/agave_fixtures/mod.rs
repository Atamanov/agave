use helios_bn254::{G1Bytes, G2Bytes, PairBytes, ScalarBytes};

pub const FQ_MODULUS_HEX: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
pub const FR_MODULUS_HEX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

pub fn bytes<const N: usize>(value: &str) -> [u8; N] {
    let decoded = hex::decode(value).expect("valid fixture hex");
    decoded
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| panic!("fixture has {} bytes, expected {N}", value.len()))
}

pub fn scalar(value: u64) -> ScalarBytes {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    ScalarBytes(out)
}

pub fn fq_modulus() -> [u8; 32] {
    bytes(FQ_MODULUS_HEX)
}

pub fn fr_modulus() -> ScalarBytes {
    ScalarBytes(bytes(FR_MODULUS_HEX))
}

pub fn fr_minus_one() -> ScalarBytes {
    ScalarBytes(bytes(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
    ))
}

pub fn g1_generator() -> G1Bytes {
    let mut out = [0u8; 64];
    out[31] = 1;
    out[63] = 2;
    G1Bytes(out)
}

pub fn g1_negative_generator() -> G1Bytes {
    let mut out = [0u8; 64];
    out[31] = 1;
    out[32..].copy_from_slice(&bytes::<32>(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
    ));
    G1Bytes(out)
}

pub fn g1_off_curve() -> G1Bytes {
    let mut out = [0u8; 64];
    out[31] = 1;
    out[63] = 3;
    G1Bytes(out)
}

/// Standard BN254 G2 generator in EIP-197 order: x1 | x0 | y1 | y0.
pub fn g2_generator() -> G2Bytes {
    G2Bytes(bytes(
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
         1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
         090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
         12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
    ))
}

pub fn g2_off_curve() -> G2Bytes {
    let mut out = g2_generator();
    // Agave's negative test increments y.c0 by one. This fixture has no carry.
    out.0[127] += 1;
    out
}

/// Deterministic twist point with x=(1, 0), on curve but outside the r-order subgroup.
pub fn g2_non_subgroup() -> G2Bytes {
    G2Bytes(bytes(
        "0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000001\
         0d1271953ed9ea0836846e70a1934187998c7f790cb4d7511b7f8da82de048a4\
         2869111d5381f072f8e2728fdb825a51aadd70e52c9830e9ab4b871c0531f1bb",
    ))
}

pub fn g2_negative_non_subgroup() -> G2Bytes {
    G2Bytes(bytes(
        "0000000000000000000000000000000000000000000000000000000000000000\
         0000000000000000000000000000000000000000000000000000000000000001\
         2351dcdda257b62181cbd745dfee16d5fdf4eb185bbcf33c20a0fe6eaa9cb4a3\
         07fb3d558dafafb6bf6dd326a5fefe0beca3f9ac3bd999a390d504fad34b0b8c",
    ))
}

pub fn pair(g1: G1Bytes, g2: G2Bytes) -> PairBytes {
    PairBytes { g1, g2 }
}
