/// Thin wrapper around ark_bn254::Fr for convenient byte conversion.
/// All serialization uses 32-byte big-endian format (matching snarkjs/EIP-197).
use ark_bn254::Fr as ArkFr;
use ark_ff::biginteger::BigInteger;
use ark_ff::{BigInt, Field, One, PrimeField, Zero};

/// Convert 32 big-endian bytes to ark BigInt<4> (little-endian u64 limbs).
pub fn bigint_from_be_bytes(bytes: &[u8; 32]) -> BigInt<4> {
    BigInt([
        u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
        u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
    ])
}

/// Convert ark BigInt<4> to 32 big-endian bytes.
pub fn bigint_to_be_bytes(n: &BigInt<4>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&n.0[3].to_be_bytes());
    bytes[8..16].copy_from_slice(&n.0[2].to_be_bytes());
    bytes[16..24].copy_from_slice(&n.0[1].to_be_bytes());
    bytes[24..32].copy_from_slice(&n.0[0].to_be_bytes());
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

impl Fr {
    pub fn zero() -> Self {
        Self(ArkFr::zero())
    }

    pub fn one() -> Self {
        Self(ArkFr::one())
    }

    /// Convert big-endian bytes to Fr, rejecting non-canonical values.
    /// Returns `None` if the value is >= the BN254 scalar field modulus.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let bigint = bigint_from_be_bytes(bytes);
        if bigint >= <ArkFr as PrimeField>::MODULUS {
            return None;
        }
        // Safe: we just verified bigint < MODULUS
        Some(Self(ArkFr::from_bigint(bigint).unwrap()))
    }

    /// Convert big-endian bytes to Fr with silent modular reduction.
    /// Non-canonical values (>= field modulus) are reduced without error.
    pub fn from_be_bytes_unchecked(bytes: &[u8]) -> Self {
        if bytes.len() == 32 {
            let bytes32: &[u8; 32] = bytes.try_into().unwrap();
            let mut bigint = bigint_from_be_bytes(bytes32);
            // Fast path: canonical input (< MODULUS)
            if let Some(fr) = ArkFr::from_bigint(bigint) {
                return Self(fr);
            }
            // Fast reduction: subtract MODULUS until < MODULUS
            // For 256-bit keccak outputs, at most ~5 subtractions needed
            let modulus = <ArkFr as PrimeField>::MODULUS;
            loop {
                let mut tmp = bigint;
                let borrow = tmp.sub_with_borrow(&modulus);
                if borrow {
                    break;
                }
                bigint = tmp;
            }
            return Self(ArkFr::from_bigint(bigint).unwrap());
        }
        // Non-32-byte fallback (unused in practice)
        let mut le = [0u8; 32];
        let len = bytes.len().min(32);
        let start = 32 - len;
        le[start..].copy_from_slice(&bytes[..len]);
        le.reverse();
        Self(ArkFr::from_le_bytes_mod_order(&le))
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        bigint_to_be_bytes(&self.0.into_bigint())
    }

    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Self)
    }
}

impl core::ops::Add for Fr {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::Sub for Fr {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl core::ops::Mul for Fr {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self(self.0 * rhs.0)
    }
}

impl core::ops::Neg for Fr {
    type Output = Self;
    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl From<u64> for Fr {
    fn from(v: u64) -> Self {
        Self(ArkFr::from(v))
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshSerialize for Fr {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&self.to_be_bytes())
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for Fr {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Fr::from_be_bytes(&buf).ok_or_else(|| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "Fr value >= field modulus",
            )
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Fr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.to_be_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Fr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FrVisitor;
        impl<'de> serde::de::Visitor<'de> for FrVisitor {
            type Value = Fr;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Fr, E> {
                let bytes: [u8; 32] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &"32 bytes"))?;
                Fr::from_be_bytes(&bytes).ok_or_else(|| E::custom("Fr value >= field modulus"))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Fr, A::Error> {
                let mut bytes = [0u8; 32];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"32 bytes"))?;
                }
                Fr::from_be_bytes(&bytes)
                    .ok_or_else(|| serde::de::Error::custom("Fr value >= field modulus"))
            }
        }
        deserializer.deserialize_bytes(FrVisitor)
    }
}

