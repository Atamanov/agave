/// G2 point on BN254: 128 bytes big-endian (EIP-197 order: x1 || x0 || y1 || y0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "bytemuck",
    derive(bytemuck_derive::Pod, bytemuck_derive::Zeroable)
)]
#[cfg_attr(
    feature = "zerocopy",
    derive(
        zerocopy::FromBytes,
        zerocopy::IntoBytes,
        zerocopy::Immutable,
        zerocopy::KnownLayout,
        zerocopy::Unaligned
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[repr(transparent)]
pub struct G2(pub [u8; 128]);

impl G2 {
    pub fn as_bytes(&self) -> &[u8; 128] {
        &self.0
    }
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8; 128]> for G2 {
    fn as_ref(&self) -> &[u8; 128] {
        &self.0
    }
}

impl From<[u8; 128]> for G2 {
    fn from(bytes: [u8; 128]) -> Self {
        Self(bytes)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for G2 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for G2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct G2Visitor;
        impl<'de> serde::de::Visitor<'de> for G2Visitor {
            type Value = G2;
            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("128 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<G2, E> {
                let bytes: [u8; 128] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &"128 bytes"))?;
                Ok(G2(bytes))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<G2, A::Error> {
                let mut bytes = [0u8; 128];
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &"128 bytes"))?;
                }
                Ok(G2(bytes))
            }
        }
        deserializer.deserialize_bytes(G2Visitor)
    }
}

