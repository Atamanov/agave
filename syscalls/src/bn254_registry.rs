//! Authenticated, account-backed BN254 verifying-key registry.
//!
//! The account contains canonical source points and post-final-exponentiation
//! targets derived during initialization. No process-global cache participates
//! in verification.

use {
    solana_bn254_batch_syscall::{
        AltBn128BatchError, PREPARED_G2_BYTES, PodG1G2Pair, PodG1RegisteredG2Pair, PodG2Point,
        PodGtElement, PodScalar, PodTrustedGtExponent, REGISTRY_PREPARED_G2_BYTES,
        RegisteredG2Pair, pairing_check_registered, registered_g2_from_authenticated_bytes,
        trusted_gt_from_authenticated_bytes, trusted_gt_from_pair, trusted_gt_multiexp,
        trusted_gt_to_bytes, validate_registered_g2,
    },
    solana_pubkey::Pubkey,
    thiserror::Error,
};

pub use solana_bn254_batch_syscall::{
    REGISTRY_ABI_VERSION, REGISTRY_G2_ENTRY_BYTES, REGISTRY_GT_ENTRY_BYTES, REGISTRY_HEADER_BYTES,
    REGISTRY_MAX_G2_ENTRIES, REGISTRY_MAX_GT_ENTRIES, REGISTRY_MAX_REGISTERED_PAIRS,
    pack_gt_multiexp_shape, pack_registered_pairing_shape, pack_registry_init_shape,
    registry_account_len,
};

pub const REGISTRY_MAGIC: &[u8; 8] = b"B254VK3\0";
pub const REGISTRY_VERSION: u8 = 3;
pub const REGISTRY_FROZEN: u8 = 1;
pub const REGISTRY_CURVE_BN254: u8 = 1;
pub const REGISTRY_BACKEND_B5: u8 = 5;
pub const REGISTRY_PDA_SEED: &[u8] = b"bn254-b5-vk-registry-v3";
const _: () = assert!(PREPARED_G2_BYTES == REGISTRY_PREPARED_G2_BYTES);

const G2_ID_DOMAIN: &[u8] = b"agave:bn254:b5:g2-registry:v3";
const GT_ID_DOMAIN: &[u8] = b"agave:bn254:b5:gt-registry:v3";
const KEYSET_DOMAIN: &[u8] = b"agave:bn254:b5:keyset:v3";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryInitShape {
    pub g2_count: u16,
    pub gt_count: u16,
    pub account_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredPairingShape {
    pub full_count: u16,
    pub registered_count: u16,
    pub account_index: u16,
}

pub(crate) fn unpack_registry_init_shape(shape: u64) -> Option<RegistryInitShape> {
    ((shape >> 48) as u16 == REGISTRY_ABI_VERSION).then_some(RegistryInitShape {
        g2_count: shape as u16,
        gt_count: (shape >> 16) as u16,
        account_index: (shape >> 32) as u16,
    })
}

pub(crate) fn unpack_registered_pairing_shape(shape: u64) -> Option<RegisteredPairingShape> {
    ((shape >> 48) as u16 == REGISTRY_ABI_VERSION).then_some(RegisteredPairingShape {
        full_count: shape as u16,
        registered_count: (shape >> 16) as u16,
        account_index: (shape >> 32) as u16,
    })
}

pub(crate) fn unpack_gt_multiexp_shape(shape: u64) -> Option<(u16, u16)> {
    ((shape >> 48) as u16 == REGISTRY_ABI_VERSION).then_some((shape as u16, (shape >> 32) as u16))
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid registry shape")]
    InvalidShape,
    #[error("invalid or unauthenticated registry account")]
    InvalidAccount,
    #[error("registry source or target failed BN254 validation: {0}")]
    Backend(#[from] AltBn128BatchError),
    #[error("unknown, duplicated, or corrupted registry identifier")]
    InvalidIdentifier,
}

#[derive(Clone, Debug)]
pub struct PreparedVkRegistryAccount {
    pub key: Pubkey,
    pub data: Vec<u8>,
    pub g2_ids: Vec<[u8; 32]>,
    pub gt_ids: Vec<[u8; 32]>,
}

#[derive(Clone, Copy)]
pub struct RegistryAccountView<'a> {
    pub key: Pubkey,
    pub owner: Pubkey,
    pub data: &'a [u8],
    pub is_writable: bool,
}

#[derive(Clone, Copy)]
struct Header {
    g2_count: usize,
    gt_count: usize,
    consumer: [u8; 32],
    keyset_digest: [u8; 32],
}

pub fn registry_address(consumer: Pubkey, keyset_digest: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[REGISTRY_PDA_SEED, keyset_digest], &consumer).0
}

fn parse_header(data: &[u8]) -> Result<Header, RegistryError> {
    if data.get(..8) != Some(REGISTRY_MAGIC.as_slice())
        || data.get(8).copied() != Some(REGISTRY_VERSION)
        || data.get(9).copied() != Some(REGISTRY_FROZEN)
        || data.get(10).copied() != Some(REGISTRY_CURVE_BN254)
        || data.get(11).copied() != Some(REGISTRY_BACKEND_B5)
    {
        return Err(RegistryError::InvalidAccount);
    }
    let g2_count = u16::from_le_bytes(
        data.get(12..14)
            .ok_or(RegistryError::InvalidAccount)?
            .try_into()
            .map_err(|_| RegistryError::InvalidAccount)?,
    ) as usize;
    let gt_count = u16::from_le_bytes(
        data.get(14..16)
            .ok_or(RegistryError::InvalidAccount)?
            .try_into()
            .map_err(|_| RegistryError::InvalidAccount)?,
    ) as usize;
    if g2_count > REGISTRY_MAX_G2_ENTRIES
        || gt_count > REGISTRY_MAX_GT_ENTRIES
        || g2_count.saturating_add(gt_count) == 0
        || data.len() != registry_account_len(g2_count, gt_count)
    {
        return Err(RegistryError::InvalidAccount);
    }
    let consumer = data
        .get(16..48)
        .ok_or(RegistryError::InvalidAccount)?
        .try_into()
        .map_err(|_| RegistryError::InvalidAccount)?;
    let keyset_digest = data
        .get(48..80)
        .ok_or(RegistryError::InvalidAccount)?
        .try_into()
        .map_err(|_| RegistryError::InvalidAccount)?;
    Ok(Header {
        g2_count,
        gt_count,
        consumer,
        keyset_digest,
    })
}

fn authenticate(
    consumer: [u8; 32],
    account: RegistryAccountView<'_>,
) -> Result<Header, RegistryError> {
    if account.is_writable || account.owner.to_bytes() != consumer {
        return Err(RegistryError::InvalidAccount);
    }
    let header = parse_header(account.data)?;
    if header.consumer != consumer
        || registry_address(Pubkey::new_from_array(consumer), &header.keyset_digest) != account.key
    {
        return Err(RegistryError::InvalidAccount);
    }
    Ok(header)
}

fn g2_entry_range(index: usize) -> core::ops::Range<usize> {
    let start = REGISTRY_HEADER_BYTES.saturating_add(index.saturating_mul(REGISTRY_G2_ENTRY_BYTES));
    start..start.saturating_add(REGISTRY_G2_ENTRY_BYTES)
}

fn gt_entry_range(g2_count: usize, index: usize) -> core::ops::Range<usize> {
    let start = REGISTRY_HEADER_BYTES
        .saturating_add(g2_count.saturating_mul(REGISTRY_G2_ENTRY_BYTES))
        .saturating_add(index.saturating_mul(REGISTRY_GT_ENTRY_BYTES));
    start..start.saturating_add(REGISTRY_GT_ENTRY_BYTES)
}

fn g2_entry_id(
    registry_key: &Pubkey,
    index: usize,
    source: &[u8; 128],
    prepared: &[u8],
) -> [u8; 32] {
    let mut id = solana_keccak_hasher::hashv(&[
        G2_ID_DOMAIN,
        registry_key.as_ref(),
        &[REGISTRY_VERSION],
        &(index as u32).to_le_bytes(),
        source,
        prepared,
    ])
    .to_bytes();
    id[..2].copy_from_slice(&(index as u16).to_le_bytes());
    id
}

fn gt_entry_id(
    registry_key: &Pubkey,
    index: usize,
    source: &[u8; 192],
    target: &[u8; 384],
) -> [u8; 32] {
    let mut id = solana_keccak_hasher::hashv(&[
        GT_ID_DOMAIN,
        registry_key.as_ref(),
        &[REGISTRY_VERSION],
        &(index as u32).to_le_bytes(),
        source,
        target,
    ])
    .to_bytes();
    id[..2].copy_from_slice(&(index as u16).to_le_bytes());
    id
}

fn indexed_entry(id: &[u8; 32], count: usize) -> Result<usize, RegistryError> {
    let index = usize::from(u16::from_le_bytes([id[0], id[1]]));
    (index < count)
        .then_some(index)
        .ok_or(RegistryError::InvalidIdentifier)
}

/// Commits the ordered canonical key sources used to derive a registry PDA.
///
/// Init rejects a caller-supplied digest that does not match this value. The
/// current program can therefore precommit the exact keyset in its PDA seeds;
/// prepared lines and GT targets remain deterministic init-time derivatives.
pub fn registry_keyset_digest(g2_sources: &[PodG2Point], gt_sources: &[PodG1G2Pair]) -> [u8; 32] {
    let mut hasher = solana_keccak_hasher::Hasher::default();
    hasher.hashv(&[
        KEYSET_DOMAIN,
        &[REGISTRY_VERSION],
        &(g2_sources.len() as u16).to_le_bytes(),
        &(gt_sources.len() as u16).to_le_bytes(),
    ]);
    for source in g2_sources {
        hasher.hash(&source.0);
    }
    for source in gt_sources {
        hasher.hash(bytemuck::bytes_of(source));
    }
    hasher.result().to_bytes()
}

pub fn prepare_registry_account_bytes(
    consumer: [u8; 32],
    keyset_digest: [u8; 32],
    g2_sources: &[PodG2Point],
    gt_sources: &[PodG1G2Pair],
) -> Result<PreparedVkRegistryAccount, RegistryError> {
    if g2_sources.len() > REGISTRY_MAX_G2_ENTRIES
        || gt_sources.len() > REGISTRY_MAX_GT_ENTRIES
        || g2_sources.len().saturating_add(gt_sources.len()) == 0
    {
        return Err(RegistryError::InvalidShape);
    }
    if keyset_digest != registry_keyset_digest(g2_sources, gt_sources) {
        return Err(RegistryError::InvalidIdentifier);
    }
    let registry_key = registry_address(Pubkey::new_from_array(consumer), &keyset_digest);
    let mut validated_g2 = Vec::with_capacity(g2_sources.len());
    for source in g2_sources {
        validated_g2.push(validate_registered_g2(source)?);
    }
    let mut trusted_gt = Vec::with_capacity(gt_sources.len());
    for source in gt_sources {
        if source.g1.0.iter().all(|byte| *byte == 0) || source.g2.0.iter().all(|byte| *byte == 0) {
            return Err(RegistryError::InvalidShape);
        }
        trusted_gt.push(trusted_gt_from_pair(source)?);
    }

    let mut data = vec![0u8; registry_account_len(g2_sources.len(), gt_sources.len())];
    data[..8].copy_from_slice(REGISTRY_MAGIC);
    data[8] = REGISTRY_VERSION;
    data[9] = REGISTRY_FROZEN;
    data[10] = REGISTRY_CURVE_BN254;
    data[11] = REGISTRY_BACKEND_B5;
    data[12..14].copy_from_slice(&(g2_sources.len() as u16).to_le_bytes());
    data[14..16].copy_from_slice(&(gt_sources.len() as u16).to_le_bytes());
    data[16..48].copy_from_slice(&consumer);
    data[48..80].copy_from_slice(&keyset_digest);

    let mut g2_ids = Vec::with_capacity(g2_sources.len());
    for (index, validated) in validated_g2.iter().enumerate() {
        let source = validated.to_bytes();
        let prepared = validated.prepared_bytes();
        debug_assert_eq!(prepared.len(), PREPARED_G2_BYTES);
        let id = g2_entry_id(&registry_key, index, &source.0, &prepared);
        g2_ids.push(id);
        let entry = &mut data[g2_entry_range(index)];
        entry[..32].copy_from_slice(&id);
        entry[32..160].copy_from_slice(&source.0);
        entry[160..].copy_from_slice(&prepared);
    }

    let mut gt_ids = Vec::with_capacity(gt_sources.len());
    for (index, source) in gt_sources.iter().enumerate() {
        let target = trusted_gt_to_bytes(&trusted_gt[index]);
        let source_bytes: &[u8; 192] = bytemuck::bytes_of(source)
            .try_into()
            .map_err(|_| RegistryError::InvalidShape)?;
        let id = gt_entry_id(&registry_key, index, source_bytes, &target.0);
        gt_ids.push(id);
        let entry = &mut data[gt_entry_range(g2_sources.len(), index)];
        entry[..32].copy_from_slice(&id);
        entry[32..224].copy_from_slice(source_bytes);
        entry[224..].copy_from_slice(&target.0);
    }

    #[cfg(feature = "research-observer")]
    solana_bn254_batch_syscall::research_observer::record_registry_init(
        g2_sources.len(),
        gt_sources.len(),
    );
    Ok(PreparedVkRegistryAccount {
        key: registry_key,
        data,
        g2_ids,
        gt_ids,
    })
}

pub fn pairing_check_registry_account(
    consumer: [u8; 32],
    account: RegistryAccountView<'_>,
    full: &[PodG1G2Pair],
    registered: &[PodG1RegisteredG2Pair],
) -> Result<bool, RegistryError> {
    let total = full
        .len()
        .checked_add(registered.len())
        .ok_or(RegistryError::InvalidShape)?;
    if total == 0
        || total > REGISTRY_MAX_REGISTERED_PAIRS
        || registered.len() > REGISTRY_MAX_G2_ENTRIES
    {
        return Err(RegistryError::InvalidShape);
    }
    let header = authenticate(consumer, account)?;
    let mut seen = [false; REGISTRY_MAX_G2_ENTRIES];
    let mut resolved = Vec::with_capacity(registered.len());
    for pair in registered {
        let index = indexed_entry(&pair.g2_id, header.g2_count)?;
        let entry = account
            .data
            .get(g2_entry_range(index))
            .ok_or(RegistryError::InvalidAccount)?;
        let stored_id: &[u8; 32] = entry[..32]
            .try_into()
            .map_err(|_| RegistryError::InvalidAccount)?;
        if seen[index] || stored_id != &pair.g2_id {
            return Err(RegistryError::InvalidIdentifier);
        }
        seen[index] = true;
        let source: &[u8; 128] = entry[32..160]
            .try_into()
            .map_err(|_| RegistryError::InvalidAccount)?;
        let prepared = &entry[160..];
        // SAFETY: the read-only, current-program-owned, precommitted PDA and
        // frozen header authenticate this init-produced entry. The indexed ID
        // is checked directly; the hot path deliberately does not rescan or
        // rehash the 37,584-byte prepared backend schedule.
        let g2 = unsafe { registered_g2_from_authenticated_bytes(&PodG2Point(*source), prepared) }?;
        resolved.push(RegisteredG2Pair { g1: pair.g1, g2 });
    }
    pairing_check_registered(full, &resolved).map_err(RegistryError::from)
}

pub fn trusted_gt_multiexp_registry_account(
    consumer: [u8; 32],
    account: RegistryAccountView<'_>,
    operands: &[PodTrustedGtExponent],
) -> Result<PodGtElement, RegistryError> {
    if operands.is_empty() || operands.len() > REGISTRY_MAX_GT_ENTRIES {
        return Err(RegistryError::InvalidShape);
    }
    let header = authenticate(consumer, account)?;
    let mut seen = [false; REGISTRY_MAX_GT_ENTRIES];
    let mut targets = Vec::with_capacity(operands.len());
    let mut exponents = Vec::<PodScalar>::with_capacity(operands.len());
    for operand in operands {
        let index = indexed_entry(&operand.target_id, header.gt_count)?;
        let entry = account
            .data
            .get(gt_entry_range(header.g2_count, index))
            .ok_or(RegistryError::InvalidAccount)?;
        let stored_id: &[u8; 32] = entry[..32]
            .try_into()
            .map_err(|_| RegistryError::InvalidAccount)?;
        if seen[index] || stored_id != &operand.target_id {
            return Err(RegistryError::InvalidIdentifier);
        }
        seen[index] = true;
        let target: &[u8; 384] = entry[224..]
            .try_into()
            .map_err(|_| RegistryError::InvalidAccount)?;
        // SAFETY: the same authenticated account boundary described above
        // guarantees this target was derived from its init-time source pair.
        targets.push(unsafe { trusted_gt_from_authenticated_bytes(&PodGtElement(*target)) }?);
        exponents.push(operand.exponent);
    }
    trusted_gt_multiexp(&targets, &exponents).map_err(RegistryError::from)
}
