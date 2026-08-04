use {
    crate::{Error, contract::reject_deprecated_or_derived_json},
    serde::{Serialize, de::DeserializeOwned},
    solana_sha256_hasher::hash,
    std::{
        fs,
        path::{Path, PathBuf},
    },
};

pub fn read_bytes(path: &Path) -> Result<Vec<u8>, Error> {
    fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(hash(bytes).to_bytes())
}

pub fn read_json<T: DeserializeOwned>(
    path: &Path,
    reject_legacy: bool,
) -> Result<(T, String), Error> {
    let bytes = read_bytes(path)?;
    let digest = sha256_hex(&bytes);
    let raw = std::str::from_utf8(&bytes).map_err(|error| {
        Error::Contract(format!("{} is not UTF-8 JSON: {error}", path.display()))
    })?;
    if reject_legacy {
        reject_deprecated_or_derived_json(raw, &path.display().to_string())?;
    }
    let value = serde_json::from_str(raw).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })?;
    Ok((value, digest))
}

pub fn resolve_reference(base_file: &Path, reference: &str) -> Result<PathBuf, Error> {
    let reference_path = Path::new(reference);
    let path = if reference_path.is_absolute() {
        reference_path.to_path_buf()
    } else {
        base_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(reference_path)
    };
    Ok(path)
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source,
    })
}

pub fn write_text(path: &Path, value: &str) -> Result<(), Error> {
    fs::write(path, value).map_err(|source| Error::Write {
        path: path.to_path_buf(),
        source,
    })
}

pub fn validate_hex_digest(value: &str, label: &str) -> Result<(), Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Contract(format!(
            "{label} must be a lowercase 64-character SHA-256 digest"
        )));
    }
    Ok(())
}
