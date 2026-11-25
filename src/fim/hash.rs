use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const DEFAULT_MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
const STREAM_BUF_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum FimError {
    Io(io::Error),
    TooLarge { path: String, size: u64, limit: u64 },
    InvalidInput(String),
    Json(serde_json::Error),
}

impl fmt::Display for FimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FimError::Io(err) => write!(f, "filesystem I/O error: {err}"),
            FimError::TooLarge { path, size, limit } => {
                write!(
                    f,
                    "file {path:?} ({size} bytes) exceeds limit of {limit} bytes"
                )
            }
            FimError::InvalidInput(msg) => write!(f, "{msg}"),
            FimError::Json(err) => write!(f, "snapshot JSON error: {err}"),
        }
    }
}

impl std::error::Error for FimError {}

impl From<io::Error> for FimError {
    fn from(err: io::Error) -> Self {
        FimError::Io(err)
    }
}

impl From<serde_json::Error> for FimError {
    fn from(err: serde_json::Error) -> Self {
        FimError::Json(err)
    }
}

pub fn hash_file_streaming(path: &Path, max_bytes: u64) -> Result<(String, u64), FimError> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let meta_len = meta.len();
    if max_bytes > 0 && meta_len > max_bytes {
        return Err(FimError::TooLarge {
            path: path.display().to_string(),
            size: meta_len,
            limit: max_bytes,
        });
    }

    let mut hasher = Sha256::new();
    let mut buf = [0u8; STREAM_BUF_SIZE];
    let mut total: u64 = 0;

    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if max_bytes > 0 && total > max_bytes {
            return Err(FimError::TooLarge {
                path: path.display().to_string(),
                size: total,
                limit: max_bytes,
            });
        }
        hasher.update(&buf[..read]);
    }

    let digest = hasher.finalize();
    Ok((to_hex_lower(&digest), total))
}

fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
