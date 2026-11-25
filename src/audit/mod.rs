pub mod docker;
pub mod ssh;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub const MAX_CONFIG_BYTES: usize = 1024 * 1024; // 1 MiB cap for static config parsing

pub(crate) fn read_bounded_text(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    if meta.len() > MAX_CONFIG_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "configuration file {:?} exceeds {} byte limit",
                path, MAX_CONFIG_BYTES
            ),
        ));
    }

    let mut buf = Vec::with_capacity(meta.len() as usize);
    let mut limited = (&mut file).take((MAX_CONFIG_BYTES + 1) as u64);
    limited.read_to_end(&mut buf)?;
    if buf.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "configuration file {:?} exceeds {} byte limit",
                path, MAX_CONFIG_BYTES
            ),
        ));
    }
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
