//! Bounded, read-only configuration loading. Persistence requires a separate recovery design.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use thiserror::Error;
use tunlatch_core::config::{Config, ConfigError, MAX_CONFIG_BYTES};

/// Configuration loading failures preserve the existing settings at the caller.
#[derive(Debug, Error)]
pub enum LoadError {
    /// Opening or reading failed.
    #[error("cannot read configuration: {0}")]
    Io(#[from] io::Error),
    /// Only regular files may be used as configuration.
    #[error("configuration must be a regular file")]
    NotRegular,
    /// UTF-8 decoding failed.
    #[error("configuration must contain UTF-8 text: {0}")]
    Encoding(#[from] std::string::FromUtf8Error),
    /// Schema validation failed.
    #[error(transparent)]
    Invalid(#[from] ConfigError),
}

/// Load at most the parser limit plus one byte, including files growing during a read.
///
/// This development reader is not a privileged persistence store. No settings are written.
pub fn load(path: &Path) -> Result<Config, LoadError> {
    // O_NONBLOCK prevents a FIFO substituted for the path from blocking the caller.
    use std::os::unix::fs::OpenOptionsExt;
    let file = File::options()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(LoadError::NotRegular);
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge.into());
    }
    Ok(Config::parse(&String::from_utf8(bytes)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_symlinks_non_regular_files_and_oversized_input()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        std::fs::write(&path, include_str!("../../../examples/config.toml"))?;
        assert_eq!(load(&path)?, Config::default());
        let link = dir.path().join("linked.toml");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(load(&link).is_err());
        assert!(matches!(load(dir.path()), Err(LoadError::NotRegular)));
        std::fs::write(&path, vec![b' '; MAX_CONFIG_BYTES + 1])?;
        assert!(matches!(
            load(&path),
            Err(LoadError::Invalid(ConfigError::TooLarge))
        ));
        Ok(())
    }
}
