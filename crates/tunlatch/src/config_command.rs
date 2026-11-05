//! Offline inspection and export of configuration drafts; these operations never apply policy.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, bail};
use tunlatch_core::config::Config;
use tunlatch_core::policy::{ConfigV2, MAX_POLICY_INPUT_BYTES, PolicyErrorCode};

fn read(path: &Path) -> anyhow::Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        bail!("configuration must be a regular file, not a symlink");
    }
    let file = File::options()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("configuration must be a regular file");
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_POLICY_INPUT_BYTES {
        bail!("configuration exceeds {MAX_POLICY_INPUT_BYTES} bytes");
    }
    Ok(bytes)
}

fn draft(path: &Path) -> anyhow::Result<ConfigV2> {
    ConfigV2::parse_toml(&read(path)?).context("configuration rejected")
}

/// Validate a v2 draft or a legacy v1 configuration without changing it.
pub fn check(path: &Path) -> anyhow::Result<String> {
    let bytes = read(path)?;
    match ConfigV2::parse_toml(&bytes) {
        Ok(config) => Ok(format!(
            "Configuration valid (draft); desired = {:?}; digest = {}. No changes applied. Protection remains UNKNOWN.",
            config.desired(),
            config.digest()
        )),
        Err(error) if error.code() == PolicyErrorCode::MigrationRequired => {
            let text = std::str::from_utf8(&bytes).context("configuration must be UTF-8")?;
            let config = Config::parse(text).context("configuration rejected")?;
            Ok(format!(
                "Configuration valid (legacy configuration); desired = {:?}. No changes applied. Protection remains UNKNOWN.",
                config.desired()
            ))
        }
        Err(error) => Err(error).context("configuration rejected"),
    }
}

/// Inspect a v2 import and optionally compare its normalized content with another v2 draft.
pub fn import_preview(path: &Path, current: Option<&Path>) -> anyhow::Result<String> {
    let incoming = draft(path)?;
    let mut output = format!(
        "Import preview (draft): desired = {:?}; {} rules; {} candidate direct exceptions; digest = {}.\n",
        incoming.desired(),
        incoming.rules().len(),
        incoming.direct_exceptions().len(),
        incoming.digest()
    );
    if let Some(current) = current {
        let previous = draft(current)?;
        let old: serde_json::Value = serde_json::from_slice(previous.canonical_json())?;
        let new: serde_json::Value = serde_json::from_slice(incoming.canonical_json())?;
        if old == new {
            output.push_str("Compared with current draft: no changes.\n");
        } else {
            output.push_str("Compared with current draft, changed sections:\n");
            for key in ["desired", "rules", "direct_exceptions"] {
                if old.get(key) != new.get(key) {
                    output.push_str(&format!("  {key}: {} -> {}\n", old[key], new[key]));
                }
            }
        }
    }
    output.push_str(
        "Preview only; no changes applied or authorizations imported. Protection remains UNKNOWN.",
    );
    Ok(output)
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn allocate_export_file(
    parent: &Path,
    destination: &Path,
    next_temp: &AtomicU64,
) -> anyhow::Result<(TempFile, File)> {
    (0..128)
        .find_map(|_| {
            let sequence = next_temp.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".tunlatch-{}-{sequence}.tmp", std::process::id()));
            // A self-rename would leave the destination owned by the temporary-file guard.
            if path.file_name() == destination.file_name() {
                return None;
            }
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => Some(Ok((TempFile(path), file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .context("cannot allocate temporary export file")?
        .map_err(Into::into)
}

/// Write normalized v2 TOML via a temporary file in the destination directory.
/// Existing files are replaced only when `overwrite` is true.
pub fn export(source: &Path, destination: &Path, overwrite: bool) -> anyhow::Result<String> {
    let config = draft(source)?;
    let output = config.to_toml()?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if destination.file_name().is_none() {
        bail!("destination must name a file");
    }
    match fs::symlink_metadata(destination) {
        Ok(meta) if !meta.file_type().is_file() => {
            bail!("destination must be a regular file, not a symlink")
        }
        Ok(_) if !overwrite => bail!("destination already exists; use overwrite explicitly"),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let (temp, mut file) = allocate_export_file(parent, destination, &NEXT_TEMP)?;
    file.write_all(output.as_bytes())?;
    file.sync_all()?;
    drop(file);
    if overwrite {
        // Reject any currently visible non-regular destination before replacement.
        match fs::symlink_metadata(destination) {
            Ok(meta) if !meta.file_type().is_file() => {
                bail!("destination must be a regular file, not a symlink")
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        fs::rename(&temp.0, destination)?;
    } else {
        // Linking is atomic and fails if any destination entry already exists.
        fs::hard_link(&temp.0, destination)?;
    }
    Ok(format!(
        "Exported normalized draft (digest {}). No changes applied. Protection remains UNKNOWN.",
        config.digest()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn directory() -> anyhow::Result<TempFile> {
        let path = std::env::temp_dir().join(format!(
            "tunlatch-config-test-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(TempFile(path))
    }
    struct Dir(TempFile);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0.0);
        }
    }
    const VALID: &str =
        "schema_version = 2\ndesired = \"disabled\"\nrules = []\ndirect_exceptions = []\n";

    #[test]
    fn config_command_temporary_file_never_occupies_destination() -> anyhow::Result<()> {
        let dir = Dir(directory()?);
        let name = format!(".tunlatch-{}-0.tmp", std::process::id());
        for destination in [
            dir.0.0.join(&name),
            Path::new("relative").join(&name),
            PathBuf::from(&name),
        ] {
            let sequence = AtomicU64::new(0);
            let (temp, file) = allocate_export_file(&dir.0.0, &destination, &sequence)?;
            assert_ne!(temp.0.file_name(), destination.file_name());
            assert!(!dir.0.0.join(&name).exists());
            assert!(temp.0.is_file());
            let temporary_path = temp.0.clone();
            drop(file);
            drop(temp);
            assert!(!temporary_path.exists());
        }
        Ok(())
    }

    #[test]
    fn config_command_round_trip_and_preview() -> anyhow::Result<()> {
        let dir = Dir(directory()?);
        let input = dir.0.0.join("input");
        let output = dir.0.0.join("output");
        fs::write(&input, VALID)?;
        assert!(check(&input)?.contains("valid (draft)"));
        export(&input, &output, false)?;
        assert!(import_preview(&input, Some(&output))?.contains("no changes"));
        fs::write(&input, VALID.replace("disabled", "enabled"))?;
        assert!(import_preview(&input, Some(&output))?.contains("desired:"));
        assert!(export(&input, &output, false).is_err());
        assert!(fs::read_to_string(&output)?.contains("disabled"));
        export(&input, &output, true)?;
        assert!(fs::read_to_string(&output)?.contains("enabled"));
        Ok(())
    }

    #[test]
    fn config_command_rejects_bad_inputs_and_preserves_destination() -> anyhow::Result<()> {
        let dir = Dir(directory()?);
        let input = dir.0.0.join("input");
        let output = dir.0.0.join("output");
        let link = dir.0.0.join("link");
        fs::write(&input, VALID)?;
        fs::write(&output, "original")?;
        symlink(&input, &link)?;
        assert!(check(&link).is_err());
        assert!(check(&dir.0.0).is_err());
        assert!(export(&input, &link, true).is_err());
        fs::write(&input, format!("{VALID}authorized = true\n"))?;
        assert!(import_preview(&input, None).is_err());
        assert!(export(&input, &output, true).is_err());
        assert_eq!(fs::read_to_string(&output)?, "original");
        fs::write(&input, "invalid")?;
        assert!(export(&input, &output, true).is_err());
        assert_eq!(fs::read_to_string(&output)?, "original");
        fs::write(&input, VALID)?;
        assert!(export(&input, &dir.0.0.join("missing").join("output"), false).is_err());
        assert_eq!(fs::read_to_string(&output)?, "original");
        fs::write(&input, vec![b' '; MAX_POLICY_INPUT_BYTES + 1])?;
        assert!(check(&input).is_err());
        Ok(())
    }
}
