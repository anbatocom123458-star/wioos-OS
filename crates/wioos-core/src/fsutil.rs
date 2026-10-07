//! Locked, atomic JSON state helpers shared by the runtime, CLI and services.
//!
//! State files are written to a temporary file with `0600` permissions and
//! then renamed into place, under an exclusive advisory lock. This is the same
//! mechanism Phase 1 used for the verification store, extracted so every
//! subsystem shares one implementation.

use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{de::DeserializeOwned, Serialize};
use std::io::Write;

/// Run `op` while holding an exclusive lock derived from `path`
/// (`path` -> `path.with_extension("lock")`).
pub fn with_locked_file<T>(
    path: &Path,
    op: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let lock_file = std::fs::File::create(path.with_extension("lock"))?;
    lock_file.lock_exclusive()?;
    let result = op();
    FileExt::unlock(&lock_file)?;
    result
}

/// Read JSON from `path`, returning `T::default()` when the file does not
/// exist yet. Corrupt files are reported as errors, never silently replaced.
pub fn read_json_or_default<T: DeserializeOwned + Default>(
    path: &Path,
) -> std::io::Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    serde_json::from_slice(&std::fs::read(path)?).map_err(std::io::Error::other)
}

/// Atomically write JSON with `0600` permissions on Unix.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let temp_path = path.with_extension("tmp");
    let payload = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    std::fs::write(&temp_path, payload)?;
    restrict_permissions(&temp_path);
    std::fs::rename(&temp_path, path)?;
    Ok(())
}

/// Locked read-modify-write cycle: lock, load (or default), apply, persist.
pub fn update_json<T, R>(
    path: &Path,
    update: impl FnOnce(&mut T) -> std::io::Result<R>,
) -> std::io::Result<R>
where
    T: Default + Serialize + DeserializeOwned,
{
    with_locked_file(path, || {
        let mut value = read_json_or_default(path)?;
        let result = update(&mut value)?;
        write_json_atomic(path, &value)?;
        Ok(result)
    })
}

/// Append one JSON line to a JSONL log under the file lock.
pub fn append_json_line<T: Serialize>(
    path: &Path,
    value: &T,
) -> std::io::Result<()> {
    with_locked_file(path, || {
        let line = serde_json::to_string(value).map_err(std::io::Error::other)?;
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        restrict_permissions(path);
        Ok(())
    })
}

/// Apps root inside the WIOOS state directory.
pub fn apps_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("apps")
}

/// Application registry file inside the state directory.
pub fn registry_path(state_dir: &Path) -> PathBuf {
    apps_dir(state_dir).join("registry.json")
}

/// Security event log inside the state directory.
pub fn security_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("security-log.jsonl")
}

/// Restrict file permissions to owner-only on Unix. No-op elsewhere.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
