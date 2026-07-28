//! Deployment-scoped maintenance lock for the packaged Rust runtime.

use fs4::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub struct RuntimeLock {
    _file: File,
}

/// Acquire the shared runtime side of a deployment lock.
///
/// This is public only so the clean-room cutover tests can exercise the exact
/// lock protocol used by the packaged binary.
#[doc(hidden)]
pub fn acquire_runtime_lock(
    path: &Path,
    expected_uid: u32,
    expected_dev: u64,
    expected_ino: u64,
    transaction_marker: &Path,
) -> Result<RuntimeLock, String> {
    if !path.is_absolute()
        || path.parent().is_none()
        || transaction_marker.parent() != path.parent()
    {
        return Err("deployment maintenance lock configuration is invalid".into());
    }
    #[cfg(unix)]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "deployment maintenance lock is unavailable".to_owned())?;
    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| "deployment maintenance lock is unavailable".to_owned())?;

    let metadata = file
        .metadata()
        .map_err(|_| "deployment maintenance lock identity is unverifiable".to_owned())?;
    if !metadata.is_file() {
        return Err("deployment maintenance lock identity is unverifiable".into());
    }
    #[cfg(unix)]
    if metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.dev() != expected_dev
        || metadata.ino() != expected_ino
    {
        return Err("deployment maintenance lock identity is unverifiable".into());
    }
    FileExt::try_lock_shared(&file).map_err(|_| "deployment maintenance is active".to_owned())?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|_| "deployment maintenance lock identity is unverifiable".to_owned())?;
    #[cfg(unix)]
    if !path_metadata.is_file()
        || path_metadata.uid() != expected_uid
        || path_metadata.mode() & 0o777 != 0o600
        || path_metadata.nlink() != 1
        || (path_metadata.dev(), path_metadata.ino()) != (metadata.dev(), metadata.ino())
    {
        return Err("deployment maintenance lock identity is unverifiable".into());
    }
    #[cfg(not(unix))]
    if !path_metadata.is_file() {
        return Err("deployment maintenance lock identity is unverifiable".into());
    }
    match fs::symlink_metadata(transaction_marker) {
        Ok(_) => return Err("deployment recovery is required".into()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err("deployment recovery state is unverifiable".into()),
    }
    Ok(RuntimeLock { _file: file })
}

pub fn acquire_packaged_runtime_lock() -> Result<Option<RuntimeLock>, String> {
    let Some(path) = option_env!("PAYGATE_DEPLOYMENT_RUNTIME_LOCK") else {
        return Ok(None);
    };
    let uid = option_env!("PAYGATE_DEPLOYMENT_RUNTIME_UID")
        .ok_or_else(|| "deployment maintenance lock configuration is incomplete".to_owned())?
        .parse::<u32>()
        .map_err(|_| "deployment maintenance lock configuration is invalid".to_owned())?;
    let dev = option_env!("PAYGATE_DEPLOYMENT_RUNTIME_LOCK_DEV")
        .ok_or_else(|| "deployment maintenance lock configuration is incomplete".to_owned())?
        .parse::<u64>()
        .map_err(|_| "deployment maintenance lock configuration is invalid".to_owned())?;
    let ino = option_env!("PAYGATE_DEPLOYMENT_RUNTIME_LOCK_INO")
        .ok_or_else(|| "deployment maintenance lock configuration is incomplete".to_owned())?
        .parse::<u64>()
        .map_err(|_| "deployment maintenance lock configuration is invalid".to_owned())?;
    let marker = option_env!("PAYGATE_DEPLOYMENT_TRANSACTION_MARKER")
        .ok_or_else(|| "deployment maintenance lock configuration is incomplete".to_owned())?;
    acquire_runtime_lock(Path::new(path), uid, dev, ino, Path::new(marker)).map(Some)
}
