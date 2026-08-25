//! Deployment-scoped maintenance lock for the packaged Rust runtime.

use fs4::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::io::AsRawFd;
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
    expected_identity: &str,
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
        || descriptor_identity(&file, &metadata)? != expected_identity
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

#[cfg(target_os = "macos")]
fn darwin_attribute(
    file: &File,
    common: libc::attrgroup_t,
    volume: libc::attrgroup_t,
    buffer: &mut [u8],
) -> Result<(), String> {
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: common,
        volattr: volume,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let result = unsafe {
        libc::fgetattrlist(
            file.as_raw_fd(),
            std::ptr::from_mut(&mut attributes).cast(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
        )
    };
    if result != 0 {
        return Err("deployment maintenance lock identity is unverifiable".into());
    }
    let returned = u32::from_ne_bytes(
        buffer[..4]
            .try_into()
            .map_err(|_| "deployment maintenance lock identity is unverifiable")?,
    );
    if returned as usize != buffer.len() {
        return Err("deployment maintenance lock identity is unverifiable".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn descriptor_identity(file: &File, _metadata: &fs::Metadata) -> Result<String, String> {
    let mut object = [0_u8; 12];
    darwin_attribute(file, libc::ATTR_CMN_OBJPERMANENTID, 0, &mut object)?;
    let object_number = u32::from_ne_bytes(
        object[4..8]
            .try_into()
            .map_err(|_| "deployment maintenance lock identity is unverifiable")?,
    );
    let generation = u32::from_ne_bytes(
        object[8..12]
            .try_into()
            .map_err(|_| "deployment maintenance lock identity is unverifiable")?,
    );
    let mut volume = [0_u8; 20];
    darwin_attribute(
        file,
        0,
        libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID,
        &mut volume,
    )?;
    let volume_uuid = &volume[4..20];
    if object_number == 0 || volume_uuid.iter().all(|value| *value == 0) {
        return Err("deployment maintenance lock identity is unverifiable".into());
    }
    let uuid = volume_uuid
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<String>();
    Ok(format!(
        "darwin-volume-object-v1:{uuid}:{object_number}:{generation}"
    ))
}

#[cfg(target_os = "linux")]
fn descriptor_identity(_file: &File, metadata: &fs::Metadata) -> Result<String, String> {
    Ok(format!(
        "linux-device-inode-v1:{}:{}",
        metadata.dev(),
        metadata.ino()
    ))
}

#[doc(hidden)]
#[allow(dead_code)]
pub fn identity_for_path(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "deployment maintenance lock identity is unverifiable".to_owned())?;
    #[cfg(not(unix))]
    let file = File::open(path)
        .map_err(|_| "deployment maintenance lock identity is unverifiable".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "deployment maintenance lock identity is unverifiable".to_owned())?;
    descriptor_identity(&file, &metadata)
}

pub fn acquire_packaged_runtime_lock() -> Result<Option<RuntimeLock>, String> {
    let Some(path) = option_env!("PAYGATE_DEPLOYMENT_RUNTIME_LOCK") else {
        return Ok(None);
    };
    let uid = option_env!("PAYGATE_DEPLOYMENT_RUNTIME_UID")
        .ok_or_else(|| "deployment maintenance lock configuration is incomplete".to_owned())?
        .parse::<u32>()
        .map_err(|_| "deployment maintenance lock configuration is invalid".to_owned())?;
    let identity = option_env!("PAYGATE_DEPLOYMENT_RUNTIME_LOCK_IDENTITY")
        .ok_or_else(|| "deployment maintenance lock configuration is incomplete".to_owned())?
        .to_owned();
    let marker = option_env!("PAYGATE_DEPLOYMENT_TRANSACTION_MARKER")
        .ok_or_else(|| "deployment maintenance lock configuration is incomplete".to_owned())?;
    acquire_runtime_lock(Path::new(path), uid, &identity, Path::new(marker)).map(Some)
}
