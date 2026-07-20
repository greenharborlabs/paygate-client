//! Locked, atomic schema-v1 credential cache compatible with the Python client.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs4::FileExt;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::keyring::{
    CredentialSecretRecord, CredentialSecretStore, FallbackCoordinator, Mode0600FallbackStore,
    OsKeyringStore,
};
use super::{DEFAULT_NAMESPACE, normalize_namespace};

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("credential cache is corrupt")]
    Corrupt,
    #[error("credential cache I/O failed")]
    Io,
    #[error("credential cache file is unsafe")]
    Unsafe,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialScope {
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub request_key: String,
    pub origin_host: Option<String>,
    pub service: Option<String>,
    pub protocol: String,
    pub payer_backend: String,
    pub policy_hash: String,
}
fn default_namespace() -> String {
    DEFAULT_NAMESPACE.into()
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedCredential {
    #[serde(rename = "id")]
    pub credential_id: String,
    pub scope: CredentialScope,
    #[serde(deserialize_with = "authorization_or_keyring_marker")]
    pub authorization: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub max_uses: Option<u64>,
    #[serde(default)]
    pub use_count: u64,
    pub last_success_at: Option<i64>,
    pub last_rejected_at: Option<i64>,
    pub payment_hash: Option<String>,
    pub challenge_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_storage: Option<String>,
}
fn authorization_or_keyring_marker<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}
impl CachedCredential {
    pub fn usable(&self, now: i64) -> bool {
        self.expires_at.is_none_or(|v| v > now)
            && self.max_uses.is_none_or(|v| self.use_count < v)
            && self.last_rejected_at.is_none()
    }
}
#[derive(Serialize, Deserialize)]
struct CacheFile {
    version: u64,
    credentials: Vec<CachedCredential>,
}
#[derive(Clone, Debug)]
pub struct FileCredentialCache {
    pub path: PathBuf,
    pub namespace: String,
}
impl FileCredentialCache {
    pub fn new(path: impl Into<PathBuf>, namespace: Option<&str>) -> Result<Self, CacheError> {
        Ok(Self {
            path: crate::config::expand_path(path.into()),
            namespace: normalize_namespace(namespace).map_err(|_| CacheError::Corrupt)?,
        })
    }
    pub fn default_path(namespace: Option<&str>) -> Result<PathBuf, CacheError> {
        let n = normalize_namespace(namespace).map_err(|_| CacheError::Corrupt)?;
        Ok(if n == DEFAULT_NAMESPACE {
            crate::config::expand_path("~/.config/paygate-client/credentials.json")
        } else {
            crate::config::expand_path("~/.config/paygate-client/profiles")
                .join(n)
                .join("credentials.json")
        })
    }
    pub fn list(&self) -> Result<Vec<CachedCredential>, CacheError> {
        self.with_lock(|| self.load())
    }
    pub fn get(
        &self,
        scope: &CredentialScope,
        now: i64,
    ) -> Result<Option<CachedCredential>, CacheError> {
        let target = scoped(scope, &self.namespace);
        Ok(self
            .list()?
            .into_iter()
            .find(|c| c.scope == target && c.usable(now)))
    }
    pub fn put(&self, mut credential: CachedCredential) -> Result<(), CacheError> {
        credential.scope.namespace = self.namespace.clone();
        self.with_lock(|| {
            let mut all = self.load()?;
            all.retain(|v| v.credential_id != credential.credential_id);
            all.push(credential);
            self.save(&all)
        })
    }
    pub fn delete(&self, id: &str) -> Result<(), CacheError> {
        self.with_lock(|| {
            let mut all = self.load()?;
            all.retain(|v| v.credential_id != id);
            self.secret_store()
                .delete(&self.namespace, id)
                .map_err(|_| CacheError::Io)?;
            self.save(&all)
        })
    }
    pub fn mark_success(&self, id: &str, now: i64) -> Result<(), CacheError> {
        self.update(id, |c| {
            c.use_count += 1;
            c.last_success_at = Some(now);
        })
    }
    pub fn mark_rejected(&self, id: &str, now: i64) -> Result<(), CacheError> {
        self.update(id, |c| c.last_rejected_at = Some(now))
    }
    fn update(&self, id: &str, f: impl FnOnce(&mut CachedCredential)) -> Result<(), CacheError> {
        self.with_lock(|| {
            let mut all = self.load()?;
            if let Some(c) = all.iter_mut().find(|v| v.credential_id == id) {
                f(c);
                self.save(&all)?;
            }
            Ok(())
        })
    }
    fn load(&self) -> Result<Vec<CachedCredential>, CacheError> {
        // Open and validate the same descriptor that is read.  Checking a
        // path and reopening it would let an attacker replace it in between.
        let Some(mut state) = open_safe_read(&self.path)? else {
            return Ok(vec![]);
        };
        let mut bytes = Vec::new();
        state.read_to_end(&mut bytes).map_err(|_| CacheError::Io)?;
        let file: CacheFile = serde_json::from_slice(&bytes).map_err(|_| CacheError::Corrupt)?;
        if file.version != 1 {
            return Err(CacheError::Corrupt);
        };
        let mut ids = std::collections::BTreeSet::new();
        for c in &file.credentials {
            if c.credential_id.is_empty()
                || !ids.insert((c.scope.namespace.clone(), c.credential_id.clone()))
            {
                return Err(CacheError::Corrupt);
            }
        }
        // Python schema-v1 keyring entries intentionally contain a null
        // authorization.  They are valid metadata, but never usable until a
        // secret is recovered through the classified fallback coordinator.
        let store = self.secret_store();
        Ok(file
            .credentials
            .into_iter()
            .filter_map(|mut credential| {
                if credential.authorization.is_empty()
                    && credential.secret_storage.as_deref() == Some("keyring")
                {
                    credential.authorization = store
                        .get(&credential.scope.namespace, &credential.credential_id)
                        .ok()
                        .flatten()?;
                }
                (!credential.authorization.is_empty()).then_some(credential)
            })
            .collect())
    }
    fn save(&self, values: &[CachedCredential]) -> Result<(), CacheError> {
        let store = self.secret_store();
        for credential in values {
            store
                .put(&secret_record(credential))
                .map_err(|_| CacheError::Io)?;
        }
        let mut value = serde_json::to_value(&CacheFile {
            version: 1,
            credentials: values.to_vec(),
        })
        .map_err(|_| CacheError::Corrupt)?;
        // Persist metadata only. Authorization is delegated to the keyring
        // coordinator, including the 0600 fallback when the OS backend is
        // explicitly unavailable.
        if let Some(entries) = value
            .get_mut("credentials")
            .and_then(serde_json::Value::as_array_mut)
        {
            for entry in entries {
                entry["authorization"] = serde_json::Value::Null;
                entry["secretStorage"] = serde_json::Value::String("keyring".into());
            }
        }
        let bytes =
            crate::serialization::to_pretty_json(&value).map_err(|_| CacheError::Corrupt)?;
        atomic_write(&self.path, &bytes)
    }
    fn secret_store(&self) -> FallbackCoordinator<OsKeyringStore, Mode0600FallbackStore> {
        FallbackCoordinator {
            primary: OsKeyringStore,
            fallback: Mode0600FallbackStore::new(self.path.with_extension("keyring.json")),
        }
    }
    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T, CacheError>) -> Result<T, CacheError> {
        let lock = self.path.with_extension(
            format!(
                "{}lock",
                self.path
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| format!("{x}. "))
                    .unwrap_or_default()
            )
            .replace(' ', ""),
        );
        if let Some(p) = lock.parent() {
            fs::create_dir_all(p).map_err(|_| CacheError::Io)?
        };
        let file = open_safe(&lock, true)?;
        FileExt::lock(&file).map_err(|_| CacheError::Io)?;
        let r = f();
        let _ = FileExt::unlock(&file);
        r
    }
}
fn secret_record(c: &CachedCredential) -> CredentialSecretRecord {
    CredentialSecretRecord {
        namespace: c.scope.namespace.clone(),
        credential_id: c.credential_id.clone(),
        authorization: c.authorization.clone(),
        request_key: c.scope.request_key.clone(),
        origin_host: c.scope.origin_host.clone(),
        service: c.scope.service.clone(),
        protocol: c.scope.protocol.clone(),
        payer_backend: c.scope.payer_backend.clone(),
        policy_hash: c.scope.policy_hash.clone(),
        created_at: c.created_at,
    }
}
fn scoped(scope: &CredentialScope, namespace: &str) -> CredentialScope {
    let mut out = scope.clone();
    out.namespace = namespace.into();
    out
}
pub fn build_request_key(method: &str, url: &str, body: Option<&[u8]>) -> String {
    let mut h = Sha256::new();
    h.update(method.to_uppercase());
    h.update([0]);
    h.update(url);
    h.update([0]);
    if let Some(body) = body {
        h.update(body)
    };
    hex::encode(h.finalize())
}
pub fn build_credential_id(scope: &CredentialScope, authorization: &str) -> String {
    let mut h = Sha256::new();
    h.update(&scope.namespace);
    h.update([0]);
    h.update(&scope.request_key);
    h.update([0]);
    h.update(authorization);
    hex::encode(h.finalize())[..24].into()
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|_| CacheError::Io)?;
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|v| v.to_str()).unwrap_or("state"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let write = (|| {
        #[cfg(unix)]
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| CacheError::Io)?;
        #[cfg(not(unix))]
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|_| CacheError::Io)?;
        f.write_all(bytes).map_err(|_| CacheError::Io)?;
        f.sync_all().map_err(|_| CacheError::Io)?;
        drop(f);
        fs::rename(&tmp, path).map_err(|_| CacheError::Io)?;
        File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|_| CacheError::Io)
    })();
    if write.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|_| CacheError::Io)?;
    Ok(())
}
fn open_safe(path: &Path, create: bool) -> Result<File, CacheError> {
    #[cfg(unix)]
    {
        if let Ok(m) = fs::symlink_metadata(path) {
            if m.file_type().is_symlink() || !m.file_type().is_file() {
                return Err(CacheError::Unsafe);
            }
        }
        let mut o = OpenOptions::new();
        o.read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600);
        if create {
            o.create(true);
        };
        let f = o.open(path).map_err(|_| CacheError::Io)?;
        if f.metadata()
            .map_err(|_| CacheError::Io)?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(CacheError::Unsafe);
        };
        Ok(f)
    }
    #[cfg(not(unix))]
    {
        let _ = create;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|_| CacheError::Io)
    }
}
fn open_safe_read(path: &Path) -> Result<Option<File>, CacheError> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CacheError::Io),
        };
        let metadata = file.metadata().map_err(|_| CacheError::Io)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(CacheError::Unsafe);
        }
        Ok(Some(file))
    }
    #[cfg(not(unix))]
    {
        let file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CacheError::Io),
        };
        if !file.metadata().map_err(|_| CacheError::Io)?.file_type().is_file() {
            return Err(CacheError::Unsafe);
        }
        Ok(Some(file))
    }
}
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
