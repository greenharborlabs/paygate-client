//! Cross-language credential-secret storage boundary.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fs4::FileExt;
use serde_json::Value;
use thiserror::Error;

pub const SERVICE: &str = "paygate-client.credentials";

pub fn account(namespace: &str, credential_id: &str) -> String {
    format!("{namespace}:{credential_id}")
}

/// Ordered lookup accounts. Only the default namespace may read the legacy account.
pub fn lookup_accounts(namespace: &str, credential_id: &str) -> Vec<String> {
    let mut accounts = vec![account(namespace, credential_id)];
    if namespace == "default" {
        accounts.push(credential_id.to_owned());
    }
    accounts
}

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("credential backend is unavailable")]
    BackendUnavailable,
    #[error("credential was not found")]
    NotFound,
    #[error("credential storage failed closed")]
    Storage,
    #[error("credential file is malformed")]
    Malformed,
    #[error("credential file is unsafe")]
    UnsafeFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSecretRecord {
    pub namespace: String,
    pub credential_id: String,
    pub authorization: String,
    pub request_key: String,
    pub origin_host: Option<String>,
    pub service: Option<String>,
    pub protocol: String,
    pub payer_backend: String,
    pub policy_hash: String,
    pub created_at: i64,
}

pub trait CredentialSecretStore {
    fn get(&self, namespace: &str, credential_id: &str)
    -> Result<Option<String>, SecretStoreError>;
    fn put(&self, record: &CredentialSecretRecord) -> Result<(), SecretStoreError>;
    fn delete(&self, namespace: &str, credential_id: &str) -> Result<(), SecretStoreError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeyringStore;

impl CredentialSecretStore for OsKeyringStore {
    fn get(
        &self,
        namespace: &str,
        credential_id: &str,
    ) -> Result<Option<String>, SecretStoreError> {
        for item in lookup_accounts(namespace, credential_id) {
            let entry = keyring::Entry::new(SERVICE, &item).map_err(classify_keyring)?;
            match entry.get_password() {
                Ok(secret) => return Ok(Some(secret)),
                Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(classify_keyring(error)),
            }
        }
        Ok(None)
    }

    fn put(&self, record: &CredentialSecretRecord) -> Result<(), SecretStoreError> {
        keyring::Entry::new(SERVICE, &account(&record.namespace, &record.credential_id))
            .map_err(classify_keyring)?
            .set_password(&record.authorization)
            .map_err(classify_keyring)
    }

    fn delete(&self, namespace: &str, credential_id: &str) -> Result<(), SecretStoreError> {
        // Legacy deletion is deliberately default-only, matching legacy lookup.
        for item in lookup_accounts(namespace, credential_id) {
            let entry = keyring::Entry::new(SERVICE, &item).map_err(classify_keyring)?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(error) => return Err(classify_keyring(error)),
            }
        }
        Ok(())
    }
}

fn classify_keyring(error: keyring::Error) -> SecretStoreError {
    match error {
        keyring::Error::NoDefaultStore | keyring::Error::NotSupportedByStore(_) => {
            SecretStoreError::BackendUnavailable
        }
        keyring::Error::NoEntry => SecretStoreError::NotFound,
        // In particular, NoStorageAccess (locked/permission denied), malformed data, and
        // ambiguous entries fail closed and never select the plaintext fallback.
        _ => SecretStoreError::Storage,
    }
}

#[derive(Debug, Clone)]
pub struct Mode0600FallbackStore {
    path: PathBuf,
}

impl Mode0600FallbackStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn with_locked_file<T>(
        &self,
        create_data: bool,
        operation: impl FnOnce(Option<&mut File>) -> Result<T, SecretStoreError>,
    ) -> Result<T, SecretStoreError> {
        let lock_path = PathBuf::from(format!("{}.lock", self.path.display()));
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent).map_err(|_| SecretStoreError::Storage)?;
        }
        let lock = safe_open(&lock_path, true)?;
        FileExt::lock(&lock).map_err(|_| SecretStoreError::Storage)?;
        let mut data = if self.path.exists() || create_data {
            Some(safe_open(&self.path, create_data)?)
        } else {
            None
        };
        let result = operation(data.as_mut());
        let unlock = FileExt::unlock(&lock).map_err(|_| SecretStoreError::Storage);
        match result {
            Ok(value) => unlock.map(|()| value),
            Err(error) => Err(error),
        }
    }

    fn put_record(&self, record: &CredentialSecretRecord) -> Result<(), SecretStoreError> {
        self.with_locked_file(true, |file| {
            let file = file.ok_or(SecretStoreError::Storage)?;
            let mut root = read_schema_or_empty(file)?;
            let entries = root
                .get_mut("credentials")
                .and_then(Value::as_array_mut)
                .ok_or(SecretStoreError::Malformed)?;
            let matches = matching_indexes(entries, &record.namespace, &record.credential_id)?;
            if matches.len() > 1 {
                return Err(SecretStoreError::Malformed);
            }
            let encoded = encode_record(record);
            if let Some(index) = matches.first().copied() {
                entries[index] = encoded;
            } else {
                entries.push(encoded);
            }
            write_schema(file, &self.path, &root)
        })
    }
}

impl CredentialSecretStore for Mode0600FallbackStore {
    fn get(
        &self,
        namespace: &str,
        credential_id: &str,
    ) -> Result<Option<String>, SecretStoreError> {
        self.with_locked_file(false, |file| {
            let Some(file) = file else { return Ok(None) };
            let root = read_schema(file)?;
            let entries = root
                .get("credentials")
                .and_then(Value::as_array)
                .ok_or(SecretStoreError::Malformed)?;
            let matches = matching_indexes(entries, namespace, credential_id)?;
            if matches.len() > 1 {
                return Err(SecretStoreError::Malformed);
            }
            let Some(index) = matches.first().copied() else {
                return Ok(None);
            };
            match entries[index].get("authorization") {
                Some(Value::String(secret)) => Ok(Some(secret.clone())),
                _ => Err(SecretStoreError::Malformed),
            }
        })
    }

    fn put(&self, record: &CredentialSecretRecord) -> Result<(), SecretStoreError> {
        self.put_record(record)
    }

    fn delete(&self, namespace: &str, credential_id: &str) -> Result<(), SecretStoreError> {
        self.with_locked_file(false, |file| {
            let file = file.ok_or(SecretStoreError::NotFound)?;
            let mut root = read_schema(file)?;
            let entries = root
                .get_mut("credentials")
                .and_then(Value::as_array_mut)
                .ok_or(SecretStoreError::Malformed)?;
            let matches = matching_indexes(entries, namespace, credential_id)?;
            if matches.len() > 1 {
                return Err(SecretStoreError::Malformed);
            }
            let index = matches.first().copied().ok_or(SecretStoreError::NotFound)?;
            entries.remove(index);
            write_schema(file, &self.path, &root)
        })
    }
}

/// Select fallback only for an explicitly classified unavailable backend.
pub struct FallbackCoordinator<P, F> {
    pub primary: P,
    pub fallback: F,
}

impl<P: CredentialSecretStore, F: CredentialSecretStore> CredentialSecretStore
    for FallbackCoordinator<P, F>
{
    fn get(
        &self,
        namespace: &str,
        credential_id: &str,
    ) -> Result<Option<String>, SecretStoreError> {
        match self.primary.get(namespace, credential_id) {
            Err(SecretStoreError::BackendUnavailable) => {
                self.fallback.get(namespace, credential_id)
            }
            result => result,
        }
    }
    fn put(&self, record: &CredentialSecretRecord) -> Result<(), SecretStoreError> {
        match self.primary.put(record) {
            Err(SecretStoreError::BackendUnavailable) => self.fallback.put(record),
            result => result,
        }
    }
    fn delete(&self, namespace: &str, credential_id: &str) -> Result<(), SecretStoreError> {
        match self.primary.delete(namespace, credential_id) {
            Err(SecretStoreError::BackendUnavailable) => {
                self.fallback.delete(namespace, credential_id)
            }
            result => result,
        }
    }
}

fn read_schema(file: &mut File) -> Result<Value, SecretStoreError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SecretStoreError::Storage)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| SecretStoreError::Storage)?;
    let root: Value = serde_json::from_slice(&bytes).map_err(|_| SecretStoreError::Malformed)?;
    if root.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(SecretStoreError::Malformed);
    }
    Ok(root)
}

fn read_schema_or_empty(file: &mut File) -> Result<Value, SecretStoreError> {
    if file
        .metadata()
        .map_err(|_| SecretStoreError::Storage)?
        .len()
        == 0
    {
        Ok(serde_json::json!({"version": 1, "credentials": []}))
    } else {
        read_schema(file)
    }
}

fn matching_indexes(
    entries: &[Value],
    namespace: &str,
    credential_id: &str,
) -> Result<Vec<usize>, SecretStoreError> {
    let mut matches = Vec::new();
    let mut identities = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        let object = entry.as_object().ok_or(SecretStoreError::Malformed)?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or(SecretStoreError::Malformed)?;
        let scope = object
            .get("scope")
            .and_then(Value::as_object)
            .ok_or(SecretStoreError::Malformed)?;
        let entry_namespace = scope
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or("default");
        if !identities.insert((entry_namespace, id)) {
            return Err(SecretStoreError::Malformed);
        }
        if id == credential_id && entry_namespace == namespace {
            matches.push(index);
        }
    }
    Ok(matches)
}

fn encode_record(record: &CredentialSecretRecord) -> Value {
    serde_json::json!({
        "id": record.credential_id,
        "scope": {
            "namespace": record.namespace,
            "requestKey": record.request_key,
            "originHost": record.origin_host,
            "service": record.service,
            "protocol": record.protocol,
            "payerBackend": record.payer_backend,
            "policyHash": record.policy_hash,
        },
        "authorization": record.authorization,
        "secretStorage": "file",
        "createdAt": record.created_at,
        "expiresAt": null,
        "maxUses": null,
        "useCount": 0,
        "lastSuccessAt": null,
        "lastRejectedAt": null,
        "paymentHash": null,
        "challengeId": null,
    })
}

fn write_schema(file: &mut File, path: &Path, root: &Value) -> Result<(), SecretStoreError> {
    let mut bytes = serde_json::to_vec_pretty(root).map_err(|_| SecretStoreError::Malformed)?;
    bytes.push(b'\n');
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SecretStoreError::Storage)?;
    file.set_len(0).map_err(|_| SecretStoreError::Storage)?;
    file.write_all(&bytes)
        .map_err(|_| SecretStoreError::Storage)?;
    file.flush().map_err(|_| SecretStoreError::Storage)?;
    file.sync_all().map_err(|_| SecretStoreError::Storage)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| SecretStoreError::Storage)?;
    verify_file(file)
}

#[cfg(unix)]
fn safe_open(path: &Path, create: bool) -> Result<File, SecretStoreError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err(SecretStoreError::UnsafeFile);
        }
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600);
    if create {
        options.create(true);
    }
    let file = options.open(path).map_err(|_| SecretStoreError::Storage)?;
    verify_file(&file)?;
    Ok(file)
}

#[cfg(unix)]
fn verify_file(file: &File) -> Result<(), SecretStoreError> {
    let meta = file.metadata().map_err(|_| SecretStoreError::Storage)?;
    if !meta.file_type().is_file() || meta.mode() & 0o777 != 0o600 {
        return Err(SecretStoreError::UnsafeFile);
    }
    Ok(())
}
