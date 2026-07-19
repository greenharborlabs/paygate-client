use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use paygate::state::keyring::{
    CredentialSecretRecord, CredentialSecretStore, FallbackCoordinator, Mode0600FallbackStore,
    OsKeyringStore, SERVICE, SecretStoreError, account, lookup_accounts,
};

#[test]
fn identifiers_preserve_namespaced_and_legacy_default_lookup() {
    assert_eq!(SERVICE, "paygate-client.credentials");
    assert_eq!(account("team-a", "primary"), "team-a:primary");
    assert_eq!(
        lookup_accounts("default", "primary"),
        ["default:primary", "primary"]
    );
    assert_eq!(lookup_accounts("team-a", "primary"), ["team-a:primary"]);
}

fn python_file(action: &str, path: &Path, id: &str, secret: &str) {
    let script = r#"
import sys, types
class Unavailable:
    def get_password(self,*a): raise RuntimeError('unavailable')
    def set_password(self,*a): raise RuntimeError('unavailable')
    def delete_password(self,*a): raise RuntimeError('unavailable')
sys.modules['keyring'] = Unavailable()
from paygate_client.session_cache import CachedCredential, CredentialScope, FileCredentialCache
action,path,cid,secret=sys.argv[1:]
cache=FileCredentialCache(path, namespace='qualification')
scope=CredentialScope('request', 'example.test', 'svc', 'L402', 'test', 'policy', 'qualification')
if action == 'put': cache.put(CachedCredential(cid, scope, secret, 1))
elif action == 'assert':
    found=[x for x in cache.list() if x.credential_id == cid]
    assert len(found) == 1 and found[0].authorization == secret
elif action == 'delete': cache.delete(cid)
elif action == 'absent': assert all(x.credential_id != cid for x in cache.list())
"#;
    let status = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(action)
        .arg(path)
        .arg(id)
        .arg(secret)
        .status()
        .expect("run real Python FileCredentialCache");
    assert!(
        status.success(),
        "Python file-cache action failed: {action}"
    );
}

#[cfg(unix)]
fn assert_0600(path: &Path) {
    assert_eq!(
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777,
        0o600
    );
}

fn record(id: &str, secret: &str) -> CredentialSecretRecord {
    CredentialSecretRecord {
        namespace: "qualification".into(),
        credential_id: id.into(),
        authorization: secret.into(),
        request_key: "request".into(),
        origin_host: Some("example.test".into()),
        service: Some("svc".into()),
        protocol: "L402".into(),
        payer_backend: "test".into(),
        policy_hash: "policy".into(),
        created_at: 1,
    }
}

#[test]
#[cfg(unix)]
fn schema_v1_fallback_interoperates_in_both_language_directions() {
    let root = std::env::temp_dir().join(format!(
        "paygate-keyring-qualification-{}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("exclusive qualification root");

    let rust_path = root.join("rust-created.json");
    let rust_store = Mode0600FallbackStore::new(&rust_path);
    rust_store
        .put(&record("rust-creates", "rust-secret"))
        .unwrap();
    assert_0600(&rust_path);
    python_file("assert", &rust_path, "rust-creates", "rust-secret");
    python_file("delete", &rust_path, "rust-creates", "unused");
    assert_eq!(
        rust_store.get("qualification", "rust-creates").unwrap(),
        None
    );

    rust_store
        .put(&record("rust-deletes", "delete-secret"))
        .unwrap();
    rust_store.put(&record("unrelated", "keep-me")).unwrap();
    rust_store.delete("qualification", "rust-deletes").unwrap();
    assert_0600(&rust_path);
    python_file("absent", &rust_path, "rust-deletes", "unused");
    python_file("assert", &rust_path, "unrelated", "keep-me");
    assert!(
        rust_store
            .get("other-namespace", "unrelated")
            .unwrap()
            .is_none()
    );

    let path = root.join("python-created.json");
    let store = Mode0600FallbackStore::new(&path);

    let python_id = "python-writes";
    python_file("put", &path, python_id, "python-secret");
    assert_0600(&path);
    assert_eq!(
        store.get("qualification", python_id).unwrap().as_deref(),
        Some("python-secret")
    );
    store.delete("qualification", python_id).unwrap();
    assert_0600(&path);
    python_file("absent", &path, python_id, "unused");

    fs::remove_dir_all(root).expect("remove qualification data");
}

struct ClassifiedStore(Result<Option<String>, SecretStoreError>);

impl CredentialSecretStore for ClassifiedStore {
    fn get(&self, _: &str, _: &str) -> Result<Option<String>, SecretStoreError> {
        match &self.0 {
            Ok(value) => Ok(value.clone()),
            Err(SecretStoreError::BackendUnavailable) => Err(SecretStoreError::BackendUnavailable),
            Err(_) => Err(SecretStoreError::Storage),
        }
    }
    fn put(&self, _: &CredentialSecretRecord) -> Result<(), SecretStoreError> {
        match &self.0 {
            Ok(_) => Ok(()),
            Err(SecretStoreError::BackendUnavailable) => Err(SecretStoreError::BackendUnavailable),
            Err(_) => Err(SecretStoreError::Storage),
        }
    }
    fn delete(&self, _: &str, _: &str) -> Result<(), SecretStoreError> {
        Err(SecretStoreError::Storage)
    }
}

#[test]
fn coordinator_falls_back_only_for_classified_unavailability() {
    let unavailable = FallbackCoordinator {
        primary: ClassifiedStore(Err(SecretStoreError::BackendUnavailable)),
        fallback: ClassifiedStore(Ok(Some("fallback".into()))),
    };
    assert_eq!(
        unavailable.get("default", "id").unwrap().as_deref(),
        Some("fallback")
    );
    unavailable.put(&record("id", "secret")).unwrap();
    let closed = FallbackCoordinator {
        primary: ClassifiedStore(Err(SecretStoreError::Storage)),
        fallback: ClassifiedStore(Ok(Some("must-not-read".into()))),
    };
    assert!(closed.get("default", "id").is_err());
    assert!(closed.put(&record("id", "secret")).is_err());
}

#[test]
#[cfg(unix)]
fn fallback_fails_closed_on_duplicate_records_for_every_operation() {
    let root =
        std::env::temp_dir().join(format!("paygate-keyring-duplicates-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let path = root.join("credentials.json");
    let store = Mode0600FallbackStore::new(&path);
    store.put(&record("duplicate", "first")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let entries = value["credentials"].as_array_mut().unwrap();
    let duplicate = entries[0].clone();
    entries.push(duplicate);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    assert!(store.get("qualification", "duplicate").is_err());
    assert!(store.get("qualification", "different-id").is_err());
    assert!(store.put(&record("duplicate", "replacement")).is_err());
    assert!(store.delete("qualification", "duplicate").is_err());
    let after: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(after["credentials"].as_array().unwrap().len(), 2);
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "requires native OS keyring plus Python keyring==25.6.0"]
fn os_keyring_has_independent_bidirectional_and_legacy_probes() {
    let suffix = format!("wave2-{}", std::process::id());
    let py_id = format!("py-{suffix}");
    let rust_id = format!("rust-{suffix}");
    let legacy_id = format!("legacy-{suffix}");
    let store = OsKeyringStore;

    let python = |code: &str, account: &str, secret: &str| {
        let status = Command::new("python3")
            .arg("-c")
            .arg(code)
            .arg(SERVICE)
            .arg(account)
            .arg(secret)
            .status()
            .expect("Python keyring");
        assert!(status.success());
    };

    python(
        "import keyring,sys; keyring.set_password(*sys.argv[1:])",
        &account("qualification", &py_id),
        "python-secret",
    );
    assert_eq!(
        store.get("qualification", &py_id).unwrap().as_deref(),
        Some("python-secret")
    );
    store.delete("qualification", &py_id).unwrap();
    python(
        "import keyring,sys; assert keyring.get_password(sys.argv[1],sys.argv[2]) is None",
        &account("qualification", &py_id),
        "unused",
    );

    store.put(&record(&rust_id, "rust-secret")).unwrap();
    python(
        "import keyring,sys; assert keyring.get_password(sys.argv[1],sys.argv[2]) == sys.argv[3]; keyring.delete_password(sys.argv[1],sys.argv[2])",
        &account("qualification", &rust_id),
        "rust-secret",
    );
    assert_eq!(store.get("qualification", &rust_id).unwrap(), None);

    python(
        "import keyring,sys; keyring.set_password(*sys.argv[1:])",
        &legacy_id,
        "legacy-secret",
    );
    assert_eq!(
        store.get("default", &legacy_id).unwrap().as_deref(),
        Some("legacy-secret")
    );
    assert_eq!(store.get("qualification", &legacy_id).unwrap(), None);
    store.delete("default", &legacy_id).unwrap();
}

#[cfg(unix)]
#[test]
fn fallback_rejects_symlinks_and_wrong_permissions() {
    let root = std::env::temp_dir().join(format!("paygate-keyring-safety-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let real = root.join("real.json");
    fs::write(&real, b"{\"version\":1,\"credentials\":[]}").unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(
        Mode0600FallbackStore::new(&link)
            .get("default", "x")
            .is_err()
    );
    fs::set_permissions(&real, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        Mode0600FallbackStore::new(&real)
            .get("default", "x")
            .is_err()
    );
    fs::remove_dir_all(root).unwrap();
}
