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
    let python = std::env::var("PAYGATE_QUALIFICATION_PYTHON")
        .expect("PAYGATE_QUALIFICATION_PYTHON must select the controlled Python interpreter");
    let status = Command::new(python)
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

struct NativeKeyringCleanup<S: CredentialSecretStore> {
    store: S,
    entries: Vec<(&'static str, String)>,
}

impl<S: CredentialSecretStore> NativeKeyringCleanup<S> {
    fn new(store: S, entries: Vec<(&'static str, String)>) -> Self {
        Self { store, entries }
    }
}

impl<S: CredentialSecretStore> Drop for NativeKeyringCleanup<S> {
    fn drop(&mut self) {
        // Best effort is deliberate: cleanup must never replace the test's original panic.
        for (namespace, credential_id) in &self.entries {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = self.store.delete(namespace, credential_id);
            }));
        }
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
fn native_keyring_cleanup_is_unwind_safe_and_best_effort() {
    use std::cell::RefCell;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::rc::Rc;

    struct RecordingStore(Rc<RefCell<Vec<(String, String)>>>);

    impl CredentialSecretStore for RecordingStore {
        fn get(&self, _: &str, _: &str) -> Result<Option<String>, SecretStoreError> {
            unreachable!()
        }

        fn put(&self, _: &CredentialSecretRecord) -> Result<(), SecretStoreError> {
            unreachable!()
        }

        fn delete(&self, namespace: &str, credential_id: &str) -> Result<(), SecretStoreError> {
            self.0
                .borrow_mut()
                .push((namespace.to_owned(), credential_id.to_owned()));
            if credential_id == "py-unique" {
                panic!("simulated cleanup panic");
            }
            Err(SecretStoreError::Storage)
        }
    }

    let calls = Rc::new(RefCell::new(Vec::new()));
    {
        let _cleanup = NativeKeyringCleanup::new(
            RecordingStore(Rc::clone(&calls)),
            vec![("qualification", "normal-unique".to_owned())],
        );
    }
    assert_eq!(
        calls.borrow().as_slice(),
        [("qualification".to_owned(), "normal-unique".to_owned())]
    );
    calls.borrow_mut().clear();

    let failure = catch_unwind(AssertUnwindSafe({
        let calls = Rc::clone(&calls);
        move || {
            let _cleanup = NativeKeyringCleanup::new(
                RecordingStore(calls),
                vec![
                    ("qualification", "py-unique".to_owned()),
                    ("qualification", "rust-unique".to_owned()),
                    ("default", "legacy-unique".to_owned()),
                ],
            );
            panic!("original qualification failure");
        }
    }));

    let failure = failure.expect_err("the original qualification panic must propagate");
    assert_eq!(
        *failure
            .downcast::<&'static str>()
            .expect("original panic payload"),
        "original qualification failure"
    );
    assert_eq!(
        calls.borrow().as_slice(),
        [
            ("qualification".to_owned(), "py-unique".to_owned()),
            ("qualification".to_owned(), "rust-unique".to_owned()),
            ("default".to_owned(), "legacy-unique".to_owned()),
        ]
    );
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
#[ignore = "requires controlled native OS keyring plus Python keyring==25.7.0"]
fn os_keyring_has_independent_bidirectional_and_legacy_probes() {
    assert_eq!(
        std::env::var("PAYGATE_QUALIFICATION_KEYRING_MODE").as_deref(),
        Ok("native"),
        "native OS-keyring qualification must be explicitly selected"
    );
    let suffix = format!("wave2-{}", std::process::id());
    let py_id = format!("py-{suffix}");
    let rust_id = format!("rust-{suffix}");
    let legacy_id = format!("legacy-{suffix}");
    let store = OsKeyringStore;
    let _cleanup = NativeKeyringCleanup::new(
        store,
        vec![
            ("qualification", py_id.clone()),
            ("qualification", rust_id.clone()),
            ("default", legacy_id.clone()),
        ],
    );

    let python_path = std::env::var("PAYGATE_QUALIFICATION_PYTHON").expect(
        "PAYGATE_QUALIFICATION_PYTHON must select Python with the reviewed keyring backend",
    );
    assert!(
        std::path::Path::new(&python_path).is_absolute(),
        "no ambient Python interpreter"
    );
    let preflight = Command::new(&python_path)
        .arg("-c")
        .arg(r#"import importlib.metadata,keyring,sys; assert importlib.metadata.version("keyring") == '25.7.0'; n=(keyring.get_keyring().__class__.__module__+'.'+keyring.get_keyring().__class__.__name__).lower(); assert not any(x in n for x in ('null','file','chainer','fail')); assert ('secretservice' in n) if sys.platform.startswith('linux') else ('macos' in n or 'keychain' in n)"#)
        .status().expect("verify controlled native keyring");
    assert!(
        preflight.success(),
        "controlled interpreter must expose the native OS backend"
    );
    let python = |code: &str, account: &str, secret: &str| {
        let status = Command::new(&python_path)
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
