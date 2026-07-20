#[cfg(unix)]
use std::ffi::CString;
use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use clap::Parser;
use fs4::{FileExt, TryLockError};
use paygate::cli::Cli;
use paygate::config::expand_path;
use paygate::state::cache::{CachedCredential, FileCredentialCache};
use paygate::state::ledger::{DailySpendLedger, LedgerError};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "paygate-wave3-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn wait_until_marker(path: &Path, expected: &[u8], children: &mut [&mut Child]) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while fs::read(path).ok().as_deref() != Some(expected) {
        for child in children.iter_mut() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("ledger worker exited before contention evidence: {status}");
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("ledger worker did not exit after the parent released the lock");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn filesystem_boundaries_expand_home_and_preserve_reservations() {
    let expected = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
    assert_eq!(expand_path("~/paygate-test"), expected.join("paygate-test"));
    assert!(
        FileCredentialCache::default_path(None)
            .unwrap()
            .starts_with(&expected)
    );
    assert!(
        DailySpendLedger::default_path(None)
            .unwrap()
            .starts_with(&expected)
    );
}

#[test]
#[cfg(unix)]
fn python_keyring_metadata_is_valid_but_unusable_without_a_secret() {
    let root = std::env::temp_dir().join(format!("paygate-wave3-cache-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let path = root.join("credentials.json");
    fs::write(&path, br#"{"version":1,"credentials":[{"id":"missing-secret","scope":{"namespace":"default","requestKey":"r","originHost":null,"service":null,"protocol":"Payment","payerBackend":"test-mode","policyHash":"p"},"authorization":null,"createdAt":1,"expiresAt":null,"maxUses":null,"useCount":0,"lastSuccessAt":null,"lastRejectedAt":null,"paymentHash":null,"challengeId":null,"secretStorage":"keyring"}]}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let cache = FileCredentialCache::new(&path, None).unwrap();
    assert!(cache.list().is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn python_file_backed_credential_is_readable_with_all_public_metadata() {
    let root = std::env::temp_dir().join(format!(
        "paygate-wave3-python-cache-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("credentials.json");
    fs::write(&path, br#"{"version":1,"credentials":[{"id":"python-credential","scope":{"namespace":"default","requestKey":"request","originHost":"example.test","service":"svc","protocol":"L402","payerBackend":"test-mode","policyHash":"policy"},"authorization":"L402 python-secret","createdAt":1,"expiresAt":2,"maxUses":3,"useCount":1,"lastSuccessAt":4,"lastRejectedAt":null,"paymentHash":"hash","challengeId":"challenge"}]}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let credentials = FileCredentialCache::new(&path, None)
        .unwrap()
        .list()
        .unwrap();
    assert_eq!(credentials.len(), 1);
    let credential = &credentials[0];
    assert_eq!(credential.authorization, "L402 python-secret");
    assert_eq!(credential.max_uses, Some(3));
    assert_eq!(credential.last_success_at, Some(4));
    assert_eq!(credential.payment_hash.as_deref(), Some("hash"));
    assert_eq!(credential.challenge_id.as_deref(), Some("challenge"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_compile_contract_preserves_backend_json_flags() {
    Cli::try_parse_from([
        "paygate",
        "backend",
        "doctor",
        "--config",
        "config.yaml",
        "--json",
    ])
    .expect("doctor --json remains accepted");
    Cli::try_parse_from([
        "paygate",
        "backend",
        "pay-invoice",
        "lnbc1example",
        "--config",
        "config.yaml",
        "--max-fee-sats",
        "1",
        "--json",
    ])
    .expect("pay-invoice --json remains accepted");
}

#[test]
#[cfg(unix)]
fn unsafe_symlink_state_is_rejected_without_following_it() {
    let root = std::env::temp_dir().join(format!(
        "paygate-wave3-unsafe-state-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let target = root.join("target.json");
    fs::write(&target, b"{}").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

    let cache_path = root.join("credentials.json");
    symlink(&target, &cache_path).unwrap();
    assert!(
        FileCredentialCache::new(&cache_path, None)
            .unwrap()
            .list()
            .is_err()
    );

    let ledger_path = root.join("ledger.json");
    symlink(&target, &ledger_path).unwrap();
    assert!(DailySpendLedger::new(&ledger_path).spent_today().is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[cfg(unix)]
fn corrupt_cache_and_ledger_state_is_rejected_without_panics_or_silent_reset() {
    let root = TestDir::new("corruption");

    let cache_cases: &[(&str, &[u8])] = &[
        ("truncated", br#"{"version":1,"credentials":["#),
        ("version", br#"{"version":2,"credentials":[]}"#),
        (
            "schema",
            br#"{"version":1,"credentials":{"secret":"do-not-leak"}}"#,
        ),
    ];
    for (name, bytes) in cache_cases {
        let path = root.path().join(format!("cache-{name}.json"));
        write_private(&path, bytes);
        let error = FileCredentialCache::new(&path, None)
            .unwrap()
            .list()
            .expect_err("corrupt cache state must fail closed");
        assert!(!error.to_string().contains("do-not-leak"));
        assert_eq!(fs::read(&path).unwrap(), *bytes, "{name} cache was reset");
    }

    let ledger_cases: &[(&str, &[u8])] = &[
        ("truncated", br#"{"2026-07-19":{"committed_sats":0"#),
        ("schema", br#"{"version":2}"#),
        (
            "overflow",
            br#"{"2026-07-19":{"committed_sats":0,"reservations":{"first":18446744073709551615,"second":1}}}"#,
        ),
    ];
    for (name, bytes) in ledger_cases {
        let path = root.path().join(format!("ledger-{name}.json"));
        write_private(&path, bytes);
        let error = DailySpendLedger::new(&path)
            .spent_on("2026-07-19")
            .expect_err("corrupt ledger state must fail closed");
        assert!(!error.to_string().contains("do-not-leak"));
        assert_eq!(fs::read(&path).unwrap(), *bytes, "{name} ledger was reset");
    }
}

#[test]
#[cfg(unix)]
fn failed_atomic_write_preserves_prior_valid_ledger_bytes() {
    let root = TestDir::new("atomic-failure");
    let root_c = CString::new(root.path().as_os_str().as_bytes()).unwrap();
    let name_max = unsafe { libc::pathconf(root_c.as_ptr(), libc::_PC_NAME_MAX) };
    assert!(name_max > 32, "filesystem must report a usable NAME_MAX");

    // The state name and its `.lock` sibling fit, but the atomic temp name
    // necessarily exceeds NAME_MAX. This injects failure before rename without
    // permissions, timing, environment variables, or process-global state.
    let state_name = "l".repeat(name_max as usize - 6);
    let path = root.path().join(state_name);
    let prior = br#"{"2040-01-02":{"committed_sats":7,"reservations":{}}}"#;
    write_private(&path, prior);

    let error = DailySpendLedger::new(&path)
        .reserve(1, 100)
        .expect_err("overlong atomic temp path must fail before replacement");
    assert!(matches!(error, LedgerError::Io));
    let after = fs::read(&path).unwrap();
    assert_eq!(after, prior, "failed atomic write replaced prior state");
    let decoded: serde_json::Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(decoded["2040-01-02"]["committed_sats"], 7);

    // Move the exact preserved inode to a component length that permits the
    // ledger's read-and-rewrite contract, then prove public-interface readability.
    let readable_path = root.path().join("preserved-ledger.json");
    fs::rename(&path, &readable_path).unwrap();
    assert_eq!(
        DailySpendLedger::new(readable_path)
            .spent_on("2040-01-02")
            .unwrap(),
        7
    );
}

#[test]
#[cfg(unix)]
fn cross_process_ledger_worker() {
    let Some(path_value) = std::env::var_os("PAYGATE_WAVE3_LEDGER_WORKER_PATH") else {
        return;
    };
    let path = PathBuf::from(path_value);
    let ready = PathBuf::from(
        std::env::var_os("PAYGATE_WAVE3_LEDGER_WORKER_READY")
            .expect("worker ready path is required"),
    );

    let lock_path = path.with_extension("json.lock");
    let contention_probe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    match FileExt::try_lock(&contention_probe) {
        Err(TryLockError::WouldBlock) => fs::write(ready, b"CONTENDED").unwrap(),
        Ok(()) => {
            FileExt::unlock(&contention_probe).unwrap();
            panic!("worker acquired lock before observing parent contention");
        }
        Err(TryLockError::Error(error)) => panic!("worker contention probe failed: {error}"),
    }
    drop(contention_probe);

    match DailySpendLedger::new(path).reserve(20, 20) {
        Ok(mut reservation) => {
            reservation.commit().unwrap();
            println!("WORKER:COMMITTED");
        }
        Err(LedgerError::BudgetExceeded) => println!("WORKER:BUDGET_EXCEEDED"),
        Err(error) => panic!("unexpected ledger worker failure: {error}"),
    }
}

#[test]
#[cfg(unix)]
fn separate_processes_contend_for_exclusive_budget_ownership() {
    let root = TestDir::new("process-contention");
    let ledger_path = root.path().join("ledger.json");
    let lock_path = ledger_path.with_extension("json.lock");
    let held_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&lock_path)
        .unwrap();
    FileExt::lock(&held_lock).unwrap();

    let executable = std::env::current_exe().unwrap();
    let ready_a = root.path().join("worker-a.ready");
    let ready_b = root.path().join("worker-b.ready");
    let spawn_worker = |ready: &Path| {
        Command::new(&executable)
            .args(["--exact", "cross_process_ledger_worker", "--nocapture"])
            .env("PAYGATE_WAVE3_LEDGER_WORKER_PATH", &ledger_path)
            .env("PAYGATE_WAVE3_LEDGER_WORKER_READY", ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let mut child_a = spawn_worker(&ready_a);
    let mut child_b = spawn_worker(&ready_b);

    wait_until_marker(&ready_a, b"CONTENDED", &mut [&mut child_a, &mut child_b]);
    wait_until_marker(&ready_b, b"CONTENDED", &mut [&mut child_a, &mut child_b]);
    assert!(child_a.try_wait().unwrap().is_none());
    assert!(child_b.try_wait().unwrap().is_none());
    FileExt::unlock(&held_lock).unwrap();

    let outputs = [wait_for_child(child_a), wait_for_child(child_b)];
    let mut committed = 0;
    let mut rejected = 0;
    for output in outputs {
        assert!(
            output.status.success(),
            "worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        committed += usize::from(stdout.contains("WORKER:COMMITTED"));
        rejected += usize::from(stdout.contains("WORKER:BUDGET_EXCEEDED"));
    }
    assert_eq!((committed, rejected), (1, 1));

    let ledger = DailySpendLedger::new(&ledger_path);
    assert_eq!(ledger.spent_today().unwrap(), 20);
    let final_state: serde_json::Value =
        serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
    let entries = final_state.as_object().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = entries.values().next().unwrap();
    assert_eq!(entry["committed_sats"], 20);
    assert_eq!(entry["reservations"], serde_json::json!({}));
}

#[test]
#[cfg(unix)]
fn table_driven_cache_variants_preserve_rust_read_semantics() {
    let root = TestDir::new("python-cache-properties");
    let fixtures = [
        serde_json::json!({
            "version": 1,
            "credentials": [{
                "id": "active",
                "scope": {
                    "namespace": "default", "requestKey": "request-a",
                    "originHost": null, "service": null, "protocol": "Payment",
                    "payerBackend": "test-mode", "policyHash": "policy-a"
                },
                "authorization": "Payment fixture-a", "createdAt": 0,
                "expiresAt": null, "maxUses": null, "useCount": 0,
                "lastSuccessAt": null, "lastRejectedAt": null,
                "paymentHash": null, "challengeId": null, "secretStorage": "file"
            }]
        }),
        serde_json::json!({
            "credentials": [{
                "authorization": "L402 fixture-b", "challengeId": "challenge-b",
                "createdAt": 50, "expiresAt": 200, "id": "exhausted",
                "lastRejectedAt": null, "lastSuccessAt": 80, "maxUses": 2,
                "paymentHash": "hash-b",
                "scope": {
                    "namespace": "default", "originHost": "example.test:443",
                    "payerBackend": "test-mode", "policyHash": "policy-b",
                    "protocol": "L402", "requestKey": "request-b", "service": "orders"
                },
                "useCount": 2
            }],
            "version": 1
        }),
        serde_json::json!({
            "version": 1,
            "credentials": [{
                "id": "rejected",
                "scope": {
                    "namespace": "profile-a", "requestKey": "request-c",
                    "originHost": "api.example", "service": "billing", "protocol": "Payment",
                    "payerBackend": "test-mode", "policyHash": "policy-c"
                },
                "authorization": "Payment fixture-c", "createdAt": 99,
                "expiresAt": 500, "maxUses": 9, "useCount": 1,
                "lastSuccessAt": null, "lastRejectedAt": 100,
                "paymentHash": null, "challengeId": null, "secretStorage": "file"
            }]
        }),
    ];
    let expected = [
        ("active", "default", 0, true),
        ("exhausted", "default", 2, false),
        ("rejected", "profile-a", 1, false),
    ];

    for (index, (fixture, expectation)) in fixtures.iter().zip(expected).enumerate() {
        let path = root.path().join(format!("cache-{index}.json"));
        let bytes = serde_json::to_vec(fixture).unwrap();
        write_private(&path, &bytes);
        let namespace = (expectation.1 != "default").then_some(expectation.1);
        let loaded = FileCredentialCache::new(&path, namespace)
            .unwrap()
            .list()
            .unwrap();
        assert_eq!(loaded.len(), 1);
        let credential = &loaded[0];
        assert_eq!(credential.credential_id, expectation.0);
        assert_eq!(credential.scope.namespace, expectation.1);
        assert_eq!(credential.use_count, expectation.2);
        assert_eq!(credential.usable(100), expectation.3);
    }
}

#[test]
#[cfg(unix)]
fn table_driven_ledger_variants_preserve_semantics_not_formatting() {
    let root = TestDir::new("python-ledger-properties");
    let fixtures = [
        serde_json::json!({"2000-01-02": {"committed_sats": 5, "reservations": {}}}),
        serde_json::json!({"2000-01-02": {
            "committed_sats": 0,
            "reservations": {"00112233445566778899aabbccddeeff": 5}
        }}),
        serde_json::json!({
            "2000-01-02": {"committed_sats": 1, "reservations": {}},
            "2000-01-03": {"committed_sats": 144, "reservations": {"pending": 3}}
        }),
    ];
    let expected_spend = [5, 0, 1];

    for (index, (fixture, expected)) in fixtures.iter().zip(expected_spend).enumerate() {
        let path = root.path().join(format!("ledger-{index}.json"));
        write_private(&path, &serde_json::to_vec_pretty(fixture).unwrap());
        let ledger = DailySpendLedger::new(&path);
        assert_eq!(ledger.spent_on("2000-01-02").unwrap(), expected);

        let rewritten: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            &rewritten, fixture,
            "semantic state changed for case {index}"
        );
        for entry in rewritten.as_object().unwrap().values() {
            assert!(entry.get("committed_sats").unwrap().is_u64());
            assert!(entry.get("reservations").unwrap().is_object());
        }
    }
}

#[test]
fn qualified_python_oracle_cache_bytes_preserve_rust_field_semantics() {
    // This frozen evidence was produced by the repository's qualified Python
    // oracle at baseline commit f56cbd0c4bdf07254282a52e51bcf88ff1f48478.
    let evidence: serde_json::Value =
        serde_json::from_str(include_str!("../compat/python_oracle/golden/evidence.json")).unwrap();
    assert_eq!(
        evidence["baseline_commit"],
        "f56cbd0c4bdf07254282a52e51bcf88ff1f48478"
    );
    let oracle_state = &evidence["probes"]["state"]["cache"];
    assert_eq!(
        oracle_state,
        &evidence["case_evidence"]["cache.schema"]["observations"]["state.cache"]
    );
    let cache_file: serde_json::Value =
        serde_json::from_str(oracle_state["bytes"].as_str().unwrap()).unwrap();
    assert_eq!(cache_file["version"], 1);
    let rust: CachedCredential =
        serde_json::from_value(cache_file["credentials"][0].clone()).unwrap();

    let show_stdout = evidence["case_evidence"]["credentials.show_found"]["observations"]
        ["credentials.show_found"]["stdout"]
        .as_str()
        .unwrap();
    let python_show: serde_json::Value = serde_json::from_str(show_stdout).unwrap();
    let expected = &python_show["credential"];

    assert_eq!(rust.credential_id, expected["id"].as_str().unwrap());
    assert_eq!(rust.scope.namespace, expected["scope"]["namespace"]);
    assert_eq!(rust.scope.request_key, expected["scope"]["requestKey"]);
    assert_eq!(
        rust.scope.origin_host.as_deref(),
        expected["scope"]["originHost"].as_str()
    );
    assert_eq!(
        rust.scope.service.as_deref(),
        expected["scope"]["service"].as_str()
    );
    assert_eq!(rust.scope.protocol, expected["scope"]["protocol"]);
    assert_eq!(rust.scope.payer_backend, expected["scope"]["payerBackend"]);
    assert_eq!(rust.scope.policy_hash, expected["scope"]["policyHash"]);
    assert_eq!(rust.created_at, expected["createdAt"].as_i64().unwrap());
    assert_eq!(rust.expires_at, expected["expiresAt"].as_i64());
    assert_eq!(rust.max_uses, expected["maxUses"].as_u64());
    assert_eq!(rust.use_count, expected["useCount"].as_u64().unwrap());
    assert_eq!(rust.last_success_at, expected["lastSuccessAt"].as_i64());
    assert_eq!(rust.last_rejected_at, expected["lastRejectedAt"].as_i64());
    assert_eq!(
        rust.payment_hash.as_deref(),
        expected["paymentHash"].as_str()
    );
    assert_eq!(
        rust.challenge_id.as_deref(),
        expected["challengeId"].as_str()
    );
    assert_eq!(rust.secret_storage.as_deref(), Some("keyring"));
    assert!(
        rust.authorization.is_empty(),
        "null keyring marker is not a secret"
    );
    assert_eq!(expected["authorization"], "[REDACTED_CREDENTIAL]");
    assert_eq!(oracle_state["hit"], true);
    assert!(rust.usable(946_782_245));
}

#[test]
#[cfg(unix)]
fn qualified_python_oracle_ledger_bytes_are_semantically_readable() {
    let evidence: serde_json::Value =
        serde_json::from_str(include_str!("../compat/python_oracle/golden/evidence.json")).unwrap();
    let oracle = &evidence["probes"]["state"]["ledger"];
    let root = TestDir::new("qualified-python-oracle");
    let cases = [("reserved_bytes", 0, 1), ("committed_bytes", 5, 0)];

    for (field, expected_committed, expected_reservations) in cases {
        let path = root.path().join(format!("{field}.json"));
        let bytes = oracle[field]
            .as_str()
            .expect("qualified oracle state must contain ledger bytes")
            .as_bytes();
        write_private(&path, bytes);

        let ledger = DailySpendLedger::new(&path);
        assert_eq!(ledger.spent_on("2000-01-02").unwrap(), expected_committed);
        let semantic: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            semantic["2000-01-02"]["reservations"]
                .as_object()
                .unwrap()
                .len(),
            expected_reservations
        );
        assert_eq!(semantic["2000-01-02"]["committed_sats"], expected_committed);
    }
}
