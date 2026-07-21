//! Qualification-only evidence from the compiled public CLI.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CASE_IDS: [&str; 3] = [
    "credentials.list.success",
    "credentials.show_missing",
    "credentials.show_state",
];

const STATE_FIELDS: [&str; 12] = [
    "id",
    "scope",
    "authorization",
    "createdAt",
    "expiresAt",
    "maxUses",
    "useCount",
    "lastSuccessAt",
    "lastRejectedAt",
    "paymentHash",
    "challengeId",
    "secretStorage",
];
const PUBLIC_CREDENTIAL_FIELDS: [&str; 11] = [
    "id",
    "scope",
    "authorization",
    "createdAt",
    "expiresAt",
    "maxUses",
    "useCount",
    "lastSuccessAt",
    "lastRejectedAt",
    "paymentHash",
    "challengeId",
];
const SCOPE_FIELDS: [&str; 7] = [
    "namespace",
    "requestKey",
    "originHost",
    "service",
    "protocol",
    "payerBackend",
    "policyHash",
];

fn has_exact_fields(object: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}

fn invalid_child_data<T>() -> Result<T, &'static str> {
    // Never include child-controlled values in qualification diagnostics.
    Err("invalid qualification child data")
}

fn sha256(path: &Path) -> String {
    hex::encode(Sha256::digest(fs::read(path).expect("read identity input")))
}

fn source_commit() -> String {
    if let Ok(value) = std::env::var("PAYGATE_SOURCE_COMMIT") {
        return value;
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git must provide a source commit for local qualification");
    assert!(output.status.success(), "source commit unavailable");
    String::from_utf8(output.stdout)
        .expect("commit UTF-8")
        .trim()
        .to_owned()
}

fn private_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("paygate-semantic-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&path).expect("private test directory");
    path
}

/// The child needs a usable credential, but evidence must never retain its
/// authorization.  This fixture is created locally for each process run.
fn execution_state() -> Value {
    json!({"version": 1, "credentials": [{
        "id": "fixture-id",
        "scope": {"namespace": "oracle", "requestKey": "GET https://example.test/resource", "originHost": "example.test:443", "service": "orders", "protocol": "L402", "payerBackend": "test-mode", "policyHash": "2222222222222222222222222222222222222222222222222222222222222222"},
        "authorization": "L402 qualification-placeholder", "createdAt": 946782245, "expiresAt": 946782305,
        "maxUses": null, "useCount": 0, "lastSuccessAt": null, "lastRejectedAt": null,
        "paymentHash": null, "challengeId": null, "secretStorage": "keyring"
    }]})
}

fn safe_public_credential(value: &Value) -> Result<Value, &'static str> {
    let credential = match value.as_object() {
        Some(credential) if has_exact_fields(credential, &PUBLIC_CREDENTIAL_FIELDS) => credential,
        _ => return invalid_child_data(),
    };
    if credential.get("paymentHash") != Some(&Value::Null)
        || credential.get("challengeId") != Some(&Value::Null)
        || !credential
            .get("scope")
            .and_then(Value::as_object)
            .is_some_and(|scope| has_exact_fields(scope, &SCOPE_FIELDS))
    {
        return invalid_child_data();
    }
    Ok(json!({
        "id": credential["id"], "scope": credential["scope"],
        "authorization": "[REDACTED_CREDENTIAL]",
        "createdAt": credential["createdAt"], "expiresAt": credential["expiresAt"],
        "maxUses": credential["maxUses"], "useCount": credential["useCount"],
        "lastSuccessAt": credential["lastSuccessAt"], "lastRejectedAt": credential["lastRejectedAt"],
        "paymentHash": null, "challengeId": null,
    }))
}

fn safe_public_state_credential(value: &Value) -> Result<Value, &'static str> {
    let credential = match value.as_object() {
        Some(credential) if has_exact_fields(credential, &STATE_FIELDS) => credential,
        _ => return invalid_child_data(),
    };
    safe_public_credential(&Value::Object(
        PUBLIC_CREDENTIAL_FIELDS
            .iter()
            .map(|field| ((*field).to_owned(), credential[*field].clone()))
            .collect(),
    ))
}

fn safe_state(value: &Value) -> Result<Value, &'static str> {
    let state = match value.as_object() {
        Some(state)
            if has_exact_fields(state, &["version", "credentials"])
                && state.get("version") == Some(&Value::from(1)) =>
        {
            state
        }
        _ => return invalid_child_data(),
    };
    let credentials = match state.get("credentials").and_then(Value::as_array) {
        Some(credentials) => credentials,
        None => return invalid_child_data(),
    };
    let mut safe_credentials = Vec::with_capacity(credentials.len());
    for credential in credentials {
        let public = safe_public_state_credential(credential)?;
        let mut projected = public.as_object().expect("safe credential object").clone();
        projected.insert("authorization".into(), Value::Null);
        projected.insert("secretStorage".into(), Value::String("keyring".into()));
        safe_credentials.push(Value::Object(projected));
    }
    Ok(json!({"version": 1, "credentials": safe_credentials}))
}

fn safe_stdout(case_id: &str, value: &Value, state: &Value) -> Result<Value, &'static str> {
    let object = match value.as_object() {
        Some(object) => object,
        None => return invalid_child_data(),
    };
    match case_id {
        "credentials.list.success" => {
            if !has_exact_fields(object, &["ok", "credentials"])
                || object.get("ok") != Some(&Value::Bool(true))
                || object
                    .get("credentials")
                    .and_then(Value::as_array)
                    .is_none()
            {
                return invalid_child_data();
            }
            let expected = state
                .get("credentials")
                .and_then(Value::as_array)
                .ok_or("invalid qualification child data")?;
            let public = expected
                .iter()
                .map(safe_public_state_credential)
                .collect::<Result<Vec<_>, _>>()?;
            let observed = object["credentials"]
                .as_array()
                .expect("validated CLI credentials array")
                .iter()
                .map(safe_public_credential)
                .collect::<Result<Vec<_>, _>>()?;
            if observed != public {
                return if observed.len() != public.len() {
                    Err("invalid qualification child credential count")
                } else {
                    invalid_child_data()
                };
            }
            Ok(json!({"ok": true, "credentials": public}))
        }
        "credentials.show_state" => {
            if !has_exact_fields(object, &["ok", "credential"])
                || object.get("ok") != Some(&Value::Bool(true))
            {
                return invalid_child_data();
            }
            let expected = state
                .get("credentials")
                .and_then(Value::as_array)
                .and_then(|items| items.first())
                .ok_or("invalid qualification child data")
                .and_then(safe_public_state_credential)?;
            let observed = safe_public_credential(&object["credential"])?;
            if observed != expected {
                return invalid_child_data();
            }
            Ok(json!({"ok": true, "credential": expected}))
        }
        "credentials.show_missing" => {
            let error = match object.get("error").and_then(Value::as_object) {
                Some(error)
                    if has_exact_fields(object, &["ok", "paid", "error"])
                        && object.get("ok") == Some(&Value::Bool(false))
                        && object.get("paid") == Some(&Value::Bool(false))
                        && has_exact_fields(error, &["code", "message"]) =>
                {
                    error
                }
                _ => return invalid_child_data(),
            };
            let code = match error.get("code").and_then(Value::as_str) {
                Some(code)
                    if code.is_ascii()
                        && code.replace('_', "").chars().all(char::is_alphabetic) =>
                {
                    code
                }
                _ => return invalid_child_data(),
            };
            Ok(json!({"ok": false, "error": {"code": code}}))
        }
        _ => invalid_child_data(),
    }
}

fn run_compiled_cli(args: &[&str], cache: &Path) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_paygate"))
        .args(args)
        .args(["--profile", "oracle", "--cache-path"])
        .arg(cache)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("compiled paygate must start");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().expect("compiled paygate status").is_some() {
            return child.wait_with_output().expect("compiled paygate output");
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop timed-out compiled paygate");
            let _ = child.wait_with_output();
            panic!("compiled paygate timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_case(case_id: &str, args: &[&str]) -> Value {
    let root = private_dir();
    let cache = root.join("credentials.json");
    let private_before = execution_state();
    fs::write(
        &cache,
        serde_json::to_vec(&private_before).expect("state JSON"),
    )
    .expect("write private state");
    #[cfg(unix)]
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o600))
        .expect("make private state owner-only");
    let child = run_compiled_cli(args, &cache);
    assert!(child.stderr.is_empty(), "CLI emitted unexpected stderr");
    let stdout: Value = serde_json::from_slice(&child.stdout).expect("CLI stdout must be JSON");
    let private_after: Value =
        serde_json::from_slice(&fs::read(&cache).expect("read post-run state"))
            .expect("post-run state must be JSON");
    let exit_code = child
        .status
        .code()
        .expect("CLI must not terminate by signal");
    let expected_zero = case_id != "credentials.show_missing";
    assert_eq!(exit_code == 0, expected_zero, "unexpected CLI status class");
    let mut argv = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    argv.extend([
        "--profile".into(),
        "oracle".into(),
        "--cache-path".into(),
        "<TEST_CACHE>".into(),
    ]);
    let _ = fs::remove_dir_all(&root);
    let before = safe_state(&private_before).expect("invalid qualification child data");
    let after = safe_state(&private_after).expect("invalid qualification child data");
    let stdout_json = safe_stdout(case_id, &stdout, &before)
        .unwrap_or_else(|reason| panic!("{reason} for {case_id}"));
    json!({
        "argv": argv, "stdout_json": stdout_json, "exit_code": exit_code,
        "stderr_class": "empty", "state": {
            "before": before, "after": after
        }
    })
}

#[test]
fn safe_projections_redact_secrets_and_reject_unsafe_fields() {
    let mut state = execution_state();
    state["credentials"][0]["authorization"] = json!("credential-secret");
    let projected = safe_state(&state).expect("fixture state is safe after projection");
    let rendered = projected.to_string();
    assert!(!rendered.contains("credential-secret"));
    assert_eq!(projected["credentials"][0]["authorization"], Value::Null);

    state["credentials"][0]["paymentHash"] = json!("payment-hash-secret");
    assert_eq!(safe_state(&state), Err("invalid qualification child data"));

    let unsafe_success = json!({"ok": true, "credential": {"invoice": "lnbc-secret"}});
    assert_eq!(
        safe_stdout("credentials.show_state", &unsafe_success, &projected),
        Err("invalid qualification child data")
    );
    let arbitrary_success = json!({"ok": true, "unexpected": "preimage-secret"});
    assert_eq!(
        safe_stdout("credentials.list.success", &arbitrary_success, &projected),
        Err("invalid qualification child data")
    );
}

#[test]
fn writes_independent_compiled_cli_semantic_evidence() {
    let output = std::env::var("PAYGATE_SEMANTIC_EVIDENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("paygate-semantic-evidence-local.json"));
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_paygate"));
    let lock = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let binary_sha256 = sha256(&executable);
    let cargo_lock_sha256 = sha256(&lock);
    if let Ok(expected) = std::env::var("PAYGATE_BINARY_SHA256") {
        assert_eq!(expected, binary_sha256);
    }
    if let Ok(expected) = std::env::var("PAYGATE_CARGO_LOCK_SHA256") {
        assert_eq!(expected, cargo_lock_sha256);
    }
    let commit = source_commit();
    assert!(
        commit.len() == 40 && commit.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid source commit"
    );
    let cases = json!({
        CASE_IDS[0]: run_case(CASE_IDS[0], &["credentials", "list"]),
        CASE_IDS[1]: run_case(CASE_IDS[1], &["credentials", "show", "missing-id"]),
        CASE_IDS[2]: run_case(CASE_IDS[2], &["credentials", "show", "fixture-id"]),
    });
    fs::write(output, serde_json::to_vec(&json!({
        "schema_version": 2, "case_ids": CASE_IDS, "producer": "compiled-paygate-cli", "cases": cases,
        "provenance": {"executable_sha256": binary_sha256, "source_commit": commit, "cargo_lock_sha256": cargo_lock_sha256}
    })).expect("serialize evidence")).expect("write evidence");
}
