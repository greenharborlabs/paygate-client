use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;

static CUTOVER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut mode = fs::metadata(path).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(path, mode).unwrap();
}

fn run(command: &mut Command) -> bool {
    command.status().unwrap().success()
}

fn checkpoint(script: &Path, candidate: &Path, acceptance: &Path, record: Option<&Path>, rollback: Option<&Path>, gate: &str) {
    let mut command = Command::new(script);
    command.args(["checkpoint", "--candidate"]).arg(candidate)
        .args(["--acceptance"]).arg(acceptance).args(["--gate", gate, "--operator", "operator-01"]);
    if let Some(record) = record { command.args(["--record"]).arg(record); }
    if let Some(rollback) = rollback { command.args(["--rollback-dir"]).arg(rollback); }
    match gate {
        "invoice-approved" => { command.args(["--name", "CUTOVER-INVOICE-01", "--max-amount-sats", "10", "--max-fee-sats", "2", "--daily-cap-sats", "25"]); }
        "request-approved" => { command.args(["--name", "CUTOVER-REQUEST-01"]); }
        gate if gate.ends_with("-pass") => { command.args(["--result", "PASS"]); }
        _ => {}
    }
    command.arg("--confirm");
    assert!(run(&mut command), "checkpoint {gate} failed");
}

fn replace_symlink(path: &Path, target: &Path) {
    fs::remove_file(path).unwrap();
    symlink(target, path).unwrap();
}

#[test]
fn bounded_process_classifier_detects_python_paygate_shapes_without_false_positives() {
    let _guard = CUTOVER_TEST_LOCK.lock().unwrap();
    let root = std::env::temp_dir().join(format!("paygate-process-scan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let old_entry = root.join("old-paygate.py");
    fs::write(&old_entry, "import time\ntime.sleep(30)\n").unwrap();
    fs::write(root.join("paygate.py"), "import time\ntime.sleep(30)\n").unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/cutover-rust-paygate.sh");
    let scan = |old: &Path| {
        run(Command::new(&script).arg("_process-check")
            .env("PAYGATE_OLD_ENTRY", old)
            .env("PAYGATE_QUARANTINE_ENTRY", root.join("quarantine-paygate"))
            .env("PAYGATE_RECORDED_WRAPPER", old))
    };

    let mut unrelated = Command::new("python3").args(["-c", "import time; time.sleep(30)"]).spawn().unwrap();
    assert!(scan(&old_entry));
    unrelated.kill().unwrap(); let _ = unrelated.wait();

    let mut direct = Command::new("python3").args(["-W", "ignore"]).arg(&old_entry).spawn().unwrap();
    assert!(!scan(&old_entry));
    direct.kill().unwrap(); let _ = direct.wait();

    let mut module = Command::new("python3").args(["-m", "paygate"]).current_dir(&root).spawn().unwrap();
    assert!(!scan(&old_entry));
    module.kill().unwrap(); let _ = module.wait();
    let mut dynamic_import = Command::new("python3").args(["-c", "__import__('paygate');__import__('time').sleep(30)"]).current_dir(&root).spawn().unwrap();
    assert!(!scan(&old_entry));
    dynamic_import.kill().unwrap(); let _ = dynamic_import.wait();

    let mut env_wrapped = Command::new("/usr/bin/env").arg("PAYGATE_TEST=1").arg("python3").arg(&old_entry).spawn().unwrap();
    assert!(!scan(&old_entry));
    env_wrapped.kill().unwrap(); let _ = env_wrapped.wait();
    let mut env_valued = Command::new("/usr/bin/env").args(["-u", "PAYGATE_TEST", "python3"]).arg(&old_entry).spawn().unwrap();
    assert!(!scan(&old_entry));
    env_valued.kill().unwrap(); let _ = env_valued.wait();
    let mut post_selector_data = Command::new("python3").args(["-c", "import time; time.sleep(30)"]).arg(&old_entry).spawn().unwrap();
    assert!(!scan(&old_entry));
    post_selector_data.kill().unwrap(); let _ = post_selector_data.wait();
    let mut post_selector_import_data = Command::new("python3").args(["-c", "__import__('time').sleep(30)", "import paygate"]).spawn().unwrap();
    assert!(!scan(&old_entry));
    post_selector_import_data.kill().unwrap(); let _ = post_selector_import_data.wait();
    let run_path_code = format!("import runpy;runpy.run_path({:?})", old_entry.to_string_lossy());
    let mut run_path = Command::new("python3").args(["-c", &run_path_code]).spawn().unwrap();
    assert!(!scan(&old_entry));
    run_path.kill().unwrap(); let _ = run_path.wait();
    let embedded = format!("PAYGATE_DATA={}", root.join("quarantine-paygate").display());
    let mut embedded_path = Command::new("python3").args(["-c", "__import__('time').sleep(30)"]).arg(&embedded).spawn().unwrap();
    assert!(!scan(&old_entry));
    embedded_path.kill().unwrap(); let _ = embedded_path.wait();
    let oversized = format!("{}{}", "x".repeat(9000), old_entry.display());
    let mut oversized_path = Command::new("python3").args(["-c", "__import__('time').sleep(30)"]).arg(&oversized).spawn().unwrap();
    assert!(!scan(&old_entry));
    oversized_path.kill().unwrap(); let _ = oversized_path.wait();

    let fake_python = root.join("python3");
    symlink("/bin/sh", &fake_python).unwrap();
    executable(&root.join("quarantine-paygate"), "#!/bin/sh\nsleep 30\n:\n");
    let mut unknown_quarantine = Command::new(&fake_python).args(["-o", "nounset"]).arg(root.join("quarantine-paygate"))
        .stdout(Stdio::null()).spawn().unwrap();
    let mut rejected = false;
    for _ in 0..20 {
        if !scan(&old_entry) { rejected = true; break; }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    unknown_quarantine.kill().unwrap(); let _ = unknown_quarantine.wait();
    assert!(rejected);
    assert!(!run(Command::new(&script).arg("_supervisor-check")
        .env("PAYGATE_OLD_ENTRY", &old_entry).env("PAYGATE_QUARANTINE_ENTRY", root.join("quarantine-paygate"))
        .env("PAYGATE_RECORDED_WRAPPER", &old_entry).env("PAYGATE_RECORDED_SUPERVISOR", "unknown")
        .env("PAYGATE_RUST_TARGET", root.join("rust-paygate"))));
    let _ = fs::remove_dir_all(&root);
}

#[cfg(target_os = "macos")]
#[test]
fn supervisor_phase_contract_is_exact() {
    let _guard = CUTOVER_TEST_LOCK.lock().unwrap();
    let root = std::env::temp_dir().join(format!("paygate-supervisor-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let launchctl = root.join("launchctl");
    executable(&launchctl, "#!/bin/sh\nif [ \"$1\" = list ]; then printf '%s\\n' \"${MOCK_LAUNCHCTL_LIST:-}\"; else printf '%s\\n' \"${MOCK_LAUNCHCTL_DETAIL:-}\"; fi\n");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/cutover-rust-paygate.sh");
    let wrapper = root.join("bin/paygate");
    let rust = root.join("candidate/paygate");
    let old = root.join("python/bin/paygate");
    let quarantine = root.join("python.quarantine/bin/paygate");
    let path = format!("{}:{}", root.display(), std::env::var("PATH").unwrap());
    let supervisor = |phase: &str, list: &str, detail: &str| {
        run(Command::new(&script).arg("_supervisor-check")
            .env("PATH", &path).env("MOCK_LAUNCHCTL_LIST", list).env("MOCK_LAUNCHCTL_DETAIL", detail)
            .env("PAYGATE_OLD_ENTRY", &old).env("PAYGATE_QUARANTINE_ENTRY", &quarantine)
            .env("PAYGATE_RECORDED_WRAPPER", &wrapper).env("PAYGATE_RECORDED_SUPERVISOR", "launchctl:com.greenharbor.paygate")
            .env("PAYGATE_RUST_TARGET", &rust).env("PAYGATE_RUNTIME_PHASE", phase))
    };
    assert!(supervisor("installed", "123\t0\tcom.greenharbor.paygate", &format!("program = {}\npid = 123", wrapper.display())));
    assert!(!supervisor("preinstall", "", &format!("program = {}", wrapper.display())));
    assert!(supervisor("preinstall", "-\t0\tcom.greenharbor.paygate", &format!("program = {}", wrapper.display())));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn clean_room_cutover_is_identity_bound_fail_closed_and_reversible() {
    let _guard = CUTOVER_TEST_LOCK.lock().unwrap();
    let root = std::env::temp_dir().join(format!("paygate-cutover-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for dir in ["repo/scripts", "repo/src", "deploy/bin", "deploy/python/bin", "state/wallet"] {
        fs::create_dir_all(root.join(dir)).unwrap();
    }
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["preflight-minimal-rust-cutover.sh", "package-rust-paygate.sh", "cutover-rust-paygate.sh"] {
        fs::copy(source.join("scripts").join(name), root.join("repo/scripts").join(name)).unwrap();
    }
    fs::write(root.join("repo/Cargo.toml"), "[package]\nname='paygate-client'\nversion='0.1.0'\nedition='2021'\n\n[[bin]]\nname='paygate'\npath='src/main.rs'\n").unwrap();
    fs::write(root.join("repo/src/main.rs"), "fn main(){println!(\"{}\", r#\"{\"ok\":true,\"runtime\":\"rust\"}\"#);}\n").unwrap();
    let excluded_tracked = [
        ".github/workflows/rust-integration-qualification.yml",
        ".github/workflows/rust-platform.yml",
        "scripts/bootstrap-native-keyring.py",
        "tests/keyring_qualification.rs",
        "tests/platform-smoke/test_platform_qualification_scaffold.py",
        "tests/platform-smoke/test_wave5_qualification_contracts.py",
    ];
    for relative in excluded_tracked {
        let file = root.join("repo").join(relative);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, format!("baseline:{relative}\n")).unwrap();
    }

    assert!(run(Command::new("python3").args(["-m", "venv"]).arg(root.join("deploy/python"))));
    let base_python = fs::canonicalize(root.join("deploy/python/bin/python3")).unwrap();
    let base_python_bytes = fs::read(&base_python).unwrap();
    let old_target = root.join("deploy/python/bin/paygate");
    let canonical_raw_python = fs::canonicalize(root.join("deploy/python/bin")).unwrap().join("python3");
    executable(&old_target, &format!("#!{}\nprintf '{{\"runtime\":\"python\"}}\\n'\n", canonical_raw_python.display()));
    let launcher = root.join("deploy/bin/paygate");
    symlink(&old_target, &launcher).unwrap();
    fs::write(root.join("state/config.yaml"), "payer: test-mode\n").unwrap();
    fs::write(root.join("state/wallet/wallet.db"), "wallet\n").unwrap();
    fs::write(root.join("state/credentials.json"), "{}\n").unwrap();
    fs::write(root.join("state/ledger.json"), "{}\n").unwrap();

    let repo = root.join("repo");
    assert!(run(Command::new("cargo").arg("generate-lockfile").current_dir(&repo)));
    for args in [["init", "-q"].as_slice(), ["config", "user.email", "cutover@example.invalid"].as_slice(), ["config", "user.name", "cutover-test"].as_slice(), ["add", "."].as_slice(), ["commit", "-qm", "fixture"].as_slice()] {
        assert!(run(Command::new("git").args(args).current_dir(&repo)));
    }

    // The excluded dirty baseline exists before preflight and must survive byte-for-byte.
    for relative in excluded_tracked {
        fs::write(repo.join(relative), format!("wave5-dirty:{relative}\n")).unwrap();
    }
    fs::create_dir_all(repo.join("compat")).unwrap();
    fs::write(repo.join("compat/native-keyring-requirements.txt"), "keyring==25.7.0\n").unwrap();
    let dirty_status = Command::new("git").args(["status", "--porcelain=v1", "-z", "--untracked-files=all"]).current_dir(&repo).output().unwrap().stdout;
    let tracked_dirty: Vec<_> = excluded_tracked.iter().map(|relative| ((*relative).to_owned(), fs::read(repo.join(relative)).unwrap())).collect();
    let untracked_dirty = fs::read(repo.join("compat/native-keyring-requirements.txt")).unwrap();

    let record = root.join("preflight.json");
    let path = format!("{}:{}", root.join("deploy/bin").display(), std::env::var("PATH").unwrap());
    assert!(run(Command::new(repo.join("scripts/preflight-minimal-rust-cutover.sh"))
        .args(["record", "--repo"]).arg(&repo).args(["--output"]).arg(&record).env("PATH", &path)));
    let mut preflight: serde_json::Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    assert_eq!(preflight["dirty_baseline"]["path_count"], 7);
    preflight["state"]["config"] = root.join("state/config.yaml").to_string_lossy().into_owned().into();
    preflight["state"]["wallet_storage"] = root.join("state/wallet").to_string_lossy().into_owned().into();
    preflight["state"]["credential_cache"] = root.join("state/credentials.json").to_string_lossy().into_owned().into();
    preflight["state"]["ledger"] = root.join("state/ledger.json").to_string_lossy().into_owned().into();
    fs::write(&record, serde_json::to_vec_pretty(&preflight).unwrap()).unwrap();
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();

    let candidate = root.join("candidate");
    assert!(run(Command::new(repo.join("scripts/package-rust-paygate.sh"))
        .args(["--repo"]).arg(&repo).args(["--record"]).arg(&record).args(["--output"]).arg(&candidate).env("PATH", &path)));
    let output = Command::new(candidate.join("paygate")).output().unwrap();
    assert!(output.status.success());
    let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    let cutover = repo.join("scripts/cutover-rust-paygate.sh");
    let acceptance = root.join("acceptance.json");
    for gate in ["fixture-oracle-pass", "rust-product-tests-pass", "candidate-doctor-pass", "invoice-approved", "invoice-pass", "request-approved", "request-pass"] {
        checkpoint(&cutover, &candidate, &acceptance, None, None, gate);
    }

    let valid_acceptance: serde_json::Value = serde_json::from_slice(&fs::read(&acceptance).unwrap()).unwrap();
    let mut invalid_acceptances = Vec::new();
    let mut value = valid_acceptance.clone(); value["candidate_identity"]["binary_sha256"] = "00".repeat(32).into(); invalid_acceptances.push(("candidate", value));
    let mut value = valid_acceptance.clone(); value["schema"] = "wrong-schema".into(); invalid_acceptances.push(("schema", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0]["passed"] = "true".into(); invalid_acceptances.push(("truthy-string", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0]["passed"] = 1.into(); invalid_acceptances.push(("truthy-integer", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][3].as_object_mut().unwrap().remove("max_fee_sats"); invalid_acceptances.push(("missing-cap", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][3]["daily_cap_sats"] = 0.into(); invalid_acceptances.push(("invalid-cap", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][3]["name"] = "".into(); invalid_acceptances.push(("invalid-name", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][5].as_object_mut().unwrap().remove("name"); invalid_acceptances.push(("missing-name", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0]["result"] = "OK".into(); invalid_acceptances.push(("invalid-result", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0].as_object_mut().unwrap().remove("result"); invalid_acceptances.push(("missing-result", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0].as_object_mut().unwrap().remove("operator"); invalid_acceptances.push(("missing-operator", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0].as_object_mut().unwrap().remove("recorded_at_epoch"); invalid_acceptances.push(("missing-timestamp", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0]["recorded_at_epoch"] = "now".into(); invalid_acceptances.push(("invalid-timestamp", value));
    let mut value = valid_acceptance.clone(); let first_timestamp = value["checkpoints"][0]["recorded_at_epoch"].as_i64().unwrap(); value["checkpoints"][1]["recorded_at_epoch"] = (first_timestamp - 1).into(); invalid_acceptances.push(("unordered-timestamp", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"].as_array_mut().unwrap().swap(0, 1); invalid_acceptances.push(("reordered", value));
    let mut value = valid_acceptance.clone(); value["cutover_session_id"] = "11".repeat(16).into(); invalid_acceptances.push(("rekeyed-session", value));
    let mut value = valid_acceptance.clone(); value["cutover_session_id"] = "33".repeat(16).into(); for entry in value["checkpoints"].as_array_mut().unwrap() { entry["cutover_session_id"] = "33".repeat(16).into(); } invalid_acceptances.push(("coherent-rekey", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0]["cutover_session_id"] = "22".repeat(16).into(); invalid_acceptances.push(("entry-session-mismatch", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0].as_object_mut().unwrap().remove("cutover_session_id"); invalid_acceptances.push(("entry-session-missing", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"][0]["cutover_session_id"] = "bad".into(); invalid_acceptances.push(("entry-session-malformed", value));
    let mut value = valid_acceptance.clone(); let duplicate = value["checkpoints"][6].clone(); value["checkpoints"].as_array_mut().unwrap().push(duplicate); invalid_acceptances.push(("duplicate", value));
    let mut value = valid_acceptance.clone(); value["checkpoints"].as_array_mut().unwrap().push(serde_json::json!({"gate":"extra","passed":true,"recorded_at_epoch":1,"operator":"operator-01","result":"PASS"})); invalid_acceptances.push(("extra", value));
    for (label, malformed) in invalid_acceptances {
        let malformed_path = root.join(format!("invalid-{label}.json"));
        let refused_rollback = root.join(format!("invalid-{label}-rollback"));
        fs::write(&malformed_path, serde_json::to_vec_pretty(&malformed).unwrap()).unwrap();
        assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
            .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&refused_rollback).args(["--acceptance"]).arg(&malformed_path).env("PATH", &path)), "malformed acceptance {label} was accepted");
        assert!(!refused_rollback.exists());
        assert_eq!(fs::read_link(&launcher).unwrap(), old_target);
    }

    let witness_session = valid_acceptance["cutover_session_id"].as_str().unwrap();
    let witness_dir = root.join("acceptance.json.witnesses").join(witness_session);
    let first_witness = witness_dir.join("01-fixture-oracle-pass.json");
    let parked_witness = root.join("parked-witness.json");
    fs::rename(&first_witness, &parked_witness).unwrap();
    let omitted_rollback = root.join("omitted-witness-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&omitted_rollback).args(["--acceptance"]).arg(&acceptance).env("PATH", &path)));
    fs::rename(&parked_witness, &first_witness).unwrap();
    let witness_bytes = fs::read(&first_witness).unwrap();
    fs::set_permissions(&first_witness, fs::Permissions::from_mode(0o600)).unwrap(); fs::write(&first_witness, "{}\n").unwrap(); fs::set_permissions(&first_witness, fs::Permissions::from_mode(0o400)).unwrap();
    let tampered_rollback = root.join("tampered-witness-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&tampered_rollback).args(["--acceptance"]).arg(&acceptance).env("PATH", &path)));
    fs::set_permissions(&first_witness, fs::Permissions::from_mode(0o600)).unwrap(); fs::write(&first_witness, witness_bytes).unwrap(); fs::set_permissions(&first_witness, fs::Permissions::from_mode(0o400)).unwrap();
    let extra_witness = witness_dir.join("99-extra.json"); fs::write(&extra_witness, "{}\n").unwrap(); fs::set_permissions(&extra_witness, fs::Permissions::from_mode(0o400)).unwrap();
    let extra_rollback = root.join("extra-witness-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&extra_rollback).args(["--acceptance"]).arg(&acceptance).env("PATH", &path)));
    fs::remove_file(extra_witness).unwrap();

    let ledger_bytes = fs::read(root.join("state/ledger.json")).unwrap();
    let outside_state = root.join("outside-ledger.json");
    fs::write(&outside_state, "must-not-change\n").unwrap();
    fs::remove_file(root.join("state/ledger.json")).unwrap();
    symlink(&outside_state, root.join("state/ledger.json")).unwrap();
    let symlink_rollback = root.join("symlink-state-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&symlink_rollback).args(["--acceptance"]).arg(&acceptance).env("PATH", &path)));
    assert_eq!(fs::read_to_string(&outside_state).unwrap(), "must-not-change\n");
    assert!(!symlink_rollback.exists());
    fs::remove_file(root.join("state/ledger.json")).unwrap();
    fs::write(root.join("state/ledger.json"), ledger_bytes).unwrap();

    let rollback = root.join("rollback");
    assert!(run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&rollback).args(["--acceptance"]).arg(&acceptance).env("PATH", &path)));
    let installed_target = fs::read_link(&launcher).unwrap();
    let stale_rollback = root.join("stale-reinstall-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&stale_rollback).args(["--acceptance"]).arg(&acceptance).env("PATH", &path)));
    assert!(!stale_rollback.exists());

    // An unknown/retargeted launcher and a damaged backup both fail before state mutation.
    fs::write(root.join("state/credentials.json"), "post-install\n").unwrap();
    let unknown_target = root.join("unknown-paygate");
    executable(&unknown_target, "#!/bin/sh\nexit 0\n");
    replace_symlink(&launcher, &unknown_target);
    assert!(!run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&rollback)));
    assert_eq!(fs::read_to_string(root.join("state/credentials.json")).unwrap(), "post-install\n");
    replace_symlink(&launcher, &installed_target);
    let backup_ledger = rollback.join("state/ledger");
    let ledger_backup_bytes = fs::read(&backup_ledger).unwrap();
    fs::write(&backup_ledger, "corrupt\n").unwrap();
    assert!(!run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&rollback)));
    assert_eq!(fs::read_to_string(root.join("state/credentials.json")).unwrap(), "post-install\n");
    fs::write(&backup_ledger, ledger_backup_bytes).unwrap();
    let rollback_manifest_path = rollback.join("manifest.json");
    let rollback_manifest_bytes = fs::read(&rollback_manifest_path).unwrap();
    let rollback_manifest: serde_json::Value = serde_json::from_slice(&rollback_manifest_bytes).unwrap();

    let receipt_path = Path::new(rollback_manifest["transaction_receipt"].as_str().unwrap());
    let acceptance_before_receipt_check = fs::read(&acceptance).unwrap();
    fs::set_permissions(receipt_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut refused_checkpoint = Command::new(&cutover);
    refused_checkpoint.args(["checkpoint", "--candidate"]).arg(&candidate).args(["--acceptance"]).arg(&acceptance)
        .args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&rollback)
        .args(["--gate", "installed-doctor-pass", "--operator", "operator-01", "--result", "PASS", "--confirm"]);
    assert!(!run(&mut refused_checkpoint));
    assert_eq!(fs::read(&acceptance).unwrap(), acceptance_before_receipt_check);
    fs::set_permissions(receipt_path, fs::Permissions::from_mode(0o400)).unwrap();
    let receipt_hardlink = root.join("receipt-hardlink.json");
    fs::hard_link(receipt_path, &receipt_hardlink).unwrap();
    let mut refused_checkpoint = Command::new(&cutover);
    refused_checkpoint.args(["checkpoint", "--candidate"]).arg(&candidate).args(["--acceptance"]).arg(&acceptance)
        .args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&rollback)
        .args(["--gate", "installed-doctor-pass", "--operator", "operator-01", "--result", "PASS", "--confirm"]);
    assert!(!run(&mut refused_checkpoint));
    assert_eq!(fs::read(&acceptance).unwrap(), acceptance_before_receipt_check);
    fs::remove_file(receipt_hardlink).unwrap();
    let receipt_bytes = fs::read(receipt_path).unwrap();
    for mutation in ["extra", "mismatch"] {
        let mut receipt_json: serde_json::Value = serde_json::from_slice(&receipt_bytes).unwrap();
        if mutation == "extra" { receipt_json["extra"] = true.into(); } else { receipt_json["acceptance_record"] = "/wrong/acceptance.json".into(); }
        fs::set_permissions(receipt_path, fs::Permissions::from_mode(0o600)).unwrap(); fs::write(receipt_path, serde_json::to_vec_pretty(&receipt_json).unwrap()).unwrap(); fs::set_permissions(receipt_path, fs::Permissions::from_mode(0o400)).unwrap();
        let mut refused_checkpoint = Command::new(&cutover);
        refused_checkpoint.args(["checkpoint", "--candidate"]).arg(&candidate).args(["--acceptance"]).arg(&acceptance)
            .args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&rollback)
            .args(["--gate", "installed-doctor-pass", "--operator", "operator-01", "--result", "PASS", "--confirm"]);
        assert!(!run(&mut refused_checkpoint), "receipt {mutation} was accepted");
    }
    fs::set_permissions(receipt_path, fs::Permissions::from_mode(0o600)).unwrap(); fs::write(receipt_path, receipt_bytes).unwrap(); fs::set_permissions(receipt_path, fs::Permissions::from_mode(0o400)).unwrap();

    checkpoint(&cutover, &candidate, &acceptance, Some(&record), Some(&rollback), "installed-doctor-pass");
    checkpoint(&cutover, &candidate, &acceptance, Some(&record), Some(&rollback), "restart-cache-pass");
    checkpoint(&cutover, &candidate, &acceptance, Some(&record), Some(&rollback), "runtime-only-pass");

    let recovery = root.join("recovery.json");
    let mut drift_record = preflight.clone();
    drift_record["state"]["ledger"] = root.join("state/other-ledger.json").to_string_lossy().into_owned().into();
    let drift_path = root.join("drift.json");
    fs::write(&drift_path, serde_json::to_vec_pretty(&drift_record).unwrap()).unwrap();
    fs::set_permissions(&drift_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!run(Command::new(&cutover).arg("finalize").args(["--repo"]).arg(&repo).args(["--record"]).arg(&drift_path)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&rollback).args(["--acceptance"]).arg(&acceptance)
        .args(["--recovery-record"]).arg(&recovery).args(["--confirm", "FINALIZE_RUST_AND_RETAIN_QUARANTINE"]).env("PATH", &path)));
    assert!(!recovery.exists() && rollback.exists() && !old_target.exists());

    let mut supervisor_record = preflight.clone();
    supervisor_record["deployment"]["supervisor"] = "unknown-supervisor".into();
    let supervisor_path = root.join("supervisor-drift.json");
    fs::write(&supervisor_path, serde_json::to_vec_pretty(&supervisor_record).unwrap()).unwrap();
    fs::set_permissions(&supervisor_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!run(Command::new(&cutover).arg("finalize").args(["--repo"]).arg(&repo).args(["--record"]).arg(&supervisor_path)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&rollback).args(["--acceptance"]).arg(&acceptance)
        .args(["--recovery-record"]).arg(&recovery).args(["--confirm", "FINALIZE_RUST_AND_RETAIN_QUARANTINE"]).env("PATH", &path)));
    assert!(!recovery.exists() && rollback.exists() && !old_target.exists());

    // Dirty-baseline drift is caught by the W1 guard before finalization mutates anything.
    fs::write(repo.join(excluded_tracked[0]), "additional drift\n").unwrap();
    assert!(!run(Command::new(&cutover).arg("finalize").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&rollback).args(["--acceptance"]).arg(&acceptance)
        .args(["--recovery-record"]).arg(&recovery).args(["--confirm", "FINALIZE_RUST_AND_RETAIN_QUARANTINE"]).env("PATH", &path)));
    fs::write(repo.join(excluded_tracked[0]), &tracked_dirty[0].1).unwrap();
    assert!(!recovery.exists() && rollback.exists() && !old_target.exists());

    fs::write(&recovery, "preexisting\n").unwrap();
    assert!(!run(Command::new(&cutover).arg("finalize").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&rollback).args(["--acceptance"]).arg(&acceptance)
        .args(["--recovery-record"]).arg(&recovery).args(["--confirm", "FINALIZE_RUST_AND_RETAIN_QUARANTINE"]).env("PATH", &path)));
    assert!(rollback.exists() && !old_target.exists());
    fs::remove_file(&recovery).unwrap();

    assert!(run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&rollback)));
    assert_eq!(fs::read_link(&launcher).unwrap(), old_target);
    assert_eq!(fs::read_to_string(root.join("state/credentials.json")).unwrap(), "{}\n");
    fs::write(root.join("state/credentials.json"), "post-rollback\n").unwrap();
    assert!(run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&rollback)));
    assert_eq!(fs::read_to_string(root.join("state/credentials.json")).unwrap(), "post-rollback\n");
    let consumed_rollback = root.join("consumed-reinstall-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&consumed_rollback).args(["--acceptance"]).arg(&acceptance).env("PATH", &path)));
    assert!(!consumed_rollback.exists());

    // Replacement at the locked final-publication boundary is detected before
    // a receipt, acceptance promotion, or launcher mutation.
    let replaced_acceptance = root.join("replaced-acceptance.json");
    for gate in ["fixture-oracle-pass", "rust-product-tests-pass", "candidate-doctor-pass", "invoice-approved", "invoice-pass", "request-approved", "request-pass"] {
        checkpoint(&cutover, &candidate, &replaced_acceptance, None, None, gate);
    }
    let replacement = root.join("replacement.json");
    fs::copy(&replaced_acceptance, &replacement).unwrap();
    let replaced_rollback = root.join("replaced-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&replaced_rollback).args(["--acceptance"]).arg(&replaced_acceptance)
        .env("PAYGATE_CUTOVER_TEST_HOOK", "replace-acceptance").env("PAYGATE_CUTOVER_TEST_ACCEPTANCE_REPLACEMENT", &replacement).env("PATH", &path)));
    assert_eq!(fs::read_link(&launcher).unwrap(), old_target);

    // A durable receipt consumes the cutover session even when switch
    // verification is forced to fail and restore Python.
    let receipt_acceptance = root.join("receipt-acceptance.json");
    for gate in ["fixture-oracle-pass", "rust-product-tests-pass", "candidate-doctor-pass", "invoice-approved", "invoice-pass", "request-approved", "request-pass"] {
        checkpoint(&cutover, &candidate, &receipt_acceptance, None, None, gate);
    }
    let preinstall_bytes = fs::read(&receipt_acceptance).unwrap();
    let receipt_rollback = root.join("receipt-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&receipt_rollback).args(["--acceptance"]).arg(&receipt_acceptance)
        .env("PAYGATE_CUTOVER_TEST_HOOK", "force-switch-failure").env("PATH", &path)));
    assert_eq!(fs::read_link(&launcher).unwrap(), old_target);
    fs::write(&receipt_acceptance, preinstall_bytes).unwrap();
    let replay_rollback = root.join("receipt-replay-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&replay_rollback).args(["--acceptance"]).arg(&receipt_acceptance).env("PATH", &path)));
    assert_eq!(fs::read_link(&launcher).unwrap(), old_target);
    fs::write(&receipt_acceptance, "malformed\n").unwrap();
    assert!(run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&receipt_rollback)));
    assert!(run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&receipt_rollback)));

    // A crash immediately after launcher replacement remains independently
    // rollback-capable even when acceptance disappears.
    let crash_acceptance = root.join("crash-acceptance.json");
    for gate in ["fixture-oracle-pass", "rust-product-tests-pass", "candidate-doctor-pass", "invoice-approved", "invoice-pass", "request-approved", "request-pass"] {
        checkpoint(&cutover, &candidate, &crash_acceptance, None, None, gate);
    }
    let crash_rollback = root.join("crash-rollback");
    assert!(!run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&crash_rollback).args(["--acceptance"]).arg(&crash_acceptance)
        .env("PAYGATE_CUTOVER_TEST_HOOK", "after-launcher").env("PATH", &path)));
    assert_eq!(fs::read_link(&launcher).unwrap(), installed_target);
    fs::remove_file(&crash_acceptance).unwrap();
    assert!(run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&crash_rollback)));
    assert_eq!(fs::read_link(&launcher).unwrap(), old_target);
    assert!(run(Command::new(&cutover).arg("rollback").args(["--record"]).arg(&record).args(["--rollback-dir"]).arg(&crash_rollback)));

    // A complete accepted run crosses the recovery boundary only after both removals.
    let final_rollback = root.join("final-rollback");
    let final_acceptance = root.join("final-acceptance.json");
    for gate in ["fixture-oracle-pass", "rust-product-tests-pass", "candidate-doctor-pass", "invoice-approved", "invoice-pass", "request-approved", "request-pass"] {
        checkpoint(&cutover, &candidate, &final_acceptance, None, None, gate);
    }
    assert!(run(Command::new(&cutover).arg("install").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&final_rollback).args(["--acceptance"]).arg(&final_acceptance).env("PATH", &path)));
    let checkpoint_replacement = root.join("checkpoint-replacement.json");
    fs::copy(&final_acceptance, &checkpoint_replacement).unwrap();
    let before_checkpoint = fs::read(&final_acceptance).unwrap();
    assert!(!run(Command::new(&cutover).args(["checkpoint", "--candidate"]).arg(&candidate)
        .args(["--acceptance"]).arg(&final_acceptance).args(["--record"]).arg(&record)
        .args(["--rollback-dir"]).arg(&final_rollback).args(["--gate", "installed-doctor-pass", "--operator", "operator-01", "--result", "PASS", "--confirm"])
        .env("PAYGATE_CUTOVER_TEST_CHECKPOINT_REPLACEMENT", &checkpoint_replacement)));
    assert_eq!(fs::read(&final_acceptance).unwrap(), before_checkpoint);
    checkpoint(&cutover, &candidate, &final_acceptance, Some(&record), Some(&final_rollback), "installed-doctor-pass");
    checkpoint(&cutover, &candidate, &final_acceptance, Some(&record), Some(&final_rollback), "restart-cache-pass");
    checkpoint(&cutover, &candidate, &final_acceptance, Some(&record), Some(&final_rollback), "runtime-only-pass");
    assert!(run(Command::new(&cutover).arg("finalize").args(["--repo"]).arg(&repo).args(["--record"]).arg(&record)
        .args(["--candidate"]).arg(&candidate).args(["--rollback-dir"]).arg(&final_rollback).args(["--acceptance"]).arg(&final_acceptance)
        .args(["--recovery-record"]).arg(&recovery).args(["--confirm", "FINALIZE_RUST_AND_RETAIN_QUARANTINE"]).env("PATH", &path)));
    assert!(!final_rollback.exists());
    assert!(!old_target.exists());
    assert_eq!(fs::read(&base_python).unwrap(), base_python_bytes);
    let recovery_json: serde_json::Value = serde_json::from_slice(&fs::read(&recovery).unwrap()).unwrap();
    let candidate_json: serde_json::Value = serde_json::from_slice(&fs::read(candidate.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(recovery_json["schema"], "paygate-rust-recovery-boundary-v2");
    assert_eq!(recovery_json["python_paygate_deactivated"], true);
    assert_eq!(recovery_json["python_environment_cleanup_required"], true);
    assert!(Path::new(recovery_json["python_environment_quarantine"].as_str().unwrap()).is_dir());
    for key in ["source_commit", "cargo_lock_sha256", "binary_sha256", "rust_target"] {
        assert_eq!(recovery_json["candidate_identity"][key], candidate_json[key]);
    }
    let final_status = Command::new("git").args(["status", "--porcelain=v1", "-z", "--untracked-files=all"]).current_dir(&repo).output().unwrap().stdout;
    assert_eq!(final_status, dirty_status);
    for (relative, bytes) in tracked_dirty {
        assert_eq!(fs::read(repo.join(&relative)).unwrap(), bytes);
        assert!(fs::symlink_metadata(repo.join(relative)).unwrap().file_type().is_file());
    }
    assert_eq!(fs::read(repo.join("compat/native-keyring-requirements.txt")).unwrap(), untracked_dirty);
    assert!(fs::symlink_metadata(repo.join("compat/native-keyring-requirements.txt")).unwrap().file_type().is_file());
    let _ = fs::remove_dir_all(&root);
}
