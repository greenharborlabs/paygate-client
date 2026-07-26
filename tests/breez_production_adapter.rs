use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use paygate::config::{BreezNetwork, EnvRef, load_config};
use paygate::payers::base::PaymentError;
use paygate::payers::breez::{
    BreezSecretProvider, BreezSparkSdk, ProcessBreezSecrets, ProductionBreezSparkSdk,
};

struct TestDir(PathBuf);

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "paygate-breez-production-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
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

fn config_text(network: &str, timeout: u64) -> String {
    format!(
        r#"
payer:
  backend: breez
breez:
  api_key_env: PAYGATE_TEST_BREEZ_API_KEY
  mnemonic_env: PAYGATE_TEST_BREEZ_MNEMONIC
  network: {network}
  storage_dir: ~/.local/share/paygate-client/breez
  completion_timeout_secs: {timeout}
policy:
  max_request_sats: 20
  max_fee_sats: 2
  daily_budget_sats: 100
  allowed_hosts: [example.com]
  allowed_services: [example]
protocol:
  preferred: Payment
  allow_l402: false
"#
    )
}

#[test]
fn selected_breez_config_retains_references_but_never_secret_values() {
    let root = TestDir::new();
    let config_path = root.path().join("config.yaml");
    fs::write(&config_path, config_text("mainnet", 10)).unwrap();
    assert!(load_config(&config_path).is_err());

    let api_secret = "sentinel-api-secret";
    let mnemonic_secret = "sentinel mnemonic secret";
    fs::write(
        root.path().join("voltage-env.sh"),
        format!(
            "export PAYGATE_TEST_BREEZ_API_KEY='{api_secret}'\nexport PAYGATE_TEST_BREEZ_MNEMONIC='{mnemonic_secret}'\n"
        ),
    )
    .unwrap();
    let loaded = load_config(&config_path).unwrap();
    let breez = loaded.breez.unwrap();
    assert_eq!(
        breez.api_key_env,
        EnvRef("PAYGATE_TEST_BREEZ_API_KEY".into())
    );
    assert_eq!(
        breez.mnemonic_env,
        EnvRef("PAYGATE_TEST_BREEZ_MNEMONIC".into())
    );
    assert_eq!(breez.network, BreezNetwork::Mainnet);
    assert!(breez.storage_dir.is_absolute());
    assert_eq!(breez.completion_timeout_secs, 10);
    let debug = format!("{breez:?}");
    assert!(!debug.contains(api_secret));
    assert!(!debug.contains(mnemonic_secret));
}

struct EnvGuard(String);

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: this test uses a process-unique variable name, so no other
        // test or production thread can rely on it.
        unsafe { std::env::remove_var(&self.0) };
    }
}

struct ReloadingCountingSecrets {
    inner: ProcessBreezSecrets,
    resolutions: Arc<AtomicUsize>,
}

impl BreezSecretProvider for ReloadingCountingSecrets {
    fn resolve(&self, reference: &EnvRef) -> Result<String, PaymentError> {
        self.resolutions.fetch_add(1, Ordering::Relaxed);
        self.inner.resolve(reference)
    }
}

#[test]
fn wallet_resolution_reloads_voltage_env_with_process_precedence_without_retention() {
    let root = TestDir::new();
    let unique = format!(
        "{}_{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let api_var = format!("PAYGATE_TEST_BREEZ_API_{unique}");
    let mnemonic_var = format!("PAYGATE_TEST_BREEZ_MNEMONIC_{unique}");
    let file_api = "sentinel-file-api-secret";
    let process_api = "sentinel-process-api-secret";
    let file_mnemonic = "sentinel file mnemonic secret";
    let config_path = root.path().join("config.yaml");
    let text = config_text("mainnet", 1)
        .replace("PAYGATE_TEST_BREEZ_API_KEY", &api_var)
        .replace("PAYGATE_TEST_BREEZ_MNEMONIC", &mnemonic_var);
    fs::write(&config_path, text).unwrap();
    fs::write(
        root.path().join("voltage-env.sh"),
        format!("export {api_var}='{file_api}'\nexport {mnemonic_var}='{file_mnemonic}'\n"),
    )
    .unwrap();
    // SAFETY: the name contains this process ID plus a monotonic test counter.
    unsafe { std::env::set_var(&api_var, process_api) };
    let _env_guard = EnvGuard(api_var.clone());

    let loaded = load_config(&config_path).unwrap();
    let serialized = serde_json::to_string(&loaded).unwrap();
    let debug = format!("{loaded:?}");
    for secret in [file_api, process_api, file_mnemonic] {
        assert!(!serialized.contains(secret));
        assert!(!debug.contains(secret));
    }

    let config = loaded.breez.unwrap();
    let direct = ProcessBreezSecrets::for_config(&config);
    assert_eq!(direct.resolve(&config.api_key_env).unwrap(), process_api);
    assert_eq!(direct.resolve(&config.mnemonic_env).unwrap(), file_mnemonic);

    let resolutions = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn BreezSecretProvider> = Arc::new(ReloadingCountingSecrets {
        inner: ProcessBreezSecrets::for_config(&config),
        resolutions: resolutions.clone(),
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let error = runtime.block_on(async {
        ProductionBreezSparkSdk::with_secret_provider(config, provider)
            .check_ready()
            .await
            .unwrap_err()
    });
    assert_eq!(resolutions.load(Ordering::Relaxed), 2);
    let error_text = format!("{error:?} {error}");
    for secret in [file_api, process_api, file_mnemonic] {
        assert!(!error_text.contains(secret));
    }
}

#[test]
fn invalid_network_and_timeout_fail_before_sdk_construction() {
    let root = TestDir::new();
    fs::write(
        root.path().join("voltage-env.sh"),
        "export PAYGATE_TEST_BREEZ_API_KEY=x\nexport PAYGATE_TEST_BREEZ_MNEMONIC=y\n",
    )
    .unwrap();
    let config_path = root.path().join("config.yaml");
    for text in [
        config_text("regtest", 10),
        config_text("mainnet", 0),
        config_text("mainnet", 3_601),
    ] {
        fs::write(&config_path, text).unwrap();
        assert!(load_config(&config_path).is_err());
    }
}

struct CountingSecrets(AtomicUsize);

impl BreezSecretProvider for CountingSecrets {
    fn resolve(&self, _: &EnvRef) -> Result<String, PaymentError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok("not-retained-at-config-load".into())
    }
}

#[test]
fn production_adapter_is_lazy_and_safe_to_construct_inside_a_runtime() {
    let root = TestDir::new();
    fs::write(
        root.path().join("voltage-env.sh"),
        "export PAYGATE_TEST_BREEZ_API_KEY=x\nexport PAYGATE_TEST_BREEZ_MNEMONIC=y\n",
    )
    .unwrap();
    let config_path = root.path().join("config.yaml");
    fs::write(&config_path, config_text("mainnet", 10)).unwrap();
    let config = load_config(&config_path).unwrap().breez.unwrap();
    let secrets = Arc::new(CountingSecrets(AtomicUsize::new(0)));
    let provider: Arc<dyn BreezSecretProvider> = secrets.clone();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let sdk = ProductionBreezSparkSdk::with_secret_provider(config, provider);
        assert!(format!("{sdk:?}").contains("ProductionBreezSparkSdk"));
    });
    assert_eq!(secrets.0.load(Ordering::Relaxed), 0);
}
