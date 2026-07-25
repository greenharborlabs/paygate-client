#![cfg(feature = "breez-qualification")]

use std::io::Read;
use std::path::PathBuf;

use breez_sdk_spark::{
    BreezSdk, ConnectRequest, GetInfoRequest, Network, PaymentRequest, PrepareSendPaymentRequest,
    ReceivePaymentMethod, ReceivePaymentRequest, Seed, connect, default_config,
};
use sha2::{Digest, Sha256};

struct ExclusiveStorage(PathBuf);

impl ExclusiveStorage {
    fn create(identity: &[u8]) -> Self {
        let suffix = hex::encode(&Sha256::digest(identity)[..12]);
        let path = std::env::temp_dir().join(format!("paygate-breez-qualification-{suffix}"));
        std::fs::create_dir(&path).expect("fresh qualification storage collision");
        Self(path)
    }
}

impl Drop for ExclusiveStorage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Qualification-only capability wrapper: deliberately has no SDK accessor or send method.
struct NonPayingQualificationWallet {
    sdk: Option<BreezSdk>,
    _storage: ExclusiveStorage,
}

impl NonPayingQualificationWallet {
    async fn connect() -> Self {
        let target = std::env::var("PAYGATE_QUALIFICATION_TARGET").expect("target identity");
        let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".into());
        let attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "0".into());
        let mut random = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut random))
            .expect("32 bytes of OS randomness");
        let identity = Sha256::new()
            .chain_update(b"paygate-wave2-nonpaying-v2")
            .chain_update(random)
            .chain_update(target)
            .chain_update(run_id)
            .chain_update(attempt)
            .chain_update(std::process::id().to_le_bytes())
            .finalize();
        let storage = ExclusiveStorage::create(&identity);
        let sdk = connect(ConnectRequest {
            config: default_config(Network::Mainnet),
            seed: Seed::Entropy(identity.to_vec()),
            storage_dir: storage.0.to_string_lossy().into_owned(),
        })
        .await
        .unwrap_or_else(|_| panic!("qualification wallet connection failed"));
        Self {
            sdk: Some(sdk),
            _storage: storage,
        }
    }

    async fn check_ready(&self) {
        self.sdk
            .as_ref()
            .expect("connected")
            .get_info(GetInfoRequest {
                ensure_synced: Some(true),
            })
            .await
            .unwrap_or_else(|_| panic!("qualification wallet readiness failed"));
    }

    async fn receive_one_sat_invoice(&self) -> String {
        self.sdk
            .as_ref()
            .expect("connected")
            .receive_payment(ReceivePaymentRequest {
                payment_method: ReceivePaymentMethod::Bolt11Invoice {
                    description: "paygate non-paying dependency qualification".to_owned(),
                    amount_sats: Some(1),
                    expiry_secs: Some(600),
                    payment_hash: None,
                },
            })
            .await
            .unwrap_or_else(|_| panic!("qualification invoice creation failed"))
            .payment_request
    }

    async fn prepare_only(&self, invoice: String) {
        let prepared = self
            .sdk
            .as_ref()
            .expect("connected")
            .prepare_send_payment(PrepareSendPaymentRequest {
                payment_request: PaymentRequest::Input { input: invoice },
                amount: None,
                token_identifier: None,
                conversion_options: None,
                fee_policy: None,
            })
            .await
            .unwrap_or_else(|_| panic!("qualification prepare-only call failed"));
        assert_eq!(prepared.amount, 1);
    }

    async fn disconnect(mut self) {
        self.sdk
            .take()
            .expect("connected")
            .disconnect()
            .await
            .unwrap_or_else(|_| panic!("qualification disconnect failed"));
    }
}

#[tokio::test]
#[ignore = "requires public Breez Spark service; native CI runs this explicitly"]
async fn connect_readiness_prepare_disconnect_without_send() {
    let wallet = NonPayingQualificationWallet::connect().await;
    wallet.check_ready().await;
    let invoice = wallet.receive_one_sat_invoice().await;
    wallet.prepare_only(invoice).await;
    wallet.disconnect().await;
}

#[test]
fn qualification_source_has_no_direct_send_capability() {
    let source = include_str!("breez_lifecycle_qualification.rs");
    let forbidden = [".send", "_payment("].concat();
    assert!(!source.contains(&forbidden));
    assert!(source.contains(".prepare_send_payment("));
}
