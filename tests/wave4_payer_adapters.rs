use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use paygate::error::DomainError;
use paygate::orchestrator::{RealPayerFactory, UntrustedPaymentChallenge, submit_payment};
use paygate::payers::SyntheticPaymentChallenge;
use paygate::payers::base::{
    CancellationSemantics, PaymentError, RawPaymentResult, RealPayer, SubmissionOutcome,
    ValidatedBolt11, verify_payment_result,
};
use paygate::payers::breez::{
    BreezSparkPayer, BreezSparkSdk, BreezStorage, PreparedPayment, SparkPaymentResult,
};
use paygate::payers::lnd_rest::{
    LndPaymentEvent, LndPaymentRequest, LndRestPayer, LndRestTransport,
};
use paygate::payers::phoenixd::PhoenixdPayer;
use paygate::payers::test_mode::TestModePayer;
use paygate::policy::PolicyConfig;
use sha2::{Digest, Sha256};

const INVOICE: &str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";

#[derive(Default)]
struct FakeLnd {
    request: Mutex<Option<LndPaymentRequest>>,
    events: Vec<LndPaymentEvent>,
}
#[async_trait]
impl LndRestTransport for FakeLnd {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        Ok(())
    }
    async fn stream_payment(
        &self,
        request: LndPaymentRequest,
    ) -> Result<Vec<LndPaymentEvent>, PaymentError> {
        *self.request.lock().unwrap() = Some(request);
        Ok(self.events.clone())
    }
    async fn disconnect(&self) -> Result<(), PaymentError> {
        Ok(())
    }
}

#[tokio::test]
async fn lnd_uses_fee_bound_request_without_redirects_and_requires_terminal_result() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    let fake = FakeLnd {
        request: Mutex::new(None),
        events: vec![
            LndPaymentEvent::InFlight,
            LndPaymentEvent::Succeeded {
                amount_sats: invoice.amount_sats(),
                fee_sats: 2,
                payment_hash: hex::encode(invoice.payment_hash()),
                preimage_hex: "00".repeat(32),
            },
        ],
    };
    let payer = LndRestPayer::new(fake);
    assert_eq!(
        payer
            .pay(&invoice, 1, CancellationSemantics::BeforeSubmission)
            .await,
        Err(PaymentError::FeeExceeded)
    );
    let request = payer.transport().request.lock().unwrap().clone().unwrap();
    assert!(!request.follow_redirects);
    assert_eq!(request.max_fee_sats, 1);
}

#[tokio::test]
async fn lnd_ambiguous_cancellation_never_touches_transport() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    let payer = LndRestPayer::new(FakeLnd::default());
    let result = payer
        .pay(&invoice, 1, CancellationSemantics::AfterSubmissionUnknown)
        .await
        .unwrap();
    assert_eq!(result.outcome, SubmissionOutcome::SubmittedUnknown);
    assert!(payer.transport().request.lock().unwrap().is_none());
}

#[tokio::test]
async fn lnd_rejects_malformed_and_nonterminal_streams_without_network() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    for (events, expected) in [
        (vec![], PaymentError::MalformedResponse),
        (vec![LndPaymentEvent::InFlight], PaymentError::Timeout),
    ] {
        let payer = LndRestPayer::new(FakeLnd {
            request: Mutex::new(None),
            events,
        });
        assert_eq!(
            payer
                .pay(&invoice, 1, CancellationSemantics::BeforeSubmission)
                .await,
            Err(expected)
        );
    }
}

#[tokio::test]
async fn lnd_successful_terminal_response_still_requires_invoice_bound_proof() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    let payer = LndRestPayer::new(FakeLnd {
        request: Mutex::new(None),
        events: vec![LndPaymentEvent::Succeeded {
            amount_sats: invoice.amount_sats(),
            fee_sats: 1,
            payment_hash: hex::encode(invoice.payment_hash()),
            preimage_hex: "00".repeat(32),
        }],
    });
    let raw = payer
        .pay(&invoice, 1, CancellationSemantics::BeforeSubmission)
        .await
        .unwrap();
    assert_eq!(raw.outcome, SubmissionOutcome::Succeeded);
    assert_eq!(
        verify_payment_result(&invoice, raw),
        Err(PaymentError::ProofMismatch)
    );
}

struct FakeSpark {
    calls: Arc<Mutex<Vec<&'static str>>>,
    fee: u64,
    disconnect_error: Arc<AtomicBool>,
    result: Option<SparkPaymentResult>,
}
#[async_trait]
impl BreezSparkSdk for FakeSpark {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        self.calls.lock().unwrap().push("ready");
        Ok(())
    }
    async fn prepare_bolt11(&self, _: &str) -> Result<PreparedPayment, PaymentError> {
        self.calls.lock().unwrap().push("prepare");
        Ok(PreparedPayment {
            id: "p".into(),
            fee_sats: self.fee,
        })
    }
    async fn send_prepared(&self, _: &PreparedPayment) -> Result<SparkPaymentResult, PaymentError> {
        self.calls.lock().unwrap().push("send");
        Ok(self.result.clone().unwrap_or(SparkPaymentResult {
            amount_sats: 2_500_000,
            fee_sats: self.fee,
            payment_hash: None,
            preimage_hex: None,
            outcome: SubmissionOutcome::FailedFinal,
        }))
    }
    async fn disconnect(&self) -> Result<(), PaymentError> {
        self.calls.lock().unwrap().push("disconnect");
        if self.disconnect_error.load(Ordering::Acquire) {
            Err(PaymentError::Transport)
        } else {
            Ok(())
        }
    }
}

#[tokio::test]
async fn breez_claims_storage_and_enforces_prepared_fee_before_send() {
    let path = std::env::temp_dir().join(format!("paygate-wave4-{}", std::process::id()));
    let storage = BreezStorage::acquire(&path).unwrap();
    assert!(BreezStorage::acquire(&path).is_err());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = BreezSparkPayer::new(
        FakeSpark {
            calls: calls.clone(),
            fee: 2,
            disconnect_error: Arc::new(AtomicBool::new(false)),
            result: None,
        },
        storage,
    );
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    assert_eq!(
        payer
            .pay(&invoice, 1, CancellationSemantics::BeforeSubmission)
            .await,
        Err(PaymentError::FeeExceeded)
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec!["ready", "prepare", "disconnect"]
    );
    drop(payer);
    assert!(BreezStorage::acquire(&path).is_ok());
    let _ = std::fs::remove_dir(&path);
}

#[tokio::test]
async fn breez_failed_disconnect_keeps_storage_claim_until_a_successful_retry() {
    let path = std::env::temp_dir().join(format!("paygate-wave4-cleanup-{}", std::process::id()));
    let storage = BreezStorage::acquire(&path).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = BreezSparkPayer::new(
        FakeSpark {
            calls: calls.clone(),
            fee: 0,
            disconnect_error: Arc::new(AtomicBool::new(true)),
            result: None,
        },
        storage,
    );
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    assert_eq!(
        payer
            .pay(&invoice, 1, CancellationSemantics::BeforeSubmission)
            .await,
        Err(PaymentError::Transport)
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec!["ready", "prepare", "send", "disconnect"]
    );
    assert!(BreezStorage::acquire(&path).is_err());
    drop(payer);
    assert!(BreezStorage::acquire(&path).is_err());
    // The intentionally unreleased marker is removed by this test's teardown,
    // only after proving that dropping did not release it.
    std::fs::remove_file(path.join(".paygate-breez-owner.lock")).unwrap();
    let _ = std::fs::remove_dir(&path);
}

#[tokio::test]
async fn breez_successful_disconnect_retry_releases_storage_claim() {
    let path = std::env::temp_dir().join(format!("paygate-wave4-retry-{}", std::process::id()));
    let storage = BreezStorage::acquire(&path).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let disconnect_error = Arc::new(AtomicBool::new(true));
    let payer = BreezSparkPayer::new(
        FakeSpark {
            calls,
            fee: 0,
            disconnect_error: disconnect_error.clone(),
            result: None,
        },
        storage,
    );
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    assert_eq!(
        payer
            .pay(&invoice, 1, CancellationSemantics::BeforeSubmission)
            .await,
        Err(PaymentError::Transport)
    );
    assert!(BreezStorage::acquire(&path).is_err());
    disconnect_error.store(false, Ordering::Release);
    payer.disconnect().await.unwrap();
    assert!(BreezStorage::acquire(&path).is_ok());
    drop(payer);
    let _ = std::fs::remove_dir(&path);
}

fn matching_invoice() -> (ValidatedBolt11, String) {
    let preimage = [7_u8; 32];
    let payment_hash = sha256::Hash::hash(&preimage);
    let key = SecretKey::from_slice(&[42_u8; 32]).unwrap();
    let secp = Secp256k1::new();
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description("paygate Breez fake success".into())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(1_000)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
        .unwrap();
    (
        ValidatedBolt11::parse(invoice.to_string()).unwrap(),
        hex::encode(preimage),
    )
}

#[tokio::test]
async fn breez_fake_success_authorizes_only_with_invoice_bound_proof() {
    let (invoice, preimage_hex) = matching_invoice();
    let path = std::env::temp_dir().join(format!("paygate-wave4-success-{}", std::process::id()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let result = SparkPaymentResult {
        amount_sats: invoice.amount_sats(),
        fee_sats: 0,
        payment_hash: Some(hex::encode(invoice.payment_hash())),
        preimage_hex: Some(preimage_hex),
        outcome: SubmissionOutcome::Succeeded,
    };
    let made_calls = calls.clone();
    let storage_path = path.clone();
    let authorization = submit_payment::<BreezSparkPayer<FakeSpark>, _>(
        UntrustedPaymentChallenge {
            invoice: invoice.original().into(),
            amount_sats: invoice.amount_sats(),
            payment_hash: Some(hex::encode(invoice.payment_hash())),
            service: Some("svc".into()),
            request: "/resource".into(),
        },
        "paygate.test:443",
        &PolicyConfig {
            allowed_hosts: vec!["paygate.test:443".into()],
            allowed_services: vec!["svc".into()],
            max_request_sats: 3_000_000,
            max_fee_sats: 1,
        },
        "token",
        RealPayerFactory::new(true, move |_| {
            Ok(BreezSparkPayer::new(
                FakeSpark {
                    calls: made_calls,
                    fee: 0,
                    disconnect_error: Arc::new(AtomicBool::new(false)),
                    result: Some(result),
                },
                BreezStorage::acquire(&storage_path).unwrap(),
            ))
        }),
    )
    .await;
    assert!(authorization.unwrap().starts_with("L402 token:"));
    assert_eq!(
        *calls.lock().unwrap(),
        vec!["ready", "ready", "prepare", "send", "disconnect"]
    );
    assert!(BreezStorage::acquire(&path).is_ok());
    let _ = std::fs::remove_dir(&path);
}

struct CleanupPayer(Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl RealPayer for CleanupPayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        self.0.lock().unwrap().push("ready");
        Ok(())
    }

    async fn pay(
        &self,
        invoice: &ValidatedBolt11,
        _: u64,
        _: CancellationSemantics,
    ) -> Result<RawPaymentResult, PaymentError> {
        self.0.lock().unwrap().push("send");
        Ok(RawPaymentResult {
            amount_sats: invoice.amount_sats(),
            fee_sats: 0,
            payment_hash: Some(hex::encode(invoice.payment_hash())),
            preimage_hex: Some("00".repeat(32)),
            outcome: SubmissionOutcome::Succeeded,
        })
    }

    async fn disconnect(&self) -> Result<(), PaymentError> {
        self.0.lock().unwrap().push("disconnect");
        Ok(())
    }
}

#[tokio::test]
async fn submit_payment_disconnects_after_proof_verification_failure() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let made = calls.clone();
    let result = submit_payment::<CleanupPayer, _>(
        UntrustedPaymentChallenge {
            invoice: invoice.original().to_owned(),
            amount_sats: invoice.amount_sats(),
            payment_hash: Some(hex::encode(invoice.payment_hash())),
            service: Some("svc".into()),
            request: "/resource".into(),
        },
        "paygate.test:443",
        &PolicyConfig {
            allowed_hosts: vec!["paygate.test:443".into()],
            allowed_services: vec!["svc".into()],
            max_request_sats: 3_000_000,
            max_fee_sats: 1,
        },
        "token",
        RealPayerFactory::new(true, move |_| Ok(CleanupPayer(made))),
    )
    .await;
    assert_eq!(result, Err(DomainError::PaymentProof));
    assert_eq!(*calls.lock().unwrap(), vec!["ready", "send", "disconnect"]);
}

#[tokio::test]
async fn phoenixd_never_becomes_a_submission_path() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    let payer = PhoenixdPayer;
    assert_eq!(payer.check_ready().await, Err(PaymentError::Unsupported));
    assert_eq!(
        payer
            .pay(&invoice, 1, CancellationSemantics::BeforeSubmission)
            .await,
        Err(PaymentError::Unsupported)
    );
}

#[test]
fn test_mode_is_deterministic_and_not_bound_to_real_invoice_proof() {
    let challenge = SyntheticPaymentChallenge::new(3, "11".repeat(32), "22".repeat(32)).unwrap();
    let payer = TestModePayer;
    let first = payer.pay(&challenge);
    assert_eq!(first, payer.pay(&challenge));
    assert_ne!(
        first.payment_hash.as_deref().unwrap(),
        challenge.payment_hash_hex()
    );
    assert_eq!(
        first.payment_hash.as_deref().unwrap(),
        hex::encode(Sha256::digest(
            hex::decode(first.preimage_hex.unwrap()).unwrap()
        ))
    );
}
