use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use paygate::commands::backend::pay_invoice_with_payer;
use paygate::config::{PayerConfig, PaygateConfig, PolicyConfig, ProtocolConfig};
use paygate::diagnostics::doctor_with_payer;
use paygate::payers::base::{
    CancellationSemantics, PaymentAttemptOutcome, PaymentError, PostSubmitCondition,
    RawPaymentResult, RealPayer, ValidatedBolt11,
};
use paygate::payers::breez::{
    BreezSparkPayer, BreezSparkSdk, BreezStorage, PreparedPayment, SparkPaymentResult,
};
use paygate::state::ledger::DailySpendLedger;

const AMOUNTLESS: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

struct FakePayer {
    calls: Arc<Mutex<Vec<&'static str>>>,
    outcome: PaymentAttemptOutcome,
    ready_error: Option<PaymentError>,
    disconnect_error: Option<PaymentError>,
}

#[async_trait]
impl RealPayer for FakePayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        self.calls.lock().unwrap().push("ready");
        self.ready_error.clone().map_or(Ok(()), Err)
    }

    async fn pay(
        &self,
        _: &ValidatedBolt11,
        _: u64,
        _: CancellationSemantics,
    ) -> PaymentAttemptOutcome {
        self.calls.lock().unwrap().push("pay");
        self.outcome.clone()
    }

    async fn disconnect(&self) -> Result<(), PaymentError> {
        self.calls.lock().unwrap().push("disconnect");
        self.disconnect_error.clone().map_or(Ok(()), Err)
    }
}

fn matching_invoice() -> (String, String, String) {
    let preimage = [7_u8; 32];
    let payment_hash = sha256::Hash::hash(&preimage);
    let key = SecretKey::from_slice(&[42_u8; 32]).unwrap();
    let secp = Secp256k1::new();
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description("paygate backend command".into())
        .payment_hash(payment_hash)
        .payment_secret(PaymentSecret([0; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .amount_milli_satoshis(1_000)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &key))
        .unwrap();
    (
        invoice.to_string(),
        payment_hash.to_string(),
        hex::encode(preimage),
    )
}

fn config() -> PaygateConfig {
    PaygateConfig {
        payer: PayerConfig {
            backend: "breez".into(),
        },
        breez: None,
        policy: PolicyConfig {
            max_request_sats: 10,
            max_fee_sats: 1,
            daily_budget_sats: 10,
            allowed_hosts: vec!["example.test:443".into()],
            allowed_services: vec!["orders".into()],
        },
        protocol: ProtocolConfig {
            preferred: "Payment".into(),
            allow_l402: false,
        },
    }
}

fn confirmed(payment_hash: &str, preimage: &str, fee_sats: u64) -> PaymentAttemptOutcome {
    PaymentAttemptOutcome::confirmed(RawPaymentResult {
        amount_sats: 1,
        fee_sats,
        payment_hash: Some(payment_hash.into()),
        preimage_hex: Some(preimage.into()),
    })
}

#[tokio::test]
async fn capped_payment_pays_once_verifies_redacts_and_commits() {
    let (invoice, payment_hash, preimage) = matching_invoice();
    let config = config();
    let root = std::env::temp_dir().join(format!("paygate-backend-command-{}", std::process::id()));
    let ledger = DailySpendLedger::new(root.join("ledger.json"));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = FakePayer {
        calls: calls.clone(),
        outcome: confirmed(&payment_hash, &preimage, 1),
        ready_error: None,
        disconnect_error: None,
    };

    let result = pay_invoice_with_payer(&config, &invoice, Some(1), &ledger, &payer).await;

    assert_eq!(
        result,
        serde_json::json!({
            "ok": true,
            "backend": "breez",
            "payment": {
                "amountSats": 1,
                "feeSats": 1,
                "paymentHash": payment_hash,
                "preimage": "[REDACTED_SECRET]",
            },
            "preimageVerified": true,
            "verificationSource": "invoice",
        })
    );
    assert!(!result.to_string().contains(&preimage));
    assert_eq!(*calls.lock().unwrap(), vec!["ready", "pay", "disconnect"]);
    assert_eq!(ledger.spent_today().unwrap(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn doctor_checks_readiness_and_disconnects_without_paying() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = FakePayer {
        calls: calls.clone(),
        outcome: PaymentAttemptOutcome::NotSubmitted(PaymentError::NotImplemented),
        ready_error: None,
        disconnect_error: None,
    };

    let result = doctor_with_payer("breez", &payer).await;

    assert_eq!(result["ok"], true);
    assert_eq!(result["capabilities"]["preimageRequired"], true);
    assert_eq!(result["capabilities"]["maxFeeLimitSupported"], true);
    assert_eq!(*calls.lock().unwrap(), vec!["ready", "disconnect"]);
}

#[tokio::test]
async fn doctor_cleanup_failure_is_classified_and_never_pays() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = FakePayer {
        calls: calls.clone(),
        outcome: PaymentAttemptOutcome::NotSubmitted(PaymentError::NotImplemented),
        ready_error: None,
        disconnect_error: Some(PaymentError::Transport),
    };

    let result = doctor_with_payer("breez", &payer).await;

    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "PAYER_BACKEND_CLEANUP_FAILED");
    assert_eq!(*calls.lock().unwrap(), vec!["ready", "disconnect"]);
}

#[tokio::test]
async fn ambiguous_submission_is_never_retried_and_keeps_budget() {
    let (invoice, _, _) = matching_invoice();
    let root =
        std::env::temp_dir().join(format!("paygate-backend-ambiguous-{}", std::process::id()));
    let ledger = DailySpendLedger::new(root.join("ledger.json"));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = FakePayer {
        calls: calls.clone(),
        outcome: PaymentAttemptOutcome::SubmittedUnknown(PaymentError::AmbiguousSubmission),
        ready_error: None,
        disconnect_error: None,
    };

    let result = pay_invoice_with_payer(&config(), &invoice, Some(1), &ledger, &payer).await;

    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "PAYER_BACKEND_SUBMISSION_UNKNOWN");
    assert_eq!(*calls.lock().unwrap(), vec!["ready", "pay", "disconnect"]);
    assert_eq!(ledger.spent_today().unwrap(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn confirmed_final_fee_failure_stays_paid_and_exposes_only_redacted_proof() {
    let (invoice, payment_hash, preimage) = matching_invoice();
    let root =
        std::env::temp_dir().join(format!("paygate-backend-final-fee-{}", std::process::id()));
    let ledger = DailySpendLedger::new(root.join("ledger.json"));
    let mut outcome = confirmed(&payment_hash, &preimage, 2);
    outcome.add_post_submit_condition(PostSubmitCondition::FinalFeeExceeded);
    let payer = FakePayer {
        calls: Arc::new(Mutex::new(Vec::new())),
        outcome,
        ready_error: None,
        disconnect_error: None,
    };

    let result = pay_invoice_with_payer(&config(), &invoice, Some(1), &ledger, &payer).await;

    assert_eq!(result["ok"], false);
    assert_eq!(result["paid"], true);
    assert_eq!(result["error"]["code"], "PAYER_BACKEND_FEE_LIMIT_EXCEEDED");
    assert_eq!(result["payment"]["preimage"], "[REDACTED_SECRET]");
    assert!(!result.to_string().contains(&preimage));
    assert_eq!(ledger.spent_today().unwrap(), 1);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn invalid_invoice_and_fee_policy_fail_before_touching_payer_or_ledger() {
    let (invoice, _, _) = matching_invoice();
    let root =
        std::env::temp_dir().join(format!("paygate-backend-precheck-{}", std::process::id()));
    let ledger = DailySpendLedger::new(root.join("ledger.json"));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = FakePayer {
        calls: calls.clone(),
        outcome: PaymentAttemptOutcome::NotSubmitted(PaymentError::NotImplemented),
        ready_error: None,
        disconnect_error: None,
    };

    for (candidate, cap) in [
        (AMOUNTLESS, Some(1)),
        (invoice.as_str(), Some(0)),
        (invoice.as_str(), Some(2)),
    ] {
        let result = pay_invoice_with_payer(&config(), candidate, cap, &ledger, &payer).await;
        assert_eq!(result["ok"], false);
    }
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(ledger.spent_today().unwrap(), 0);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn ambiguous_submission_with_disconnect_failure_keeps_unknown_primary_classification() {
    let (invoice, _, _) = matching_invoice();
    let root = std::env::temp_dir().join(format!(
        "paygate-backend-ambiguous-cleanup-{}",
        std::process::id()
    ));
    let ledger = DailySpendLedger::new(root.join("ledger.json"));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = FakePayer {
        calls: calls.clone(),
        outcome: PaymentAttemptOutcome::SubmittedUnknown(PaymentError::AmbiguousSubmission),
        ready_error: None,
        disconnect_error: Some(PaymentError::Transport),
    };

    let result = pay_invoice_with_payer(&config(), &invoice, Some(1), &ledger, &payer).await;

    assert_eq!(result["ok"], false);
    assert_eq!(result["error"]["code"], "PAYER_BACKEND_SUBMISSION_UNKNOWN");
    assert_eq!(*calls.lock().unwrap(), vec!["ready", "pay", "disconnect"]);
    assert_eq!(ledger.spent_today().unwrap(), 1);
    let _ = std::fs::remove_dir_all(root);
}

struct HighQuoteSdk {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl BreezSparkSdk for HighQuoteSdk {
    type Prepared = ();

    async fn check_ready(&self) -> Result<(), PaymentError> {
        self.calls.lock().unwrap().push("ready");
        Ok(())
    }

    async fn prepare_bolt11(
        &self,
        _: &str,
    ) -> Result<PreparedPayment<Self::Prepared>, PaymentError> {
        self.calls.lock().unwrap().push("prepare");
        Ok(PreparedPayment::new(2, ()))
    }

    async fn send_prepared(&self, _: Self::Prepared) -> Result<SparkPaymentResult, PaymentError> {
        self.calls.lock().unwrap().push("send");
        Err(PaymentError::Transport)
    }

    async fn disconnect(&self) -> Result<(), PaymentError> {
        self.calls.lock().unwrap().push("disconnect");
        Ok(())
    }
}

#[tokio::test]
async fn quote_over_effective_cap_is_rejected_before_send_and_releases_budget() {
    let (invoice, _, _) = matching_invoice();
    let root =
        std::env::temp_dir().join(format!("paygate-backend-high-quote-{}", std::process::id()));
    let storage = BreezStorage::acquire(root.join("wallet")).unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payer = BreezSparkPayer::new(
        HighQuoteSdk {
            calls: calls.clone(),
        },
        storage,
    );
    let ledger = DailySpendLedger::new(root.join("ledger.json"));

    let result = pay_invoice_with_payer(&config(), &invoice, Some(1), &ledger, &payer).await;

    assert_eq!(result["ok"], false);
    assert_eq!(
        result["error"]["code"],
        "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT"
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec!["ready", "prepare", "disconnect"]
    );
    assert_eq!(ledger.spent_today().unwrap(), 0);
    drop(payer);
    let _ = std::fs::remove_dir_all(root);
}
