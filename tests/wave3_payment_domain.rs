use async_trait::async_trait;
use paygate::error::DomainError;
use paygate::orchestrator::{RealPayerFactory, UntrustedPaymentChallenge, submit_payment};
use paygate::payers::base::{
    CancellationSemantics, PaymentError, RawPaymentResult, RealPayer, SubmissionOutcome,
    ValidatedBolt11,
};
use paygate::policy::PolicyConfig;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const INVOICE: &str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";
const AMOUNTLESS: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";

fn policy() -> PolicyConfig {
    PolicyConfig {
        allowed_hosts: vec!["paygate.test:443".into()],
        allowed_services: vec!["svc".into()],
        max_request_sats: 3_000_000,
        max_fee_sats: 5,
    }
}

fn challenge(invoice: &str) -> UntrustedPaymentChallenge {
    let invoice = ValidatedBolt11::parse(invoice).ok();
    UntrustedPaymentChallenge {
        invoice: invoice
            .as_ref()
            .map_or_else(|| "not-an-invoice".into(), |i| i.original().into()),
        amount_sats: invoice.as_ref().map_or(1, ValidatedBolt11::amount_sats),
        payment_hash: invoice.map(|i| hex::encode(i.payment_hash())),
        service: Some("svc".into()),
        request: "/resource".into(),
    }
}

struct FakePayer {
    raw: RawPaymentResult,
    calls: Arc<AtomicUsize>,
}
#[async_trait]
impl RealPayer for FakePayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn pay(
        &self,
        _: &ValidatedBolt11,
        _: u64,
        cancellation: CancellationSemantics,
    ) -> Result<RawPaymentResult, PaymentError> {
        assert_eq!(cancellation, CancellationSemantics::BeforeSubmission);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.raw.clone())
    }
    async fn disconnect(&self) -> Result<(), PaymentError> {
        Ok(())
    }
}

#[tokio::test]
async fn invalid_inputs_never_construct_or_touch_a_payer() {
    for mut input in [
        challenge("not-an-invoice"),
        challenge(AMOUNTLESS),
        UntrustedPaymentChallenge {
            amount_sats: 0,
            ..challenge(INVOICE)
        },
        UntrustedPaymentChallenge {
            payment_hash: Some("00".repeat(32)),
            ..challenge(INVOICE)
        },
    ] {
        if input.invoice == "not-an-invoice" {
            input.amount_sats = 1;
        }
        let constructed = Arc::new(AtomicUsize::new(0));
        let touched = Arc::new(AtomicUsize::new(0));
        let made = constructed.clone();
        let seen = touched.clone();
        let result = submit_payment::<FakePayer, _>(
            input,
            "paygate.test:443",
            &policy(),
            "token",
            RealPayerFactory::new(true, move |_| {
                made.fetch_add(1, Ordering::SeqCst);
                Ok(FakePayer {
                    raw: impossible_raw(),
                    calls: seen,
                })
            }),
        )
        .await;
        assert!(matches!(
            result,
            Err(DomainError::Invoice | DomainError::Challenge)
        ));
        assert_eq!(constructed.load(Ordering::SeqCst), 0);
        assert_eq!(touched.load(Ordering::SeqCst), 0);
    }
}

fn impossible_raw() -> RawPaymentResult {
    RawPaymentResult {
        amount_sats: 0,
        fee_sats: 0,
        payment_hash: None,
        preimage_hex: None,
        outcome: SubmissionOutcome::FailedFinal,
    }
}

#[tokio::test]
async fn valid_binding_rejects_proof_mismatch_after_payer_submission() {
    let invoice = ValidatedBolt11::parse(INVOICE).unwrap();
    let preimage = [7_u8; 32];
    // The signed fixture's hash cannot be paired with an arbitrary preimage, so
    // this deliberately proves the raw verifier blocks credential issuance.
    let raw = RawPaymentResult {
        amount_sats: invoice.amount_sats(),
        fee_sats: 1,
        payment_hash: Some(hex::encode(invoice.payment_hash())),
        preimage_hex: Some(hex::encode(preimage)),
        outcome: SubmissionOutcome::Succeeded,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let result = submit_payment::<FakePayer, _>(
        challenge(INVOICE),
        "paygate.test:443",
        &policy(),
        "token",
        RealPayerFactory::new(true, move |_| Ok(FakePayer { raw, calls: seen })),
    )
    .await;
    assert_eq!(result, Err(DomainError::PaymentProof));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn raw_proof_fixture_is_deliberately_hash_bound() {
    assert_ne!(
        Sha256::digest([7_u8; 32]).as_slice(),
        ValidatedBolt11::parse(INVOICE).unwrap().payment_hash()
    );
}
