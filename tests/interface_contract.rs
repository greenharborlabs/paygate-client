use async_trait::async_trait;
use paygate::payers::base::{
    CancellationSemantics, PaymentError, RawPaymentResult, RealPayer, SubmissionOutcome,
    SyntheticPaymentChallenge, ValidatedBolt11, VerifiedPaymentResult, verify_payment_result,
};
use paygate::payers::{PayerAdapter, PayerRegistryInput};

fn assert_send<T: Send>(_: T) {}

struct ContractPayer;

#[async_trait]
impl RealPayer for ContractPayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        Ok(())
    }

    async fn pay(
        &self,
        _invoice: &ValidatedBolt11,
        _max_fee_sats: u64,
        _cancellation: CancellationSemantics,
    ) -> Result<RawPaymentResult, PaymentError> {
        Err(PaymentError::NotImplemented)
    }

    async fn disconnect(&self) -> Result<(), PaymentError> {
        Ok(())
    }
}

#[test]
fn shared_interfaces_are_implementable_without_functional_payment() {
    let payer = ContractPayer;
    assert_send(payer.check_ready());
    assert_send(payer.disconnect());

    let synthetic = SyntheticPaymentChallenge::new(21, "00".repeat(32), "11".repeat(32))
        .expect("well-formed synthetic challenge");
    assert_eq!(synthetic.amount_sats(), 21);

    let registry = PayerRegistryInput {
        adapter: PayerAdapter::BreezSpark,
        namespace: "default".to_owned(),
        credential_id: "primary".to_owned(),
    };
    assert_eq!(registry.adapter, PayerAdapter::BreezSpark);

    let raw = RawPaymentResult {
        amount_sats: 21,
        fee_sats: 1,
        payment_hash: Some("00".repeat(32)),
        preimage_hex: Some("11".repeat(32)),
        outcome: SubmissionOutcome::FailedFinal,
    };
    let verify: fn(
        &ValidatedBolt11,
        RawPaymentResult,
    ) -> Result<VerifiedPaymentResult, PaymentError> = verify_payment_result;
    let _ = (raw, verify);
}

#[test]
fn submission_outcomes_are_exhaustive_and_cancellation_is_explicit() {
    let outcomes = [
        SubmissionOutcome::NotSubmitted,
        SubmissionOutcome::SubmittedUnknown,
        SubmissionOutcome::Succeeded,
        SubmissionOutcome::FailedFinal,
    ];
    assert_eq!(outcomes.len(), 4);
    assert_eq!(
        CancellationSemantics::BeforeSubmission,
        CancellationSemantics::BeforeSubmission
    );
    assert_eq!(
        CancellationSemantics::AfterSubmissionUnknown,
        CancellationSemantics::AfterSubmissionUnknown
    );
}

#[test]
fn verified_payment_result_exposes_only_read_only_accessor_contracts() {
    let _amount_sats: fn(&VerifiedPaymentResult) -> u64 = VerifiedPaymentResult::amount_sats;
    let _fee_sats: fn(&VerifiedPaymentResult) -> u64 = VerifiedPaymentResult::fee_sats;
    let _payment_hash: fn(&VerifiedPaymentResult) -> &[u8; 32] =
        VerifiedPaymentResult::payment_hash;
    let _preimage: fn(&VerifiedPaymentResult) -> &[u8; 32] = VerifiedPaymentResult::preimage;
    let _outcome: fn(&VerifiedPaymentResult) -> SubmissionOutcome = VerifiedPaymentResult::outcome;
}
