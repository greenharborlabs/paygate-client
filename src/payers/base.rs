//! Shared payer contracts frozen before adapter implementation.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use crate::invoice::ValidatedBolt11;

/// A deterministic test-only challenge that cannot cross a real-payer boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticPaymentChallenge {
    amount_sats: u64,
    payment_hash_hex: String,
    preimage_hex: String,
}

impl SyntheticPaymentChallenge {
    pub fn new(
        amount_sats: u64,
        payment_hash_hex: String,
        preimage_hex: String,
    ) -> Result<Self, PaymentError> {
        decode_32(&payment_hash_hex, "synthetic payment hash")?;
        decode_32(&preimage_hex, "synthetic preimage")?;
        Ok(Self {
            amount_sats,
            payment_hash_hex,
            preimage_hex,
        })
    }

    pub fn amount_sats(&self) -> u64 {
        self.amount_sats
    }

    pub fn payment_hash_hex(&self) -> &str {
        &self.payment_hash_hex
    }

    pub fn preimage_hex(&self) -> &str {
        &self.preimage_hex
    }
}

/// Whether cancellation is still known to be safe or submission is ambiguous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationSemantics {
    BeforeSubmission,
    AfterSubmissionUnknown,
}

impl CancellationSemantics {
    /// A pre-submission cancellation is safe to retry; an interrupted submitted
    /// payment is deliberately ambiguous and must never be retried automatically.
    pub const fn retry_is_safe(self) -> bool {
        matches!(self, Self::BeforeSubmission)
    }

    pub const fn required_outcome(self) -> SubmissionOutcome {
        match self {
            Self::BeforeSubmission => SubmissionOutcome::NotSubmitted,
            Self::AfterSubmissionUnknown => SubmissionOutcome::SubmittedUnknown,
        }
    }
}

/// State the ledger must preserve after a payer attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionOutcome {
    NotSubmitted,
    SubmittedUnknown,
    Succeeded,
    FailedFinal,
}

/// Backend data remains untrusted until the common verifier succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPaymentResult {
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub payment_hash: Option<String>,
    pub preimage_hex: Option<String>,
    pub outcome: SubmissionOutcome,
}

/// Proof-bound payment result safe for credential construction.
///
/// Instances are issued only by [`verify_payment_result`], after binding backend proof material
/// to a validated invoice. Consumers can inspect the proof through the read-only accessors, but
/// cannot construct or alter it.
///
/// ```compile_fail
/// use paygate::payers::base::{SubmissionOutcome, VerifiedPaymentResult};
///
/// let _forged = VerifiedPaymentResult {
///     amount_sats: 21,
///     fee_sats: 0,
///     payment_hash: [0; 32],
///     preimage: [0; 32],
///     outcome: SubmissionOutcome::Succeeded,
/// };
/// ```
///
/// ```compile_fail
/// use paygate::payers::base::VerifiedPaymentResult;
///
/// fn corrupt(result: &mut VerifiedPaymentResult) {
///     result.amount_sats = 0;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPaymentResult {
    amount_sats: u64,
    fee_sats: u64,
    payment_hash: [u8; 32],
    preimage: [u8; 32],
    outcome: SubmissionOutcome,
}

impl VerifiedPaymentResult {
    pub fn amount_sats(&self) -> u64 {
        self.amount_sats
    }

    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    pub fn payment_hash(&self) -> &[u8; 32] {
        &self.payment_hash
    }

    pub fn preimage(&self) -> &[u8; 32] {
        &self.preimage
    }

    pub fn outcome(&self) -> SubmissionOutcome {
        self.outcome
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PaymentError {
    #[error("payer implementation is not available")]
    NotImplemented,
    #[error("payment input is invalid")]
    InvalidInput,
    #[error("payment proof does not match the validated invoice")]
    ProofMismatch,
    #[error("payment result is incomplete")]
    MissingProof,
    #[error("payment submission outcome is ambiguous")]
    AmbiguousSubmission,
    #[error("payment cancellation state is inconsistent")]
    InvalidCancellationState,
}

/// Check cancellation reports at the payment boundary.  In particular, callers
/// cannot accidentally treat an ambiguous post-submission cancellation as a
/// failed, retryable payment.
pub fn verify_cancellation(
    cancellation: CancellationSemantics,
    outcome: SubmissionOutcome,
) -> Result<(), PaymentError> {
    if outcome == cancellation.required_outcome() {
        return Ok(());
    }
    if cancellation == CancellationSemantics::AfterSubmissionUnknown
        || outcome == SubmissionOutcome::SubmittedUnknown
    {
        return Err(PaymentError::AmbiguousSubmission);
    }
    Err(PaymentError::InvalidCancellationState)
}

/// Object-safe asynchronous contract implemented only by real payer adapters.
#[async_trait]
pub trait RealPayer: Send + Sync {
    async fn check_ready(&self) -> Result<(), PaymentError>;

    async fn pay(
        &self,
        invoice: &ValidatedBolt11,
        max_fee_sats: u64,
        cancellation: CancellationSemantics,
    ) -> Result<RawPaymentResult, PaymentError>;

    async fn disconnect(&self) -> Result<(), PaymentError>;
}

pub fn verify_payment_result(
    invoice: &ValidatedBolt11,
    raw: RawPaymentResult,
) -> Result<VerifiedPaymentResult, PaymentError> {
    if raw.outcome != SubmissionOutcome::Succeeded {
        return Err(PaymentError::MissingProof);
    }
    if raw.amount_sats != invoice.amount_sats() {
        return Err(PaymentError::ProofMismatch);
    }
    let payment_hash = decode_32(
        raw.payment_hash
            .as_deref()
            .ok_or(PaymentError::MissingProof)?,
        "payment hash",
    )?;
    let preimage = decode_32(
        raw.preimage_hex
            .as_deref()
            .ok_or(PaymentError::MissingProof)?,
        "preimage",
    )?;
    if payment_hash != *invoice.payment_hash()
        || Sha256::digest(preimage).as_slice() != payment_hash
    {
        return Err(PaymentError::ProofMismatch);
    }
    Ok(VerifiedPaymentResult {
        amount_sats: raw.amount_sats,
        fee_sats: raw.fee_sats,
        payment_hash,
        preimage,
        outcome: raw.outcome,
    })
}

fn decode_32(value: &str, _field: &str) -> Result<[u8; 32], PaymentError> {
    let bytes = hex::decode(value).map_err(|_| PaymentError::InvalidInput)?;
    bytes.try_into().map_err(|_| PaymentError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_payment_result_exposes_read_only_proof_values() {
        let result = VerifiedPaymentResult {
            amount_sats: 21,
            fee_sats: 1,
            payment_hash: [2; 32],
            preimage: [3; 32],
            outcome: SubmissionOutcome::Succeeded,
        };

        assert_eq!(result.amount_sats(), 21);
        assert_eq!(result.fee_sats(), 1);
        assert_eq!(result.payment_hash(), &[2; 32]);
        assert_eq!(result.preimage(), &[3; 32]);
        assert_eq!(result.outcome(), SubmissionOutcome::Succeeded);
    }

    #[test]
    fn cancellation_after_submission_is_never_retry_safe() {
        assert!(CancellationSemantics::BeforeSubmission.retry_is_safe());
        assert!(!CancellationSemantics::AfterSubmissionUnknown.retry_is_safe());
        assert_eq!(
            verify_cancellation(
                CancellationSemantics::AfterSubmissionUnknown,
                SubmissionOutcome::NotSubmitted,
            ),
            Err(PaymentError::AmbiguousSubmission)
        );
    }

    #[test]
    fn verifier_rejects_payment_proof_mismatch() {
        let invoice = ValidatedBolt11::parse(
            "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu",
        )
        .expect("valid fixture");
        let raw = RawPaymentResult {
            amount_sats: invoice.amount_sats(),
            fee_sats: 0,
            payment_hash: Some(hex::encode(invoice.payment_hash())),
            preimage_hex: Some("00".repeat(32)),
            outcome: SubmissionOutcome::Succeeded,
        };

        assert_eq!(
            verify_payment_result(&invoice, raw),
            Err(PaymentError::ProofMismatch)
        );
    }
}
