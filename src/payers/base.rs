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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPaymentResult {
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub payment_hash: [u8; 32],
    pub preimage: [u8; 32],
    pub outcome: SubmissionOutcome,
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
