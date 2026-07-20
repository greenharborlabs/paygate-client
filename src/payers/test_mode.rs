//! Deterministic, deliberately non-real payment support.

use sha2::{Digest, Sha256};

use super::base::{PaymentError, RawPaymentResult, SubmissionOutcome, SyntheticPaymentChallenge};

/// A test-only payer. It intentionally does not implement `RealPayer`: that
/// prevents a signed BOLT11 invoice from ever receiving synthetic proof data.
#[derive(Clone, Debug, Default)]
pub struct TestModePayer;

impl TestModePayer {
    pub fn check_ready(&self) -> Result<(), PaymentError> {
        Ok(())
    }

    /// Generate deterministic material from the synthetic challenge only.
    pub fn pay(&self, challenge: &SyntheticPaymentChallenge) -> RawPaymentResult {
        let preimage = Sha256::digest(
            [
                b"paygate-test-mode-v1".as_slice(),
                challenge.payment_hash_hex().as_bytes(),
                &challenge.amount_sats().to_le_bytes(),
            ]
            .concat(),
        );
        let payment_hash = Sha256::digest(preimage);
        RawPaymentResult {
            amount_sats: challenge.amount_sats(),
            fee_sats: 0,
            payment_hash: Some(hex::encode(payment_hash)),
            preimage_hex: Some(hex::encode(preimage)),
            outcome: SubmissionOutcome::Succeeded,
        }
    }
}

pub fn qualification_stub() -> Result<(), PaymentError> {
    Ok(())
}
