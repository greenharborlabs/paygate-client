//! Credential construction from verified proofs only.

use crate::challenge::NormalizedPaymentChallenge;
use crate::payers::base::VerifiedPaymentResult;
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialError {
    #[error("credential token is invalid")]
    InvalidToken,
    #[error("payment proof does not belong to the selected challenge")]
    ProofMismatch,
}

/// Build an L402 value without exposing proof data through errors.
pub fn build_l402_authorization(
    token: &str,
    challenge: &NormalizedPaymentChallenge,
    payment: &VerifiedPaymentResult,
) -> Result<String, CredentialError> {
    if token.is_empty()
        || token.contains([':', ',', '\r', '\n'])
        || token.chars().any(char::is_control)
    {
        return Err(CredentialError::InvalidToken);
    }
    if payment.payment_hash() != challenge.payment_hash() {
        return Err(CredentialError::ProofMismatch);
    }
    Ok(format!("L402 {token}:{}", hex::encode(payment.preimage())))
}
