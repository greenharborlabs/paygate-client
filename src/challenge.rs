//! Challenge normalization.  Strings received from an HTTP header are never a
//! payment capability; they must be bound to a [`ValidatedBolt11`].

use crate::invoice::{InvoiceError, ValidatedBolt11};
use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChallengeError {
    #[error("payment challenge is malformed")]
    Malformed,
    #[error("payment challenge is missing an invoice")]
    MissingInvoice,
    #[error("payment challenge amount does not match the invoice")]
    AmountMismatch,
    #[error("payment challenge hash does not match the invoice")]
    HashMismatch,
    #[error("payment challenge hash is malformed")]
    InvalidHash,
    #[error("payment challenge invoice is invalid")]
    InvalidInvoice,
}

impl From<InvoiceError> for ChallengeError {
    fn from(_: InvoiceError) -> Self {
        Self::InvalidInvoice
    }
}

/// Payment input whose amount and hash are both signed by the BOLT11 invoice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedPaymentChallenge {
    invoice: ValidatedBolt11,
    service: Option<String>,
    request: String,
}

impl NormalizedPaymentChallenge {
    pub fn invoice(&self) -> &ValidatedBolt11 {
        &self.invoice
    }
    pub fn amount_sats(&self) -> u64 {
        self.invoice.amount_sats()
    }
    pub fn payment_hash(&self) -> &[u8; 32] {
        self.invoice.payment_hash()
    }
    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }
    pub fn request(&self) -> &str {
        &self.request
    }
}

/// Normalize separately parsed challenge fields before policy or payer use.
pub fn normalize_payment_challenge(
    invoice: &str,
    challenge_amount_sats: u64,
    challenge_payment_hash: Option<&str>,
    service: Option<String>,
    request: String,
) -> Result<NormalizedPaymentChallenge, ChallengeError> {
    if invoice.is_empty() {
        return Err(ChallengeError::MissingInvoice);
    }
    let invoice = ValidatedBolt11::parse(invoice)?;
    if challenge_amount_sats != invoice.amount_sats() {
        return Err(ChallengeError::AmountMismatch);
    }
    if let Some(hash) = challenge_payment_hash {
        let bytes = hex::decode(hash).map_err(|_| ChallengeError::InvalidHash)?;
        let hash: [u8; 32] = bytes.try_into().map_err(|_| ChallengeError::InvalidHash)?;
        if hash != *invoice.payment_hash() {
            return Err(ChallengeError::HashMismatch);
        }
    }
    Ok(NormalizedPaymentChallenge {
        invoice,
        service,
        request,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHOLE_SAT_INVOICE: &str = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdeessp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q5sqqqqqqqqqqqqqqqpqsq67gye39hfg3zd8rgc80k32tvy9xk2xunwm5lzexnvpx6fd77en8qaq424dxgt56cag2dpt359k3ssyhetktkpqh24jqnjyw6uqd08sgptq44qu";

    #[test]
    fn rejects_challenge_amount_and_hash_mismatches() {
        let invoice = ValidatedBolt11::parse(WHOLE_SAT_INVOICE).expect("valid fixture");
        assert_eq!(
            normalize_payment_challenge(
                WHOLE_SAT_INVOICE,
                invoice.amount_sats() + 1,
                None,
                None,
                "/resource".to_owned(),
            ),
            Err(ChallengeError::AmountMismatch)
        );
        assert_eq!(
            normalize_payment_challenge(
                WHOLE_SAT_INVOICE,
                invoice.amount_sats(),
                Some(&"00".repeat(32)),
                None,
                "/resource".to_owned(),
            ),
            Err(ChallengeError::HashMismatch)
        );
    }
}
