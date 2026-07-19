//! Breez Spark adapter stub. No wallet is opened in Wave 2 production code.

use super::base::PaymentError;

pub fn qualification_stub() -> Result<(), PaymentError> {
    Err(PaymentError::NotImplemented)
}
