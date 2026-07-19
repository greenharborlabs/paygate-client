//! Phoenixd adapter stub.

use super::base::PaymentError;

pub fn qualification_stub() -> Result<(), PaymentError> {
    Err(PaymentError::NotImplemented)
}
