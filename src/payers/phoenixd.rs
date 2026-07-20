//! Phoenixd is intentionally unsupported in this release.

use super::base::{
    CancellationSemantics, PaymentError, RawPaymentResult, RealPayer, ValidatedBolt11,
};
use async_trait::async_trait;

/// Fail-closed placeholder: it owns no endpoint or submission capability.
#[derive(Clone, Debug, Default)]
pub struct PhoenixdPayer;

#[async_trait]
impl RealPayer for PhoenixdPayer {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        Err(PaymentError::Unsupported)
    }
    async fn pay(
        &self,
        _invoice: &ValidatedBolt11,
        _max_fee_sats: u64,
        _cancellation: CancellationSemantics,
    ) -> Result<RawPaymentResult, PaymentError> {
        Err(PaymentError::Unsupported)
    }
    async fn disconnect(&self) -> Result<(), PaymentError> {
        Ok(())
    }
}

pub fn qualification_stub() -> Result<(), PaymentError> {
    Err(PaymentError::Unsupported)
}
