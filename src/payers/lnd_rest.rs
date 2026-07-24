//! LND REST payment adapter with an injectable transport.
//!
//! The transport boundary is intentionally small: production HTTP code can use
//! it without exposing a `reqwest::Client` (and its credential/redirect policy)
//! to tests, while fake transports can model streamed status transitions.

use async_trait::async_trait;

use super::base::{
    CancellationSemantics, PaymentError, RawPaymentResult, RealPayer, SubmissionOutcome,
    ValidatedBolt11,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LndPaymentRequest {
    pub bolt11: String,
    pub max_fee_sats: u64,
    /// Must remain false for authenticated LND requests.
    pub follow_redirects: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LndPaymentEvent {
    InFlight,
    Succeeded {
        amount_sats: u64,
        fee_sats: u64,
        payment_hash: String,
        preimage_hex: String,
    },
    FailedFinal,
}

#[async_trait]
pub trait LndRestTransport: Send + Sync {
    async fn check_ready(&self) -> Result<(), PaymentError>;
    /// Returns the complete sequence received from LND's streaming endpoint.
    async fn stream_payment(
        &self,
        request: LndPaymentRequest,
    ) -> Result<Vec<LndPaymentEvent>, PaymentError>;
    async fn disconnect(&self) -> Result<(), PaymentError>;
}

pub struct LndRestPayer<T> {
    transport: T,
}

impl<T> LndRestPayer<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

#[async_trait]
impl<T: LndRestTransport> RealPayer for LndRestPayer<T> {
    async fn check_ready(&self) -> Result<(), PaymentError> {
        self.transport.check_ready().await
    }

    async fn pay(
        &self,
        invoice: &ValidatedBolt11,
        max_fee_sats: u64,
        cancellation: CancellationSemantics,
    ) -> Result<RawPaymentResult, PaymentError> {
        // The caller uses this explicit value to report a cancellation. It is
        // never converted into a retry-safe final failure.
        if cancellation == CancellationSemantics::AfterSubmissionUnknown {
            return Ok(unknown());
        }
        let events = self
            .transport
            .stream_payment(LndPaymentRequest {
                bolt11: invoice.original().to_owned(),
                max_fee_sats,
                follow_redirects: false,
            })
            .await?;
        let terminal = events.last().ok_or(PaymentError::MalformedResponse)?;
        match terminal {
            LndPaymentEvent::Succeeded {
                amount_sats,
                fee_sats,
                payment_hash,
                preimage_hex,
            } => {
                if *fee_sats > max_fee_sats {
                    return Err(PaymentError::FeeExceeded);
                }
                Ok(RawPaymentResult {
                    amount_sats: *amount_sats,
                    fee_sats: *fee_sats,
                    payment_hash: Some(payment_hash.clone()),
                    preimage_hex: Some(preimage_hex.clone()),
                    outcome: SubmissionOutcome::Succeeded,
                })
            }
            LndPaymentEvent::FailedFinal => Ok(RawPaymentResult {
                amount_sats: invoice.amount_sats(),
                fee_sats: 0,
                payment_hash: None,
                preimage_hex: None,
                outcome: SubmissionOutcome::FailedFinal,
            }),
            LndPaymentEvent::InFlight => Err(PaymentError::Timeout),
        }
    }

    async fn disconnect(&self) -> Result<(), PaymentError> {
        self.transport.disconnect().await
    }
}

fn unknown() -> RawPaymentResult {
    RawPaymentResult {
        amount_sats: 0,
        fee_sats: 0,
        payment_hash: None,
        preimage_hex: None,
        outcome: SubmissionOutcome::SubmittedUnknown,
    }
}

pub fn qualification_stub() -> Result<(), PaymentError> {
    Ok(())
}
