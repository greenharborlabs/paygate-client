//! Adapter exports and registry input frozen before Wave 4 implementations.

pub mod base;
pub mod breez;
pub mod lnd_rest;
pub mod phoenixd;
pub mod test_mode;

pub use base::{
    CancellationSemantics, PaymentError, RawPaymentResult, RealPayer, SubmissionOutcome,
    SyntheticPaymentChallenge, ValidatedBolt11, VerifiedPaymentResult, verify_payment_result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayerAdapter {
    TestMode,
    LndRest,
    Phoenixd,
    BreezSpark,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayerRegistryInput {
    pub adapter: PayerAdapter,
    pub namespace: String,
    pub credential_id: String,
}
