//! Public domain errors deliberately contain classifications, never input or proof material.

use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    #[error("invoice validation failed")]
    Invoice,
    #[error("challenge validation failed")]
    Challenge,
    #[error("payment policy rejected request")]
    Policy,
    #[error("payment proof verification failed")]
    PaymentProof,
    #[error("credential construction failed")]
    Credential,
    #[error("payment submission outcome is unknown")]
    SubmissionUnknown,
}
