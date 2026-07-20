//! The narrow security boundary between an untrusted HTTP challenge and a payer.
//!
//! In particular, a payer factory is not called until the invoice, challenge,
//! and local policy have all been accepted.  Keeping that sequencing here makes
//! it difficult for future HTTP code to accidentally open a wallet for an
//! invalid challenge.

use crate::challenge::{ChallengeError, normalize_payment_challenge};
use crate::credentials::{CredentialError, build_l402_authorization};
use crate::error::DomainError;
use crate::payers::base::{CancellationSemantics, PaymentError, RealPayer, verify_payment_result};
use crate::policy::{PolicyApproval, PolicyConfig, PolicyError, bind_policy};

/// Fields received from a remote payment challenge.  They are data, not a
/// payment capability, until [`submit_payment`] has normalized and bound them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UntrustedPaymentChallenge {
    pub invoice: String,
    pub amount_sats: u64,
    pub payment_hash: Option<String>,
    pub service: Option<String>,
    pub request: String,
}

/// Adapter-owned capability used to delay wallet/payer construction until policy
/// has approved the exact normalized challenge.
pub struct RealPayerFactory<F> {
    supports_fee_limit: bool,
    construct: F,
}

impl<F> RealPayerFactory<F> {
    pub fn new(supports_fee_limit: bool, construct: F) -> Self {
        Self {
            supports_fee_limit,
            construct,
        }
    }
}

/// Validate, authorize, submit, verify, and turn a payment into an L402 value.
///
/// `construct` is deliberately invoked after policy binding.  No payer method,
/// wallet access, or network operation is reachable for invalid input.
pub async fn submit_payment<P, F>(
    challenge: UntrustedPaymentChallenge,
    host: &str,
    policy: &PolicyConfig,
    token: &str,
    factory: RealPayerFactory<F>,
) -> Result<String, DomainError>
where
    P: RealPayer,
    F: FnOnce(PolicyApproval) -> Result<P, PaymentError>,
{
    let normalized = normalize_payment_challenge(
        &challenge.invoice,
        challenge.amount_sats,
        challenge.payment_hash.as_deref(),
        challenge.service,
        challenge.request,
    )
    .map_err(map_challenge_error)?;
    let approval = bind_policy(policy, host, normalized, factory.supports_fee_limit)
        .map_err(map_policy_error)?;

    let payer = (factory.construct)(approval.clone()).map_err(map_payment_error)?;
    payer.check_ready().await.map_err(map_payment_error)?;
    let raw = payer
        .pay(
            approval.challenge().invoice(),
            approval.max_fee_sats(),
            CancellationSemantics::BeforeSubmission,
        )
        .await
        .map_err(map_payment_error)?;
    let verified =
        verify_payment_result(approval.challenge().invoice(), raw).map_err(map_payment_error)?;
    build_l402_authorization(token, approval.challenge(), &verified).map_err(map_credential_error)
}

fn map_challenge_error(error: ChallengeError) -> DomainError {
    match error {
        ChallengeError::InvalidInvoice => DomainError::Invoice,
        ChallengeError::Malformed
        | ChallengeError::MissingInvoice
        | ChallengeError::AmountMismatch
        | ChallengeError::HashMismatch
        | ChallengeError::InvalidHash => DomainError::Challenge,
    }
}

fn map_policy_error(_: PolicyError) -> DomainError {
    DomainError::Policy
}

fn map_payment_error(error: PaymentError) -> DomainError {
    match error {
        PaymentError::AmbiguousSubmission => DomainError::SubmissionUnknown,
        PaymentError::NotImplemented
        | PaymentError::InvalidInput
        | PaymentError::ProofMismatch
        | PaymentError::MissingProof
        | PaymentError::InvalidCancellationState => DomainError::PaymentProof,
    }
}

fn map_credential_error(_: CredentialError) -> DomainError {
    DomainError::Credential
}
