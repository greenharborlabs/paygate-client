//! The narrow security boundary between an untrusted HTTP challenge and a payer.
//!
//! In particular, a payer factory is not called until the invoice, challenge,
//! and local policy have all been accepted.  Keeping that sequencing here makes
//! it difficult for future HTTP code to accidentally open a wallet for an
//! invalid challenge.

use crate::challenge::{ChallengeError, ParsedChallenge, normalize_payment_challenge};
use crate::credentials::{CredentialError, CredentialTemplate, build_l402_authorization};
use crate::error::DomainError;
use crate::payers::base::{
    CancellationSemantics, PaymentAttemptOutcome, PaymentError, PostSubmitCondition, RealPayer,
    verify_payment_result,
};
use crate::policy::{PolicyApproval, PolicyConfig, PolicyError, bind_policy};
use crate::state::ledger::{DailySpendLedger, LedgerError, LedgerMutationOutcome};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionError {
    Challenge,
    Policy,
    Reservation,
    ReservationBudget,
    ReservationDuplicate,
    Payer,
    SubmissionUnknown,
    Proof,
    Credential,
    Rollback,
    Commit,
    PostSubmit,
}

#[derive(Clone, Debug)]
pub struct PaymentTransactionResult {
    pub paid: bool,
    pub authorization: Option<String>,
    pub payment_hash: Option<String>,
    pub fee_sats: Option<u64>,
    pub error: Option<TransactionError>,
    pub post_submit_conditions: Vec<PostSubmitCondition>,
    pub reservation_retained: bool,
    reservation: Option<crate::state::ledger::LedgerReservation>,
}

impl PaymentTransactionResult {
    fn failed(error: TransactionError, reservation_retained: bool) -> Self {
        Self {
            paid: false,
            authorization: None,
            payment_hash: None,
            fee_sats: None,
            error: Some(error),
            post_submit_conditions: Vec::new(),
            reservation_retained,
            reservation: None,
        }
    }

    /// Finalize a verified payment only after credential persistence has had
    /// its chance to fail closed. A failed commit leaves the guard pending.
    pub fn commit(&mut self) -> Result<(), TransactionError> {
        let Some(reservation) = self.reservation.as_mut() else {
            return Ok(());
        };
        match reservation.commit_classified() {
            LedgerMutationOutcome::AppliedDurably => {
                self.reservation = None;
                self.reservation_retained = false;
                Ok(())
            }
            LedgerMutationOutcome::AppliedWithDurabilityWarning => {
                self.reservation = None;
                self.reservation_retained = false;
                self.error = Some(TransactionError::Commit);
                Err(TransactionError::Commit)
            }
            LedgerMutationOutcome::NotApplied(_) => {
                self.error = Some(TransactionError::Commit);
                self.reservation_retained = true;
                Err(TransactionError::Commit)
            }
        }
    }

    pub const fn has_pending_guard(&self) -> bool {
        self.reservation.is_some()
    }
}

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

#[derive(Clone, Debug)]
pub struct PreparedChallenge {
    pub parsed: ParsedChallenge,
    pub approval: PolicyApproval,
    pub credential_template: CredentialTemplate,
}

pub fn prepare_challenge(
    challenge: &ParsedChallenge,
    host: &str,
    request_scope: &str,
    policy: &PolicyConfig,
    payer_supports_fee_limit: bool,
    source: Option<&str>,
) -> Result<PreparedChallenge, TransactionError> {
    let untrusted = untrusted_challenge(challenge, request_scope)?;
    let normalized = normalize_payment_challenge(
        &untrusted.invoice,
        untrusted.amount_sats,
        untrusted.payment_hash.as_deref(),
        untrusted.service,
        untrusted.request,
    )
    .map_err(|_| TransactionError::Challenge)?;
    let credential_template = CredentialTemplate::prepare(challenge, &normalized, source)
        .map_err(|_| TransactionError::Challenge)?;
    let approval = bind_policy(policy, host, normalized, payer_supports_fee_limit)
        .map_err(|_| TransactionError::Policy)?;
    Ok(PreparedChallenge {
        parsed: challenge.clone(),
        approval,
        credential_template,
    })
}

fn untrusted_challenge(
    challenge: &ParsedChallenge,
    request_scope: &str,
) -> Result<UntrustedPaymentChallenge, TransactionError> {
    match challenge {
        ParsedChallenge::Payment(value) => Ok(UntrustedPaymentChallenge {
            invoice: value.invoice.clone(),
            amount_sats: value.amount_sats,
            payment_hash: value.payment_hash.clone(),
            service: value.service.clone(),
            request: value.request.clone(),
        }),
        ParsedChallenge::L402(value) => crate::invoice::ValidatedBolt11::parse(&value.invoice)
            .map(|invoice| UntrustedPaymentChallenge {
                invoice: value.invoice.clone(),
                amount_sats: invoice.amount_sats(),
                payment_hash: Some(hex::encode(invoice.payment_hash())),
                service: None,
                request: request_scope.to_owned(),
            })
            .map_err(|_| TransactionError::Challenge),
    }
}

impl<F> RealPayerFactory<F> {
    pub fn new(supports_fee_limit: bool, construct: F) -> Self {
        Self {
            supports_fee_limit,
            construct,
        }
    }

    pub fn supports_fee_limit(&self) -> bool {
        self.supports_fee_limit
    }
}

/// Execute the payment half of a request as one monotonic ledger transaction.
/// The returned authorization can only exist after common proof verification.
pub async fn execute_payment_transaction<P, F>(
    challenge: &ParsedChallenge,
    host: &str,
    request_scope: &str,
    policy: &PolicyConfig,
    daily_budget_sats: u64,
    ledger: &DailySpendLedger,
    source: Option<&str>,
    factory: RealPayerFactory<F>,
) -> PaymentTransactionResult
where
    P: RealPayer,
    F: FnOnce(PolicyApproval) -> Result<P, PaymentError>,
{
    let prepared = match prepare_challenge(
        challenge,
        host,
        request_scope,
        policy,
        factory.supports_fee_limit,
        source,
    ) {
        Ok(value) => value,
        Err(error) => return PaymentTransactionResult::failed(error, false),
    };
    let approval = prepared.approval;
    let mut reservation = match ledger.reserve_guarded(
        approval.challenge().amount_sats(),
        daily_budget_sats,
        request_scope,
        approval.challenge().payment_hash(),
    ) {
        Ok(value) => value,
        Err(LedgerError::BudgetExceeded) => {
            return PaymentTransactionResult::failed(TransactionError::ReservationBudget, false);
        }
        Err(LedgerError::DuplicatePayment) => {
            return PaymentTransactionResult::failed(TransactionError::ReservationDuplicate, true);
        }
        Err(_) => return PaymentTransactionResult::failed(TransactionError::Reservation, false),
    };
    let payer = match (factory.construct)(approval.clone()) {
        Ok(value) => value,
        Err(_) => return rollback_failure(&mut reservation, TransactionError::Payer),
    };
    let mut outcome = match payer.check_ready().await {
        Ok(()) => {
            payer
                .pay(
                    approval.challenge().invoice(),
                    approval.max_fee_sats(),
                    CancellationSemantics::BeforeSubmission,
                )
                .await
        }
        Err(error) => PaymentAttemptOutcome::NotSubmitted(error),
    };
    if payer.disconnect().await.is_err() {
        match &mut outcome {
            PaymentAttemptOutcome::Confirmed { .. } => {
                outcome.add_post_submit_condition(PostSubmitCondition::DisconnectFailed)
            }
            PaymentAttemptOutcome::SubmittedUnknown(_) => {}
            PaymentAttemptOutcome::NotSubmitted(_)
            | PaymentAttemptOutcome::SubmittedFailedFinal(_) => {
                return rollback_failure(&mut reservation, TransactionError::Payer);
            }
        }
    }
    match outcome {
        PaymentAttemptOutcome::NotSubmitted(_) | PaymentAttemptOutcome::SubmittedFailedFinal(_) => {
            rollback_failure(&mut reservation, TransactionError::Payer)
        }
        PaymentAttemptOutcome::SubmittedUnknown(_) => {
            PaymentTransactionResult::failed(TransactionError::SubmissionUnknown, true)
        }
        PaymentAttemptOutcome::Confirmed {
            raw,
            post_submit_conditions,
        } => {
            let verified = match verify_payment_result(approval.challenge().invoice(), raw) {
                Ok(value) => value,
                Err(_) => return PaymentTransactionResult::failed(TransactionError::Proof, true),
            };
            let authorization = match prepared.credential_template.render(&verified) {
                Ok(value) => value,
                Err(_) => {
                    return PaymentTransactionResult {
                        paid: true,
                        authorization: None,
                        payment_hash: Some(hex::encode(verified.payment_hash())),
                        fee_sats: Some(verified.fee_sats()),
                        error: Some(TransactionError::Credential),
                        post_submit_conditions,
                        reservation_retained: true,
                        reservation: Some(reservation),
                    };
                }
            };
            let error = if !post_submit_conditions.is_empty() {
                Some(TransactionError::PostSubmit)
            } else {
                None
            };
            PaymentTransactionResult {
                paid: true,
                authorization: Some(authorization),
                payment_hash: Some(hex::encode(verified.payment_hash())),
                fee_sats: Some(verified.fee_sats()),
                error,
                post_submit_conditions,
                reservation_retained: true,
                reservation: Some(reservation),
            }
        }
    }
}

fn rollback_failure(
    reservation: &mut crate::state::ledger::LedgerReservation,
    primary: TransactionError,
) -> PaymentTransactionResult {
    match reservation.rollback_classified() {
        LedgerMutationOutcome::AppliedDurably => PaymentTransactionResult::failed(primary, false),
        LedgerMutationOutcome::AppliedWithDurabilityWarning => {
            PaymentTransactionResult::failed(TransactionError::Rollback, false)
        }
        LedgerMutationOutcome::NotApplied(_) => {
            PaymentTransactionResult::failed(TransactionError::Rollback, true)
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
    let mut outcome = match payer.check_ready().await {
        Ok(()) => {
            payer
                .pay(
                    approval.challenge().invoice(),
                    approval.max_fee_sats(),
                    CancellationSemantics::BeforeSubmission,
                )
                .await
        }
        Err(error) => PaymentAttemptOutcome::NotSubmitted(error),
    };

    // The operation owns lifecycle. Every constructed payer receives exactly
    // one awaited cleanup attempt, including failed readiness.
    if let Err(error) = payer.disconnect().await {
        match &mut outcome {
            PaymentAttemptOutcome::Confirmed { .. } => {
                outcome.add_post_submit_condition(PostSubmitCondition::DisconnectFailed);
            }
            // Cleanup failure cannot make an already-submitted ambiguous
            // payment retryable. Preserve the stronger submission state.
            PaymentAttemptOutcome::SubmittedUnknown(_) => {}
            PaymentAttemptOutcome::NotSubmitted(_)
            | PaymentAttemptOutcome::SubmittedFailedFinal(_) => {
                return Err(map_payment_error(error));
            }
        }
    }

    match outcome {
        PaymentAttemptOutcome::Confirmed {
            raw,
            post_submit_conditions,
        } => {
            // Proof validation has public precedence over every later
            // condition and remains the sole issuer of authorization-capable
            // payment material.
            let verified = verify_payment_result(approval.challenge().invoice(), raw)
                .map_err(map_payment_error)?;
            let authorization = build_l402_authorization(token, approval.challenge(), &verified)
                .map_err(map_credential_error)?;
            if post_submit_conditions.contains(&PostSubmitCondition::DisconnectFailed) {
                return Err(map_payment_error(PaymentError::Transport));
            }
            if post_submit_conditions.contains(&PostSubmitCondition::FinalFeeExceeded) {
                return Err(map_payment_error(PaymentError::FeeExceeded));
            }
            Ok(authorization)
        }
        PaymentAttemptOutcome::SubmittedUnknown(_) => Err(DomainError::SubmissionUnknown),
        PaymentAttemptOutcome::NotSubmitted(error)
        | PaymentAttemptOutcome::SubmittedFailedFinal(error) => Err(map_payment_error(error)),
    }
}

fn map_challenge_error(error: ChallengeError) -> DomainError {
    match error {
        ChallengeError::InvalidInvoice => DomainError::Invoice,
        ChallengeError::Malformed
        | ChallengeError::MissingInvoice
        | ChallengeError::AmountMismatch
        | ChallengeError::HashMismatch
        | ChallengeError::InvalidHash
        | ChallengeError::Unsupported
        | ChallengeError::ProtocolDisabled
        | ChallengeError::Expired => DomainError::Challenge,
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
        | PaymentError::InvalidCancellationState
        | PaymentError::FeeExceeded
        | PaymentError::MalformedResponse
        | PaymentError::Timeout
        | PaymentError::Unsupported
        | PaymentError::Transport => DomainError::PaymentProof,
    }
}

fn map_credential_error(_: CredentialError) -> DomainError {
    DomainError::Credential
}
