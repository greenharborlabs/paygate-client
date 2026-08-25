use serde_json::{Value, json};

use crate::cli::BackendCommand;
use crate::commands::CommandResult;
use crate::config::{ConfigError, PaygateConfig, expand_path, load_config};
use crate::diagnostics::{classify, diagnostic_error, doctor_with_payer};
use crate::invoice::ValidatedBolt11;
use crate::payers::base::{
    CancellationSemantics, LedgerAction, PaymentAttemptOutcome, PaymentError, PostSubmitCondition,
    RealPayer, verify_payment_result,
};
use crate::payers::breez::BreezSparkPayer;
use crate::state::ledger::{DailySpendLedger, LedgerError};

pub async fn run(command: BackendCommand) -> CommandResult {
    let config = match &command {
        BackendCommand::Doctor { config, .. } | BackendCommand::PayInvoice { config, .. } => config,
    };
    let loaded = load_config(expand_path(config)).map_err(|error| match error {
        ConfigError::MissingSecret(_) => (
            "PAYGATE_SECRET_MISSING",
            "required payer secret is unavailable",
        ),
        _ => (
            "PAYGATE_CONFIG_INVALID",
            "configuration is invalid or unavailable",
        ),
    })?;
    match command {
        BackendCommand::Doctor { .. } if loaded.payer.backend == "test-mode" => Ok(json!({
            "ok": true,
            "backend": "test-mode",
            "configValid": true,
            "envSecretsAvailable": true,
            "backendReady": true,
            "capabilities": {"preimageRequired": true, "maxFeeLimitSupported": true}
        })),
        BackendCommand::Doctor { .. } if loaded.payer.backend == "breez" => {
            let backend = loaded.payer.backend.clone();
            let Some(config) = loaded.breez else {
                return Ok(diagnostic_error(
                    &backend,
                    (
                        "PAYGATE_CONFIG_INVALID",
                        "configuration is invalid or unavailable",
                    ),
                ));
            };
            let payer = match BreezSparkPayer::production(config) {
                Ok(payer) => payer,
                Err(error) => return Ok(diagnostic_error(&backend, classify(error))),
            };
            Ok(doctor_with_payer(&backend, &payer).await)
        }
        BackendCommand::Doctor { .. } => Ok(diagnostic_error(
            &loaded.payer.backend,
            (
                "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
                "selected payer backend is unsupported for this operation",
            ),
        )),
        BackendCommand::PayInvoice {
            invoice,
            max_fee_sats,
            ..
        } => {
            let backend = loaded.payer.backend.clone();
            if backend != "breez" {
                return Ok(diagnostic_error(
                    &backend,
                    (
                        "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
                        "selected payer backend is unsupported for this operation",
                    ),
                ));
            }
            let Some(breez) = loaded.breez.clone() else {
                return Ok(diagnostic_error(
                    &backend,
                    (
                        "PAYGATE_CONFIG_INVALID",
                        "configuration is invalid or unavailable",
                    ),
                ));
            };
            // Acquire exclusive wallet ownership only after every purely local
            // invoice/policy check has passed.
            if let Err(error) = validate_payment_input(&loaded, &invoice, max_fee_sats) {
                return Ok(error);
            }
            let payer = match BreezSparkPayer::production(breez) {
                Ok(payer) => payer,
                Err(error) => return Ok(diagnostic_error(&backend, classify(error))),
            };
            let ledger_path = DailySpendLedger::default_path(Some("default"))
                .map_err(|_| ("state_unavailable", "payment state is unavailable"))?;
            let ledger = DailySpendLedger::new(ledger_path);
            Ok(pay_invoice_with_payer(&loaded, &invoice, max_fee_sats, &ledger, &payer).await)
        }
    }
}

fn validate_payment_input(
    config: &PaygateConfig,
    invoice: &str,
    requested_fee_cap: Option<u64>,
) -> Result<(ValidatedBolt11, u64), Value> {
    let parsed = ValidatedBolt11::parse(invoice).map_err(|_| {
        diagnostic_error(
            &config.payer.backend,
            (
                "PAYER_BACKEND_MALFORMED_RESPONSE",
                "invoice must be a valid amount-bearing BOLT11 invoice",
            ),
        )
    })?;
    if parsed.amount_sats() == 0 || parsed.amount_sats() > config.policy.max_request_sats {
        return Err(diagnostic_error(
            &config.payer.backend,
            (
                "policy_denied",
                "invoice amount exceeds the configured request limit",
            ),
        ));
    }
    let effective_fee_cap = requested_fee_cap.unwrap_or(config.policy.max_fee_sats);
    if effective_fee_cap == 0 || effective_fee_cap > config.policy.max_fee_sats {
        return Err(diagnostic_error(
            &config.payer.backend,
            (
                "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
                "requested fee limit is outside configured policy",
            ),
        ));
    }
    Ok((parsed, effective_fee_cap))
}

/// Execute one standalone bounded attempt. The payer is injected so command
/// tests can observe lifecycle and submission counts without SDK/network use.
pub async fn pay_invoice_with_payer<P: RealPayer + ?Sized>(
    config: &PaygateConfig,
    invoice: &str,
    requested_fee_cap: Option<u64>,
    ledger: &DailySpendLedger,
    payer: &P,
) -> Value {
    let backend = &config.payer.backend;
    if backend != "breez" {
        return diagnostic_error(
            backend,
            (
                "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
                "selected payer backend is unsupported for this operation",
            ),
        );
    }
    let (invoice, fee_cap) = match validate_payment_input(config, invoice, requested_fee_cap) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mut reservation =
        match ledger.reserve(invoice.amount_sats(), config.policy.daily_budget_sats) {
            Ok(reservation) => reservation,
            Err(LedgerError::BudgetExceeded) => {
                return diagnostic_error(
                    backend,
                    ("policy_denied", "daily payment budget would be exceeded"),
                );
            }
            Err(_) => {
                return diagnostic_error(
                    backend,
                    ("state_unavailable", "payment state is unavailable"),
                );
            }
        };

    if let Err(error) = payer.check_ready().await {
        let cleanup = payer.disconnect().await;
        let rollback = reservation.rollback();
        if cleanup.is_err() || rollback.is_err() {
            return diagnostic_error(
                backend,
                (
                    "PAYER_BACKEND_CLEANUP_FAILED",
                    "payer backend cleanup failed",
                ),
            );
        }
        return diagnostic_error(backend, classify(error));
    }

    let mut outcome = payer
        .pay(&invoice, fee_cap, CancellationSemantics::BeforeSubmission)
        .await;
    if payer.disconnect().await.is_err() {
        match &mut outcome {
            PaymentAttemptOutcome::Confirmed { .. } => {
                outcome.add_post_submit_condition(PostSubmitCondition::DisconnectFailed);
            }
            // Cleanup cannot weaken an already-ambiguous submission into a
            // merely operational failure. The budget remains committed below,
            // and the public classification continues to forbid repayment.
            PaymentAttemptOutcome::SubmittedUnknown(_) => {}
            PaymentAttemptOutcome::NotSubmitted(_)
            | PaymentAttemptOutcome::SubmittedFailedFinal(_) => {
                let state = finish_reservation(&mut reservation, outcome.ledger_action());
                if state.is_err() {
                    return diagnostic_error(
                        backend,
                        ("state_unavailable", "payment state is unavailable"),
                    );
                }
                return diagnostic_error(
                    backend,
                    (
                        "PAYER_BACKEND_CLEANUP_FAILED",
                        "payer backend cleanup failed",
                    ),
                );
            }
        }
    }

    let state_result = finish_reservation(&mut reservation, outcome.ledger_action());
    match outcome {
        PaymentAttemptOutcome::Confirmed {
            raw,
            post_submit_conditions,
        } => {
            let verified = match verify_payment_result(&invoice, raw) {
                Ok(verified) => verified,
                Err(_) => {
                    return json!({
                        "ok": false, "paid": true, "backend": backend,
                        "error": {"code": "PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED", "message": "payment proof verification failed"}
                    });
                }
            };
            let payment = json!({
                "amountSats": verified.amount_sats(),
                "feeSats": verified.fee_sats(),
                "paymentHash": hex::encode(verified.payment_hash()),
                "preimage": "[REDACTED_SECRET]",
            });
            let error = if state_result.is_err() {
                Some((
                    "PAYER_STATE_COMMIT_FAILED",
                    "confirmed payment state could not be committed",
                ))
            } else if post_submit_conditions.contains(&PostSubmitCondition::DisconnectFailed) {
                Some((
                    "PAYER_BACKEND_CLEANUP_FAILED",
                    "confirmed payment cleanup failed",
                ))
            } else if post_submit_conditions.contains(&PostSubmitCondition::FinalFeeExceeded) {
                Some((
                    "PAYER_BACKEND_FEE_LIMIT_EXCEEDED",
                    "confirmed payment fee exceeded policy",
                ))
            } else {
                None
            };
            match error {
                Some((code, message)) => json!({
                    "ok": false, "paid": true, "backend": backend,
                    "payment": payment, "preimageVerified": true,
                    "verificationSource": "invoice",
                    "error": {"code": code, "message": message}
                }),
                None => json!({
                    "ok": true, "backend": backend,
                    "payment": payment, "preimageVerified": true,
                    "verificationSource": "invoice"
                }),
            }
        }
        PaymentAttemptOutcome::SubmittedUnknown(_) => diagnostic_error(
            backend,
            (
                "PAYER_BACKEND_SUBMISSION_UNKNOWN",
                "payment submission outcome is unknown and must not be retried",
            ),
        ),
        PaymentAttemptOutcome::NotSubmitted(error)
        | PaymentAttemptOutcome::SubmittedFailedFinal(error) => {
            if state_result.is_err() {
                diagnostic_error(
                    backend,
                    ("state_unavailable", "payment state is unavailable"),
                )
            } else {
                diagnostic_error(backend, classify_payment(error))
            }
        }
    }
}

fn finish_reservation(
    reservation: &mut crate::state::ledger::LedgerReservation,
    action: LedgerAction,
) -> Result<(), LedgerError> {
    match action {
        LedgerAction::Commit => reservation.commit(),
        LedgerAction::Release => reservation.rollback(),
    }
}

fn classify_payment(error: PaymentError) -> (&'static str, &'static str) {
    match error {
        PaymentError::FeeExceeded => (
            "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
            "prepared fee exceeds configured limit",
        ),
        PaymentError::Timeout => ("PAYER_BACKEND_TIMEOUT", "payer backend timed out"),
        PaymentError::AmbiguousSubmission => (
            "PAYER_BACKEND_SUBMISSION_UNKNOWN",
            "payment submission outcome is unknown and must not be retried",
        ),
        PaymentError::MissingProof => (
            "PAYER_BACKEND_MISSING_PREIMAGE",
            "payer backend returned incomplete payment proof",
        ),
        PaymentError::ProofMismatch => (
            "PAYER_BACKEND_PREIMAGE_VERIFICATION_FAILED",
            "payment proof verification failed",
        ),
        _ => (
            "PAYER_BACKEND_PAYMENT_REJECTED",
            "payer backend rejected the payment",
        ),
    }
}
