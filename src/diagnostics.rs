//! Backend lifecycle diagnostics shared by the CLI and command-level tests.

use serde_json::{Value, json};

use crate::payers::base::{PaymentError, RealPayer};

/// Exercise backend connection/readiness and cleanup without constructing an
/// invoice or entering the payment method at all.
pub async fn doctor_with_payer<P: RealPayer + ?Sized>(backend: &str, payer: &P) -> Value {
    let readiness = payer.check_ready().await;
    let cleanup = payer.disconnect().await;
    match (readiness, cleanup) {
        (Ok(()), Ok(())) => json!({
            "ok": true,
            "backend": backend,
            "configValid": true,
            "envSecretsAvailable": true,
            "backendReady": true,
            "capabilities": {
                "preimageRequired": true,
                "maxFeeLimitSupported": true,
            }
        }),
        (_, Err(_)) => diagnostic_error(
            backend,
            (
                "PAYER_BACKEND_CLEANUP_FAILED",
                "payer backend cleanup failed",
            ),
        ),
        (Err(error), Ok(())) => diagnostic_error(backend, classify(error)),
    }
}

pub(crate) fn diagnostic_error(backend: &str, error: (&'static str, &'static str)) -> Value {
    json!({
        "ok": false,
        "paid": false,
        "backend": backend,
        "error": {"code": error.0, "message": error.1}
    })
}

pub(crate) fn classify(error: PaymentError) -> (&'static str, &'static str) {
    match error {
        PaymentError::Timeout => ("PAYER_BACKEND_TIMEOUT", "payer backend timed out"),
        PaymentError::Unsupported | PaymentError::NotImplemented => (
            "PAYER_BACKEND_UNSUPPORTED_FEE_LIMIT",
            "selected payer backend cannot enforce the configured fee limit",
        ),
        PaymentError::InvalidInput => (
            "PAYER_BACKEND_SELECTION_FAILED",
            "payer backend configuration or storage is unavailable",
        ),
        _ => ("PAYER_BACKEND_UNREACHABLE", "payer backend is unavailable"),
    }
}
