use serde_json::json;

use crate::cli::BackendCommand;
use crate::commands::{CommandResult, config_error};
use crate::config::{expand_path, load_config};

pub async fn run(command: BackendCommand) -> CommandResult {
    let config = match &command {
        BackendCommand::Doctor { config, .. } | BackendCommand::PayInvoice { config, .. } => config,
    };
    let loaded = load_config(expand_path(config)).map_err(config_error)?;
    match command {
        BackendCommand::Doctor { .. } if loaded.payer.backend == "test-mode" => Ok(
            json!({"ok": true, "backend": "test-mode", "capabilities": {"maxFeeLimitSupported": true}}),
        ),
        BackendCommand::Doctor { .. } => Err((
            "backend_unavailable",
            "selected backend execution is unavailable",
        )),
        BackendCommand::PayInvoice {
            invoice,
            max_fee_sats,
            ..
        } => {
            if invoice.trim().is_empty() || max_fee_sats == Some(0) {
                return Err(("invalid_request", "invalid payment input"));
            }
            Err((
                "execution_unavailable",
                "validated payment execution requires the payment runtime",
            ))
        }
    }
}
