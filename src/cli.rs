//! Public command-line grammar and request-input validation.
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::config::{expand_path, load_config};
use crate::state::cache::FileCredentialCache;
use crate::state::ledger::DailySpendLedger;

pub const DEFAULT_CONFIG_PATH: &str = "~/.config/paygate-client/config.yaml";
#[derive(Debug, Parser)]
#[command(name = "paygate", about = "Paygate command-line client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[arg(long, global = true)]
    pub version: bool,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    Request(RequestArgs),
    Backend {
        #[command(subcommand)]
        command: BackendCommand,
    },
    Credentials {
        #[command(subcommand)]
        command: CredentialsCommand,
    },
}
#[derive(Debug, Args)]
pub struct RequestArgs {
    pub method: String,
    pub url: String,
    #[arg(short,long,default_value=DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,
    #[arg(long, alias = "data")]
    pub body: Option<String>,
    #[arg(long)]
    pub timeout: Option<f64>,
    #[arg(long)]
    pub no_pay: bool,
    #[arg(long)]
    pub refresh_credential: bool,
    #[arg(long)]
    pub no_cache: bool,
    #[arg(long, default_value = "default")]
    pub profile: String,
    #[arg(long)]
    pub cache_path: Option<PathBuf>,
    #[arg(long)]
    pub ledger_path: Option<PathBuf>,
    #[arg(long, default_value = "challenge-defined")]
    pub cache_policy: String,
    #[arg(long)]
    pub verbose: bool,
    #[arg(long)]
    pub trace_json: bool,
}
#[derive(Debug, Subcommand)]
pub enum BackendCommand {
    Doctor {
        #[arg(short,long,default_value=DEFAULT_CONFIG_PATH)]
        config: PathBuf,
        /// Retained for Python CLI compatibility. Output is always a JSON envelope.
        #[arg(long)]
        json: bool,
    },
    PayInvoice {
        invoice: String,
        #[arg(short,long,default_value=DEFAULT_CONFIG_PATH)]
        config: PathBuf,
        #[arg(long)]
        max_fee_sats: Option<u64>,
        /// Retained for Python CLI compatibility. Output is always a JSON envelope.
        #[arg(long)]
        json: bool,
    },
}
#[derive(Debug, Subcommand)]
pub enum CredentialsCommand {
    List {
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        cache_path: Option<PathBuf>,
    },
    Show {
        credential_id: String,
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        cache_path: Option<PathBuf>,
    },
    Purge {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        service: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, default_value = "default")]
        profile: String,
        #[arg(long)]
        cache_path: Option<PathBuf>,
    },
}

/// Safe Wave-3 CLI dispatcher.  It owns parsing-adjacent validation and state
/// setup, but intentionally does not perform HTTP or payment execution.
pub fn run_cli(cli: Cli) -> i32 {
    let result = match cli.command {
        Some(Command::Request(args)) => run_request(args),
        Some(Command::Backend { command }) => run_backend(command),
        Some(Command::Credentials { command }) => run_credentials(command),
        None => return 0,
    };
    match result {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err((code, message)) => {
            // All messages are fixed classifications; never echo command args,
            // paths, config parser text, invoices, or credential material.
            println!(
                "{}",
                json!({"ok": false, "paid": false, "error": {"code": code, "message": message}})
            );
            1
        }
    }
}

fn run_request(args: RequestArgs) -> Result<serde_json::Value, (&'static str, &'static str)> {
    parse_headers(&args.headers).map_err(|_| ("invalid_request", "invalid request input"))?;
    if args.method.trim().is_empty()
        || !args.url.starts_with("http://") && !args.url.starts_with("https://")
        || args.timeout.is_some_and(|v| !v.is_finite() || v <= 0.0)
    {
        return Err(("invalid_request", "invalid request input"));
    }
    let namespace = crate::state::normalize_namespace(Some(&args.profile))
        .map_err(|_| ("invalid_request", "invalid profile"))?;
    let config_path = expand_path(&args.config);
    load_config(&config_path).map_err(config_error)?;
    if !args.no_cache {
        let path = args.cache_path.map(expand_path).unwrap_or_else(|| {
            FileCredentialCache::default_path(Some(&namespace)).expect("validated namespace")
        });
        let cache = FileCredentialCache::new(path, Some(&namespace))
            .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
        cache
            .list()
            .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
    }
    let ledger_path = args.ledger_path.map(expand_path).unwrap_or_else(|| {
        DailySpendLedger::default_path(Some(&namespace)).expect("validated namespace")
    });
    let ledger = DailySpendLedger::new(ledger_path);
    ledger
        .spent_today()
        .map_err(|_| ("state_unavailable", "spend state is unavailable"))?;
    Err((
        "execution_unavailable",
        "validated execution requires the payment runtime",
    ))
}
fn run_backend(command: BackendCommand) -> Result<serde_json::Value, (&'static str, &'static str)> {
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
fn run_credentials(
    command: CredentialsCommand,
) -> Result<serde_json::Value, (&'static str, &'static str)> {
    let (profile, path) = match &command {
        CredentialsCommand::List {
            profile,
            cache_path,
        }
        | CredentialsCommand::Show {
            profile,
            cache_path,
            ..
        }
        | CredentialsCommand::Purge {
            profile,
            cache_path,
            ..
        } => (profile, cache_path),
    };
    let namespace = crate::state::normalize_namespace(Some(profile))
        .map_err(|_| ("invalid_request", "invalid profile"))?;
    let path = path.as_ref().map(expand_path).unwrap_or_else(|| {
        FileCredentialCache::default_path(Some(&namespace)).expect("validated namespace")
    });
    let cache = FileCredentialCache::new(path, Some(&namespace))
        .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
    let credentials = cache
        .list()
        .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
    match command {
        CredentialsCommand::List { .. } => Ok(
            json!({"ok": true, "credentials": credentials.into_iter().map(redacted_credential).collect::<Vec<_>>() }),
        ),
        CredentialsCommand::Show { credential_id, .. } => credentials
            .into_iter()
            .find(|c| c.credential_id == credential_id)
            .map(redacted_credential)
            .map(|c| json!({"ok": true, "credential": c}))
            .ok_or(("credential_not_found", "credential was not found")),
        CredentialsCommand::Purge { .. } => Err((
            "execution_unavailable",
            "credential deletion requires the payment runtime",
        )),
    }
}
fn redacted_credential(c: crate::state::cache::CachedCredential) -> serde_json::Value {
    // This is a public CLI contract, deliberately kept in lock-step with the
    // Python CachedCredential.redacted() shape.  Storage implementation
    // details are not part of that contract.
    json!({
        "id": c.credential_id,
        "scope": c.scope,
        "authorization": "[REDACTED_CREDENTIAL]",
        "createdAt": c.created_at,
        "expiresAt": c.expires_at,
        "maxUses": c.max_uses,
        "useCount": c.use_count,
        "lastSuccessAt": c.last_success_at,
        "lastRejectedAt": c.last_rejected_at,
        "paymentHash": c.payment_hash,
        "challengeId": c.challenge_id,
    })
}
fn config_error(_: crate::config::ConfigError) -> (&'static str, &'static str) {
    ("config_invalid", "configuration is invalid or unavailable")
}
pub fn parse_headers(headers: &[String]) -> Result<BTreeMap<String, String>, &'static str> {
    let mut out = BTreeMap::new();
    for header in headers {
        let (name, value) = header.split_once(':').ok_or("invalid header")?;
        if name.trim().is_empty() {
            return Err("invalid header");
        }
        out.insert(name.trim().into(), value.trim_start().into());
    }
    Ok(out)
}
