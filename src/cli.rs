//! Public command-line grammar and request-input validation.
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

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
pub async fn run_cli(cli: Cli) -> i32 {
    let result = match cli.command {
        Some(Command::Request(args)) => crate::commands::request::run(args).await,
        Some(Command::Backend { command }) => crate::commands::backend::run(command).await,
        Some(Command::Credentials { command }) => crate::commands::credentials::run(command).await,
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
