use crate::cli::{RequestArgs, parse_headers};
use crate::commands::{CommandResult, config_error};
use crate::config::{expand_path, load_config};
use crate::state::cache::FileCredentialCache;
use crate::state::ledger::DailySpendLedger;

pub async fn run(args: RequestArgs) -> CommandResult {
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
        FileCredentialCache::new(path, Some(&namespace))
            .map_err(|_| ("state_unavailable", "credential state is unavailable"))?
            .list()
            .map_err(|_| ("state_unavailable", "credential state is unavailable"))?;
    }
    let ledger_path = args.ledger_path.map(expand_path).unwrap_or_else(|| {
        DailySpendLedger::default_path(Some(&namespace)).expect("validated namespace")
    });
    DailySpendLedger::new(ledger_path)
        .spent_today()
        .map_err(|_| ("state_unavailable", "spend state is unavailable"))?;
    Err((
        "execution_unavailable",
        "validated execution requires the payment runtime",
    ))
}
