//! Async command dispatch modules. The process owns the single Tokio runtime;
//! command handlers never construct or block on a nested runtime.

pub mod backend;
pub mod credentials;
pub mod request;

pub type CommandResult = Result<serde_json::Value, (&'static str, &'static str)>;

pub(crate) fn config_error(_: crate::config::ConfigError) -> (&'static str, &'static str) {
    ("config_invalid", "configuration is invalid or unavailable")
}
