//! Rust cutover crate. Modules are intentionally skeletal until their owning wave.

pub mod challenge;
pub mod cli;
pub mod config;
pub mod credentials;
pub mod diagnostics;
pub mod error;
pub mod http;
pub mod invoice;
pub mod orchestrator;
pub mod payers;
pub mod policy;
pub mod redaction;
pub mod serialization;
pub mod state;
pub mod trace;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
