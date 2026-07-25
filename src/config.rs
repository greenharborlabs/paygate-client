//! Safe YAML configuration input boundary.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle, Scanner, StrInput, TokenType};
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("config file not found")]
    Missing,
    #[error("invalid configuration")]
    Invalid,
    #[error("unknown payer backend")]
    UnknownBackend,
    #[error("required environment value is missing: {0}")]
    MissingSecret(String),
    #[error(transparent)]
    Input(#[from] ConfigInputError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvRef(pub String);
impl EnvRef {
    pub fn resolve(&self, env: &HashMap<String, String>) -> Result<String, ConfigError> {
        env.get(&self.0)
            .filter(|v| !v.is_empty())
            .cloned()
            .ok_or_else(|| ConfigError::MissingSecret(self.0.clone()))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayerConfig {
    pub backend: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyConfig {
    pub max_request_sats: u64,
    pub max_fee_sats: u64,
    pub daily_budget_sats: u64,
    pub allowed_hosts: Vec<String>,
    pub allowed_services: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolConfig {
    pub preferred: String,
    pub allow_l402: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaygateConfig {
    pub payer: PayerConfig,
    pub policy: PolicyConfig,
    pub protocol: ProtocolConfig,
}

/// Expand the only shell-like spelling accepted at filesystem boundaries.  We
/// deliberately do not expand environment variables or `~other`, which would
/// make config interpretation depend on a shell.
pub fn expand_path(path: impl AsRef<Path>) -> PathBuf {
    let path = path.as_ref();
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if text == "~" || text.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(text.strip_prefix("~/").unwrap_or(""));
        }
    }
    path.to_path_buf()
}

/// Load config with process environment taking precedence over `voltage-env.sh`.
pub fn load_config(path: impl AsRef<Path>) -> Result<PaygateConfig, ConfigError> {
    let expanded = expand_path(path);
    let path = expanded.as_path();
    let bytes = fs::read(path).map_err(|_| ConfigError::Missing)?;
    let raw: serde_json::Value = from_safe_yaml(&bytes)?;
    let root = raw.as_object().ok_or(ConfigError::Invalid)?;
    let payer = root
        .get("payer")
        .and_then(serde_json::Value::as_object)
        .ok_or(ConfigError::Invalid)?;
    let backend = string(payer, "backend")?;
    if !matches!(
        backend.as_str(),
        "test-mode" | "phoenixd" | "lnd-rest" | "breez"
    ) {
        return Err(ConfigError::UnknownBackend);
    }
    // Resolve references for the selected backend only.  Values never enter
    // the returned configuration, keeping Debug/display and CLI errors safe.
    validate_selected_backend(root, &backend, &load_config_env(path))?;
    let policy = root
        .get("policy")
        .and_then(serde_json::Value::as_object)
        .ok_or(ConfigError::Invalid)?;
    let max_request_sats = number(policy, "max_request_sats")?;
    let max_fee_sats = number(policy, "max_fee_sats")?;
    let daily_budget_sats = number(policy, "daily_budget_sats")?;
    if max_request_sats > daily_budget_sats {
        return Err(ConfigError::Invalid);
    }
    let allowed_hosts = strings(policy, "allowed_hosts")?;
    let allowed_services = strings(policy, "allowed_services")?;
    if allowed_hosts.is_empty() || allowed_services.is_empty() {
        return Err(ConfigError::Invalid);
    }
    let protocol = match root.get("protocol") {
        None | Some(serde_json::Value::Null) => ProtocolConfig {
            preferred: "Payment".into(),
            allow_l402: false,
        },
        Some(v) => {
            let p = v.as_object().ok_or(ConfigError::Invalid)?;
            let preferred = p
                .get("preferred")
                .map(|_| string(p, "preferred"))
                .transpose()?
                .unwrap_or_else(|| "Payment".into());
            let allow_l402 = p
                .get("allow_l402")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !matches!(preferred.as_str(), "Payment" | "L402")
                || (preferred == "L402" && !allow_l402)
            {
                return Err(ConfigError::Invalid);
            }
            ProtocolConfig {
                preferred,
                allow_l402,
            }
        }
    };
    Ok(PaygateConfig {
        payer: PayerConfig { backend },
        policy: PolicyConfig {
            max_request_sats,
            max_fee_sats,
            daily_budget_sats,
            allowed_hosts,
            allowed_services,
        },
        protocol,
    })
}

pub fn load_config_env(path: impl AsRef<Path>) -> HashMap<String, String> {
    let expanded = expand_path(path);
    let path = expanded.as_path();
    let mut result = HashMap::new();
    if let Ok(text) = fs::read_to_string(
        path.parent()
            .unwrap_or_else(|| Path::new("."))
            .join("voltage-env.sh"),
    ) {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("export ") {
                if let Some((key, value)) = rest.split_once('=') {
                    if key.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
                        && key
                            .chars()
                            .next()
                            .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
                    {
                        result.insert(key.into(), value.trim_matches(['\'', '"']).into());
                    }
                }
            }
        }
    }
    result.extend(std::env::vars());
    result
}
fn validate_selected_backend(
    root: &serde_json::Map<String, serde_json::Value>,
    backend: &str,
    env: &HashMap<String, String>,
) -> Result<(), ConfigError> {
    let (section, required): (&str, &[&str]) = match backend {
        "test-mode" => return Ok(()),
        "phoenixd" => ("phoenixd", &["password_env"]),
        "lnd-rest" => ("lnd", &["rest_url_env", "macaroon_hex_env"]),
        "breez" => ("breez", &["api_key_env", "mnemonic_env"]),
        _ => return Err(ConfigError::UnknownBackend),
    };
    let values = root
        .get(section)
        .and_then(serde_json::Value::as_object)
        .ok_or(ConfigError::Invalid)?;
    for key in required {
        let variable = string(values, key)?;
        EnvRef(variable).resolve(env)?;
    }
    Ok(())
}
fn string(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, ConfigError> {
    map.get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned)
        .ok_or(ConfigError::Invalid)
}
fn number(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> Result<u64, ConfigError> {
    map.get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or(ConfigError::Invalid)
}
fn strings(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>, ConfigError> {
    map.get(key)
        .and_then(serde_json::Value::as_array)
        .ok_or(ConfigError::Invalid)?
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or(ConfigError::Invalid)
        })
        .collect()
}

/// A deliberately redacted configuration error. Source bytes and parser diagnostics are not
/// retained because configuration can contain credentials.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigInputError {
    #[error("configuration is not valid UTF-8")]
    Utf8,
    #[error("configuration is empty")]
    Empty,
    #[error("configuration contains a disallowed YAML construct: {0}")]
    Unsafe(&'static str),
    #[error("configuration YAML is malformed")]
    Malformed,
    #[error("configuration does not match the required schema")]
    Schema,
}

#[derive(Default)]
struct MappingState {
    keys: BTreeSet<String>,
    expecting_key: bool,
}

enum Frame {
    Map(MappingState),
    Sequence,
}

/// Deserialize one document from Paygate's qualified safe YAML subset.
pub fn from_safe_yaml<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ConfigInputError> {
    let input = std::str::from_utf8(bytes).map_err(|_| ConfigInputError::Utf8)?;
    if input.trim().is_empty() {
        return Err(ConfigInputError::Empty);
    }
    validate_events(input)?;
    let options = serde_saphyr::options! {
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
        with_snippet: false,
    };
    serde_saphyr::from_str_with_options(input, options).map_err(|_| ConfigInputError::Schema)
}

fn validate_events(input: &str) -> Result<(), ConfigInputError> {
    let mut scanner = Scanner::new(StrInput::new(input));
    while let Some(token) = scanner
        .next_token()
        .map_err(|_| ConfigInputError::Malformed)?
    {
        if matches!(
            token.1,
            TokenType::VersionDirective(..) | TokenType::TagDirective(..)
        ) {
            return Err(ConfigInputError::Unsafe("directives"));
        }
    }
    let mut parser = Parser::new_from_str(input);
    let mut documents = 0usize;
    let mut frames: Vec<Frame> = Vec::new();
    let mut root_nodes = 0usize;

    while let Some(item) = parser.next_event() {
        let (event, _) = item.map_err(|_| ConfigInputError::Malformed)?;
        match event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Comment(..) => {}
            Event::DocumentStart(_, version) => {
                documents += 1;
                root_nodes = 0;
                if documents > 1 {
                    return Err(ConfigInputError::Unsafe("multiple documents"));
                }
                if version.is_some() {
                    return Err(ConfigInputError::Unsafe("directives"));
                }
            }
            Event::Alias(_) => return Err(ConfigInputError::Unsafe("aliases")),
            Event::Scalar(value, style, anchor, tag) => {
                reject_properties(anchor, tag.is_some())?;
                if style == ScalarStyle::Plain
                    && matches!(
                        value.to_ascii_lowercase().as_str(),
                        "y" | "yes" | "n" | "no" | "on" | "off"
                    )
                {
                    return Err(ConfigInputError::Unsafe("YAML 1.1 booleans"));
                }
                if matches!(frames.last(), Some(Frame::Map(map)) if map.expecting_key) {
                    let Frame::Map(map) = frames.last_mut().expect("checked above") else {
                        unreachable!()
                    };
                    if value == "<<" {
                        return Err(ConfigInputError::Unsafe("merge keys"));
                    }
                    if !map.keys.insert(value.to_string()) {
                        return Err(ConfigInputError::Unsafe("duplicate keys"));
                    }
                    map.expecting_key = false;
                } else {
                    finish_value(&mut frames, &mut root_nodes)?;
                }
            }
            Event::MappingStart(_, anchor, tag) => {
                reject_properties(anchor, tag.is_some())?;
                if matches!(frames.last(), Some(Frame::Map(map)) if map.expecting_key) {
                    return Err(ConfigInputError::Unsafe("composite keys"));
                }
                frames.push(Frame::Map(MappingState {
                    expecting_key: true,
                    ..MappingState::default()
                }));
            }
            Event::MappingEnd => {
                let Frame::Map(map) = frames.pop().ok_or(ConfigInputError::Malformed)? else {
                    return Err(ConfigInputError::Malformed);
                };
                if !map.expecting_key {
                    return Err(ConfigInputError::Malformed);
                }
                finish_value(&mut frames, &mut root_nodes)?;
            }
            Event::SequenceStart(_, anchor, tag) => {
                reject_properties(anchor, tag.is_some())?;
                if matches!(frames.last(), Some(Frame::Map(map)) if map.expecting_key) {
                    return Err(ConfigInputError::Unsafe("composite keys"));
                }
                frames.push(Frame::Sequence);
            }
            Event::SequenceEnd => {
                if !matches!(frames.pop(), Some(Frame::Sequence)) {
                    return Err(ConfigInputError::Malformed);
                }
                finish_value(&mut frames, &mut root_nodes)?;
            }
            Event::Nothing => return Err(ConfigInputError::Malformed),
        }
    }
    if documents != 1 || root_nodes != 1 || !frames.is_empty() {
        return Err(ConfigInputError::Malformed);
    }
    Ok(())
}

fn reject_properties(anchor: usize, tagged: bool) -> Result<(), ConfigInputError> {
    if anchor != 0 {
        return Err(ConfigInputError::Unsafe("anchors"));
    }
    if tagged {
        return Err(ConfigInputError::Unsafe("tags"));
    }
    Ok(())
}

fn finish_value(frames: &mut [Frame], root_nodes: &mut usize) -> Result<(), ConfigInputError> {
    match frames.last_mut() {
        Some(Frame::Map(map)) if !map.expecting_key => map.expecting_key = true,
        Some(Frame::Map(_)) | Some(Frame::Sequence) => {}
        None => {
            *root_nodes += 1;
            if *root_nodes > 1 {
                return Err(ConfigInputError::Unsafe("trailing document content"));
            }
        }
    }
    Ok(())
}
