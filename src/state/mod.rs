//! Persistent-state module boundaries owned by Wave 3.

pub mod cache;
pub mod keyring;
pub mod ledger;

pub const DEFAULT_NAMESPACE: &str = "default";

pub fn normalize_namespace(namespace: Option<&str>) -> Result<String, &'static str> {
    let value = namespace.unwrap_or(DEFAULT_NAMESPACE).trim();
    let value = if value.is_empty() {
        DEFAULT_NAMESPACE
    } else {
        value
    };
    if value == "." || value == ".." || value.contains('/') || value.contains('\\') {
        return Err("profile must not contain path separators or dot segments");
    }
    Ok(value.to_owned())
}
