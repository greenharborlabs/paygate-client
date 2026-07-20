//! Qualification-only bridge: exercise Rust state parsing and emit canonical evidence.
use paygate::state::cache::CachedCredential;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};

#[test]
fn writes_real_rust_state_semantic_evidence() {
    let output = PathBuf::from(std::env::var("PAYGATE_SEMANTIC_EVIDENCE")
        .expect("explicit PAYGATE_SEMANTIC_EVIDENCE output path is required"));
    let python: Value = serde_json::from_str(include_str!("../compat/python_oracle/golden/evidence.json")).unwrap();
    let semantic = python["case_evidence"]["cache.schema"]["observations"]["state.cache"].clone();
    let state: Value = serde_json::from_str(semantic["bytes"].as_str().unwrap()).unwrap();
    let credential: CachedCredential = serde_json::from_value(state["credentials"][0].clone()).unwrap();
    assert!(credential.usable(946_782_245));
    let result = json!({"schema_version": 1, "cases": {"cache.schema": {
        "semantic_json": semantic, "state": state, "exit": 0
    }}});
    fs::write(output, serde_json::to_vec(&result).unwrap()).unwrap();
}
