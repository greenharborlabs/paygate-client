use paygate::http::{MAX_RESPONSE_BODY_BYTES, serialize_body};

#[test]
fn response_body_preserves_json_text_binary_and_enforces_limit() {
    assert_eq!(
        serialize_body(br#"{"answer":42}"#).unwrap(),
        serde_json::json!({"json":{"answer":42}})
    );
    assert_eq!(
        serialize_body(b"hello").unwrap(),
        serde_json::json!({"body":"hello"})
    );
    assert_eq!(
        serialize_body(&[0xff, 0x00]).unwrap(),
        serde_json::json!({"bodyBase64":"/wA="})
    );
    assert!(serialize_body(&vec![0; MAX_RESPONSE_BODY_BYTES + 1]).is_err());
}

#[test]
fn response_serialization_recursively_redacts_sensitive_body_fields() {
    let value =
        serialize_body(br#"{"nested":{"preimage":"aaaaaaaa","api_key":"key"},"safe":"ok"}"#)
            .unwrap();
    assert_eq!(value["json"]["nested"]["preimage"], "[REDACTED_SECRET]");
    assert_eq!(value["json"]["nested"]["api_key"], "[REDACTED_SECRET]");
    assert_eq!(value["json"]["safe"], "ok");
    assert_eq!(
        serialize_body(b"invoice=lnbc1secret").unwrap()["body"],
        "[REDACTED_SECRET]"
    );
}

#[test]
fn response_headers_preserve_auth_scheme_but_redact_custom_secrets() {
    use paygate::http::{HttpResponse, serialize_response};
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        "Payment opaque".parse().unwrap(),
    );
    headers.insert("x-api-key", "top-secret".parse().unwrap());
    headers.insert("x-request-id", "safe".parse().unwrap());
    let value = serialize_response(&HttpResponse {
        status: reqwest::StatusCode::OK,
        headers,
        body: vec![],
    })
    .unwrap();
    assert_eq!(
        value["headers"]["authorization"],
        "Payment [REDACTED_CREDENTIAL]"
    );
    assert_eq!(value["headers"]["x-api-key"], "[REDACTED_SECRET]");
    assert_eq!(value["headers"]["x-request-id"], "safe");
}
