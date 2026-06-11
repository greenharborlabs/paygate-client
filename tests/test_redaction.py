import copy

from paygate_client.redaction import redact_error_envelope, redact_text


def test_redacts_env_secret_values_and_preimages():
    macaroon = "a" * 64
    preimage = "b" * 64
    text = (
        "PAYGATE_CLIENT_LND_MACAROON_HEX value "
        f"{macaroon} failed after preimage {preimage}"
    )

    redacted = redact_text(text, extra_secrets=(macaroon,))

    assert macaroon not in redacted
    assert preimage not in redacted
    assert "[REDACTED" in redacted


def test_redacts_authorization_credentials_and_passwords_in_envelope():
    envelope = {
        "ok": False,
        "error": {
            "message": "backend password hunter2 rejected",
            "headers": {
                "Authorization": "Payment token:credential",
                "authorization": "L402 token:preimage",
                "password": "hunter2",
            },
        },
    }

    redacted = redact_error_envelope(envelope, extra_secrets=("hunter2",))

    rendered = repr(redacted)
    assert "hunter2" not in rendered
    assert "token:credential" not in rendered
    assert "token:preimage" not in rendered
    assert (
        redacted["error"]["headers"]["Authorization"] == "Payment [REDACTED_CREDENTIAL]"
    )
    assert redacted["error"]["headers"]["authorization"] == "L402 [REDACTED_CREDENTIAL]"
    assert redacted["error"]["headers"]["password"] == "[REDACTED_SECRET]"


def test_secret_like_keys_are_redacted_by_default():
    envelope = {
        "password": "hunter2",
        "macaroon_hex": "abc",
        "token": "tkn",
        "api_key": "key",
    }
    redacted = redact_error_envelope(envelope)

    assert redacted["password"] == "[REDACTED_SECRET]"
    assert redacted["macaroon_hex"] == "[REDACTED_SECRET]"
    assert redacted["token"] == "[REDACTED_SECRET]"
    assert redacted["api_key"] == "[REDACTED_SECRET]"


def test_nested_secret_like_fields_are_redacted_and_safe_fields_are_preserved():
    original = {
        "outer": [
            {"Access_Token": "abc"},
            {"api-key": "key"},
            {"clientSecret": "sec"},
            {"safe": "value"},
            {"token_count": 3},
            {"secretary": "Ada"},
            {"invoice": "lnbc1" + "1" * 25},
        ]
    }
    redacted = redact_error_envelope(original)
    copied = copy.deepcopy(original)

    assert redacted == {
        "outer": [
            {"Access_Token": "[REDACTED_SECRET]"},
            {"api-key": "[REDACTED_SECRET]"},
            {"clientSecret": "[REDACTED_SECRET]"},
            {"safe": "value"},
            {"token_count": 3},
            {"secretary": "Ada"},
            {"invoice": "lnbc1" + "1" * 25},
        ]
    }
    assert original == copied


def test_invoice_redaction_is_opt_in():
    invoice = "lnbc1p" + "q" * 100
    assert invoice in redact_text(invoice)
    assert invoice not in redact_text(invoice, redact_invoices=True)


def test_authorization_text_preserves_scheme_with_spaces_and_case():
    envelope = {
        "proxy_authorization": "payment token:credential",
    }
    redacted = redact_error_envelope(envelope)
    assert redacted["proxy_authorization"] == "payment [REDACTED_CREDENTIAL]"
