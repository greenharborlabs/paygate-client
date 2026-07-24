import hashlib
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "security/payment-canary-composite-digest-profile-v1.json"
VECTORS_PATH = ROOT / "security/payment-canary-composite-digest-vectors.json"
PROFILE_NAME = "paygate-github-protection-v1"
REPOSITORY = "greenharborlabs/paygate-client"
BACKENDS = {"lnd-testnet-canary", "breez-mainnet-canary"}
CANONICAL_VECTORS = {
    "lnd-testnet-canary": {
        "id": "lnd-testnet-canary-redacted-v1",
        "canonical_json": '{"backend":"lnd-testnet-canary","environment_configuration_digest":"sha256:3a143b10d8b7cb5b1cf2dd15449b3d83a2cb31dc2f413ac6f373921e63c8752a","profile":"paygate-github-protection-v1","repository":"greenharborlabs/paygate-client","runner_group_configuration_digest":"sha256:99c5e2da02bc57cccedf5677787ad005f8f58c4633eb4d1de3349fd764997d9f"}',  # noqa: E501
        "composite_digest": "sha256:11983aac8c2c7b783c90338259ef3cc253854ed32ceb464366e96e1d9bac0ce2",  # noqa: E501
    },
    "breez-mainnet-canary": {
        "id": "breez-mainnet-canary-redacted-v1",
        "canonical_json": '{"backend":"breez-mainnet-canary","environment_configuration_digest":"sha256:cfc6e441afbdbc2bd9f9b4ab9d209c66f4bea0da2390a1e9d4dd723a7ab8cf92","profile":"paygate-github-protection-v1","repository":"greenharborlabs/paygate-client","runner_group_configuration_digest":"sha256:99c5e2da02bc57cccedf5677787ad005f8f58c4633eb4d1de3349fd764997d9f"}',  # noqa: E501
        "composite_digest": "sha256:00b3ff268333e8761a179e6d7572a3015c29e46c541e5f21bd2caead9bb28957",  # noqa: E501
    },
}
FIELDS = {
    "backend",
    "environment_configuration_digest",
    "profile",
    "repository",
    "runner_group_configuration_digest",
}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_json(path):
    return json.loads(path.read_text(), object_pairs_hook=reject_duplicates)


def canonical_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def composite(value):
    if set(value) != FIELDS:
        raise ValueError("canonical object must contain exactly five fields")
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def semantic_object(vector):
    return {
        "backend": vector["backend"],
        "environment_configuration_digest": vector["environment_configuration_digest"],
        "profile": PROFILE_NAME,
        "repository": REPOSITORY,
        "runner_group_configuration_digest": vector[
            "runner_group_configuration_digest"
        ],
    }


def test_profile_and_redacted_vectors_are_exact_and_reproducible():
    profile = load_json(PROFILE_PATH)
    vectors = load_json(VECTORS_PATH)
    assert set(profile) == {
        "canonical_object",
        "canonicalization",
        "composite_digest",
        "future_schema_v7_claims",
        "legacy_or_unknown_profile_behavior",
        "profile",
        "repository",
        "status",
    }
    assert profile["status"] == "inactive"
    assert profile["profile"] == PROFILE_NAME
    assert profile["repository"] == REPOSITORY
    assert set(profile["canonical_object"]) == FIELDS
    assert profile["canonical_object"]["backend"] == {
        "type": "string",
        "enum": ["lnd-testnet-canary", "breez-mainnet-canary"],
    }
    assert profile["canonical_object"]["profile"] == {
        "type": "string",
        "const": PROFILE_NAME,
    }
    assert profile["canonical_object"]["repository"] == {
        "type": "string",
        "const": REPOSITORY,
    }
    for name in (
        "environment_configuration_digest",
        "runner_group_configuration_digest",
    ):
        assert profile["canonical_object"][name] == {
            "type": "string",
            "pattern": "sha256:<64 lowercase hex>",
        }
    assert profile["canonicalization"] == {
        "encoding": "utf-8",
        "json": "sorted keys, comma/colon separators, ASCII-safe JSON",
        "object_fields": [
            "backend",
            "environment_configuration_digest",
            "profile",
            "repository",
            "runner_group_configuration_digest",
        ],
    }
    assert (
        profile["composite_digest"]
        == "sha256 of exact canonical object bytes; lowercase sha256:<hex>"
    )
    assert (
        profile["legacy_or_unknown_profile_behavior"]
        == "fail-closed when schema-v7 activation occurs"
    )
    assert profile["future_schema_v7_claims"] == [
        "digest_profile",
        "baseline_composite_digest",
    ]
    assert "deployed_verifier_immutable_digest" not in profile
    assert set(vectors) == {"profile", "repository", "vectors"}
    assert vectors["profile"] == PROFILE_NAME
    assert vectors["repository"] == REPOSITORY
    assert len(vectors["vectors"]) == len(CANONICAL_VECTORS)
    assert len({item["id"] for item in vectors["vectors"]}) == len(vectors["vectors"])
    assert len({item["backend"] for item in vectors["vectors"]}) == len(
        vectors["vectors"]
    )
    assert {item["backend"] for item in vectors["vectors"]} == BACKENDS
    for vector in vectors["vectors"]:
        assert set(vector) == {
            "id",
            "backend",
            "environment_configuration_digest",
            "runner_group_configuration_digest",
            "canonical_json",
            "composite_digest",
        }
        expected_bytes = canonical_bytes(semantic_object(vector))
        expected = CANONICAL_VECTORS[vector["backend"]]
        assert vector["id"] == expected["id"]
        assert vector["canonical_json"] == expected["canonical_json"]
        assert vector["composite_digest"] == expected["composite_digest"]
        assert vector["canonical_json"].encode("ascii") == expected_bytes
        assert composite(semantic_object(vector)) == vector["composite_digest"]
        assert DIGEST.fullmatch(vector["environment_configuration_digest"])
        assert DIGEST.fullmatch(vector["runner_group_configuration_digest"])
        assert DIGEST.fullmatch(vector["composite_digest"])


def test_order_and_whitespace_are_invariant_but_each_semantic_field_changes_digest():
    vector = load_json(VECTORS_PATH)["vectors"][0]
    baseline = semantic_object(vector)
    assert composite(baseline) == composite(dict(reversed(list(baseline.items()))))
    whitespace_variant = json.loads(
        "  " + json.dumps(baseline, indent=2) + "\n",
        object_pairs_hook=reject_duplicates,
    )
    assert composite(whitespace_variant) == composite(baseline)
    replacements = {
        "backend": "breez-mainnet-canary",
        "environment_configuration_digest": "sha256:" + "1" * 64,
        "profile": "paygate-github-protection-v2",
        "repository": "greenharborlabs/other",
        "runner_group_configuration_digest": "sha256:" + "2" * 64,
    }
    for field, replacement in replacements.items():
        mutated = {**baseline, field: replacement}
        assert composite(mutated) != composite(baseline)


@pytest.mark.parametrize(
    "path, raw",
    [
        (
            "profile",
            '{"canonical_object":{"backend":{"type":"string","type":"string"}}}',
        ),
        (
            "vectors",
            '{"profile":"x","repository":"x","vectors":[{"id":"one","id":"two"}]}',
        ),
        (
            "vectors",
            '{"profile":"x","repository":"x","vectors":[{"nested":{"a":1,"a":2}}]}',
        ),
    ],
)
def test_profile_and_vectors_reject_nested_duplicate_json_keys(tmp_path, path, raw):
    target = tmp_path / f"{path}.json"
    target.write_text(raw)
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_json(target)


def test_canonical_object_requires_exact_fields():
    vector = load_json(VECTORS_PATH)["vectors"][0]
    value = semantic_object(vector)
    with pytest.raises(ValueError):
        composite({key: item for key, item in value.items() if key != "backend"})
    with pytest.raises(ValueError):
        composite({**value, "unexpected": "value"})
