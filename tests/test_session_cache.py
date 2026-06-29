from __future__ import annotations

import json

from paygate_client.session_cache import (
    CachedCredential,
    CredentialScope,
    FileCredentialCache,
    build_credential_id,
    default_cache_path,
)


def _credential(namespace: str = "default") -> CachedCredential:
    scope = CredentialScope(
        namespace=namespace,
        request_key="req",
        origin_host="example.test:443",
        service="orders",
        protocol="Payment",
        payer_backend="test-mode",
        policy_hash="policy",
    )
    return CachedCredential(
        credential_id=build_credential_id(scope, "Payment secret"),
        scope=scope,
        authorization="Payment secret",
        created_at=1,
    )


def test_default_cache_path_preserves_legacy_location() -> None:
    assert str(default_cache_path()) == "~/.config/paygate-client/credentials.json"


def test_profile_cache_path_is_namespaced() -> None:
    assert (
        str(default_cache_path("worker-a"))
        == "~/.config/paygate-client/profiles/worker-a/credentials.json"
    )


def test_file_cache_scopes_credentials_by_namespace(tmp_path) -> None:
    manager_cache = FileCredentialCache(
        tmp_path / "manager.json",
        namespace="manager",
    )
    worker_cache = FileCredentialCache(
        tmp_path / "worker.json",
        namespace="worker",
    )
    manager_credential = _credential("manager")
    worker_credential = _credential("worker")

    manager_cache.put(manager_credential)
    worker_cache.put(worker_credential)

    assert manager_cache.get(manager_credential.scope) is not None
    assert manager_cache.get(worker_credential.scope) is None
    assert worker_cache.get(worker_credential.scope) is not None
    assert worker_cache.get(manager_credential.scope) is None


def test_file_cache_loads_legacy_entries_as_default_namespace(tmp_path) -> None:
    cache_path = tmp_path / "credentials.json"
    cache_path.write_text(
        json.dumps(
            {
                "version": 1,
                "credentials": [
                    {
                        "id": "legacy",
                        "scope": {
                            "requestKey": "req",
                            "originHost": "example.test:443",
                            "service": "orders",
                            "protocol": "Payment",
                            "payerBackend": "test-mode",
                            "policyHash": "policy",
                        },
                        "authorization": "Payment legacy",
                        "createdAt": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    cache = FileCredentialCache(cache_path)
    [loaded] = cache.list()

    assert loaded.scope.namespace == "default"
    assert loaded.authorization == "Payment legacy"
