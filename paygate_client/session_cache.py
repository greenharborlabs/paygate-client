from __future__ import annotations

import builtins
import fcntl
import hashlib
import importlib
import json
import os
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from paygate_client.redaction import REDACTED_CREDENTIAL

DEFAULT_CACHE_PATH = Path("~/.config/paygate-client/credentials.json")
_KEYRING_SERVICE = "paygate-client.credentials"
DEFAULT_NAMESPACE = "default"


def normalize_namespace(namespace: str | None) -> str:
    if namespace is None or not namespace.strip():
        return DEFAULT_NAMESPACE
    normalized = namespace.strip()
    if "/" in normalized or "\\" in normalized or normalized in (".", ".."):
        raise ValueError("profile must not contain path separators or dot segments")
    return normalized


def default_cache_path(namespace: str | None = None) -> Path:
    normalized = normalize_namespace(namespace)
    if normalized == DEFAULT_NAMESPACE:
        return DEFAULT_CACHE_PATH
    return Path("~/.config/paygate-client/profiles") / normalized / "credentials.json"


@dataclass(frozen=True)
class CredentialScope:
    request_key: str
    origin_host: str | None
    service: str | None
    protocol: str
    payer_backend: str
    policy_hash: str
    namespace: str = DEFAULT_NAMESPACE


@dataclass(frozen=True)
class CachedCredential:
    credential_id: str
    scope: CredentialScope
    authorization: str
    created_at: int
    expires_at: int | None = None
    max_uses: int | None = None
    use_count: int = 0
    last_success_at: int | None = None
    last_rejected_at: int | None = None
    payment_hash: str | None = None
    challenge_id: str | None = None

    def is_usable(self, now: int | None = None) -> bool:
        current_time = int(time.time()) if now is None else now
        if self.expires_at is not None and self.expires_at <= current_time:
            return False
        if self.max_uses is not None and self.use_count >= self.max_uses:
            return False
        if self.last_rejected_at is not None:
            return False
        return True

    def redacted(self) -> dict[str, Any]:
        return {
            "id": self.credential_id,
            "scope": {
                "namespace": self.scope.namespace,
                "requestKey": self.scope.request_key,
                "originHost": self.scope.origin_host,
                "service": self.scope.service,
                "protocol": self.scope.protocol,
                "payerBackend": self.scope.payer_backend,
                "policyHash": self.scope.policy_hash,
            },
            "authorization": REDACTED_CREDENTIAL,
            "createdAt": self.created_at,
            "expiresAt": self.expires_at,
            "maxUses": self.max_uses,
            "useCount": self.use_count,
            "lastSuccessAt": self.last_success_at,
            "lastRejectedAt": self.last_rejected_at,
            "paymentHash": self.payment_hash,
            "challengeId": self.challenge_id,
        }


class CredentialCache(Protocol):
    def get(self, scope: CredentialScope) -> CachedCredential | None: ...

    def put(self, credential: CachedCredential) -> None: ...

    def mark_success(self, credential_id: str) -> None: ...

    def mark_rejected(self, credential_id: str) -> None: ...

    def delete(self, credential_id: str) -> None: ...

    def list(self) -> list[CachedCredential]: ...


class NullCredentialCache:
    def get(self, scope: CredentialScope) -> CachedCredential | None:
        return None

    def put(self, credential: CachedCredential) -> None:
        return None

    def mark_success(self, credential_id: str) -> None:
        return None

    def mark_rejected(self, credential_id: str) -> None:
        return None

    def delete(self, credential_id: str) -> None:
        return None

    def list(self) -> list[CachedCredential]:
        return []


class MemoryCredentialCache:
    def __init__(self, credentials: Iterable[CachedCredential] = ()) -> None:
        self._credentials = {item.credential_id: item for item in credentials}

    def get(self, scope: CredentialScope) -> CachedCredential | None:
        for credential in self._credentials.values():
            if _scope_matches(credential.scope, scope) and credential.is_usable():
                return credential
        return None

    def put(self, credential: CachedCredential) -> None:
        self._credentials[credential.credential_id] = credential

    def mark_success(self, credential_id: str) -> None:
        credential = self._credentials.get(credential_id)
        if credential is None:
            return
        self._credentials[credential_id] = _replace_credential(
            credential,
            use_count=credential.use_count + 1,
            last_success_at=int(time.time()),
        )

    def mark_rejected(self, credential_id: str) -> None:
        credential = self._credentials.get(credential_id)
        if credential is None:
            return
        self._credentials[credential_id] = _replace_credential(
            credential,
            last_rejected_at=int(time.time()),
        )

    def delete(self, credential_id: str) -> None:
        self._credentials.pop(credential_id, None)

    def list(self) -> list[CachedCredential]:
        return sorted(self._credentials.values(), key=lambda item: item.created_at)


class FileCredentialCache(MemoryCredentialCache):
    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        namespace: str | None = None,
    ) -> None:
        self.namespace = normalize_namespace(namespace)
        cache_path = path if path is not None else default_cache_path(self.namespace)
        self.path = Path(cache_path).expanduser()
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        super().__init__(self._load())

    def put(self, credential: CachedCredential) -> None:
        credential = _replace_scope_namespace(credential, self.namespace)
        with self._locked():
            self._credentials = {item.credential_id: item for item in self._load()}
            super().put(credential)
            self._save()

    def mark_success(self, credential_id: str) -> None:
        with self._locked():
            self._credentials = {item.credential_id: item for item in self._load()}
            super().mark_success(credential_id)
            self._save()

    def mark_rejected(self, credential_id: str) -> None:
        with self._locked():
            self._credentials = {item.credential_id: item for item in self._load()}
            super().mark_rejected(credential_id)
            self._save()

    def delete(self, credential_id: str) -> None:
        with self._locked():
            self._credentials = {item.credential_id: item for item in self._load()}
            super().delete(credential_id)
            _delete_keyring_secret(credential_id, self.namespace)
            self._save()

    def purge(
        self,
        *,
        host: str | None = None,
        service: str | None = None,
        all_credentials: bool = False,
    ) -> int:
        deleted = 0
        with self._locked():
            self._credentials = {item.credential_id: item for item in self._load()}
            for credential in builtins.list(self._credentials.values()):
                if not all_credentials:
                    if host is not None and credential.scope.origin_host != host:
                        continue
                    if service is not None and credential.scope.service != service:
                        continue
                    if host is None and service is None:
                        continue
                self._credentials.pop(credential.credential_id, None)
                _delete_keyring_secret(credential.credential_id, self.namespace)
                deleted += 1
            if deleted:
                self._save()
        return deleted

    def list(self) -> builtins.list[CachedCredential]:
        with self._locked():
            self._credentials = {item.credential_id: item for item in self._load()}
            return super().list()

    def _load(self) -> builtins.list[CachedCredential]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(raw, dict):
            return []
        credentials = raw.get("credentials", [])
        if not isinstance(credentials, list):
            return []
        loaded = []
        keyring_backend = _keyring_backend()
        for item in credentials:
            credential = _credential_from_json(item, keyring_backend=keyring_backend)
            if credential is not None:
                loaded.append(credential)
        return loaded

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        keyring_backend = _keyring_backend()
        credentials = []
        for item in self._credentials.values():
            entry = _credential_to_json(item)
            if keyring_backend is not None:
                try:
                    keyring_backend.set_password(
                        _KEYRING_SERVICE,
                        _keyring_account(item.credential_id, self.namespace),
                        item.authorization,
                    )
                    entry["authorization"] = None
                    entry["secretStorage"] = "keyring"
                except Exception:
                    entry["secretStorage"] = "file"
            else:
                entry["secretStorage"] = "file"
            credentials.append(entry)
        payload = {
            "version": 1,
            "credentials": credentials,
        }
        raw = json.dumps(payload, sort_keys=True, indent=2)
        fd = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            file_obj.write(raw)
            file_obj.write("\n")
        os.chmod(self.path, 0o600)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)


def build_request_key(method: str, url: str, body: str | bytes | None = None) -> str:
    digest = hashlib.sha256()
    digest.update(method.upper().encode("utf-8"))
    digest.update(b"\0")
    digest.update(url.encode("utf-8"))
    digest.update(b"\0")
    if isinstance(body, bytes):
        digest.update(body)
    elif body is not None:
        digest.update(body.encode("utf-8"))
    return digest.hexdigest()


def build_policy_hash(policy: object) -> str:
    payload = json.dumps(policy, default=repr, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_credential_id(scope: CredentialScope, authorization: str) -> str:
    digest = hashlib.sha256()
    digest.update(scope.namespace.encode("utf-8"))
    digest.update(b"\0")
    digest.update(scope.request_key.encode("utf-8"))
    digest.update(b"\0")
    digest.update(authorization.encode("utf-8"))
    return digest.hexdigest()[:24]


def _credential_to_json(credential: CachedCredential) -> dict[str, Any]:
    return {
        "id": credential.credential_id,
        "scope": {
            "namespace": credential.scope.namespace,
            "requestKey": credential.scope.request_key,
            "originHost": credential.scope.origin_host,
            "service": credential.scope.service,
            "protocol": credential.scope.protocol,
            "payerBackend": credential.scope.payer_backend,
            "policyHash": credential.scope.policy_hash,
        },
        "authorization": credential.authorization,
        "createdAt": credential.created_at,
        "expiresAt": credential.expires_at,
        "maxUses": credential.max_uses,
        "useCount": credential.use_count,
        "lastSuccessAt": credential.last_success_at,
        "lastRejectedAt": credential.last_rejected_at,
        "paymentHash": credential.payment_hash,
        "challengeId": credential.challenge_id,
    }


def _credential_from_json(
    value: object, *, keyring_backend: Any | None
) -> CachedCredential | None:
    if not isinstance(value, Mapping):
        return None
    scope = value.get("scope")
    if not isinstance(scope, Mapping):
        return None
    authorization = value.get("authorization")
    credential_id = value.get("id")
    if not isinstance(credential_id, str):
        return None
    namespace_value = scope.get("namespace", DEFAULT_NAMESPACE)
    namespace = (
        namespace_value if isinstance(namespace_value, str) else DEFAULT_NAMESPACE
    )
    if not isinstance(authorization, str):
        if value.get("secretStorage") != "keyring" or keyring_backend is None:
            return None
        authorization = _get_keyring_secret(
            credential_id,
            namespace,
            keyring_backend=keyring_backend,
        )
    if not isinstance(authorization, str):
        return None
    try:
        credential_scope = CredentialScope(
            namespace=normalize_namespace(namespace),
            request_key=str(scope["requestKey"]),
            origin_host=_optional_str(scope.get("originHost")),
            service=_optional_str(scope.get("service")),
            protocol=str(scope["protocol"]),
            payer_backend=str(scope["payerBackend"]),
            policy_hash=str(scope["policyHash"]),
        )
    except KeyError:
        return None
    return CachedCredential(
        credential_id=credential_id,
        scope=credential_scope,
        authorization=authorization,
        created_at=_int_or_default(value.get("createdAt"), 0),
        expires_at=_optional_int(value.get("expiresAt")),
        max_uses=_optional_int(value.get("maxUses")),
        use_count=_int_or_default(value.get("useCount"), 0),
        last_success_at=_optional_int(value.get("lastSuccessAt")),
        last_rejected_at=_optional_int(value.get("lastRejectedAt")),
        payment_hash=_optional_str(value.get("paymentHash")),
        challenge_id=_optional_str(value.get("challengeId")),
    )


def _replace_credential(
    credential: CachedCredential,
    *,
    use_count: int | None = None,
    last_success_at: int | None = None,
    last_rejected_at: int | None = None,
) -> CachedCredential:
    return CachedCredential(
        credential_id=credential.credential_id,
        scope=credential.scope,
        authorization=credential.authorization,
        created_at=credential.created_at,
        expires_at=credential.expires_at,
        max_uses=credential.max_uses,
        use_count=credential.use_count if use_count is None else use_count,
        last_success_at=(
            credential.last_success_at if last_success_at is None else last_success_at
        ),
        last_rejected_at=(
            credential.last_rejected_at
            if last_rejected_at is None
            else last_rejected_at
        ),
        payment_hash=credential.payment_hash,
        challenge_id=credential.challenge_id,
    )


def _replace_scope_namespace(
    credential: CachedCredential, namespace: str
) -> CachedCredential:
    if credential.scope.namespace == namespace:
        return credential
    scope = CredentialScope(
        namespace=namespace,
        request_key=credential.scope.request_key,
        origin_host=credential.scope.origin_host,
        service=credential.scope.service,
        protocol=credential.scope.protocol,
        payer_backend=credential.scope.payer_backend,
        policy_hash=credential.scope.policy_hash,
    )
    return CachedCredential(
        credential_id=build_credential_id(scope, credential.authorization),
        scope=scope,
        authorization=credential.authorization,
        created_at=credential.created_at,
        expires_at=credential.expires_at,
        max_uses=credential.max_uses,
        use_count=credential.use_count,
        last_success_at=credential.last_success_at,
        last_rejected_at=credential.last_rejected_at,
        payment_hash=credential.payment_hash,
        challenge_id=credential.challenge_id,
    )


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _int_or_default(value: object, default: int) -> int:
    parsed = _optional_int(value)
    return default if parsed is None else parsed


def _scope_matches(stored: CredentialScope, requested: CredentialScope) -> bool:
    if stored.request_key != requested.request_key:
        return False
    if stored.namespace != requested.namespace:
        return False
    if stored.origin_host != requested.origin_host:
        return False
    if stored.protocol != requested.protocol:
        return False
    if stored.payer_backend != requested.payer_backend:
        return False
    if stored.policy_hash != requested.policy_hash:
        return False
    return requested.service is None or stored.service == requested.service


def _keyring_backend() -> Any | None:
    try:
        return importlib.import_module("keyring")
    except Exception:
        return None


def _get_keyring_secret(
    credential_id: str, namespace: str, *, keyring_backend: Any
) -> str | None:
    accounts = [_keyring_account(credential_id, namespace)]
    if namespace == DEFAULT_NAMESPACE:
        accounts.append(credential_id)
    for account in accounts:
        try:
            value = keyring_backend.get_password(_KEYRING_SERVICE, account)
        except Exception:
            continue
        if isinstance(value, str):
            return value
    return None


def _keyring_account(credential_id: str, namespace: str) -> str:
    return f"{namespace}:{credential_id}"


def _delete_keyring_secret(credential_id: str, namespace: str) -> None:
    keyring_backend = _keyring_backend()
    if keyring_backend is None:
        return
    for account in (_keyring_account(credential_id, namespace), credential_id):
        try:
            keyring_backend.delete_password(_KEYRING_SERVICE, account)
        except Exception:
            continue
