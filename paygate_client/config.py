from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

import yaml


class ConfigError(Exception):
    """Base class for typed configuration failures."""


class MissingConfigError(ConfigError):
    pass


class InvalidYamlError(ConfigError):
    pass


class UnknownBackendError(ConfigError):
    pass


class MissingSecretError(ConfigError):
    pass


class ValidationError(ConfigError):
    pass


@dataclass(frozen=True)
class EnvRef:
    env_var: str

    def resolve(self, env: Mapping[str, str] | None = None) -> str:
        source = os.environ if env is None else env
        value = source.get(self.env_var)
        if not value:
            raise MissingSecretError(
                "Missing environment value "
                f"{self.env_var!r}; set it before loading this Paygate config."
            )
        return value


@dataclass(frozen=True)
class SecretRef(EnvRef):
    def __repr__(self) -> str:
        return f"SecretRef(env_var={self.env_var!r})"


@dataclass(frozen=True)
class PayerConfig:
    backend: str


@dataclass(frozen=True)
class PhoenixdConfig:
    url: str
    password_env: SecretRef
    fee_limit_parameter: str | None = None

    def resolve_password(self, env: Mapping[str, str] | None = None) -> str:
        return self.password_env.resolve(env)


@dataclass(frozen=True)
class LndConfig:
    rest_url_env: EnvRef
    macaroon_hex_env: SecretRef
    tls_cert_path_env: EnvRef | None = None

    def resolve_rest_url(self, env: Mapping[str, str] | None = None) -> str:
        return self.rest_url_env.resolve(env)

    def resolve_macaroon_hex(self, env: Mapping[str, str] | None = None) -> str:
        return self.macaroon_hex_env.resolve(env)

    def resolve_tls_cert_path(self, env: Mapping[str, str] | None = None) -> str | None:
        if self.tls_cert_path_env is None:
            return None
        return self.tls_cert_path_env.resolve(env)


@dataclass(frozen=True)
class PolicyConfig:
    max_request_sats: int
    max_fee_sats: int
    daily_budget_sats: int
    allowed_hosts: tuple[str, ...]
    allowed_services: tuple[str, ...]


@dataclass(frozen=True)
class ProtocolConfig:
    preferred: str = "Payment"
    allow_l402: bool = False


@dataclass(frozen=True)
class PaygateConfig:
    payer: PayerConfig
    policy: PolicyConfig
    protocol: ProtocolConfig
    phoenixd: PhoenixdConfig | None = None
    lnd: LndConfig | None = None


_SUPPORTED_BACKENDS = {"test-mode", "phoenixd", "lnd-rest"}
_SUPPORTED_PROTOCOLS = {"Payment", "L402"}


def load_config(
    path: str | os.PathLike[str], env: Mapping[str, str] | None = None
) -> PaygateConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise MissingConfigError(
            "Config file not found at "
            f"{config_path}. Create a Paygate YAML config or pass the correct path."
        )

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            raw = yaml.safe_load(config_file)
    except yaml.YAMLError as exc:
        raise InvalidYamlError(
            f"Invalid YAML in {config_path}: {exc}. Fix the YAML syntax and try again."
        ) from exc

    if not isinstance(raw, dict):
        raise InvalidYamlError(
            f"Invalid YAML in {config_path}: expected a mapping at the document root."
        )

    loaded_env = load_config_env(config_path, env=env)
    return _load_mapping(raw, env=loaded_env)


def load_config_env(
    path: str | os.PathLike[str], env: Mapping[str, str] | None = None
) -> Mapping[str, str]:
    config_path = Path(path)
    base_env = os.environ if env is None else env
    env_path = config_path.parent / "voltage-env.sh"
    if not env_path.exists():
        return base_env

    loaded = dict(_parse_export_env_file(env_path))
    if not loaded:
        return base_env
    loaded.update(base_env)
    return loaded


def _parse_export_env_file(path: Path) -> Mapping[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values

    for line in lines:
        try:
            parts = shlex.split(line, comments=True, posix=True)
        except ValueError:
            continue
        if len(parts) != 2 or parts[0] != "export":
            continue
        name, separator, value = parts[1].partition("=")
        if separator and name.isidentifier():
            values[name] = value
    return values


def _load_mapping(raw: Mapping[str, object], env: Mapping[str, str]) -> PaygateConfig:
    payer = _load_payer(raw.get("payer"))
    policy = _load_policy(raw.get("policy"))
    protocol = _load_protocol(raw.get("protocol"))

    phoenixd = None
    lnd = None
    if payer.backend == "phoenixd":
        phoenixd = _load_phoenixd(raw.get("phoenixd"), env)
    elif payer.backend == "lnd-rest":
        lnd = _load_lnd(raw.get("lnd"), env)

    return PaygateConfig(
        payer=payer,
        policy=policy,
        protocol=protocol,
        phoenixd=phoenixd,
        lnd=lnd,
    )


def _load_payer(raw: object) -> PayerConfig:
    payer = _require_mapping(raw, "payer")
    backend = _require_string(payer, "backend", "payer.backend")
    if backend not in _SUPPORTED_BACKENDS:
        supported = ", ".join(sorted(_SUPPORTED_BACKENDS))
        raise UnknownBackendError(
            f"Unknown payer.backend {backend!r}; expected one of: {supported}."
        )
    return PayerConfig(backend=backend)


def _load_phoenixd(raw: object, env: Mapping[str, str]) -> PhoenixdConfig:
    phoenixd = _require_mapping(raw, "phoenixd")
    url = _require_string(phoenixd, "url", "phoenixd.url")
    password_ref = SecretRef(
        _require_string(phoenixd, "password_env", "phoenixd.password_env")
    )
    fee_limit_parameter = None
    if phoenixd.get("fee_limit_parameter") is not None:
        fee_limit_parameter = _require_string(
            phoenixd, "fee_limit_parameter", "phoenixd.fee_limit_parameter"
        )
    password_ref.resolve(env)
    return PhoenixdConfig(
        url=url,
        password_env=password_ref,
        fee_limit_parameter=fee_limit_parameter,
    )


def _load_lnd(raw: object, env: Mapping[str, str]) -> LndConfig:
    lnd = _require_mapping(raw, "lnd")
    rest_url_ref = EnvRef(_require_string(lnd, "rest_url_env", "lnd.rest_url_env"))
    macaroon_ref = SecretRef(
        _require_string(lnd, "macaroon_hex_env", "lnd.macaroon_hex_env")
    )
    tls_cert_env = lnd.get("tls_cert_path_env")
    tls_cert_ref = None
    if tls_cert_env is not None:
        tls_cert_ref = EnvRef(
            _require_string(lnd, "tls_cert_path_env", "lnd.tls_cert_path_env")
        )

    rest_url_ref.resolve(env)
    macaroon_ref.resolve(env)
    if tls_cert_ref is not None:
        tls_cert_ref.resolve(env)
    return LndConfig(
        rest_url_env=rest_url_ref,
        macaroon_hex_env=macaroon_ref,
        tls_cert_path_env=tls_cert_ref,
    )


def _load_policy(raw: object) -> PolicyConfig:
    policy = _require_mapping(raw, "policy")
    max_request_sats = _require_non_negative_int(policy, "max_request_sats")
    max_fee_sats = _require_non_negative_int(policy, "max_fee_sats")
    daily_budget_sats = _require_non_negative_int(policy, "daily_budget_sats")
    if max_request_sats > daily_budget_sats:
        raise ValidationError(
            "policy.max_request_sats must not exceed "
            "policy.daily_budget_sats; lower the request cap or raise the "
            "daily budget."
        )
    allowed_hosts = _require_non_empty_string_list(policy, "allowed_hosts")
    allowed_services = _require_non_empty_string_list(policy, "allowed_services")
    return PolicyConfig(
        max_request_sats=max_request_sats,
        max_fee_sats=max_fee_sats,
        daily_budget_sats=daily_budget_sats,
        allowed_hosts=tuple(allowed_hosts),
        allowed_services=tuple(allowed_services),
    )


def _load_protocol(raw: object) -> ProtocolConfig:
    if raw is None:
        return ProtocolConfig()
    protocol = _require_mapping(raw, "protocol")
    preferred = protocol.get("preferred", "Payment")
    if not isinstance(preferred, str) or preferred not in _SUPPORTED_PROTOCOLS:
        raise ValidationError("protocol.preferred must be either 'Payment' or 'L402'.")
    allow_l402 = protocol.get("allow_l402", False)
    if not isinstance(allow_l402, bool):
        raise ValidationError("protocol.allow_l402 must be true or false.")
    if preferred == "L402" and not allow_l402:
        raise ValidationError(
            "protocol.preferred cannot be 'L402' unless protocol.allow_l402 is true."
        )
    return ProtocolConfig(preferred=preferred, allow_l402=allow_l402)


def _require_mapping(raw: object, path: str) -> Mapping[str, object]:
    if not isinstance(raw, dict):
        raise ValidationError(f"{path} must be a mapping in the Paygate config.")
    return raw


def _require_string(raw: Mapping[str, object], key: str, path: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} is required and must be a non-empty string.")
    return value


def _require_non_negative_int(raw: Mapping[str, object], key: str) -> int:
    path = f"policy.{key}"
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(f"{path} must be a non-negative integer number of sats.")
    return value


def _require_non_empty_string_list(
    raw: Mapping[str, object], key: str
) -> Sequence[str]:
    path = f"policy.{key}"
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise ValidationError(
            f"{path} must contain at least one explicit entry; "
            "empty allowlists fail closed."
        )
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ValidationError(f"{path} entries must be non-empty strings.")
    return value
