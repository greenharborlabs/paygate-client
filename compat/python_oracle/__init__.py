"""Frozen, offline Python compatibility oracle."""

from typing import Any

__all__ = ["OracleViolation", "run_oracle"]


def __getattr__(name: str) -> Any:
    """Lazily preserve the public oracle API without preloading its modules."""
    if name in __all__:
        from . import oracle

        return getattr(oracle, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
