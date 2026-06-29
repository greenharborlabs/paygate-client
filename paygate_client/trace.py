from __future__ import annotations

import json
import sys
from typing import Any, Protocol, TextIO

from paygate_client.redaction import redact_error_envelope


class TraceSink(Protocol):
    def emit(self, event: str, **fields: Any) -> None: ...


class NullTraceSink:
    def emit(self, event: str, **fields: Any) -> None:
        return None


class TextTraceSink:
    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = sys.stderr if stream is None else stream

    def emit(self, event: str, **fields: Any) -> None:
        redacted = redact_error_envelope(fields)
        details = " ".join(
            f"{key}={value}" for key, value in redacted.items() if value is not None
        )
        suffix = f" {details}" if details else ""
        print(f"paygate: {event}{suffix}", file=self._stream)


class JsonTraceSink:
    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = sys.stderr if stream is None else stream

    def emit(self, event: str, **fields: Any) -> None:
        payload = {"event": event}
        payload.update(redact_error_envelope(fields))
        print(json.dumps(payload, sort_keys=True), file=self._stream)


class MultiTraceSink:
    def __init__(self, *sinks: TraceSink) -> None:
        self._sinks = sinks

    def emit(self, event: str, **fields: Any) -> None:
        for sink in self._sinks:
            sink.emit(event, **fields)
