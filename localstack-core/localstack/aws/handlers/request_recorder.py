"""Handlers and helpers to record and replay fully parsed AWS requests.

This module captures the state of a ``RequestContext`` immediately before the
``ServiceRequestRouter`` dispatches a call to a service provider. It can persist
those request snapshots to disk and reconstruct them on a subsequent startup to
replay the exact same sequence of operations without relying on service
internals.
"""

from __future__ import annotations

import base64
import contextlib
import contextvars
import json
import logging
import pickle
import random
import sys
import threading
import time
import uuid
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest.mock import patch

from botocore.model import ServiceModel
from werkzeug.datastructures import Headers

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.aws.handlers.service_plugin import ServiceLoader
from localstack.aws.protocol.service_router import determine_aws_protocol
from localstack.aws.spec import ProtocolName, load_service
from localstack.http import Request, Response
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)

REQUEST_SNAPSHOT_VERSION = 3
_TYPE_KEY = "_ls_type"

SENSITIVE_HEADERS = {
    "authorization",
    "x-amz-security-token",
    "x-amz-signature",
    "proxy-authorization",
}

PATCHED_MODULE_PREFIXES = ("localstack", "botocore", "rolo", "moto")

_UUID_PATCH_LOCK = threading.Lock()
_UUID_ORIGINAL = uuid.uuid4
_REQUEST_PERSISTENCE_LOCK = threading.RLock()


class _UuidReplayContext:
    __slots__ = ("queue", "use_random_fallback")

    def __init__(self, sequence: list[str] | None, use_random_fallback: bool):
        self.queue = deque(sequence or [])
        self.use_random_fallback = use_random_fallback


class _UuidRecordContext:
    __slots__ = ("collector",)

    def __init__(self, collector: list[str]):
        self.collector = collector


_uuid_context: contextvars.ContextVar[object | None] = contextvars.ContextVar(
    "_uuid_context", default=None
)

_replay_active: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "_request_persistence_replay_active", default=False
)


def _uuid_from_random() -> uuid.UUID:
    rand_int = random.getrandbits(128)
    rand_bytes = bytearray(rand_int.to_bytes(16, "big"))
    rand_bytes[6] = (rand_bytes[6] & 0x0F) | 0x40
    rand_bytes[8] = (rand_bytes[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(rand_bytes))


def _uuid_proxy() -> uuid.UUID:
    ctx = _uuid_context.get()
    if isinstance(ctx, _UuidRecordContext):
        value = _UUID_ORIGINAL()
        ctx.collector.append(str(value))
        return value
    if isinstance(ctx, _UuidReplayContext):
        if ctx.queue:
            return uuid.UUID(ctx.queue.popleft())
        if ctx.use_random_fallback:
            return _uuid_from_random()
        return _UUID_ORIGINAL()
    return _UUID_ORIGINAL()


uuid.uuid4 = _uuid_proxy  # type: ignore[assignment]


@dataclass
class HttpRequestSnapshot:
    method: str
    path: str
    raw_path: str | None
    query_string: str | None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body_b64: str | None = None

    @classmethod
    def from_request(cls, request: Request) -> HttpRequestSnapshot:
        headers = []
        to_wsgi_list = getattr(request.headers, "to_wsgi_list", None)
        if callable(to_wsgi_list):
            header_pairs = list(to_wsgi_list())
        else:
            header_pairs = list(request.headers.items())

        for name, value in header_pairs:
            if name.lower() in SENSITIVE_HEADERS:
                value = "<redacted>"
            headers.append((name, value))

        body_bytes = b""
        try:
            body_bytes = request.get_data(cache=True) or b""
        except Exception as exc:  # pragma: no cover - extremely defensive
            LOG.debug("could not buffer request body for persistence: %s", exc)

        body_b64 = base64.b64encode(body_bytes).decode("ascii") if body_bytes else None

        query_string = (
            request.query_string.decode("latin-1")
            if isinstance(request.query_string, bytes)
            else request.query_string
        )
        raw_path = request.environ.get("RAW_URI") or request.environ.get("REQUEST_URI")

        return cls(
            method=request.method,
            path=request.path,
            raw_path=raw_path,
            query_string=query_string,
            headers=headers,
            body_b64=body_b64,
        )

    def to_request(self) -> Request:
        headers = Headers(self.headers)
        body_bytes = base64.b64decode(self.body_b64) if self.body_b64 else b""
        query_string = self.query_string or ""
        raw_path = self.raw_path or self.path
        return Request(
            method=self.method,
            path=self.path,
            headers=headers,
            body=body_bytes,
            query_string=query_string,
            raw_path=raw_path,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "raw_path": self.raw_path,
            "query_string": self.query_string,
            "headers": self.headers,
            "body_b64": self.body_b64,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> HttpRequestSnapshot:
        return cls(
            method=payload["method"],
            path=payload["path"],
            raw_path=payload.get("raw_path"),
            query_string=payload.get("query_string"),
            headers=[tuple(item) for item in payload.get("headers", [])],
            body_b64=payload.get("body_b64"),
        )


@dataclass
class RecordedClock:
    wall_time_utc: float
    monotonic_offset: float

    @classmethod
    def capture(cls, origin: float | None = None) -> RecordedClock:
        wall = time.time()
        monotonic_now = time.monotonic()
        offset = monotonic_now - origin if origin is not None else 0.0
        return cls(wall_time_utc=wall, monotonic_offset=offset)

    def to_dict(self) -> dict[str, Any]:
        return {
            "wall_time_utc": self.wall_time_utc,
            "monotonic_offset": self.monotonic_offset,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RecordedClock:
        return cls(
            wall_time_utc=payload["wall_time_utc"],
            monotonic_offset=payload.get("monotonic_offset", 0.0),
        )


@dataclass
class RequestSnapshot:
    version: int
    timestamp: str
    service: str
    operation: str
    protocol: ProtocolName | None
    region: str | None
    partition: str | None
    account_id: str | None
    request_id: str | None
    http_request: HttpRequestSnapshot
    service_request: Any
    trace_context: dict[str, Any]
    internal_request_params: dict[str, Any] | None
    random_state: str | None
    clock: RecordedClock | None
    uuid_sequence: list[str] | None

    @classmethod
    def from_context(
        cls,
        context: RequestContext,
        *,
        random_state: str | None = None,
        clock: RecordedClock | None = None,
        uuid_sequence: list[str] | None = None,
    ) -> RequestSnapshot:
        if not context.service or not context.operation:
            raise ValueError("request context is not fully parsed; cannot record snapshot")

        service_name = context.service.service_name
        operation_name = context.operation.name
        protocol: ProtocolName | None = context.protocol

        http_request = HttpRequestSnapshot.from_request(context.request)
        encoded_service_request = encode_value(context.service_request)
        trace_context = encode_value(context.trace_context or {})
        internal_params = (
            encode_value(context.internal_request_params)
            if context.internal_request_params
            else None
        )

        timestamp = datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")

        return cls(
            version=REQUEST_SNAPSHOT_VERSION,
            timestamp=timestamp,
            service=service_name,
            operation=operation_name,
            protocol=protocol,
            region=context.region,
            partition=context.partition,
            account_id=context.account_id,
            request_id=context.request_id,
            http_request=http_request,
            service_request=encoded_service_request,
            trace_context=trace_context,
            internal_request_params=internal_params,
            random_state=random_state,
            clock=clock,
            uuid_sequence=uuid_sequence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "service": self.service,
            "operation": self.operation,
            "protocol": self.protocol,
            "region": self.region,
            "partition": self.partition,
            "account_id": self.account_id,
            "request_id": self.request_id,
            "http_request": self.http_request.to_dict(),
            "service_request": self.service_request,
            "trace_context": self.trace_context,
            "internal_request_params": self.internal_request_params,
            "random_state": self.random_state,
            "clock": self.clock.to_dict() if self.clock else None,
            "uuid_sequence": self.uuid_sequence,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RequestSnapshot:
        clock_payload = payload.get("clock")
        return cls(
            version=payload["version"],
            timestamp=payload["timestamp"],
            service=payload["service"],
            operation=payload["operation"],
            protocol=payload.get("protocol"),
            region=payload.get("region"),
            partition=payload.get("partition"),
            account_id=payload.get("account_id"),
            request_id=payload.get("request_id"),
            http_request=HttpRequestSnapshot.from_dict(payload["http_request"]),
            service_request=payload.get("service_request"),
            trace_context=payload.get("trace_context", {}),
            internal_request_params=payload.get("internal_request_params"),
            random_state=payload.get("random_state"),
            clock=RecordedClock.from_dict(clock_payload) if clock_payload else None,
            uuid_sequence=payload.get("uuid_sequence"),
        )


def encode_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return {_TYPE_KEY: "bytes", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Decimal):
        return {_TYPE_KEY: "decimal", "value": str(value)}
    if isinstance(value, datetime):
        return {_TYPE_KEY: "datetime", "value": value.isoformat(timespec="microseconds")}
    if isinstance(value, dict):
        return {to_str(k): encode_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [encode_value(item) for item in value]
    if isinstance(value, tuple):
        return {_TYPE_KEY: "tuple", "value": [encode_value(item) for item in value]}
    if isinstance(value, set):
        return {_TYPE_KEY: "set", "value": [encode_value(item) for item in value]}

    # fallback to string representation
    return {_TYPE_KEY: "repr", "value": repr(value)}


def decode_value(value: Any) -> Any:
    if isinstance(value, list):
        return [decode_value(item) for item in value]
    if isinstance(value, dict):
        type_marker = value.get(_TYPE_KEY)
        if type_marker:
            if type_marker == "bytes":
                return base64.b64decode(value["value"])
            if type_marker == "decimal":
                return Decimal(value["value"])
            if type_marker == "datetime":
                return datetime.fromisoformat(value["value"])
            if type_marker == "tuple":
                return tuple(decode_value(item) for item in value["value"])
            if type_marker == "set":
                return {decode_value(item) for item in value["value"]}
            if type_marker == "repr":
                return value["value"]
        return {k: decode_value(v) for k, v in value.items() if k != _TYPE_KEY}
    return value


class SnapshotStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()

    def append(self, snapshot: RequestSnapshot) -> None:
        payload = json.dumps(snapshot.to_dict(), separators=(",", ":"))
        with self.lock:
            self._ensure_parent()
            with self.path.open("a", encoding="utf-8") as fd:
                fd.write(payload)
                fd.write("\n")

    def __iter__(self) -> Iterator[RequestSnapshot]:
        if not self.path.exists():
            return iter(())
        with self.lock:
            with self.path.open("r", encoding="utf-8") as fd:
                for line in fd:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                        yield RequestSnapshot.from_dict(payload)
                    except json.JSONDecodeError as exc:
                        LOG.warning("cannot decode snapshot line: %s", exc)

    def clear(self) -> None:
        with self.lock:
            if self.path.exists():
                self.path.unlink()

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)


@contextlib.contextmanager
def deterministic_random(state_b64: str | None):
    if not state_b64:
        yield
        return

    try:
        state = pickle.loads(base64.b64decode(state_b64))
    except Exception as exc:  # pragma: no cover - defensive
        LOG.warning("unable to decode random state for replay: %s", exc)
        yield
        return

    previous_state = random.getstate()
    random.setstate(state)
    try:
        yield
    finally:
        random.setstate(previous_state)


@contextlib.contextmanager
def deterministic_clock(clock: RecordedClock | None):
    if not clock:
        yield
        return

    original_monotonic = time.monotonic
    recorded_wall = clock.wall_time_utc
    recorded_offset = clock.monotonic_offset
    enter_real_monotonic = original_monotonic()

    def _time():
        return recorded_wall

    def _monotonic():
        return recorded_offset + (original_monotonic() - enter_real_monotonic)

    patchers = [
        patch("time.time", _time),
        patch("time.monotonic", _monotonic),
    ]

    for patcher in patchers:
        patcher.start()

    original_datetime_cls = sys.modules["datetime"].datetime

    class FrozenDateTime(original_datetime_cls):
        @classmethod
        def utcnow(cls):
            return cls.fromtimestamp(recorded_wall, tz=UTC).replace(tzinfo=None)

        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return cls.fromtimestamp(recorded_wall, tz=UTC).replace(tzinfo=None)
            return cls.fromtimestamp(recorded_wall, tz=tz)

    replacements: list[tuple[object, str, Any]] = []

    def _replace_attr(target: object, name: str, value: Any):
        try:
            current = getattr(target, name)
        except AttributeError:
            return
        replacements.append((target, name, current))
        setattr(target, name, value)

    datetime_module = sys.modules["datetime"]
    _replace_attr(datetime_module, "datetime", FrozenDateTime)

    for module in list(sys.modules.values()):
        if not module:
            continue
        module_name = getattr(module, "__name__", "")
        if not module_name.startswith(PATCHED_MODULE_PREFIXES):
            continue
        module_dict = getattr(module, "__dict__", None)
        if not module_dict:
            continue
        for attr_name, attr_value in list(module_dict.items()):
            if attr_value is original_datetime_cls:
                _replace_attr(module, attr_name, FrozenDateTime)

    try:
        yield
    finally:
        for patcher in reversed(patchers):
            patcher.stop()
        for target, name, value in reversed(replacements):
            setattr(target, name, value)


@contextlib.contextmanager
def deterministic_uuid(sequence: list[str] | None, *, use_random_fallback: bool = True):
    if not sequence and not use_random_fallback:
        yield
        return

    token = _uuid_context.set(_UuidReplayContext(sequence, use_random_fallback))
    try:
        yield
    finally:
        _uuid_context.reset(token)


@contextlib.contextmanager
def recording_uuid_capture(collector: list[str]):
    token = _uuid_context.set(_UuidRecordContext(collector))
    try:
        yield
    finally:
        _uuid_context.reset(token)


class RequestRecordingHandler(Handler):
    def __init__(
        self,
        store: SnapshotStore,
        *,
        clock_origin: float | None = None,
    ) -> None:
        self.store = store
        self.clock_origin = clock_origin

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if _replay_active.get():
            return

        lock = _REQUEST_PERSISTENCE_LOCK
        lock.acquire()
        lock_released = False

        try:
            try:
                random_state = base64.b64encode(pickle.dumps(random.getstate())).decode("ascii")
            except Exception as exc:  # pragma: no cover - extremely defensive
                LOG.warning("failed to capture random state: %s", exc)
                random_state = None

            try:
                clock = RecordedClock.capture(self.clock_origin)
            except Exception as exc:  # pragma: no cover - extremely defensive
                LOG.warning("failed to capture clock state: %s", exc)
                clock = None

            uuid_log: list[str] = []

            exit_stack = getattr(context, "_request_persistence_exit_stack", None)
            cleanup_added = True
            if exit_stack is None:
                exit_stack = contextlib.ExitStack()
                context._request_persistence_exit_stack = exit_stack
                cleanup_added = False

            exit_stack.enter_context(recording_uuid_capture(uuid_log))

            def _persist_snapshot(
                _chain: HandlerChain, _ctx: RequestContext, _resp: Response
            ) -> None:
                try:
                    snapshot = RequestSnapshot.from_context(
                        _ctx,
                        random_state=random_state,
                        clock=clock,
                        uuid_sequence=uuid_log if uuid_log else None,
                    )
                except Exception as exc:  # pragma: no cover - defensive
                    LOG.warning("failed to capture request snapshot: %s", exc)
                else:
                    self.store.append(snapshot)

            chain.finalizers.append(_persist_snapshot)

            if not cleanup_added:

                def _cleanup(_chain: HandlerChain, _ctx: RequestContext, _resp: Response) -> None:
                    try:
                        exit_stack.close()
                    finally:
                        if hasattr(_ctx, "_request_persistence_exit_stack"):
                            delattr(_ctx, "_request_persistence_exit_stack")

                chain.finalizers.append(_cleanup)

            def _release_lock(_chain: HandlerChain, _ctx: RequestContext, _resp: Response) -> None:
                nonlocal lock_released
                if not lock_released:
                    lock.release()
                    lock_released = True

            chain.finalizers.append(_release_lock)

        except Exception:
            if not lock_released:
                lock.release()
                lock_released = True
            raise

        def _ensure_release_on_error(exc: Exception | None = None) -> None:
            nonlocal lock_released
            if not lock_released:
                lock.release()
                lock_released = True

        context._request_persistence_release_guard = _ensure_release_on_error

        try:
            pass
        except Exception as exc:
            _ensure_release_on_error(exc)
            raise


class RequestReplayController:
    def __init__(
        self,
        store: SnapshotStore,
        service_loader: ServiceLoader,
        service_request_router,
        context_class: type[RequestContext],
    ) -> None:
        self.store = store
        self.service_loader = service_loader
        self.service_request_router = service_request_router
        self.context_class = context_class

    def replay_all(self) -> None:
        for snapshot in self.store:
            try:
                self._replay_snapshot(snapshot)
            except Exception as exc:
                LOG.exception(
                    "failed to replay snapshot %s/%s: %s",
                    snapshot.service,
                    snapshot.operation,
                    exc,
                )

    def _replay_snapshot(self, snapshot: RequestSnapshot) -> None:
        http_request = snapshot.http_request.to_request()
        context = self.context_class(http_request)

        service_model = self._load_service_model(snapshot)
        context.service = service_model
        context.protocol = snapshot.protocol or determine_aws_protocol(http_request, service_model)
        context.operation = service_model.operation_model(snapshot.operation)
        context.region = snapshot.region
        context.partition = snapshot.partition or "aws"
        context.account_id = snapshot.account_id
        context.request_id = snapshot.request_id
        context.service_request = decode_value(snapshot.service_request)
        context.trace_context = decode_value(snapshot.trace_context) or {}
        context.internal_request_params = (
            decode_value(snapshot.internal_request_params)
            if snapshot.internal_request_params is not None
            else None
        )

        response = Response()

        replay_chain = HandlerChain(request_handlers=[self.service_request_router])
        # ensure the service is loaded and the router populated
        self.service_loader.require_service(replay_chain, context, response)

        with _REQUEST_PERSISTENCE_LOCK:
            token = _replay_active.set(True)
            try:
                with (
                    deterministic_random(snapshot.random_state),
                    deterministic_clock(snapshot.clock),
                    deterministic_uuid(snapshot.uuid_sequence),
                ):
                    replay_chain.handle(context, response)
            finally:
                _replay_active.reset(token)

    def _load_service_model(self, snapshot: RequestSnapshot) -> ServiceModel:
        try:
            return load_service(snapshot.service, protocol=snapshot.protocol)
        except Exception:
            LOG.debug("falling back to default protocol for service %s", snapshot.service)
            return load_service(snapshot.service)


class RequestPersistenceManager:
    def __init__(self) -> None:
        configured_mode = (config.REQUEST_PERSISTENCE_MODE or "off").lower()
        path = config.REQUEST_PERSISTENCE_PATH
        if not path:
            path = config.dirs.data and (Path(config.dirs.data) / "request-snapshots.jsonl")
        self.store = SnapshotStore(Path(path)) if path else None

        self.configured_mode = configured_mode
        self.recording_enabled = False
        self.replaying_enabled = False
        self.clock_origin = None

        if not self.store:
            if configured_mode not in ("off", ""):
                LOG.warning(
                    "request persistence configured but no storage path resolved; disabling"
                )
            return

        file_exists = self.store.path.exists()

        if configured_mode in ("off", ""):
            return
        if configured_mode == "record":
            self.recording_enabled = True
        elif configured_mode == "replay":
            self.replaying_enabled = True
        elif configured_mode in {"auto", "on", "enabled"}:
            self.recording_enabled = True
            if file_exists:
                self.replaying_enabled = True
                LOG.info(
                    "request persistence: found snapshot log at %s, scheduling replay",
                    self.store.path,
                )
            else:
                LOG.info(
                    "request persistence: no snapshot log found at %s, recording new session",
                    self.store.path,
                )
        else:
            LOG.warning("unknown request persistence mode '%s', disabling", configured_mode)

        if self.recording_enabled:
            self.clock_origin = time.monotonic()

    def is_recording(self) -> bool:
        return self.store is not None and self.recording_enabled

    def is_replaying(self) -> bool:
        return self.store is not None and self.replaying_enabled

    def build_recorder(self) -> RequestRecordingHandler | None:
        if not self.is_recording():
            return None
        LOG.info("request persistence: recording gateway traffic to %s", self.store.path)
        return RequestRecordingHandler(
            self.store,
            clock_origin=self.clock_origin,
        )

    def build_replayer(
        self,
        service_loader: ServiceLoader,
        service_request_router,
        context_class: type[RequestContext],
    ) -> RequestReplayController | None:
        if not self.is_replaying():
            return None
        LOG.info("request persistence: replaying snapshots from %s", self.store.path)
        return RequestReplayController(
            self.store, service_loader, service_request_router, context_class
        )
