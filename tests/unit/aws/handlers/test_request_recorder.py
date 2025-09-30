import base64
import datetime as dt_module
import random
from decimal import Decimal

import pytest

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.core import ServiceOperation
from localstack.aws.chain import HandlerChain
from localstack.aws.handlers.request_recorder import (
    RecordedClock,
    RequestPersistenceManager,
    RequestReplayController,
    RequestSnapshot,
    SnapshotStore,
    decode_value,
    deterministic_clock,
)
from localstack.aws.handlers.service import ServiceRequestRouter
from localstack.aws.spec import load_service
from localstack.http import Request, Response
from localstack.utils import time as ls_time
from localstack.utils.strings import short_uid


@pytest.fixture
def sqs_operation():
    service = load_service("sqs")
    operation = service.operation_model("CreateQueue")
    return service, operation


@pytest.fixture
def s3_operation():
    service = load_service("s3")
    operation = service.operation_model("PutBucketLifecycleConfiguration")
    return service, operation


def _build_context(service, operation):
    request = Request(
        method="POST",
        path="/",
        headers={"Host": "localhost"},
        body=b"Action=CreateQueue&QueueName=demo",
        query_string=b"",
    )
    context = RequestContext(request)
    context.service = service
    context.protocol = service.protocol
    context.operation = operation
    context.region = "us-east-1"
    context.partition = "aws"
    context.account_id = "123456789012"
    context.service_request = {
        "QueueName": "demo",
        "Attributes": {"DelaySeconds": Decimal("5")},
        "Tags": {"env": "dev"},
        "Binary": b"\x00bin",
    }
    context.trace_context = {
        "Root": "1-5759e988-bd862e3fe1be46a994272793",
        "Sampled": "1",
    }
    context.internal_request_params = {"payload": b"payload"}
    return context


def test_snapshot_roundtrip_preserves_typed_values(sqs_operation):
    service, operation = sqs_operation
    context = _build_context(service, operation)

    snapshot = RequestSnapshot.from_context(context)
    data = snapshot.to_dict()
    restored = RequestSnapshot.from_dict(data)

    assert restored.version == snapshot.version
    assert restored.service == snapshot.service
    assert restored.operation == snapshot.operation

    decoded_request = decode_value(restored.service_request)
    assert isinstance(decoded_request["Attributes"]["DelaySeconds"], Decimal)
    assert decoded_request["Binary"] == b"\x00bin"

    http_copy = restored.http_request.to_request()
    assert http_copy.method == context.request.method
    assert base64.b64encode(context.request.get_data()) == base64.b64encode(http_copy.get_data())

    decoded_trace = decode_value(restored.trace_context)
    assert decoded_trace["Root"] == context.trace_context["Root"]

    decoded_internal = decode_value(restored.internal_request_params)
    assert decoded_internal["payload"] == context.internal_request_params["payload"]


def test_replay_invokes_registered_handler(tmp_path, sqs_operation):
    service, operation = sqs_operation
    context = _build_context(service, operation)

    store_path = tmp_path / "snapshots.jsonl"
    store = SnapshotStore(store_path)

    # record a snapshot
    snapshot = RequestSnapshot.from_context(context)
    store.append(snapshot)

    router = ServiceRequestRouter()
    captured = {}

    def fake_handler(chain, replay_context, response):
        captured["service_request"] = replay_context.service_request
        response.set_json({"Status": "OK"})

    router.add_handler(ServiceOperation(service.service_name, operation.name), fake_handler)

    class NoopLoader:
        def require_service(self, chain, replay_context, response):  # noqa: D401 - simple stub
            return

    replayer = RequestReplayController(store, NoopLoader(), router, RequestContext)
    replayer.replay_all()

    assert captured
    decoded = captured["service_request"]
    assert decoded["QueueName"] == "demo"
    assert isinstance(decoded["Attributes"]["DelaySeconds"], Decimal)


def test_auto_mode_records_when_file_missing(monkeypatch, tmp_path):
    store_path = tmp_path / "snapshots.jsonl"
    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_MODE", "auto")
    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_PATH", str(store_path))
    manager = RequestPersistenceManager()

    assert manager.is_recording()
    assert not manager.is_replaying()
    assert manager.store.path == store_path


def test_auto_mode_replays_when_file_present(monkeypatch, tmp_path):
    store_path = tmp_path / "snapshots.jsonl"
    store_path.touch()

    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_MODE", "auto")
    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_PATH", str(store_path))

    manager = RequestPersistenceManager()

    assert manager.is_recording()
    assert manager.is_replaying()
    assert manager.store.path == store_path

    router = ServiceRequestRouter()

    class NoopLoader:
        def require_service(self, chain, context, response):
            return

    replayer = manager.build_replayer(NoopLoader(), router, RequestContext)
    assert replayer is not None


def test_deterministic_clock_patches_moto_modules():
    from moto.core import utils as moto_utils

    recorded_wall = 1_710_102_030.0
    expected = dt_module.datetime.fromtimestamp(recorded_wall, tz=dt_module.UTC).replace(
        tzinfo=None
    )
    clock = RecordedClock(wall_time_utc=recorded_wall, monotonic_offset=0.0)

    assert moto_utils.utcnow() != expected

    with deterministic_clock(clock):
        assert moto_utils.utcnow() == expected
        assert dt_module.datetime.utcnow() == expected

    assert moto_utils.utcnow() != expected


def test_s3_like_random_and_time_are_deterministic(monkeypatch, tmp_path, s3_operation):
    service, operation = s3_operation
    store_path = tmp_path / "snapshots.jsonl"

    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_MODE", "record")
    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_PATH", str(store_path))

    manager = RequestPersistenceManager()
    recorder = manager.build_recorder()
    router = ServiceRequestRouter()

    outputs: list[dict[str, str]] = []

    def s3_style_handler(chain, replay_context, response):
        uid = short_uid()
        timestamp = ls_time.timestamp_millis()
        outputs.append({"uid": uid, "timestamp": timestamp})
        response.set_json({"Id": uid, "Timestamp": timestamp})

    router.add_handler(ServiceOperation(service.service_name, operation.name), s3_style_handler)

    request = Request(
        method="POST", path="/", headers={"Host": "localhost"}, body=b"", query_string=b""
    )
    context = RequestContext(request)
    context.service = service
    context.protocol = service.protocol
    context.operation = operation
    context.region = "us-east-1"
    context.partition = "aws"
    context.account_id = "000000000000"
    context.service_request = {}

    handlers = [recorder] if recorder else []
    handlers.append(router)
    chain = HandlerChain(request_handlers=handlers)
    chain.handle(context, Response())

    recorded_snapshots = list(manager.store)
    assert recorded_snapshots
    first_snapshot = recorded_snapshots[0]
    assert first_snapshot.random_state
    assert first_snapshot.clock
    assert first_snapshot.uuid_sequence

    first_output = outputs[0]

    random.seed(99999)

    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_MODE", "replay")
    monkeypatch.setattr(config, "REQUEST_PERSISTENCE_PATH", str(store_path))
    replay_manager = RequestPersistenceManager()

    class NoopLoader:
        def require_service(self, chain, replay_context, response):
            return

    replayer = RequestReplayController(replay_manager.store, NoopLoader(), router, RequestContext)
    replayer.replay_all()

    assert len(outputs) == 2
    assert outputs[0] == outputs[1] == first_output

    recorded_after_replay = list(manager.store)
    assert len(recorded_after_replay) == 1
