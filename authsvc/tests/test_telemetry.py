"""OpenTelemetry (agenticwf.auth.telemetry): request spans with bounded decision attributes, and counters."""

from urllib.parse import parse_qs, urlsplit

import pytest

pytest.importorskip("opentelemetry.sdk")
pytest.importorskip("opentelemetry.instrumentation.fastapi")

from fastapi.testclient import TestClient
from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agenticwf.auth import telemetry
from agenticwf.auth.app import create_app
from tests.test_web import env, login  # noqa: F401  (the fixture)

EXPORTER = InMemorySpanExporter()
READER = InMemoryMetricReader()


@pytest.fixture(scope="module", autouse=True)
def providers():
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(EXPORTER))
    trace.set_tracer_provider(tracer_provider)   # once per process; nothing else sets one in the tests
    metrics.set_meter_provider(MeterProvider(metric_readers=[READER]))


@pytest.fixture(autouse=True)
def instrumented(monkeypatch):
    monkeypatch.setattr(telemetry, "_tracing", True)   # as setup() would with an endpoint set
    EXPORTER.clear()


def verify_spans():
    return [s for s in EXPORTER.get_finished_spans() if s.name == "GET /verify"]


def counted(name):
    found = {}
    for resource in READER.get_metrics_data().resource_metrics:
        for scope in resource.scope_metrics:
            for metric in scope.metrics:
                if metric.name == name:
                    for point in metric.data.data_points:
                        found[tuple(sorted(point.attributes.items()))] = point.value
    return found


def fwd(method, uri, token=None):
    headers = {"X-Forwarded-Method": method, "X-Forwarded-Uri": uri}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def test_off_without_an_endpoint(monkeypatch):
    for name in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
                 "OTEL_METRICS_EXPORTER", "OTEL_SDK_DISABLED"):
        monkeypatch.delenv(name, raising=False)
    assert not telemetry.enabled() and not telemetry.metrics_enabled()
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
    assert telemetry.enabled() and not telemetry.metrics_enabled()   # Jaeger takes no metrics
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "otlp")
    assert telemetry.metrics_enabled()
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert not telemetry.enabled() and not telemetry.metrics_enabled()


def test_verify_decisions_are_on_the_request_span(settings, verifier, make_token):
    client = TestClient(create_app(settings=settings, verifier=verifier))
    token = make_token()
    client.get("/verify", headers=fwd("GET", "/api/v1/datasets/abc", token))
    client.get("/verify", headers=fwd("GET", "/api/v1/datasets/abc"))
    client.get("/verify", headers=fwd("POST", "/api/v1/datasets/abc", token))
    client.get("/verify", headers=fwd("GET", "/api/../admin", token))
    client.get("/healthz")
    allowed, missing, scope, invalid = (dict(s.attributes) for s in verify_spans())
    assert allowed["agenticwf.auth.decision"] == "allow" and allowed["agenticwf.auth.credential"] == "bearer"
    assert "agenticwf.auth.code" not in allowed
    assert (missing["agenticwf.auth.decision"], missing["agenticwf.auth.code"]) == ("deny", "missing_token")
    assert missing["agenticwf.auth.credential"] == "none"
    assert scope["agenticwf.auth.code"] == "insufficient_scope"
    assert invalid["agenticwf.auth.code"] == "invalid_request"
    assert not [s for s in EXPORTER.get_finished_spans() if "healthz" in s.name]
    for span in EXPORTER.get_finished_spans():   # never the credential, the subject or the path
        text = repr(dict(span.attributes))
        assert token not in text and "user_1" not in text and "datasets" not in text
    allowed_key = (("agenticwf.auth.credential", "bearer"), ("agenticwf.auth.decision", "allow"),
                   ("agenticwf.auth.public", False))
    assert counted("agenticwf.auth.verify")[allowed_key] >= 1


def test_login_outcomes_are_counted(env):  # noqa: F811
    client, _, _ = env
    before = counted("agenticwf.auth.logins")
    login(client)
    client.get("/auth/login")
    client.get("/auth/callback", params={"code": "good-code", "state": "forged"})
    after = counted("agenticwf.auth.logins")
    for outcome in ("ok", "invalid_state"):
        key = (("agenticwf.auth.login.outcome", outcome),)
        assert after[key] == before.get(key, 0) + 1
    callback = [s for s in EXPORTER.get_finished_spans() if s.name == "GET /auth/callback"]
    assert {s.attributes["agenticwf.auth.login.outcome"] for s in callback} == {"ok", "invalid_state"}


def test_nothing_is_recorded_without_the_sdk(monkeypatch):
    monkeypatch.setattr(telemetry, "_trace", None)
    telemetry.record_verify(allowed=True, credential="bearer")
    telemetry.record_login("ok")
