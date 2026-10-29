"""OpenTelemetry tracing and metrics of the auth service (docs/deployment.md, Tracing and metrics).

A span per HTTP request (/verify, /whoami, /auth/*; not /healthz) and per outgoing httpx call
(Logto's token and revocation endpoints), exported over OTLP/HTTP. Behind Caddy with tracing on,
the /verify span is a child of Caddy's span for the browser request, next to the backend's.

Needs the `otel` extra (``pip install 'agenticwf-auth-server[otel]'``; the container installs it), and:

    traces    OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
    metrics   OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, or OTEL_EXPORTER_OTLP_ENDPOINT with
              OTEL_METRICS_EXPORTER=otlp (Jaeger takes no metrics: off by default)

The rest is the SDK's own environment: OTEL_SERVICE_NAME (default ``agenticwf-auth``),
OTEL_RESOURCE_ATTRIBUTES, OTEL_TRACES_SAMPLER, OTEL_EXPORTER_OTLP_HEADERS, OTEL_SDK_DISABLED, ...

Only bounded outcomes are recorded (allow/deny, an error code, the credential kind), never
tokens, cookies, session ids, subjects, e-mail addresses, paths or headers.

Importing this module does nothing (``agenticwf.auth`` is also a library of the backends);
``setup()`` installs the providers, and everything here is a no-op without the SDK or before it.
"""

from __future__ import annotations

import logging
import os
from typing import Any

try:
    from opentelemetry import metrics as _metrics
    from opentelemetry import trace as _trace
except ImportError:  # the `otel` extra is not installed
    _metrics = _trace = None

log = logging.getLogger("authsvc")

SERVICE = "agenticwf-auth"
METER = "agenticwf.auth"
_tracing = _metering = False
_instruments: dict[str, Any] = {}

# Error codes from authn/authz and this service; anything else is counted as `other`.
_CODES = frozenset({"missing_token", "invalid_token", "invalid_request", "insufficient_scope", "approval_pending",
                    "invalid_origin", "temporarily_unavailable"})
_LOGIN_OUTCOMES = frozenset({"ok", "expired", "provider_error", "invalid_state", "rejected_token", "unavailable"})


def _env(name: str) -> str:
    return os.environ.get(name, "")


def enabled() -> bool:
    """Traces are asked for: an OTLP endpoint is set and the SDK is not disabled."""
    if _env("OTEL_SDK_DISABLED").lower() == "true" or _env("OTEL_TRACES_EXPORTER") == "none":
        return False
    return bool(_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or _env("OTEL_EXPORTER_OTLP_ENDPOINT"))


def metrics_enabled() -> bool:
    """Metrics are asked for: their own endpoint, or the shared one with OTEL_METRICS_EXPORTER=otlp."""
    if _env("OTEL_SDK_DISABLED").lower() == "true" or _env("OTEL_METRICS_EXPORTER") == "none":
        return False
    return bool(_env("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
                or (_env("OTEL_EXPORTER_OTLP_ENDPOINT") and _env("OTEL_METRICS_EXPORTER") == "otlp"))


def setup(service: str = SERVICE) -> bool:
    """Install the process's tracer and meter providers, exporting over OTLP/HTTP. Once per
    process; True when either is on."""
    global _tracing, _metering
    if _tracing or _metering:
        return True
    traces, metrics = enabled(), metrics_enabled()
    if not (traces or metrics):
        return False
    try:
        from opentelemetry.sdk.resources import Resource
    except ImportError:
        log.warning("an OTLP endpoint is set but the OpenTelemetry SDK is not installed "
                    "(pip install 'agenticwf-auth-server[otel]'); no traces or metrics")
        return False
    resource = Resource.create({} if _env("OTEL_SERVICE_NAME") else {"service.name": service})
    if traces:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=resource)  # flushed at exit
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        _trace.set_tracer_provider(provider)
        _tracing = True
    if metrics:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        reader = PeriodicExportingMetricReader(OTLPMetricExporter())  # every OTEL_METRIC_EXPORT_INTERVAL (60 s)
        _metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))
        _metering = True
    try:  # Logto's token and revocation endpoints
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().instrument()
    except ImportError:
        pass
    log.info("OpenTelemetry as %s: traces %s, metrics %s", _env("OTEL_SERVICE_NAME") or service,
             "on" if _tracing else "off", "on" if _metering else "off")
    return True


def instrument_app(app: Any) -> None:
    """A span and request metrics per HTTP request (not the health check), when either is on."""
    if not (_tracing or _metering):
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    except ImportError:
        return
    FastAPIInstrumentor.instrument_app(app, excluded_urls="/healthz", exclude_spans=["receive", "send"])


def _counter(name: str, unit: str, description: str) -> Any:
    """Created on first use, so importing this module creates nothing."""
    if name not in _instruments:
        _instruments[name] = _metrics.get_meter(METER).create_counter(name, unit=unit, description=description)
    return _instruments[name]


def _annotate(attributes: dict[str, Any]) -> None:
    current = _trace.get_current_span()
    if current.is_recording():
        current.set_attributes(attributes)


def record_verify(*, allowed: bool, credential: str, code: str = "", public: bool = False) -> None:
    """One /verify decision. `credential`: bearer, session or none; `code`: the error code of a denial."""
    if _trace is None:
        return
    attributes = {"agenticwf.auth.decision": "allow" if allowed else "deny",
                  "agenticwf.auth.credential": credential if credential in ("bearer", "session") else "none",
                  "agenticwf.auth.public": public}
    if not allowed:
        attributes["agenticwf.auth.code"] = code if code in _CODES else "other"
    _annotate(attributes)
    _counter("agenticwf.auth.verify", "{request}", "Decisions of /verify").add(1, attributes)


def record_login(outcome: str) -> None:
    """One browser login callback: ok, expired, provider_error, invalid_state, rejected_token, unavailable."""
    if _trace is None:
        return
    attributes = {"agenticwf.auth.login.outcome": outcome if outcome in _LOGIN_OUTCOMES else "other"}
    _annotate(attributes)
    _counter("agenticwf.auth.logins", "{login}", "Browser login callbacks, by outcome").add(1, attributes)
