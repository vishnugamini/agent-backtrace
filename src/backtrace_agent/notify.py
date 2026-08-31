from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def validate_webhook_url(url: str) -> None:
    """Require HTTPS except for loopback development servers and reject URL credentials."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Webhook URL must be an absolute HTTP(S) URL.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Webhook URL must not contain embedded credentials.")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Webhook URL must use HTTPS unless it targets localhost.")


def build_fleet_notification(fleet: dict[str, Any]) -> dict[str, Any]:
    """Build a path-free, prompt-free fleet decision payload."""
    gate = fleet["quality_gate"]
    history = fleet.get("history") or {}
    trend = history.get("trend")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "event": "fleet.gate",
        "generated_at": fleet["generated_at"],
        "result": "passed" if gate["passed"] else "failed",
        "fleet": {
            "summary": {key: int(value) for key, value in fleet["summary"].items()},
            "status_counts": {key: int(value) for key, value in fleet["status_counts"].items()},
        },
        "gate": {
            "summary": dict(gate["summary"]),
            "checks": [
                {
                    "key": check["key"],
                    "actual": check["actual"],
                    "expected": check["expected"],
                    "passed": bool(check["passed"]),
                    "skipped": bool(check["skipped"]),
                }
                for check in gate["checks"]
            ],
        },
        "trend": (
            {
                "has_baseline": bool(trend["has_baseline"]),
                "new_runs": int(trend["new_runs"]),
                "new_runs_needing_attention": int(trend["new_runs_needing_attention"]),
                "regressed_runs": int(trend["regressed_runs"]),
                "improved_runs": int(trend["improved_runs"]),
                "left_scan_window": int(trend["left_scan_window"]),
                "deltas": {key: int(value) for key, value in trend["deltas"].items()},
            }
            if trend else None
        ),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["event_id"] = "fleet-" + hashlib.sha256(canonical).hexdigest()[:32]
    return payload


def format_fleet_notification(payload: dict[str, Any], output_format: str = "generic") -> dict[str, Any]:
    """Wrap the same aggregate evidence for generic, Slack, or Teams receivers."""
    if output_format == "generic":
        return payload
    if output_format not in {"slack", "teams"}:
        raise ValueError(f"Unknown webhook format: {output_format}")
    result = payload["result"]
    gate = payload["gate"]["summary"]
    fleet = payload["fleet"]["summary"]
    headline = f"Backtrace fleet gate {result}"
    facts = [
        ("Runs", fleet["runs"]),
        ("Need attention", fleet["needs_attention"]),
        ("Unresolved", fleet["unresolved_incidents"]),
        ("Checks", f"{gate['passed']} passed · {gate['failed']} failed · {gate['skipped']} skipped"),
        ("Event", payload["event_id"]),
    ]
    check_lines = [
        f"{'SKIP' if check['skipped'] else 'PASS' if check['passed'] else 'FAIL'} · {check['key'].replace('_', ' ')} · actual {check['actual']} · expected {check['expected']}"
        for check in payload["gate"]["checks"]
    ]
    if output_format == "slack":
        return {
            "text": f"{headline}: {gate['failed']} failed, {fleet['unresolved_incidents']} unresolved.",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": headline, "emoji": True}},
                {"type": "section", "fields": [{"type": "mrkdwn", "text": f"*{label}*\n{value}"} for label, value in facts]},
                {"type": "section", "text": {"type": "mrkdwn", "text": "*Gate evidence*\n" + "\n".join(check_lines)}},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Generated {payload['generated_at']} · aggregate evidence only"}]},
            ],
        }
    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "https://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "text": headline, "weight": "Bolder", "size": "Large", "color": "Good" if result == "passed" else "Attention"},
                    {"type": "FactSet", "facts": [{"title": f"{label}:", "value": str(value)} for label, value in facts]},
                    {"type": "TextBlock", "text": "Gate evidence", "weight": "Bolder", "separator": True},
                    *[{"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"} for line in check_lines],
                    {"type": "TextBlock", "text": f"Generated {payload['generated_at']} · aggregate evidence only", "isSubtle": True, "spacing": "Medium", "wrap": True},
                ],
            },
        }],
    }


def serialize_webhook_payload(payload: dict[str, Any]) -> str:
    """Return the exact deterministic JSON representation used for preview and delivery."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def deliver_webhook(
    payload: dict[str, Any],
    url: str,
    *,
    event_id: str | None = None,
    signing_secret: str | None = None,
    timeout: float = 10.0,
    retries: int = 2,
    backoff_seconds: float = 0.25,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """POST a fleet payload without redirects; retry only transient failures."""
    validate_webhook_url(url)
    body = serialize_webhook_payload(payload).encode("utf-8")
    event_id = event_id or payload.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("Webhook delivery requires a stable event ID.")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "agent-backtrace-webhook/1",
        "X-Backtrace-Event": "fleet.gate",
        "Idempotency-Key": event_id,
    }
    if signing_secret is not None:
        headers["X-Backtrace-Signature"] = "sha256=" + hmac.new(signing_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    opener = build_opener(_NoRedirect)
    attempts = retries + 1
    for index in range(attempts):
        try:
            request = Request(url, data=body, headers=headers, method="POST")
            with opener.open(request, timeout=timeout) as response:
                status_code = int(response.status)
            if 200 <= status_code < 300:
                return {"configured": True, "status": "delivered", "attempts": index + 1, "status_code": status_code, "error": None, "event_id": event_id}
            retryable = status_code >= 500
            error = f"Webhook returned HTTP {status_code}."
        except HTTPError as exc:
            status_code = int(exc.code)
            retryable = status_code >= 500
            error = f"Webhook returned HTTP {status_code}."
        except (URLError, TimeoutError, OSError):
            status_code = None
            retryable = True
            error = "Webhook connection failed or timed out."
        if not retryable or index >= retries:
            return {"configured": True, "status": "failed", "attempts": index + 1, "status_code": status_code, "error": error, "event_id": event_id}
        sleep(backoff_seconds * (2 ** index))
    raise AssertionError("unreachable")
