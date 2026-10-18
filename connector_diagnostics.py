"""Synthetic enterprise OAuth connector troubleshooting, no token verification or I/O."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SENSITIVE_KEYS = {"access_token", "refresh_token", "authorization", "password", "secret", "api_key", "client_secret"}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    observed: str
    recommendation: str


def sanitized(value: Any) -> Any:
    """Recursively redact credential-bearing keys from outputs (including nested evidence)."""
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in SENSITIVE_KEYS else sanitized(val)
                for key, val in value.items()}
    if isinstance(value, list):
        return [sanitized(v) for v in value]
    return value


def diagnose(case: dict[str, Any]) -> dict[str, Any]:
    """Analyze *decoded, synthetic claims*, not cryptographically validated tokens."""
    identity = case["identity"]
    expected = case["expected"]
    response = case["response"]
    findings: list[Finding] = []

    def add(code: str, severity: str, observed: str, recommendation: str) -> None:
        findings.append(Finding(code, severity, observed, recommendation))

    if identity.get("issuer") != expected["issuer"]:
        add("ISSUER_MISMATCH", "high", "Token issuer does not match the trusted configuration.",
            "Check the configured identity provider and tenant; validate token signatures in the real system.")
    if identity.get("audience") != expected["audience"]:
        add("AUDIENCE_MISMATCH", "high", "Token audience does not match the connector API.",
            "Request a token for the intended resource rather than bypassing audience validation.")
    if int(identity.get("expires_at", 0)) <= int(case["now_epoch"]):
        add("TOKEN_EXPIRED", "high", "Decoded expiration has elapsed.",
            "Refresh or reauthorize with the designated OAuth flow.")
    missing = set(expected["required_scopes"]) - set(identity.get("scopes", []))
    if missing:
        add("MISSING_SCOPES", "high", "Required scopes absent: " + ", ".join(sorted(missing)),
            "Review consent and least-privilege scope mappings with the resource owner.")

    status = int(response["status"])
    if status == 401:
        add("HTTP_401", "high", "API returned 401 Unauthorized.",
            "Inspect token lifetime, trust configuration and authentication flow.")
    elif status == 403:
        add("HTTP_403", "high", "API returned 403 Forbidden.",
            "Inspect API/resource ACLs, role assignments and application permissions.")
    elif status == 429:
        retry_after = response.get("retry_after_seconds")
        wait = min(120, max(1, int(retry_after))) if retry_after is not None else 5
        add("HTTP_429", "warning", f"Rate limit reached; suggested wait: {wait}s.",
            "Respect Retry-After, apply jitter, and inspect published provider limits.")
    elif 500 <= status < 600:
        add("HTTP_5XX", "warning", f"Provider returned HTTP {status}.",
            "Use bounded exponential backoff with jitter; retain correlation IDs for escalation.")
    elif not 200 <= status < 300:
        add("HTTP_UNEXPECTED", "warning", f"Provider returned HTTP {status}.",
            "Review the API contract and diagnostic response.")

    return {
        "case_id": case["id"], "provider": case["provider"],
        "correlation_id": case["correlation_id"],
        "result": "needs_review" if findings else "checks_passed",
        "findings": [asdict(f) for f in findings],
        "observed_http_status": status,
        "boundaries": ["Decoded claims are not verified JWTs", "No live connector calls", "No credential disclosure"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic enterprise connector diagnostic workbench")
    parser.add_argument("--case", choices=["missing_scope", "expired", "rate_limited", "healthy", "wrong_audience"], default="missing_scope")
    args = parser.parse_args()
    cases = json.loads((ROOT / "scenarios.json").read_text(encoding="utf-8"))
    print(json.dumps(diagnose(cases[args.case]), indent=2))


if __name__ == "__main__":
    main()
