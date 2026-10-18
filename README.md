# Enterprise Connector Diagnostics

A **local, synthetic diagnostic workbench** for OAuth 2.0-style enterprise connector incidents. Showcases security-aware error triage, claims/configuration comparison, permission mapping, and evidence for support escalation.

This is a **diagnostic simulator**, not a complete OAuth implementation, a JWT verifier, a production IAM engine, or a connector to Jira, Salesforce, Google Workspace, Microsoft 365, etc.

## What's demonstrated

- Compare *synthetic decoded claims* with expected **issuer, audience, scopes and expiration**.
- Explain common **401 Unauthorized**, **403 Forbidden**, **429 Too Many Requests** and **5xx** failure paths.
- Provide targeted remediation suggestions and preserve a **synthetic correlation ID**.
- Calculate a bounded Retry-After recommendation without issuing any requests.
- **Never print credential-bearing fields**; example redaction is available for nested dictionaries.
- Unit tests cover expected failure classes, multiple simultaneous issues, credential non-disclosure and retry limits.

## Quick start (Python 3.10+, standard library only)

```bash
python connector_diagnostics.py --case missing_scope
python connector_diagnostics.py --case expired
python connector_diagnostics.py --case wrong_audience
python connector_diagnostics.py --case rate_limited
python connector_diagnostics.py --case healthy
python -m unittest discover -s . -p 'test_*.py' -v
```

Example JSON response:

```json
{
  "case_id": "SYN-C001",
  "provider": "Synthetic document platform",
  "correlation_id": "DEMO-2001",
  "result": "needs_review",
  "findings": [
    {"code": "MISSING_SCOPES", "severity": "high", "observed": "Required scopes absent: documents.read", "recommendation": "Review consent and least-privilege scope mappings with the resource owner."},
    {"code": "HTTP_403", "severity": "high", "observed": "API returned 403 Forbidden.", "recommendation": "Inspect API/resource ACLs, role assignments and application permissions."}
  ],
  "observed_http_status": 403,
  "boundaries": ["Decoded claims are not verified JWTs", "No live connector calls", "No credential disclosure"]
}
```

## Security notes

All cases use `.invalid` example domains and fabricated timestamps and correlation IDs. The code **does not cryptographically validate tokens**; do not pass real tokens into it. Proper production design would verify signatures against trusted keys, validate issuer/audience/expiry, implement secure OAuth flows and handle secrets only in approved systems. Debug logging can reveal sensitive information even when a diagnostic output function is redacted, so no network requests or live authentication occur here.

## Possible next iteration

Extend with a mock HTTP API, OAuth 2.0 consent test harness, deterministic exponential backoff implementation, or OpenTelemetry traces—all under synthetic local fixtures and dedicated tests.
