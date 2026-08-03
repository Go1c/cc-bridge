# Changelog

## Unreleased

### Hardened: upstream TTFB hang attribution + single-account safe retry

**Why (incident):** Clients saw `{"error":"bad gateway: upstream TTFB timeout"}` after a full 120s wait. Logs showed the same account kept serving other requests with HTTP 200 during the window — a **per-request hang**, not account-level 429/quota exhaustion. With a single active Max account, multi-account failover is unavailable.

**Behavior before**

- `forward_request` wrapped `send()` in a fixed 120s timeout and returned opaque `AppError::BadGateway("upstream TTFB timeout")`.
- Main loop immediately `return Err(e)` — no attribution, no same-account retry.
- Only HTTP 429 excluded/retried accounts; TTFB did not quarantine (already correct), but also did nothing else.

**Behavior after**

- Structured attribution WARN log on every TTFB/connect/send failure (`upstream_transport_error error_code=... account_id=...`).
- Client still gets **HTTP 502**; `error` string remains `bad gateway: upstream TTFB timeout` for compatibility, plus `error_code` and `details` fields.
- Optional same-account retry (**default 1**, pre-response only; never after bytes written to client).
- Separate **connect timeout** (default 15s) via reqwest client builder so dead TCP/proxy paths fail faster than full TTFB budget.
- **Does not** mark account rate-limited/disabled on TTFB (explicitly not treated as 429).

**Config (env)**

| Variable | Default | Notes |
|----------|---------|-------|
| `UPSTREAM_TTFB_TIMEOUT_SECS` | `120` | Headers budget for slow Opus/long-context |
| `UPSTREAM_CONNECT_TIMEOUT_SECS` | `15` | TCP/proxy/TLS handshake |
| `UPSTREAM_TTFB_RETRY_ENABLED` | `true` | Pre-response only |
| `UPSTREAM_TTFB_RETRY_MAX` | `1` | Extra attempts after first failure |

**Follow-ups intentionally skipped**

- Full Prometheus exporter for counters/histograms (process atomics + DEBUG soft metrics only for now).
- Perfect connect-vs-header split beyond reqwest `connect_timeout` + outer `send()` timeout (reqwest 0.12 folds upload+header wait into one future after connect).
