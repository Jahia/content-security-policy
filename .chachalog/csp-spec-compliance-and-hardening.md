---
content-security-policy: minor
---

CSP spec compliance, report handling and security hardening:

- Enforced and report-only policies can now be delivered **simultaneously**: a new
  "Report-only Content-Security-Policy" field (site and page level) is sent in its own
  `Content-Security-Policy-Report-Only` header alongside the enforced policy, enabling the
  recommended trial-then-enforce rollout. The legacy "Only report CSP violations" toggle is preserved.
- Violation reports are no longer lost: the built-in report endpoint accepts reports whenever a
  policy is configured; Chrome Reporting API payloads (`application/reports+json`, batched arrays,
  bare objects, charset-suffixed content types) and CSP2 `violated-directive` reports are parsed;
  source file/line/column and script samples are logged for triage.
- Violations caused by browser extensions (`chrome-extension:`, `moz-extension:`, `safari-*`,
  `webkit-masked-url:` schemes) are filtered out of the warning log, as are unactionable reports
  carrying neither a blocked URL nor a directive (typical headless-crawler noise).
- Nonces are injected into `<style>` and `<link>` tags in addition to `<script>`, only on pages
  where a policy is configured; responses for nonce-based policies are sent with
  `Cache-Control: no-store`; `report-uri`/`report-to` are no longer duplicated when already declared.
- Hardening of the unauthenticated report endpoint: request body cap (64 KB), batch cap
  (20 violations), per-IP rate limit (30/min, HTTP 429), log-forging sanitization of all logged
  fields, and `http(s)`-only validation of the custom report URL.
