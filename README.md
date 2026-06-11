<a href="https://www.jahia.com/">
    <img src="https://www.jahia.com/modules/jahiacom-templates/images/jahia-3x.png" alt="Jahia logo" title="Jahia" height="60" />
</a>

content-security-policy
=====================

The purpose of this module is to allow the definition of a Content Security Policy for a website inside [Jahia](https://www.jahia.com).

For more details about installation and usage, please refer to the [Jahia academy](https://academy.jahia.com/documentation/jahia-cms/jahia-8-2/developer/security/jahia-content-security-policy).

## Open-Source

This is an Open-Source module, you can find more details about Open-Source @ Jahia [in this repository](https://github.com/Jahia/open-source).

## Content Security Policy
Content Security Policy (CSP) is a security feature that helps prevent various types of attacks, such as Cross-Site Scripting (XSS) and data injection attacks. 
It allows web developers to control which resources can be loaded and executed by the browser.

### Example of a Content Security Policy
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com; object-src 'none'; frame-ancestors 'none';
```

### Example of a strict Content Security Policy
```http
Content-Security-Policy: 
default-src 'self' https://*.doubleclick.net; 
script-src 'nonce-' 'strict-dynamic' https: 'unsafe-inline'; 
object-src 'none'; 
base-uri 'none'; 
frame-ancestors 'none'; 
img-src 'self' data:; 
font-src 'self' data:; 
style-src 'self' 'unsafe-inline';
frame-src 'self' https://*.googletagmanager.com https://*.google-analytics.com https://*.doubleclick.net https://*.googlesyndication.com;
connect-src 'self' https://*.google-analytics.com https://*.googletagmanager.com https://*.doubleclick.net https://*.googlesyndication.com;
```
The 'nonce-' is a placeholder for a nonce value that should be generated for each request.

## Resources
- [Content Security Policy - MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Content Security Policy - Reference](https://content-security-policy.com/)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Content Security Policy - Google Developers](https://web.dev/articles/csp)
- [Lighthouse - Content Security Policy](https://developer.chrome.com/docs/lighthouse/best-practices/csp-xss)


## How to use
To use this module, you need to install it in your Jahia instance. 
Activate the module on the site you want to secure with CSP.
Once installed, you can configure the Content Security Policy for your website through the Jahia administration interface of your site.
Edit the site properties and, under Options, check **Add Content-Security-Policy at the site level**. Four fields are available:

- **Enforced Content-Security-Policy** — the policy the browser enforces (without the `Content-Security-Policy:` prefix). Multi-line input is fine; it is normalised into a single-line header.
- **Report-only Content-Security-Policy** — an optional second policy delivered in its own `Content-Security-Policy-Report-Only` header.
- **Only report CSP violations** — legacy toggle: delivers the enforced policy in report-only mode.
- **Custom violations report URL** — where browsers send violation reports; leave blank to log them in the Jahia logs via the built-in endpoint. Only absolute `http(s)` URLs are accepted.

For example:

```http
default-src 'self' https://*.doubleclick.net; 
script-src 'nonce-' 'strict-dynamic' https: 'unsafe-inline'; 
object-src 'none'; 
base-uri 'none'; 
frame-ancestors 'none'; 
img-src 'self' data:; 
font-src 'self' data:; 
style-src 'self' 'unsafe-inline';
frame-src 'self' https://*.googletagmanager.com https://*.google-analytics.com https://*.doubleclick.net https://*.googlesyndication.com;
connect-src 'self' https://*.google-analytics.com https://*.googletagmanager.com https://*.doubleclick.net https://*.googlesyndication.com;

```

The `nonce-` placeholder is replaced with a fresh per-request nonce and injected into every
`<script>`, `<style>` and `<link>` tag, so `script-src 'nonce-'` and `style-src 'nonce-'` both work.

### Enforced and report-only policies together

Two policy fields are available under Options:

- **Enforced Content-Security-Policy** (`policy`) — the policy the browser enforces.
- **Report-only Content-Security-Policy** (`policyReportOnly`) — an optional policy delivered in a
  separate `Content-Security-Policy-Report-Only` header *alongside* the enforced one.

This lets you trial a stricter candidate policy in report-only mode (watching the violation reports)
while a known-good policy stays enforced — the recommended way to tighten a CSP without breaking the
site. Both fields can also be overridden at the page level.

The legacy **Only report CSP violations** toggle (`cspReportOnly`) still works: when set, the enforced
policy is delivered in report-only mode instead.

The module appends `report-uri` and `report-to` automatically, but only when your policy does not
already declare them — so a hand-written reporting directive is never duplicated.

The built-in report endpoint accepts violation reports as soon as any policy (enforced or
report-only, at site or page level) is configured, when the report-only toggle is set, or when the
custom report URL points back at the built-in action.

## Operations

- **Scope** — headers and nonces are applied in live and preview modes only, for full HTML page
  renders; edit mode and AJAX fragments are excluded. Report routing (`cspReportOnly`,
  `cspReportUrl`) is configured at the site level only.
- **Nonce & caching** — when a policy uses the `nonce-` placeholder, the response is sent with
  `Cache-Control: no-store`: a per-request nonce can never match a response cached by a CDN or
  proxy. The HTML body is re-noncified on every request, so header and body always agree.
- **Report endpoint protections** — the endpoint (`*.contentSecurityPolicyReportOnly.do`) is
  unauthenticated by nature (browsers POST reports anonymously) and CSRF-whitelisted via
  `org.jahia.modules.jahiacsrfguard-csp.cfg`. It enforces: a 64 KB body cap, at most 20 violations
  per Reporting API batch, and a per-client-IP rate limit of 30 requests/minute (HTTP 429 beyond).
  The rate limit is **per Jahia node** (a cluster of N nodes multiplies it by N) and keys on
  `getRemoteAddr()`, which behind a reverse proxy is the proxy address — keep an edge/WAF rate
  limit as the primary control.
- **Logging** — violations are logged at **WARN** on logger
  `org.jahia.modules.csp.actions.ReportOnlyAction`, prefixed `Content Security Policy:`. Violations
  caused by browser extensions (`chrome-extension:`, `moz-extension:`, `safari-*`,
  `webkit-masked-url:` schemes) are noise and demoted to DEBUG. Raw report bodies, rejected
  oversized bodies and truncated batches are logged at DEBUG. Every logged field is sanitized
  (control characters stripped, 1024-char cap). An invalid custom report URL logs a WARN and falls
  back to the built-in endpoint.
