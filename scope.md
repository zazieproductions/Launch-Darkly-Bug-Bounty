# Scope Matrix — LaunchDarkly Bug Bounty

> Program rule: **testing is only authorized on the targets listed in scope. Any domain/property
> not listed — including any subdomain — is out of scope.** Vulns found on out-of-scope but
> LaunchDarkly-owned targets can be reported (no reward/points).

## In scope

| # | Target | Tags (per Bugcrowd) | Notes |
|---|--------|---------------------|-------|
| 1 | `app.launchdarkly.com` | Elasticsearch, PostgreSQL, ReactJS, +2 (31 known issues) | Main app + point of entry. Auth, roles, org mgmt, XSS/SSRF in user input |
| 2 | `app.launchdarkly.com/api/v2/` (and `/internal/`) | (part of #1) | Customer REST API. Auth: `ldso` session cookie **or** access token in `Authorization` header |
| 3 | `app.launchdarkly.com/private/` | (part of #1) | Internal APIs — "not meant to allow authentication to any non-LaunchDarkly users… any cases where these endpoints are improperly accessible are worthy of note" |
| 4 | LaunchDarkly SDKs (open source) | Java, Rust, Haskell, +11 (5 known issues) | GitHub repos, esp. ones ending `-sdk`. Findings in **non-`-sdk` repos are NOT accepted**. No scan/dependency results |
| 5 | `stream.launchdarkly.com` | AWS, Go | Flag streaming for client/server SDKs. Look for: improper retrieval of flag info meant for other users; client-side payloads leaking rule data |
| 6 | `events.launchdarkly.com` | Elasticsearch, AWS, Go, +2 (0 known issues) | Event recorder for metrics/experimentation |
| 7 | `docs.launchdarkly.com` / `https://launchdarkly.com/docs` | 0 / 4 known issues | Static site (Fern). User input fields (search). Cross-origin requests to app.launchdarkly.com → **CSRF noteworthy here** |

`/internal/` subroute is explicitly called out as customer-facing and in scope alongside `/api/v2/`.

## Gray zones — document before testing

These are LaunchDarkly-controlled and serve the same in-scope apps/SDKs, but are **not listed**:

| Domain | Why it's used | Default stance |
|---|---|---|
| `app.launchdarkly.us` | Federal instance (separate app instance) | **Out of scope** (different domain). Report, no reward. |
| `app.eu.launchdarkly.com` | EU instance | **Out of scope** (different domain). |
| `sdk.launchdarkly.com`, `clientsdk.launchdarkly.com`, `clientstream.launchdarkly.com`, `mobile.launchdarkly.com` | SDK polling/streaming/mobile-event hosts (documented in SDK "Domain list") | Not listed → out of scope. Only `stream.launchdarkly.com` + `events.launchdarkly.com` are listed. If a vuln exists on these, report as no-reward note. |
| `otel.observability.app.launchdarkly.com`, `pub.observability.app.launchdarkly.com` | Observability SDK ingestion | Subdomains of in-scope `app.launchdarkly.com` host? Ambiguous — it's a subdomain OF the listed host. Likely in scope, but confirm behavior first; treat as in-scope only via requests the observability SDKs make. |
| `demo.app.launchdarkly.com` | Public demo/sandbox | Subdomain of app host — likely in scope (it IS the app, demo data). Don't use for auth testing; use it to study feature behavior safely. |
| `docs-stg.launchdarkly.com` | Staging docs (linked from focus areas) | Staging of in-scope docs site. "Findings across different environments… duplicate unless materially different" — report once. |
| `apidocs.launchdarkly.com` | Redirects to `launchdarkly.com/docs/api` | Redirect of in-scope docs → fine. |

**Rule of thumb:** if the host isn't in the 7 rows above → out of scope. When in doubt, do the
recon passively, keep the report, and let triage decide.

## Excluded / non-eligible (must-read before writing any report)

From the program (summary — full list in `info`):

- Rate limiting on account verification + forgot password pages
- Third-party integrations & endpoints (explicitly out today)
- DoS/DDoS, rate-limit-bypass attempts, email bombing
- Social engineering (all forms)
- Clickjacking on pages w/o sensitive actions; CSRF on unauthenticated/no-sensitive-action forms
- MITM / physical-access issues
- Known-vulnerable libraries **without working PoC**
- CSV/Excel injection **without LD-platform-specific impact**
- SSL/TLS config best practices; missing CSP best practices
- Missing HttpOnly/Secure cookie flags — **except the `ldso` cookie** (that one is eligible)
- Email auth best practices (SPF/DKIM/DMARC)
- Outdated-browser-only issues; unusual-extension-only issues
- Version disclosure / banner / descriptive errors & stack traces
- Public 0-days with patch < 1 month (case-by-case)
- Tabnabbing; open redirects without extra impact; unlikely user-interaction issues
- **Findings in non-`-sdk` GitHub repos**; **scan/dependency results**
- Client-side SDK keys visible in properly-deployed apps; public keys on LD website (Algolia, TrackJS…)
- Jira ServiceDesk public registration; verification-email spam
- **HTML injection on text fields in app or generated emails** (excluded!) — so stored XSS via those fields is the angle, plain HTML injection is not
- Password reset link not expiring if email address changed
- Vulnerability/dependency scans on open-source repos
- P5 vulnerabilities

## Leaked credentials eligibility

Only eligible if:
1. Leaked through some LaunchDarkly action/inaction (customer self-leaks don't count), **or**
2. Not meant to be public (browser SDK IDs are meant to be public — excluded), **or**
3. Token of a LaunchDarkly-controlled account with `"bountyEligible": true` in `/api/v2/caller-identity`.

## Safe harbor

Research per policy is authorized (CFAA/DMCA exemptions, good-faith protection). Concerns →
Freshdesk portal before continuing.
