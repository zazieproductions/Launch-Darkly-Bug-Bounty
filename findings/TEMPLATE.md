# [Short vulnerability title]

- **Date found:**
- **Target(s) in scope:** (e.g. `app.launchdarkly.com/api/v2/…`, `stream.launchdarkly.com`)
- **Severity claim:** P? (CVSS vector + score; justify)
- **Role(s) used for testing:** (required by program — e.g. "Org Owner, full-scoped personal
  access token `ldp_…` (suffix only), plus member account `…+bugcrowd…`")
- **Credentials/keys used:** (reference — do not paste secrets; note where stored)

## Summary
2–4 sentences: what, where, impact.

## Why it matters (impact)
Tenant/business impact, data affected, chain if any. Quantify (which tenants? which data types?).

## Root cause
Technical explanation — the actual flaw, not just the symptom.

## Steps to reproduce
1. (account state: role, org, project/env/keys — create fresh where possible)
2. (exact request: method, URL, headers — incl. `LD-API-Version` if relevant, body)
3. (expected vs observed)

## Evidence
- Request/response captures (files in `findings/<slug>/`)
- Screenshots / video
- For SSRF: **captor proof of reach + metadata** (required)
- CVSS breakdown if rating contested

## Remediation suggestion
(concrete, e.g. "enforce X on route Y; add check Z")

## Out-of-scope / excluded check
Confirm NOT any excluded type (scan result, HTML-injection-only, out-of-scope subdomain, etc.)
and NOT a known issue (rate limiting on verify/forgot-pw pages, public client-side keys, …).

## Status
- [ ] Draft
- [ ] Submitted (Bugcrowd URL/ID)
- [ ] Triage response:
- [ ] Resolved / disputed
