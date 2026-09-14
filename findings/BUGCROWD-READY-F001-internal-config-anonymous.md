# F-001 — Unauthenticated disclosure of internal configuration via /internal/config/anonymous

**Target:** `app.launchdarkly.com`  
**URL / Location:** `https://app.launchdarkly.com/internal/config/anonymous` (GET)  
**VRT:** `Sensitive Data Exposure > Disclosure of Secrets > For Internal Asset`  
**Severity:** P4 — CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)  
**Tested:** Unauthenticated, no account. Live re-verified 2026-09-14 00:10:31 GMT from clean GitHub Actions runner. Response `200`, `282,232` bytes, `content-type: application/json`.

## Summary

`GET /internal/config/anonymous` is an intentionally unauthenticated bootstrap endpoint. Alongside expected logged-out configuration it returns `allClientSideFlags` — the evaluated values of 2,339 client-side flags for LaunchDarkly's own dogfooding environment as seen by an anonymous visitor. Those values include internal ticket references, unreleased roadmap notes, platform internals, a signup country blocklist, Marketo form identifiers, internal hostnames, and live feature-flag posture that is not intended for anonymous users.

The sibling `GET /internal/config/authenticated` correctly requires authentication (`401 Invalid account ID header`), and most other `/internal/*` routes are 401. The issue is not that the route is reachable, but what is published through it.

## Impact

Impact is to LaunchDarkly's own confidentiality, not customer tenant data. All of the following were present in the 2026-09-14 body and are readable by any anonymous internet client with a single GET:

* Internal ticket IDs in `experiment-metric-compatibility-rules[*].docNote` — e.g., `LAUNC-2510`, `MTRX-2082`
* Unreleased roadmap and status reasons — e.g., `Q3 2026 target, not yet built`, `Decoupled analysis unit isn't available yet`, `Not planned`
* Platform internals — e.g., `Federal runs legacy Airflow, which does not support trace events`, `CUPED + metric filters unsupported per commit e2c2f04`
* Business rules — `pql-signup-junk-country-list: ["EG","ID","VN","PK","BD","NP","MA","NG","DZ","KE"]`
* Marketing configuration — `marketo-form-submission-config` with form IDs `1941`, `3144`, `3247`, `3331`
* Internal hosts — `dogfoodBaseUri https://relay-fdv2-prod.ld.catamorphic.com`, `observabilityPrivateGraphUrl https://pri.observability.app.launchdarkly.com`
* Live posture signals among the 2,339 flags — e.g., `enable-google-oauth-email-verified-check=false`, `enforce-saml-conditions-validity-window=false`, `disable-legacy-access-token-auth-fallback=false`, `mfa-enforcement=false`

The `clientSideId` and third-party browser keys (Algolia, Datadog, Stripe publishable, etc.) are also in the body but are explicitly out of scope per program and are not part of this claim.

`GET /internal/plans` (same unauthenticated surface, `200`) returns the commercial plan catalogue with internal plan IDs and entitlement limits. It is included here as the same root cause rather than a separate report.

I am claiming P4 only. A potential escalation — whether `secureModeContextHash` in the same body could be used as a signing oracle — was tested and is negative (see below).

## Steps to Reproduce

No account or cookies required. From any machine:

```bash
# 1. Anonymous config — observe 200 and full body
curl -sS -i 'https://app.launchdarkly.com/internal/config/anonymous' | head -n 20

# 2. Sibling is correctly gated
curl -sS -i 'https://app.launchdarkly.com/internal/config/authenticated'
# → 401 {"code":"unauthorized","message":"Invalid account ID header"}

# 3. Route is discoverable unauthenticated
curl -sS 'https://app.launchdarkly.com/internal/' | python3 -m json.tool

# 4. Inspect disclosed fields (example)
curl -sS 'https://app.launchdarkly.com/internal/config/anonymous' | python3 -c '
import json,sys
d=json.load(sys.stdin)
f=d["allClientSideFlags"]
print(f["pql-signup-junk-country-list"])
print(d["dogfoodBaseUri"])
'
```

Expected: anonymous callers receive only safe bootstrap data.
Observed: internal tickets, roadmap dates, platform internals, blocklist, Marketo IDs, private graph host, and posture flags as listed above.

## Technical Details

The endpoint ships both logged-out UI configuration and internally-scoped flag values with no server-side classification of which flag values are safe for anonymous delivery. Any value set as a client-side flag in the dogfooding environment becomes world-readable.

Secure-mode review: the body also contains `secureModeContextHash` and the `dogfoodContext` it signs. I tested whether a caller could influence the signed context (query params, cookies, headers including `ld-flag-override`, `x-ld-project-id`, etc.) across more than ten requests. Each response contained a fresh random UUID for `dogfoodContext` and a different hash, with no caller influence. The signing-oracle escalation is therefore closed, and this report does not claim a secure-mode bypass. The hosts `ld.catamorphic.com` and `ld-stg.launchdarkly.com` were never contacted; they are reported only as disclosed strings.

## Evidence

* `ci-results/run-10/internal-config-anonymous.json` — full 282KB body captured unauthenticated by CI
* `ci-results/run-10/internal-config-anonymous.json.flagnames.txt` — sorted list of all 2,339 flag names
* `ci-results/run-10/raw/GET__internal_config_anonymous_.txt.hdr` — response headers (`200`, `application/json`, `date: Mon, 14 Sep 2026 00:10:31 GMT`, via Varnish/Fastly)
* `recon/internal-api-inventory.md` §1–2 — how the route was discovered (bundle mining, 142 `/internal/*` paths)

The endpoint can be re-fetched at any time to confirm it still returns 200.

## Remediation

* Serve only safe bootstrap data from `/internal/config/anonymous`. Move roadmap, business rules, marketing form config, and internal host references to the authenticated endpoint.
* Add a publish-time check in the dogfooding environment that blocks client-side flag values containing ticket patterns (`[A-Z]{3,}-\d+`), non-`launchdarkly.com` hostnames, or policy lists — the same client-side visibility rule documented for customers.
* Keep `secureModeContextHash` bound to a server-generated random context per session and add a regression test that asserts caller-supplied values do not affect it. Strip free-text `docNote` / `reason` fields from client-delivered values.

## Notes on Scope and Testing

* Testing was read-only (single GETs), no `ldso` cookie or `Authorization` header, no modification, no other user's data. The single customer account ID present in the body (`5d25ea5f...`) was not used in any request, header, or probe.
* The finding is in scope per `scope.md` — `app.launchdarkly.com/api/v2/` and `/internal/` are explicitly listed as customer-facing and in scope.
* This is not a scan result, not version/banner disclosure (build SHA present but not claimed), not third-party integration testing (Marketo IDs disclosed by LaunchDarkly, no Marketo system contacted), and not HTML injection / clickjacking / CSRF.
* Role used: none — fully unauthenticated. If the form requires a role, use `Unauthenticated`.

---
Researcher: zazieproductions@bugcrowdninja.com
