# Unauthenticated Sensitive Data Exposure in GET /internal/config/anonymous allows disclosure of 2,339 internal flag values and business configuration

## Summary

`GET https://app.launchdarkly.com/internal/config/anonymous` is intentionally unauthenticated and returns `allClientSideFlags` — 2,339 evaluated flag values for LaunchDarkly's own dogfooding environment as seen by an anonymous visitor. Those values include internal ticket IDs, unreleased roadmap notes, platform internals, a signup country blocklist, Marketo form identifiers, internal hostnames, and live feature-flag posture. Any internet user can retrieve this with a single `curl` and no account. The sibling `GET /internal/config/authenticated` correctly requires authentication (`401 Invalid account ID header`), so the issue is what is published through the unauthenticated route, not that it is reachable.

## Affected asset

- **URL / endpoint:** `https://app.launchdarkly.com/internal/config/anonymous`
- **HTTP method:** `GET`
- **Parameter or field:** None — no query params, headers, or cookies required. Response field `allClientSideFlags` (plus `dogfoodBaseUri`, `observabilityPrivateGraphUrl`, `secureModeContextHash` for context)
- **Account role required:** None — fully unauthenticated
- **Environment:** Production `app.launchdarkly.com`
- **Date tested:** 2026-09-14 00:10:31 GMT (live, re-verifiable from any network; `200`, `282,232` bytes, `content-type: application/json`, via Varnish/Fastly)

## Preconditions

- No account, no `ldso` cookie, no `Authorization` header, no special headers.
- A fresh browser profile or incognito session, or any machine with `curl` and `python3`.
- No private repository, no Bugcrowd account state, and no proxy history required — the endpoint is public.

## Steps to reproduce

1. Open a fresh browser profile or terminal with no LaunchDarkly cookies.
2. Fetch the anonymous config:
   ```bash
   curl -sS -i 'https://app.launchdarkly.com/internal/config/anonymous' | head -n 20
   ```
   Observe `HTTP/1.1 200` and `content-type: application/json`. Body is ~282KB JSON with `allClientSideFlags`.
3. Confirm the sibling endpoint is correctly gated:
   ```bash
   curl -sS -i 'https://app.launchdarkly.com/internal/config/authenticated'
   ```
   Observe `HTTP/1.1 401` with body `{"code":"unauthorized","message":"Invalid account ID header"}`.
4. Confirm discoverability:
   ```bash
   curl -sS 'https://app.launchdarkly.com/internal/' | python3 -m json.tool
   ```
   Observe `200` with `_links` containing `account` and `actions` — also unauthenticated.
5. Inspect disclosed fields (one-line examples, no secrets needed):
   ```bash
   curl -sS 'https://app.launchdarkly.com/internal/config/anonymous' | python3 -c '
   import json,sys
   d=json.load(sys.stdin)
   f=d["allClientSideFlags"]
   print(f["pql-signup-junk-country-list"])
   print(d["dogfoodBaseUri"])
   print(f.get("experiment-metric-compatibility-rules",[])[0].get("docNote","")[:80])
   '
   ```
   Expected: anonymous callers receive only safe bootstrap data (e.g., a client-side ID and UI toggles).
   Observed: the command prints the internal blocklist, internal relay host, and a docNote containing an internal ticket ID.

## Proof of concept

**Raw requests and responses (secrets redacted — `clientSideId` is truncated):**

Request:
```http
GET /internal/config/anonymous HTTP/1.1
Host: app.launchdarkly.com
```

Response (truncated, structure verbatim):
```http
HTTP/1.1 200 OK
content-type: application/json; charset=utf-8
via: 1.1 varnish, 1.1 varnish
date: Mon, 14 Sep 2026 00:10:31 GMT
content-length: 282232

{
  "clientSideId": "5866f389...[redacted]",
  "dogfoodBaseUri": "https://relay-fdv2-prod.ld.catamorphic.com",
  "dogfoodStreamUri": "https://relay-fdv2-prod.ld.catamorphic.com",
  "observabilityPrivateGraphUrl": "https://pri.observability.app.launchdarkly.com",
  "allClientSideFlags": {
    "pql-signup-junk-country-list": ["EG","ID","VN","PK","BD","NP","MA","NG","DZ","KE"],
    "experiment-metric-compatibility-rules": [{"docNote": "[ticket ID — redacted in this report; live body contains e.g. LAUNC-2510]", "reason": "Q3 2026 target, not yet built"}],
    "...": "... 2,339 total flags ..."
  },
  "secureModeContextHash": "c846bc46...[truncated]"
}
```

For the authenticated sibling:
```http
GET /internal/config/authenticated HTTP/1.1
Host: app.launchdarkly.com

HTTP/1.1 401 Unauthorized
{"code":"unauthorized","message":"Invalid account ID header"}
```

**Evidence attached (sanitized, no private repo):**
- `curl-headers-anonymous.txt` — captured response headers for the 200 (ATTACHED)
- `anonymous-flag-names.txt` — sorted list of all 2,339 flag names (ATTACHED, 76KB — proves scale without dumping the body)
- `anonymous-redacted-snippet.json` — 796B redacted excerpt showing structure with one `pql-signup-junk-country-list` and one `docNote` example (ATTACHED)
- Screenshot of `curl -i` from a clean profile (ATTACHED — optional but recommended)

The full 282KB body is not attached unredacted; triage can fetch it directly from the public URL above, which still returns 200.

## Impact

This is LaunchDarkly's own internal confidentiality, not customer tenant data, so I am not claiming auth bypass or tenant compromise.

Any anonymous internet user can read, with one GET:

* Internal ticket IDs in `experiment-metric-compatibility-rules[*].docNote` (maps unreleased work to the internal tracker)
* Unreleased roadmap and status reasons (`Q3 2026 target`, `Decoupled analysis unit isn't available yet`)
* Platform internals (`Federal runs legacy Airflow...`, `CUPED + metric filters unsupported per commit e2c2f04`)
* Business rules (`pql-signup-junk-country-list` — 10 countries treated as junk signups)
* Marketing configuration (`marketo-form-submission-config` with form IDs `1941`, `3144`, `3247`, `3331` used by `/internal/contact-us/forms/{formId}/public-submit`)
* Internal hosts (`dogfoodBaseUri`, `observabilityPrivateGraphUrl` including the private graph `pri.` host)
* Live posture signals among the flags (`enable-google-oauth-email-verified-check=false`, `enforce-saml-conditions-validity-window=false`, `disable-legacy-access-token-auth-fallback=false`, `mfa-enforcement=false` — full list in the attached flag-name file)

The `clientSideId` and third-party browser keys (Algolia, Datadog, Stripe publishable) are also in the body but are explicitly non-qualifying per the program brief and are not part of this claim.

`GET /internal/plans` (same unauthenticated surface, `200`) returns the commercial plan catalogue with internal plan IDs; it is noted here as the same root cause, not a second report.

A potential escalation — whether `secureModeContextHash` in the same body could be abused as a signing oracle — was tested across 10+ requests with varied query params, cookies, and headers (`ld-flag-override`, `x-ld-project-id`, etc.). Each response contained a fresh random UUID for `dogfoodContext` and a different hash with no caller influence, so no oracle was demonstrated. This report claims information disclosure only.

## Suggested remediation

- Serve only safe bootstrap data from `/internal/config/anonymous` (e.g., `clientSideId` and UI-safe toggles). Move roadmap, business rules, marketing form config, and internal host references to the authenticated endpoint.
- Add a publish-time check in the dogfooding environment that blocks client-side flag values containing ticket patterns (`[A-Z]{3,}-\d+`), non-`launchdarkly.com` hostnames, or policy lists — the same visibility rule documented for customers.
- Keep `secureModeContextHash` bound to a server-generated random context per session and add a regression test asserting caller-supplied values do not affect it. Strip free-text `docNote`/`reason` fields from client-delivered values.

---
**Researcher:** zazieproductions@bugcrowdninja.com — no test account used (anonymous internet user)
**VRT:** `Sensitive Data Exposure > Disclosure of Secrets > For Internal Asset`
**Severity:** P4 — CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3) — information disclosure only, not claimed higher
