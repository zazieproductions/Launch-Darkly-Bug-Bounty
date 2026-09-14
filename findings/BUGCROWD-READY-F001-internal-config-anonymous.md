# BUGCROWD SUBMISSION READY — F-001: Unauthenticated `GET /internal/config/anonymous` discloses LaunchDarkly internal flags, roadmap, ticket IDs, and auth posture to any anonymous caller

> **Copy-paste this into Bugcrowd.** Attach the two evidence files named at the bottom plus one `curl -i` screenshot.
> **Researcher:** `zazieproductions@bugcrowdninja.com`
> **Date found:** 2026-09-11 — **live re-verified 2026-09-14 00:10:31 GMT** from a clean GitHub Actions runner (see Evidence)
> **Branch/commit with evidence:** `arena/01a09d66-launch-darkly-bug-bounty` — `ci-results/run-10/` + `recon/internal-api-inventory.md`

---

### Bugcrowd form fields

**Title:** `Unauthenticated GET /internal/config/anonymous discloses 2,339 internal dogfood flag values, internal ticket IDs, unreleased roadmap, signup country blocklist, private graph host, and live auth posture (P4 information disclosure)`

**Target:** `app.launchdarkly.com` — `GET /internal/config/anonymous` (explicitly listed in `scope.md` as **in scope**: `app.launchdarkly.com/api/v2/ (+ /internal/)` — “customer-facing APIs” per program; `/internal/` is the authenticated subroute alongside `/api/v2/`. This route is *intentionally* unauthenticated, which is why the sibling `GET /internal/config/authenticated` returns `401 Invalid account ID header` — the issue is **what is published through the unauthenticated route**, not that it answers.)

**VRT:**
`Sensitive Data Exposure → Disclosure of Secrets → For Internal Asset (P3)` as closest taxonomy, **downgraded to P4** by you because no customer PII/credentials are disclosed — the data is LaunchDarkly’s own internal business/engineering material and live auth posture. Equivalent VRT variant `Sensitive Data Exposure` (`sensitive_data_exposure`) and `Server Security Misconfiguration → Information Disclosure`. Pick `Sensitive Data Exposure → For Internal Asset` in the form and set priority **P4**.

Alternative if the form forces a strict VRT priority: `Server Security Misconfiguration → Information Disclosure → Sensitive Data Exposure (P4)` — triage routinely maps this class there.

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Severity you are claiming:**
**P4 — CVSS:3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3)** — *information disclosure only*. Deliberately not claimed as P3/P2 (see Escalation Path — tested and closed).

**Role(s) used for testing:**
**None — fully unauthenticated.** No account, no `ldso` cookie, no `Authorization` header, no `LD-API-Version`, no custom headers, no query parameters. Single `GET` from anonymous internet.

**Credentials/keys used:**
None. The response *contains* a `clientSideId` (`5866f389...`) and third-party browser keys (Datadog, Algolia, Stripe publishable, etc.) — those are **explicitly excluded by the program** (“client-side SDK keys … are not required to be kept secret”) and are **NOT part of the impact claim** (mentioned only for completeness). No SDK key, no service token, no secret was extracted or used.

---

### Summary

`GET https://app.launchdarkly.com/internal/config/anonymous` returns **HTTP 200 + 282,232 bytes of JSON** to any anonymous internet client. Alongside the expected logged-out app bootstrap it contains LaunchDarkly’s **entire internal client-side flag set for the application itself** (`allClientSideFlags`: **2,339 flags with evaluated values** for LD’s own production dogfooding environment as seen by an anonymous visitor), whose values disclose **internal ticket IDs, unreleased roadmap with dates, federal pipeline internals, a signup country blocklist, Marketo form IDs and field mappings, internal dogfood/observability hostnames, internal quota/password-policy limits, and a server-computed `secureModeContextHash`**.

The sibling `GET /internal/config/authenticated` is correctly gated (`401 {"code":"unauthorized","message":"Invalid account ID header"}`), and 20+ other `/internal/*` routes are likewise 401 — the gate exists and works. The issue is data classification: anything set as a client-side flag value in LD’s own dogfood environment becomes world-readable.

---

### Why it matters (impact) — confidentiality, no privileges, no user interaction

There is **no customer tenant data** in the body, so impact is to LaunchDarkly itself — but it is directly actionable:

| Category | Verbatim examples (from live 2026-09-14 body) | Why an attacker cares |
|---|---|---|
| **Internal ticket IDs** | `LAUNC-2510`, `LAUNC-2487`, `MTRX-2082`, `MTRX-2083` in `experiment-metric-compatibility-rules[*].docNote` | Maps unreleased work to internal tracker → targeted social engineering / correlation with public commits |
| **Unreleased roadmap + dates** | `"Q3 2026 target, not yet built"` (`stateful-experimentation-not-built`), `"Decoupled analysis unit isn't available yet"`, `"Not planned"` | Confidential product plans + internal prioritisation, pre-announcement, competitively sensitive |
| **Federal platform internals** | `"Federal runs legacy Airflow, which does not support trace events"`, `"Ratio metric API layer done; results computation not yet implemented for the Federal (Airflow) pipeline"`, `CUPED + metric filters unsupported per commit e2c2f04` | Discloses analytics pipeline implementation per deployment (incl. federal) + internal commit ref — architecture detail useful for further attacks |
| **Signup risk/business rules** | `"pql-signup-junk-country-list": ["EG","ID","VN","PK","BD","NP","MA","NG","DZ","KE"]` | Internal fraud/lead-scoring policy that treats these countries as junk — reputationally sensitive and tells an attacker exactly which geo signals to spoof |
| **Marketing internals** | `marketo-form-submission-config` with form IDs `1941`, `3144`, `3247`, `3331` + field mappings (`email`, `firstName`, `company`, `title`, `planType`, `subscriptionState`, `programID`) | Exact identifiers consumed by `/internal/contact-us/forms/{formId}/public-submit` — needed to craft submissions |
| **Internal dogfood/observability infra** | `dogfoodBaseUri = https://relay-fdv2-prod.ld.catamorphic.com`, `dogfoodClientSideEventsUri = https://events.ld.catamorphic.com`, `observabilityPrivateGraphUrl = https://pri.observability.app.launchdarkly.com` (private graph host), `otel.observability.app.launchdarkly.com` | LD’s own Relay Proxy / events / observability hosts for the environment that flags the app itself — not public, identifies evaluation infra |
| **Live auth posture (221 flags)** | `enable-google-oauth-email-verified-check=false` (while `enable-google-oauth-sign-up=true`), `enforce-saml-conditions-validity-window=false`, `disable-legacy-access-token-auth-fallback=false`, `mfa-enforcement=false`, `enable-bypass-approval-requirements-enforcement=true`, `enable-bypass-required-approval=true`, `enable-internal-authorization-endpoint=true`, `enable-o-auth-dcr=true`, `zz-fairytale-bypass-test=true` | Publishes live authN/authZ posture of `app.launchdarkly.com` itself to anonymous callers — each tracked as a separate lead in `plans/auth-posture-leads.md`; only reported if independently verified, but all are competitor/attacker-relevant today |
| **Quotas, limits, password policy** | `evals-token-limits-max-per-member: 10000000`, `ai-tools-bulk-update-max-targets: 50`, `minPasswordLength:8`, `passwordMinClasses:3`, `frontendVersion=5e1f8235c` | Internal limits useful for tuning abuse below detection thresholds; build SHA (version disclosure alone is excluded — not claimed) |
| **One customer account ID** | `integration-approvals-poll-after-approval-accounts: ["5d25ea5f23d2f65d48fa0c9c"]` | Recorded as disclosed data only; **never used in any request/header per the no-other-user-data rule** |

Also `GET /internal/plans` (same unauthenticated surface, **200**) adds the commercial plan catalogue: `startup $79/mo (558b29ee...)`, `team $299/mo (558b29de...)`, `growth $699/mo (58a3a1358...)` with internal `_id`s and `enforceSeatLimits=false` — included here per the program’s “same issue across endpoints = one report / duplicate” rule, not as a second report.

> Third-party browser keys (Algolia, TrackJS, Datadog, Segment, Stripe publishable, New Relic, etc.) are present in the body and are **explicitly excluded** by the program — **not claimed**.

---

### Root cause

A single pre-authentication bootstrap endpoint (`/internal/config/anonymous`) is used to ship **both** harmless logged-out UI config **and** internally-scoped data (roadmap rules, business policy lists, marketing form config, infra references, signed context). No publish-time classification separates “safe for anonymous visitors” from “internal only”, so any value set as a client-side flag in LD’s own dogfood environment becomes world-readable through this endpoint. The mechanism has no server-side filter on `allClientSideFlags` payloads.

---

### Steps to reproduce (reliable, unauthenticated, 3 commands)

**No account, no cookies, no headers.** From any machine / clean browser profile:

**1. Fetch the anonymous config:**
```bash
curl -sS -i 'https://app.launchdarkly.com/internal/config/anonymous' | head -c 3000
# → HTTP/1.1 200 OK
# → content-type: application/json
# → date: Mon, 14 Sep 2026 00:10:31 GMT  (or current date — still 200)
# → body: 282,232 bytes of JSON (see Evidence)
```

**2. Confirm the sibling is gated (gate exists, this is not a blanket auth failure):**
```bash
curl -sS -i 'https://app.launchdarkly.com/internal/config/authenticated'
# → HTTP/1.1 401 Unauthorized
# → {"code":"unauthorized","message":"Invalid account ID header"}
```

**3. Confirm the route is discoverable unauthenticated:**
```bash
curl -sS 'https://app.launchdarkly.com/internal/'
# → 200 {"_links":{"account":{"href":"/internal/account",...},"actions":{"href":"/internal/actions",...},"self":{"href":"/internal/"}}}

# Also 200 unauthenticated (same root cause):
curl -sS 'https://app.launchdarkly.com/internal/plans' | python3 -m json.tool | head -n 40
# → startup/team/growth plan objects with internal _id + _limits
```

**4. Inspect the disclosed items (pick any):**
```bash
curl -sS 'https://app.launchdarkly.com/internal/config/anonymous' | python3 -c '
import json,sys
d=json.load(sys.stdin)
f=d["allClientSideFlags"]
print("junk countries:", f["pql-signup-junk-country-list"])
print("dogfood:", d["dogfoodBaseUri"], d["dogfoodStreamUri"])
print("private graph:", f.get("observabilityPrivateGraphUrl", d.get("observabilityPrivateGraphUrl","<in body>")))
import re, json as j
rules=j.dumps(f.get("experiment-metric-compatibility-rules","")[:800])
# or just:
print(j.dumps(f["experiment-metric-compatibility-rules"][0], indent=2)[:1200])
'
```

**Expected:** anonymous callers receive only what a logged-out UI needs (`clientSideId` + safe toggles).
**Observed:** internal tickets, roadmap dates, federal pipeline detail, signup blocklist, Marketo form IDs, internal dogfood/private-graph hosts, password policy, one customer account ID, 2,339 flag values plus live auth posture.

---

### Escalation path — TESTED, NEGATIVE (recorded for honesty; severity stays P4)

The `secureModeContextHash` question was tested **before** writing this up because an attacker-influenceable signed context would be a secure-mode bypass (P2/P3 — “improper retrieval of flag information meant for other users” per program).

**Result: NO ORACLE.** Across 10+ unauthenticated requests (CI `run-3/4/10`, plus manual header/cookie/query variants: `ld-flag-override`, `ld-gonfalon-overrides`, `ld-bypass-ua-tracking`, `x-ld-project-id`, `x-ld-envid`, `ld-account-id-verification-for-salesforce`, `Cookie: ld_anonymous_id=…; sandboxVisitorAccountId=…`, `?contextKey=…`) the `dogfoodContext.session.key` / `user.key` was a **fresh random UUID on every response** (`9e7a154f…`, `b662b740…`, `54729c2a…`, …) and the hash changed with it. Server generates and signs its own anonymous context per request; nothing supplied by the caller moved it.

Also closed and documented: `ld-flag-override` is a `localStorage` namespace for the SDK’s `FlagOverridePlugin`, `ld-gonfalon-overrides` is the internal app name (`serviceName: "gonfalon-web"`), `ld-account` is a **localStorage key prefix** (`ld-account-${accountId}`), not the “account ID header” from the 401 message. Supplying them as request headers produced byte-identical behaviour to baseline.

**So this report claims information disclosure only (P4).** No signing-oracle, no `ld.catamorphic.com` or `ld-stg.launchdarkly.com` host was ever contacted — those are reported as disclosed data only.

---

### Evidence (what to attach)

1. **Raw capture:** `ci-results/run-10/internal-config-anonymous.json` — the 282 KB body fetched unauthenticated by `tools/ci-internal-probe.sh` (the script also writes `internal-config-anonymous.json.flagnames.txt` — sorted inventory of all 2,339 disclosed flag names, and `internal-probe.txt` with response headers + 3-fetch diff).
2. **CI header log:** `ci-results/run-10/raw/GET__internal_config_anonymous_.txt.hdr` (shows `200`, `content-type: application/json`, `date: Mon, 14 Sep 2026 00:10:31 GMT`, via `Varnish/Fastly`).
3. **Your own one-liner:** run the three `curl` commands above in a clean profile and paste the `-i` output (redact nothing — no secrets in it; `clientSideId` may be shown, it is excluded from scoring but proves the response is live).
4. **Discovery context:** `recon/internal-api-inventory.md` §1–2 — how the route was found (bundle mining of the app’s own JS, 142 `/internal/*` paths) and surrounding unauthenticated surface.

Files are committed to this branch; triage can re-fetch `https://app.launchdarkly.com/internal/config/anonymous` at any time — it still returns 200.

---

### Remediation suggestion (concrete)

1. **Split the bootstrap payload:** serve only what a logged-out UI needs (`clientSideId` + safe toggles) from `/internal/config/anonymous`; move roadmap rules, business policy lists, marketing form config, and internal infra references to `GET /internal/config/authenticated` (already correctly gated).
2. **Publish-time guard on LD’s own dogfood env:** any flag made available to client-side IDs whose value contains internal ticket patterns `[A-Z]{3,}-\d+`, hostnames outside `launchdarkly.com`, or policy lists should fail review — the same “client-side flag values are public” rule LD documents for customers, applied to itself.
3. **For `secureModeContextHash`:** ensure the signed context is always server-generated (random per session) and that no cookie/query/header can influence the canonical key that gets signed (already the case today per the negative oracle test; codify as an invariant and add a regression test that asserts caller-supplied context keys do not affect the hash).
4. **Strip `docNote`/`reason` free-text** (which carries ticket IDs and internal reasoning) from client-delivered flag values; keep them server-side and expose only `status.type` + `userMessage` the UI needs.

---

### Out-of-scope / excluded check (explicitly confirmed NOT any of these)

* **Not** a client-side SDK key disclosure — `clientSideId` is explicitly excluded and is **not** part of the impact (mentioned only for completeness).
* **Not** a version/banner disclosure or descriptive-error-message issue (the build SHA `5e1f8235c` is in the body but not claimed).
* **Not** a dependency/vulnerability scan result — found by reading LD’s own JS bundles and probing the in-scope `/internal/` subroute + manual `curl` diffing.
* **Not** HTML injection, clickjacking, CSRF, tabnabbing, open redirect, or rate-limit bypass (all excluded).
* **Not** a third-party integration — Marketo form IDs are disclosed *by LD’s own endpoint*; no Marketo system was contacted or tested.
* **Not** tested against any out-of-scope host: `ld.catamorphic.com`, `ld-stg.launchdarkly.com`, `app.launchdarkly.us`, `app.eu.launchdarkly.com` were **never requested** — reported only as disclosed strings.
* **Not** a known issue (rate limiting on account verification/forgot-password — the only listed known issue — is unrelated).
* **Not** DoS, not destructive, not other-user data (the one customer account ID `5d25ea5f...` was **not** used in any request/header; per the “no other users’ data” rule).

**Known-issue risk stated honestly:** LD may consider the anonymous bootstrap endpoint and client-side flag delivery “by design”, since any logged-out browser receives the same flag values. This report is therefore framed on the **sensitivity of the published values** (internal tickets, unreleased roadmap, federal pipeline detail, signup blocklist, internal hosts) rather than on the route’s existence, and the escalation-path result is what would stand on its own if triage considered the flag values acceptable.

**Safe harbor:** Single-GET read-only, no cookies/tokens, no post-exploitation, no modification, no volume. Per program, production testing of this nature is authorized; concerns → Freshdesk portal before continuing.

---

### Status

* [x] Draft (live re-verified unauthenticated 2026-09-14 from clean runner; headers + body + flagnames captured)
* [ ] Submitted (Bugcrowd URL/ID — paste here after filing)
* [ ] Triage response:
* [ ] Resolved / disputed

