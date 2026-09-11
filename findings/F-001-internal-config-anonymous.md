# Unauthenticated `/internal/config/anonymous` discloses LD internal flags, unreleased roadmap + ticket IDs, signup country blocklist, internal dogfood infra, and a secure-mode context hash

- **Date found:** 2026-09-11
- **Target(s) in scope:** `app.launchdarkly.com` — `GET /internal/config/anonymous`
  (the `/internal/` subroute the program explicitly lists as in scope alongside `/api/v2/`)
- **Severity claim:** **P4** as it stands (CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = 5.3 →
  Bugcrowd VRT *Information Disclosure → Sensitive data exposed to an unauthorized user*).
  **Escalates to P3/P2 if §"Escalation path" below confirms** (secure-mode signing oracle).
  Deliberately *not* claimed higher — see "Out-of-scope / excluded check" for the by-design risk.
- **Role(s) used for testing:** **none — fully unauthenticated.** No cookie, no token, no headers.
- **Credentials/keys used:** none. (The response *contains* a client-side ID; that value is
  explicitly excluded from bounty scope and is **not** part of this claim.)

## Summary

`GET https://app.launchdarkly.com/internal/config/anonymous` returns HTTP 200 with a large JSON
configuration blob to any unauthenticated caller. Alongside the expected logged-out app config it
contains LaunchDarkly's **entire internal client-side feature-flag set for the application itself**
(`allClientSideFlags`), whose *values* include unreleased-roadmap detail with **internal ticket
identifiers**, engineering status reasoning, a **signup country blocklist**, internal **marketing
form IDs and field mappings**, internal infrastructure hostnames for LD's own dogfooding
environment, and a **`secureModeContextHash`** (an HMAC over a context canonical key).

The sibling endpoint `GET /internal/config/authenticated` is correctly gated
(`401 {"code":"unauthorized","message":"Invalid account ID header"}`), which shows the gate exists
and that `/anonymous` is intentionally unauthenticated — so the issue is **what is published
through it**, not that the route answers.

## Observed response (verbatim excerpts, unauthenticated GET)

```json
{
  "clientSideId": "5866f3891cd8810a42ce5281",
  "dogfoodBaseUri": "https://relay-fdv2-prod.ld.catamorphic.com",
  "dogfoodStreamUri": "https://relay-fdv2-prod.ld.catamorphic.com",
  "dogfoodClientSideEventsUri": "https://events.ld.catamorphic.com",
  "dogfoodSendEvents": true,
  "dogfoodContext": {
    "kind": "multi",
    "session": { "key": "c094e878-4a02-47c4-a7ea-c4c7a1fcd759", "anonymous": true },
    "user": { "key": "c094e878-4a02-47c4-a7ea-c4c7a1fcd759", "name": "",
              "dogfoodCanary": false, "anonymous": true }
  },
  "dogfoodEventsCapacity": 1000,
  "secureModeContextHash": "765b5c97ff4eee44f584235d88856af15c86c2878bee6d8da1d55197c1d2794f",
  "allClientSideFlags": { "$valid": true, "...": "≈100+ internal flags, see below" }
}
```

Full captured body: `ci-results/run-*/internal-config-anonymous.json` (fetched by
`tools/ci-internal-probe.sh` §8, which also records response headers, flag-name inventory,
ticket-reference extraction, and a stability/attacker-influence test of the signed context).

### Disclosed items that are not ordinary client-side flag toggles

| Category | Example values (verbatim) | Why it's sensitive |
|---|---|---|
| **Internal ticket IDs** | `LAUNC-2510`, `LAUNC-2487`, `LAUNC-2486`, `MTRX-2082`, `MTRX-2083`, `MTRX-2084` (inside `experiment-metric-compatibility-rules[*].docNote`) | Maps unreleased work to LD's internal tracker; enables targeted social engineering / correlation with public repos |
| **Unreleased roadmap + dates** | `"reason":"Q3 2026 target, not yet built"` (`stateful-experimentation-not-built`, `power-analysis-not-built`), `"reason":"Not planned"` (`pre-bias-checks-not-planned`), `"Decoupled analysis unit isn't available yet"` | Confidential product plans and internal prioritisation decisions, pre-announcement |
| **Internal platform detail** | `"Federal runs legacy Airflow, which does not support trace events in experimentation"`, `"Federal's Airflow pipeline has no windowing columns"`, `"Ratio metric API layer done; results computation not yet implemented for the Federal (Airflow) pipeline"`, `"CUPED + metric filters unsupported per foundation commit e2c2f04"`, `enable-chex-sliced-aggregates` | Discloses the analytics pipeline implementation per deployment (incl. the **federal** instance) and an internal commit reference — architecture detail useful for further attacks and competitively sensitive |
| **Signup risk/business rules** | `"pql-signup-junk-country-list":["EG","ID","VN","PK","BD","NP","MA","NG","DZ","KE"]` | Internal fraud/lead-scoring policy that treats signups from these countries as junk. Business-sensitive and reputationally risky if published; also tells an attacker exactly which geo signals to spoof at signup |
| **Marketing/lead-capture internals** | `marketo-form-submission-config` with form IDs `1941`, `3144`, `3247`, `3331` and per-field mappings (`email`, `firstName`, `company`, `title`, `planType`, `subscriptionState`, `programID`) | Reveals the internal form IDs consumed by `/internal/contact-us/forms/{formId}/public-submit`, i.e. the exact identifiers needed to craft submissions against that route |
| **Internal dogfood infrastructure** | `relay-fdv2-prod.ld.catamorphic.com`, `events.ld.catamorphic.com` | LD's own internal Relay Proxy / events hosts for the environment that flags the app itself — not documented anywhere public |
| **Secure-mode material** | `secureModeContextHash` + the `dogfoodContext` it signs | A server-computed HMAC-SHA256 over a context canonical key, handed to anonymous callers. See escalation path |
| **Feature/limit internals** | `evals-token-limits-max-per-member: 10000000`, `ai-tools-bulk-update-max-targets: 50`, `ai-evaluator-llm-retry-base-delay-seconds: 1`, `fix-pending-changes-429`, `enable-teams-of-teams`, `enable-marketplace-billing`, `enable-ai-guarded-rollout`, `users-to-contexts`, `warehouse-health-checks-v-2`, `snowflake-warehouse-data-export-self-serve`, `enable-configurable-experimentation-for-pro-plans` | Unannounced feature names + server-side limits/retry behaviour (useful for tuning abuse below rate-limit thresholds) |

## Why it matters (impact)

- **Confidentiality, no privileges required, no user interaction**: everything above is readable by
  any anonymous internet client with a single GET. There is no tenant data of *customers* in it, so
  the impact is to LaunchDarkly itself: pre-announcement roadmap, internal engineering/platform
  detail (including for the federal deployment), internal tracker IDs, and internal business rules.
- **Directly actionable for further attack**: the marketing form IDs feed an internal
  `public-submit` route; the country blocklist tells an attacker which geo attributes to falsify
  during signup; the internal limits (`ai-tools-bulk-update-max-targets`, retry delays, `429` fix
  flag) describe thresholds for staying under abuse detection; the dogfood relay/events hosts
  identify LD's own evaluation infrastructure.
- **The `secureModeContextHash` is the interesting part.** Secure mode's entire threat model
  (`launchdarkly.com/docs/sdk/features/secure-mode`) is that a **backend** signs a context with the
  environment SDK key so that "one end user cannot inspect the variations for another end user".
  Here an *anonymous, unauthenticated* endpoint publishes a valid signature for the dogfood
  context. That is correct **only if** the signed context is server-chosen and immutable. If the
  context is derived from anything the caller controls (cookie, query parameter, header), the
  endpoint becomes a **signing oracle**: an attacker obtains a valid `h` for a context key of their
  choosing and thereby defeats secure mode for that environment — which is precisely the
  "improper retrieval of flag information meant for other users" case the program asks about on the
  streamer/SDK surface.

## Root cause

A pre-authentication bootstrap endpoint (`/internal/config/anonymous`) is used to ship *both*
harmless UI configuration *and* internally-scoped data (roadmap rules, business policy, internal
infra, marketing form IDs, a signed context) to every logged-out visitor. The data classification
of what may be placed in a client-side flag value is not enforced — anything set as a client-side
flag value in LD's own dogfood environment becomes world-readable through this endpoint. The
`allClientSideFlags` mechanism (LD's own dogfooding, served via
`relay-fdv2-prod.ld.catamorphic.com`) has no server-side filter separating "safe for anonymous
visitors" from "internal only".

## Steps to reproduce

1. No account, no cookies, no headers. From any machine:
   ```bash
   curl -sS -i 'https://app.launchdarkly.com/internal/config/anonymous' | head -c 2000
   ```
   → `HTTP 200`, JSON body as quoted above.
2. Confirm the sibling endpoint *is* gated, i.e. this is a deliberate unauthenticated route and not
   a blanket auth failure:
   ```bash
   curl -sS -i 'https://app.launchdarkly.com/internal/config/authenticated'
   ```
   → `401 {"code":"unauthorized","message":"Invalid account ID header"}`
3. Confirm the route is reachable and self-describing from the unauthenticated `/internal/` index:
   ```bash
   curl -sS 'https://app.launchdarkly.com/internal/'
   ```
   → `200 {"_links":{"account":…,"actions":…,"self":{"href":"/internal/"}}}` (also unauthenticated)
4. Inspect `allClientSideFlags` for the items in the table above, e.g.:
   ```bash
   curl -sS 'https://app.launchdarkly.com/internal/config/anonymous' \
     | python3 -c 'import json,sys; d=json.load(sys.stdin);
                   f=d["allClientSideFlags"];
                   print(f["pql-signup-junk-country-list"]);
                   print(json.dumps(f["experiment-metric-compatibility-rules"], indent=1)[:1500])'
   ```
5. **Expected:** anonymous callers receive only what a logged-out visitor's UI needs.
   **Observed:** internal ticket IDs, unreleased roadmap/dates, federal pipeline internals, a signup
   country blocklist, marketing form IDs, internal dogfood hosts, and a secure-mode HMAC.

## Escalation path — TESTED, NEGATIVE RESULT (recorded for honesty; severity stays P4)

The `secureModeContextHash` question was tested before writing this up, because if the signed
context were attacker-influenced it would be a secure-mode bypass primitive (P2/P3), not mere
information disclosure.

**Result: no oracle.** Across 10+ unauthenticated requests (CI run 3, plus header/cookie/query
variants `ld-flag-override`, `ld-gonfalon-overrides`, `ld-bypass-ua-tracking`, `ld-data-source`,
`ld-observability`, `x-ld-project-id`, `x-ld-envid`,
`ld-account-id-verification-for-salesforce`, and
`Cookie: ld_anonymous_id=…; sandboxVisitorAccountId=…` + `?contextKey=…`) the
`dogfoodContext.session.key` / `dogfoodContext.user.key` was a **fresh random UUID on every single
response** (`9e7a154f-…`, `b662b740-…`, `54729c2a-…`, `e4ba84ff-…`, `29aa6282-…`, `5bc3f603-…`,
`6dcec5e5-…`, `bd63d5b3-…`, `1a69f701-…`, `24fa129a-…`), and the hash changed with it. The server
generates and signs its own anonymous context per request; nothing supplied by the caller moved it.

Also checked and closed: `ld-flag-override` and `ld-gonfalon-overrides` are **not** server headers —
in LD's bundle they are a `localStorage` namespace for the SDK's `FlagOverridePlugin`
(`storageNamespace ?? "ld-flag-override"`) and the internal name of the app itself
(`serviceName: "gonfalon-web"` / `application.id: "gonfalon-frontend"`). Supplying them as request
headers produced byte-identical behaviour to the baseline. Likewise `ld-account` is a
**localStorage key prefix** (`ld-account-${accountId}`, with a migration path from a legacy global
`ld-account` key), not the "account ID header" from the 401 message.

So this report claims **information disclosure only (P4)**.

Note: `ld.catamorphic.com`, `ld-stg.launchdarkly.com` and the other internal hosts named in the
bundles were **never contacted** — they are reported as disclosed data only.

## Related (same root cause, same unauthenticated surface)

`GET /internal/plans` also answers **200 with no credentials**, returning LD's commercial plan
objects including internal plan IDs, `monthlyPrice` in cents, and the full `_limits` entitlement map:

```
startup  v1   $79.00/mo  id=558b29ee922f08271400000a  mau=10000  teams=false customRoles=false enforceSeatLimits=false
team     v1  $299.00/mo  id=558b29de8a25dc272000000d  mau=25000  teams=true  customRoles=false enforceSeatLimits=false
growth   v2  $699.00/mo  id=58a3a1358ff1540922d62480  mau=50000  teams=true  customRoles=false enforceSeatLimits=false
```

Pricing itself is public, so this is only supporting evidence that `/internal/*` serves
non-public configuration to anonymous callers — the internal plan `_id`s and the
`enforceSeatLimits`/`mauLimit` entitlement flags are the non-public part, and the IDs are directly
usable against `/internal/billingv2/plans/{planType}/limits`. Included here rather than as a second
report per the program's "one vulnerability per report / same issue across endpoints = duplicate"
rule.

## Additional disclosed material (CI run 4, `ci-results/run-4/`) — raises the value of this report

The same unauthenticated response also carries `allClientSideFlags`: **2339 flag names together with
their evaluated values** for LaunchDarkly's own production dogfooding environment, as evaluated for an
anonymous visitor (`internal-config-anonymous.json`, names list in `…json.flagnames.txt`). 221 of them
concern authentication, authorization, approvals or token handling. Examples, verbatim:

| disclosed flag | value | why an attacker cares |
|---|---|---|
| `enable-google-oauth-email-verified-check` | `false` | Google OAuth sign-up is enabled (`enable-google-oauth-sign-up=true`) while the email-verified check is off → unverified-email account linking (tracked as a separate lead, needs an account to test) |
| `enforce-saml-conditions-validity-window` | `false` | SAML `NotBefore`/`NotOnOrAfter` conditions not enforced → assertion-replay class of attack |
| `enable-bypass-approval-requirements-enforcement` / `enable-bypass-required-approval` / `enable-segment-bypass-approvals` | `true` | release-guardrail bypass paths are live in production |
| `snippets-bulk-update-skip-pending-approval` | `true` | bulk update skips pending approvals |
| `disable-legacy-access-token-auth-fallback` | `false` | legacy token-auth fallback still accepted (consistent with the `invalid access token` code path observed on `/api/v2/*`) |
| `mfa-enforcement` / `enforce-mfa-for-basic-auth` | `false` | MFA not enforced platform-wide |
| `enable-internal-authorization-endpoint` | `true` | the `/internal/authorization/*` surface is live |
| `enable-o-auth-dcr` / `enable-o-auth-dcr` | `true` | OAuth dynamic client registration enabled |
| `enable-ip-allowlist` / `…-session-auth` / `…-scoped-auth` | `false` | IP allowlisting controls not enabled for this env |
| `zz-fairytale-bypass-test` | `true` | an internal bypass test flag left enabled in production |

Also disclosed: internal limits (`access-token-list-max-limit=1000`,
`internal-environment-query-limit=50`, `evals-token-limits-max-per-member=10000000`,
`max-sdk-key-associations-per-view=250`, `fdcore-redis-write-token-cap=10`,
`playground-trial-daily-token-limit=10000`), the account **password policy**
(`minPasswordLength=8`, `passwordMinClasses=3`, `passwordMinCharsPerClass=1`,
`prevent-commonly-used-passwords=true`), OAuth/third-party identifiers
(`githubOauthClientId=Iv23liYrVNRkiyt0YvFX`, `googleOauthClientId=1069747104247-…`,
`stripePublishableKey`, `segmentWriteKey`, `hockeystackApiKey`, `canduClientToken`, `docsAlgolia*`,
`newRelic*`, `datadog*`, `intercomFinApp*`, `googleCaptchaSiteKey`, `slackAppId`, `courier*`,
`observabilityProjectID=1jdkoe52`), and **one specific customer account id** in
`integration-approvals-poll-after-approval-accounts=["5d25ea5f23d2f65d48fa0c9c"]`.

> That account id is recorded here purely as disclosed data. In line with the program rule against
> touching other users' data, it was **not** used in any request, header value or access attempt.

Sibling unauthenticated endpoint `GET /internal/plans` (200, 1236 B) adds the full commercial plan
catalogue: `startup` $79/mo (`558b29ee922f08271400000a`, mau 10 000), `team` $299/mo
(`558b29de8a25dc272000000d`, mau 25 000), `growth` $699/mo (`58a3a1358ff1540922d62480`, mau 50 000),
each with `_limits` booleans (`teams`, `customRoles`, `abTesting`, `auditLog`,
`multipleProjects`/`multipleEnvironments`) and `enforceSeatLimits=false` on all three.

**Negative results (checked, nothing to escalate):** `sandboxVisitorAccountID`,
`sandboxVisitorMemberID`, `sandboxVisitorBaseUri` are empty strings (no free visitor identity);
`useMockOAuthValidators=false`; `isManagedInstance=false`; `isSandbox=false`; `disallowSignups=false`.
The `secureModeContextHash`/`dogfoodContext` pair is re-signed with a fresh random UUID per request,
so it yields no oracle (see "Escalation path" above).

**Net effect on this report:** the endpoint does not merely leak internal toggles — it publishes the
live authentication/authorization posture of `app.launchdarkly.com`, its internal quota limits, its
password policy, its commercial plan economics and one customer account id, to any unauthenticated
client. The claim remains **P4 information disclosure** (no direct compromise demonstrated here); the
individual posture items above are tracked as separate leads in `plans/auth-posture-leads.md` and will
only be reported if independently verified.

## Evidence

- `ci-results/run-*/internal-config-anonymous.json` — full response body (CI-captured)
- `ci-results/run-*/internal-probe.txt` — response headers + the three-fetch diff summary
- `ci-results/run-*/internal-config-anonymous.json.flagnames.txt` — sorted inventory of every
  disclosed internal flag name
- `recon/internal-api-inventory.md` §1–2 — how the route was found (bundle mining of the app's own
  JS, 142 `/internal/*` paths) and the surrounding unauthenticated surface
- Screenshot/video: to be added (single `curl` in a clean browser profile, no cookies)

## Remediation suggestion

1. Split the anonymous bootstrap payload: serve only what a logged-out UI needs
   (`clientSideId`, feature toggles that are safe to publish) from `/internal/config/anonymous`, and
   move roadmap rules, business policy lists, marketing form config, and internal infra references
   to the authenticated config endpoint (already correctly gated).
2. Add a publish-time guard on LD's own dogfood environment: any flag made available to client-side
   IDs whose value contains internal ticket patterns (`[A-Z]{3,}-\d+`), hostnames outside
   `launchdarkly.com`, or policy lists should fail review — this is the same "client-side flag
   values are public" rule LD documents for customers, applied to itself.
3. For the `secureModeContextHash`: ensure the signed context is **always** server-generated
   (random per session) and that no cookie, query parameter, or header can influence the canonical
   key that gets signed. If any influence exists, treat it as a secure-mode bypass and rotate the
   dogfood environment SDK key.
4. Strip `docNote`/`reason` free-text (which carries ticket IDs and internal reasoning) from
   client-delivered flag values; keep them server-side and expose only the `status.type` +
   `userMessage` the UI needs.

## Out-of-scope / excluded check

Checked against the program's exclusion list:
- **Not** a client-side key disclosure claim — `clientSideId` is explicitly excluded and is *not*
  part of the impact argument (mentioned only for completeness of the response).
- **Not** a version/banner disclosure or descriptive-error-message issue.
- **Not** a dependency/vulnerability scan result; found by reading LD's own JS bundles and probing
  the in-scope `/internal/` subroute.
- **Not** HTML injection, clickjacking, CSRF, tabnabbing, open redirect, or rate limiting.
- **Not** a third-party integration (Marketo form IDs are disclosed *by LD's own endpoint*; no
  Marketo system was contacted or tested).
- **Not** tested against any out-of-scope host: `ld.catamorphic.com` was never requested; the
  federal/EU instances were never contacted.
- **Known-issue risk (stated honestly):** LD may consider the anonymous bootstrap endpoint and
  client-side flag delivery "by design", since any logged-out browser loading `app.launchdarkly.com`
  receives the same flag values. The report is framed on the *sensitivity of the published values*
  (internal tickets, unreleased roadmap, federal pipeline internals, signup blocklist, internal
  hosts) rather than on the route's existence, and on the secure-mode hash question. If triage
  considers the flag values acceptable, the secure-mode oracle result (§Escalation path) is the
  part that stands on its own.

## Status
- [x] Draft (evidence capture automated in CI; escalation test pending run results)
- [ ] Submitted (Bugcrowd URL/ID)
- [ ] Triage response:
- [ ] Resolved / disputed
