# Internal API Surface — Inventory & Analysis

Derived from **live unauthenticated probing** (2026-09-11) plus **static analysis of the app's own
JS bundles** downloaded by CI (`ci-results/run-2/`). Everything here is passive/read-only: no
credentials were used, no data was created, no other tenant was touched.

Sources:
- `ci-results/run-2/route-matrix.txt` — status codes for ~60 unauth probes
- `ci-results/run-2/bundle-api-paths.txt` — 142 `/internal/*` paths + 190 `/api/v2/*` paths
  extracted from the SPA bundles
- `ci-results/run-2/openapi-paths.txt` — 254 documented operations (spec is public: 2.98 MB,
  `GET /api/v2/openapi.json` → 200 unauth)
- `ci-results/run-2/bundle-custom-headers.txt`, `bundle-account-strings.txt` — internal header names

---

## 1. The account-ID header gates `/api/v2/` itself ⭐⭐ (biggest lead)

Unauthenticated status codes, verbatim:

| Request (no auth, no headers) | Status | Body |
|---|---|---|
| `GET /api/v2/` | **200** | links index: `account`, `flag-statuses`, `flags`, `integrations`, `members`, `projects`, `public-ip-list`, `segments`, `tokens`, `webhooks` |
| `GET /api/v2/openapi.json` | **200** | full spec (2,985,850 B) |
| `GET /api/v2/public-ip-list` | **200** | full egress CIDR list |
| `GET /api/v2/caller-identity` | 401 | `{"code":"unauthorized","message":"invalid access token"}` |
| `GET /api/v2/projects` | 401 | `{"code":"unauthorized","message":"Invalid account ID header"}` |
| `GET /api/v2/announcements` | 401 | `{"code":"unauthorized","message":"Invalid account ID header"}` |
| `GET /internal/` | **200** | `{"_links":{account, actions, self}}` |
| `GET /internal/account` / `/internal/actions` / `/internal/announcements` | 401 | `Invalid account ID header` |
| `GET /internal/members`, `/private/`, `/api/v2/private`, `/api/v2/ips` | 404 | SPA HTML "Lost in space" |
| `GET /api/v2` , `GET /internal` | 301 | → trailing-slash redirect |

Analysis:

- Two **different** unauth error paths exist on `/api/v2/`: `invalid access token`
  (caller-identity) vs `Invalid account ID header` (projects, announcements). So for most
  `/api/v2/` resources the gateway tries to resolve an **account from a header** before/independently
  of validating a token. The header is **absent from the public contract**: the entire 2.98 MB
  OpenAPI spec contains exactly **one** header parameter — `LD-API-Version`
  (`openapi-header-params.txt`), and **zero** operations with empty `security`
  (`openapi-noauth-operations.txt` is empty). The docs page for `getAnnouncementsPublic` lists only
  `Authorization` + `status`/`limit`/`offset`.
- Candidate name found in the app's own bundles: **`ld-account`**
  (`bundle-custom-headers.txt`). Also present: `ld-account-id-verification-for-salesforce`,
  `x-ld-project-id`, `x-ld-envid`, `ld-flag-override`, `ld-gonfalon-overrides`,
  `ld-bypass-ua-tracking`, `ld-data-source`, `ld-observability`.
- Brute-forcing 21 header-name candidates × 2 dummy values against
  `/api/v2/announcements` changed **nothing** (all 401 `Invalid account ID header`).
  Conclusion: the error does not distinguish "unknown header" from "known header, invalid value",
  so **name discovery needs a valid account-id value** — or the bundle call site (CI §7f now
  captures ±220 chars around `ld-account`, `gonfalon`, `access-check`, `role-presets-bundle`,
  `entitlements`, `config/anonymous`, `upload-url`, `assignment-data-sources`).

**The decisive experiment (needs OUR OWN account id, `LD_ACCOUNT_ID` secret):**
`GET /api/v2/projects` and `GET /internal/account` with `ld-account: <our-real-account-id>` and
**no cookie, no token**. Three possible outcomes, all interesting:
1. 200 + our data → the account header alone authenticates → **unauthenticated API access**
   (P1/P2; focus area "Unauthenticated/unauthorized access to APIs").
2. 200 + *empty or differently-scoped* data → header-only context resolution; then swap in another
   account id shape to test cross-tenant scoping (never with a real third-party id — stop & report).
3. 401 with a **different message** (e.g. "invalid access token") → the header is accepted and the
   gate moves to the token layer; then the valid/invalid account-id differential is an
   **account-enumeration oracle** (reportable as info disclosure, lower severity).

---

## 2. The 142 `/internal/*` endpoints (from the app's bundles)

`/private/` appears **zero** times in the bundles — the SPA does not use it, so the program's
"`/private/` APIs" are almost certainly a different service/ingress. All 404 at the app edge.

### 2a. Probed now (read-only, safe to call unauthenticated) — CI `ci-internal-probe.sh`

Config/entitlement/plans/metadata endpoints, no identifiers required:

```
/internal/config/anonymous          /internal/config/authenticated
/internal/plans                     /internal/billingv2/plans[/{planType}/limits]
/internal/role-presets-bundle       /internal/accesses
/internal/entitlements/ai-configs   /internal/entitlements/release-guardian
/internal/metric-data-sources       /internal/usage/sdk-active
/internal/warehouse-integrations-health
/internal/unauthenticated-members/organization-verifications[/{id}]
/internal/account  /internal/actions  /internal/announcements  /internal/projects
/internal/projects/flag-count       /internal/profile[/context|/following|/notification-settings]
/internal/flags/{projectKey}        /internal/ai/evaluations/providers
/internal/authorization/access-check/{service}/bulk
/internal/billingv2/account/subscription[/usage|/usage-status|/campaigns|
                                         /trial-extension/eligibility|
                                         /opportunity/enterprise-seats]
```

Why these matter:
- **`/internal/role-presets-bundle`** — the deployed preset-role → action mapping. This is the
  reference data for the "new-action PCE sweep" (Phase 2): diff it against
  `recon/app-features.md`'s recently-added-actions table to find preset roles that were never
  updated, i.e. endpoints whose authz nobody re-reviewed.
- **`/internal/authorization/access-check/{service}/bulk`** — a bulk authorization **oracle**. If it
  answers for arbitrary resource specifiers, it discloses what any role/member can do without
  performing the action (and may be callable with a low-privilege token to enumerate other
  members' permissions → the classic "APIs returning data the user role should not have access to").
- **`/internal/entitlements/*`** — plan/add-on gates (Guardian = guarded rollouts). Compare
  responses with and without `ld-flag-override` / `ld-gonfalon-overrides`: if a client-supplied
  header flips an entitlement, that's **feature/plan gating bypass** (business-logic, focus area).
- **`/internal/unauthenticated-members/organization-verifications`** — the name says
  *unauthenticated*; if it returns organization verification records it is an
  **org-enumeration/disclosure** surface.
- **`/internal/config/anonymous` vs `/internal/config/authenticated`** — client config split by
  auth state; the anonymous one is designed to be public, so anything account-specific in it is a
  leak. Also the best place to see whether internal flags/gonfalon overrides are echoed.

### 2b. Auth-flow / mutating — **excluded from blind probing on purpose**

Never touched by any script in this repo, because they send email/tickets to real people, mutate
accounts, or are credential-bearing (program excludes support-team interfaces, email bombing, and
anything affecting other users; and `/internal/reset/{token}` + `/internal/invite/{token}`
enumeration would be an attack on real accounts):

```
/internal/account/{login,login2,signup*,signupv2,join,forgot,verify-code,resend-verification,
                   revoke-sessions,card,accrued-invoices,owner,saml,saml-app-details,scim,
                   scim/managed-teams,tokens,subscription,suggest-invites,session,
                   session/escalate,session/mfa,session/mfa-recovery}
/internal/profile/{password,mfa/confirm,mfa/disable,mfa/enable,resend-verification,
                   cancel-verification}
/internal/reset/{passwordResetToken}     /internal/invite/{token}[/mfa]
/internal/login/mfa/confirm              /internal/forgot      /internal/contact-us/**
```

Two of these are nonetheless **flagged as high-value for authenticated, own-tenant testing**
(never blind, never on someone else's account):
- **`/internal/account/session/escalate`** — a session privilege-escalation endpoint. If the app
  uses step-up auth for sensitive actions, the interesting questions are: is the escalated state
  bound to the session or to a short-lived token, can a non-privileged member call it, and does
  the escalated session persist/leak into API calls (pair with `revokeSessions` action).
- **`/internal/account/session/mfa[-recovery]`** — MFA enrollment/recovery handling.

### 2c. High-value **authenticated** targets (own tenant only) — next phase

Grouped by the vulnerability class they serve:

| Class | Endpoints |
|---|---|
| **SSRF** (program wants proof-of-reach + metadata) | `/internal/projects/{projKey}/assignment-data-sources/{dataSourceKey}/probe` ⭐ (a *probe* = server-side outbound request), `/internal/warehouse-integrations-health`, `/internal/metric-data-sources`, `/internal/projects/{projKey}/metric-data-sources/{dataSourceKey}`, plus the undocumented `/api/v2/destinations/**/{kind}/setup` + `complete-setup` + `/test-event` (§3) |
| **Data exfil / IDOR** | `/internal/projects/{projKey}/datasets/{datasetId}/{download,rows,preview,errors,rows/changes,rows/versions}` + **`/upload-url`** (server-issued upload credential — check whether the URL is scoped to the dataset/project), `/internal/projects/{projKey}/environments/{envKey}/datasets/{datasetId}/{jobs/{jobId},rows}` |
| **Cross-project/search scoping** (app is Elasticsearch-tagged) | `/internal/projects/{projectKey}/flags/search`, `/internal/projects/{projectKey}/flags/compare`, undocumented `/api/v2/projects/{x}/flag-statuses/queries` + `/query`, `/api/v2/chart/data`, `/api/v2/list/data` |
| **Targeting-structure disclosure** (pairs with H5 client-side privacy) | `/internal/projects/{projectKey}/flags/{flagKey}/environments/{environmentKey}/{targeting-analysis,audience,resolved-prerequisites,release-settings,releases}`, `/internal/projects/{projectKey}/environments/{envKey}/flags/{flagKey}/diagnostics`, `/internal/projects/{projKey}/segments/{segmentKey}/flags`, `/internal/projects/{projKey}/flag-archive-checks/{flagKey}` |
| **Views / payload filtering** (H7) | `/internal/projects/{projectKey}/views/{viewKey}/application`, `/internal/projects/{projectKey}/views/{viewKey}/application/evaluated-flags` ⭐ (evaluated flags through a *view* — exactly the filtered-payload path) |
| **Experimentation** (focus area) | `/internal/projects/{projKey}/evaluations[/runs][/{evaluationId}/runs/{runId}/{cancel,rows,summary}]`, `/internal/projects/{projectKey}/environments/{environmentKey}/usage/experiment-exposure-active`, `/internal/projects/{projectKey}/metric-events`, `/internal/projects/{projectKey}/metrics/{metricKey}/{event-instances,event-last-seen}`, undocumented `/api/v2/projects/{x}/randomization-settings` ⭐ (randomization unit/seed handling — Phase 5 asks whether seeds leak) |
| **AI / AgentControl** (newest surface, biggest authz-drift risk) | `/internal/ai-configs/{configKey}/completion` ⭐ (server-side model call → prompt injection / cost abuse / data exfil via completion), `/internal/projects/{projectKey}/ai-configs/**` (incl. `variationsBulk`, `references`, `bulk-version-update`), `/internal/ai/evaluations/providers`, `/internal/projects/{projKey}/playgrounds[/{playgroundId}]`, `/internal/projects/{projKey}/environments/{envKey}/annotations/{traceId}/spans/{spanId}` (trace annotation = the brand-new `updateTraceAnnotation` action, 2026-09) |
| **New-action PCE sweep targets** (2026 additions from `recon/app-features.md`) | `/internal/account/revoke-sessions` (`revokeSessions`), `/internal/billingv2/**` (`updateAccountTokenLimit`, `deleteSubscription`), `/internal/account/scim/managed-teams` (`enableIdPManagingTeams`), `/internal/projects/{projectKey}/flags/{flagKey}/environments/{environmentKey}/releases` + `automated-releases` (`updateAutomatedRolloutConfig`), `/internal/projects/{projectKey}/views/{viewKey}/application` (`updateViewAssociationRequirements`), SDK-key payload/views (`updateSdkKeyPayload`) |

---

## 3. 35 `/api/v2/` paths the app uses that are **not in the public spec**

Undocumented endpoints are where authz review lags. Priority order for the IDOR/authz matrix
(full list in `ci-results/run-2/`, regenerated each run as `undocumented-api-v2-paths.txt`):

| Priority | Path | Why |
|---|---|---|
| ⭐⭐ | `/api/v2/projects/{x}/randomization-settings` | Experiment randomization config (focus area); check for seed/allocation disclosure and whether a member role can write it |
| ⭐⭐ | `/api/v2/chart/data`, `/api/v2/list/data`, `/api/v2/chart/schema/suggestion` | Generic data-query endpoints — if they accept a query/schema spec, test resource-specifier scoping (cross-project read) and injection into the backing store |
| ⭐⭐ | `/api/v2/destinations/{x}/{x}/{x}/test-event`, `/api/v2/destinations/**/{s3,redshift,clickhouse,databricks,snowflake-v2,bigquery}/{setup,complete-setup}` | Server-side connectivity checks → **SSRF with proof-of-reach** (program explicitly asks for this) |
| ⭐ | `/api/v2/integration-manifests[/{x}][/dynamic-options/{x}]` | `dynamic-options` implies server-side option resolution; also an authz surface absent from the spec |
| ⭐ | `/api/v2/projects/{x}/flag-statuses/{queries,query}` | Search-ish flag-status queries → scoping across projects/envs |
| ⭐ | `/api/v2/projects/{x}/ai-configs/{x}/triggers[/{x}]` | Adaptive triggers; the spec documents `adaptive-trigger` differently → path/authz drift |
| ⭐ | `/api/v2/projects/{x}/shortcuts[/{x}]`, `/api/v2/shortcuts` | Per-user objects → trivial IDOR test (read/write another member's shortcuts) |
| ○ | `/api/v2/applications/{x}/version-adoption`, `/api/v2/tracking`, `/api/v2/members{x}`, `/api/v2/{x}`, `/api/v2/{x}/{x}/{x}/expiring-targets/{x}` | Template/telemetry artifacts; `expiring-targets` variants worth an authz check (flag/segment targeting expiry) |
| ✗ | `/api/v2/integrations`, `/api/v2/integrations/slack[/{x}]`, `/api/v2/integration-configurations/keys/snowflake-experimentation/setup` | **Third-party integrations are explicitly out of scope today** — deprioritized on purpose |

---

## 4. Streamer / events / SDK routes — real status codes (in-scope hosts)

### `stream.launchdarkly.com` (in scope)

| Route | Code | Meaning |
|---|---|---|
| `/all`, `/all?filter=x` | **401** (0 B) | server-side stream exists; needs SDK key. `filter=` accepted at routing level → H7 testable here with a real key |
| `/mping` | **401** (0 B) | **mobile ping exists on the in-scope host** |
| `/meval/AAAA` | **401** (0 B) | **mobile streaming eval exists on the in-scope host** → H5/H6 mobile-side testing is in scope after all (needs a `mob-` key from our env) |
| `/eval/{id}/{ctx}`, `/eval/contexts/{ctx}`, `/ping/x` | 404 (0 B) | client-side (browser) stream routes are NOT served here → they live on `clientstream.*` (out of scope) |
| `/msdk`, `/msdk/bulk`, `/bulk_eval/contexts`, `/sdk/evalx/...`, `/msdk/evalx/...`, `/evalx/...`, `/v1/all`, `/all/x` | 404 **`404 page not found`** (19 B) | Go's default NotFound → the service is Go/net-http; distinct from the app's JSON 404 |

Router fingerprint for the streamer: **401 = route exists + auth check; 404 with `404 page not
found` = no route; 404 with 0 B = route matched but the path shape is wrong.**
Next: probe key-shaped paths (`/events/bulk/{key}`, `/mobile/{key}`, `/meval/{ctx}?h=`) with
**our own** keys only.

### `events.launchdarkly.com` (in scope)

Every path tried returned **404 with 0 bytes**, and `/` returned **499** (nginx "client closed
request"). `POST /events/identify` and `POST /events/bulk` with `[]` → 404, i.e. the SDK key is
part of the path (`/events/bulk/{sdkKey}`, `/mobile/{mobKey}`, `/events/diagnostic/{sdkKey}` per
SDK source). **Event-endpoint mapping requires our own keys** — with them, H8/H9 (identify
overwrite, feature-event tampering, guarded-rollout gaming) become testable on an in-scope host.

### `app.launchdarkly.com` as SDK polling fallback (in scope)

| Route | Code | Body |
|---|---|---|
| `/sdk/evalx/{bogus-id}/contexts/AAAA` | **400** | `{"code":"invalid_request","message":"couldn't parse user JSON: expected value at line 1 column 1"}` |
| `/sdk/evalx/{bogus-id}/contexts/e30` (`{}`) | **400** | `couldn't parse user JSON: missing field `key`` |
| `/sdk/evalx/{bogus-id}/contexts/{valid ctx}` | **401** | empty |
| `...?withReasons=true` | 401 | empty |
| `/sdk/evalx/{bogus-id}/users/testuser` (legacy) | **400** | same parse error → **the legacy `/users/{key}` route still exists** and is served by the same base64-JSON parser |
| `/msdk/evalx/contexts/{valid ctx}` | **401** | empty (mobile poll route exists; key comes from a header, not the path) |
| `/msdk/evalx/{id}/contexts/{ctx}` | **404** | `{"code":"not_found","message":"Page not found"}` → wrong shape |
| `/sdk/goals/{id}` | 404 | empty (goals route retired) |

Handler-logic conclusion: **the context is base64-decoded and JSON-parsed *before* the client-side
ID is validated** (400 parse errors precede 401 auth). Two consequences:
1. Anyone can use this route as an unauthenticated **context-schema fuzzing oracle** (error text
   names the internal parser and the legacy "user JSON" model — the users→contexts replacement is
   still running through legacy code, which is exactly the focus-area risk). Descriptive errors are
   excluded from bounty scope, so this is *recon value*, not a report.
2. No pre-auth data leak: an invalid ID gets a clean 401 with an empty body. H5 must therefore be
   run with a **real client-side ID / mobile key from our own environment** (the oracle question is
   about *other contexts in our own env*, and about secure-mode `h` enforcement — not about
   unauthenticated access).

---

## 5. Static-asset trick for deeper bundle mining (no auth needed)

The app shell (`GET /`, `/login`, `/signup` → 200) carries:

```html
<html lang="en" data-static-asset-path="https://static.launchdarkly.com/app/s/ld/"
              data-manifest-name="manifest.422453b0d.json"
              data-bundle="unauthenticated" data-is-unauthenticated>
```

`data-bundle="unauthenticated"` implies **other named bundles** (authenticated, per-feature) whose
chunk names are all listed in the public **manifest JSON**. Pulling
`https://static.launchdarkly.com/app/s/ld/manifest.422453b0d.json` and downloading every chunk it
lists gives the *authenticated* app's code **without logging in** — that is where the remaining
`/internal/*` call sites, the `ld-account` header wiring, and per-feature endpoints live.
(Downloading public static JS is passive recon; `static.launchdarkly.com` is not a test target and
nothing is sent to it.)
