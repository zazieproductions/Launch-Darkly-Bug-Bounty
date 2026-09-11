# Auth-posture leads derived from disclosed flag values — UNVERIFIED, do not submit as-is

Source: unauthenticated `GET https://app.launchdarkly.com/internal/config/anonymous` →
`allClientSideFlags` (2339 names + values), committed in `ci-results/run-4/`. Cross-referenced with
the SPA bundles (`ci-results/run-4/bundle-ctx-*.txt`) and `ci-results/run-4/internal-probe.txt`.

**Why these are leads, not findings:** these are *client-side* flag values as evaluated for an
anonymous visitor of LaunchDarkly's own dogfooding environment. Each one describes what the SPA is
told to do; whether the server independently enforces the same behaviour is unknown. A report built
on a flag value alone would be exactly the low-effort speculation the program forbids, so every item
below stays here until it can be verified against a real account (or against code we can run).

Each entry: what is disclosed → why it could matter → the minimum verification step → blockers.

---

## L1 — Google OAuth sign-up with an unverified email (`enable-google-oauth-email-verified-check = false`)

* Disclosed: `enable-google-oauth-sign-up = true`, `enable-github-oauth-sign-up = true`,
  `enable-google-oauth-email-verified-check = **false**`, `enable-login-v2-oauth = false`,
  `require-email-verification = true`, `enable-email-verification-code = true`,
  `enforce-email-verification-landing-page = true`.
* Why it could matter: the classic OAuth account-linking flaw — if the IdP's `email_verified` claim is
  not checked, an attacker can link an email address they do not control to their own IdP identity and
  then sign in to (or create) the victim's LaunchDarkly account. Note the tension with
  `require-email-verification = true`: LD does verify emails for the password flow, so the OAuth path
  may be the weaker one.
* Verification: read the SPA's OAuth callback handling in the bundles (search `email_verified`,
  `verified_email`, `googleOauthClientId` usage) to see whether the check is client-side UI only; then,
  with an account, run the Google sign-up flow with a Google identity whose email is unverified and
  observe whether LD accepts the link.
* Blockers: needs (a) our own LD account, (b) a Google account with an unverified email — Google no
  longer makes that easy to create. Bundle analysis may be enough to show where the flag is consumed.

## L2 — SAML conditions validity window not enforced (`enforce-saml-conditions-validity-window = false`)

* Disclosed: `enforce-saml-conditions-validity-window = false`, `enable-signed-saml-authentication-requests = true`,
  `enable-encrypted-saml-assertions = true`, `custom-roles-as-saml-default-role = true`,
  `enable-domain-verification-for-sso-accounts = true`, `enable-unique-sso-entity-id = false`,
  `sso-saml = false`, `enable-join-org-sso-redirect = true`, `enable-login-domain-sso-fallback = false`.
* Why it could matter: not enforcing `NotBefore`/`NotOnOrAfter` permits **replay of a captured SAML
  assertion** (and makes clock-skew/stolen-assertion attacks practical), which is a well-known SSO
  weakness class.
* Verification: needs an account with SAML SSO configured (own IdP), then replay a captured assertion
  after its validity window and observe whether the session is created. Server-side behaviour cannot be
  inferred from a client-side flag.
* Blockers: account + an IdP we control + a second (test) account. High setup cost; only worth it if the
  user is willing to create an account and configure SSO.

## L3 — Approval/guardrail bypass flags live in production

* Disclosed: `enable-bypass-approval-requirements-enforcement = true`, `enable-bypass-required-approval = true`,
  `enable-segment-bypass-approvals = true`, `snippets-bulk-update-skip-pending-approval = true`,
  `zz-fairytale-bypass-test = true`, `enable-approvals = false`, `require-approvals-for-an-environment = false`,
  `require-approval-for-flag-archival = false`, `enable-approval-auto-apply = true`,
  `allow-workflows-with-custom-approvals = false`, `aic-disable-pending-approval-request-logic = false`,
  `allowed-post-approval-requests-global-flag-instruction-kinds = ["addVariation","removeVariation","updateDefaultVariation","updateVariation"]`.
* Why it could matter: Release Guardian / approval flows are an authorization control. If a low-privilege
  member can reach a code path where "bypass required approval" is honoured, that is a privilege-escalation
  / broken-access-control finding (the program explicitly lists authN/authZ as a focus).
* Verification: with an account, create an environment that requires approvals, then attempt a change with
  a member role that should be blocked; watch for the bypass paths. Also inspect the bundle for where
  `enable-bypass-required-approval` is consumed (client-side gating only?).
* Blockers: account; must stay inside our own account and non-destructive (no bulk changes to shared data).

## L4 — `/internal/authorization/access-check/{service}/bulk` takes credentials and a target service as *parameters*

* Evidence (SPA bundle, `ci-results/run-4/bundle-ctx-access_check_.txt`):
  ```js
  async function s({apiVersion:e, body:t, header:n, ...r}, {headers:i, signal:l}={}) {
    return ky().POST("/internal/authorization/access-check/{service}/bulk",
      {params:{path:r, header:n}, body:t, headers: …})
  }
  // caller:
  s({header:{Authorization: document.cookie}, service:"gonfalon", body:e})
  ```
  Batched via a runner: `name:"access-check-runner"`, `maxBatchSize:25`, body items shaped
  `{action, resource}` (resolver matches on `e.action===t.action && e.resource===t.resource`).
* Why it could matter, three separate angles:
  1. **Confused deputy / parameterised service:** `service` is a caller-supplied path segment and
     `header` is a caller-supplied credential map. If the endpoint forwards those to the named internal
     service, an authenticated low-privilege caller may be able to (a) enumerate other services'
     authorization policies, or (b) get an access decision computed for arbitrary supplied credentials.
  2. **Credentials in the URL (CWE-598):** `header` is passed in `params`, i.e. as a query parameter
     holding `document.cookie`. Query strings end up in access logs, proxies, browser history,
     `Referer`, and — because Datadog RUM is configured with `allowedTracingUrls` including
     `app.launchdarkly.com` — in third-party RUM traces. Mitigating uncertainty: if `ldso` is
     `HttpOnly`, `document.cookie` contains only non-HttpOnly cookies, which would greatly reduce
     impact. That cannot be determined without logging in.
  3. `enable-internal-authorization-endpoint = true` confirms the surface is live in production.
* Verification: `GET` returns **405** (route exists, POST only) — see `internal-probe.txt` §2. A single
  unauthenticated `POST` with an empty/dummy body would show whether it is gated (401 "Invalid account
  ID header") or reachable; with an account, vary `service` and `header` and compare decisions.
* Blockers: **POST is outside the standing GET-only CI constraint** — this is the open question for the
  user. An access-check call is read-only by semantics (it computes a decision, changes no state), but
  it is still a POST to an `/internal/` path.

## L5 — Legacy access-token auth fallback still enabled (`disable-legacy-access-token-auth-fallback = false`)

* Disclosed alongside: `fdcore-reject-mismatched-token-prefix = true`, `fdcore-reject-unknown-token-kind = true`,
  `restrict-api-token-version-to-latest = true`, `enable-modernized-tokens-endpoint = true`,
  `enable-new-access-token-expiry-field = true`, `enable-canary-token = true`,
  `access-token-expiry-notification-configuration = {"notifyDaysFromExpiry":[30,7,1]}`.
* Observed behaviour (CI run 4 §9): on `/api/v2/projects` and `/api/v2/announcements`,
  `Authorization: Bearer <dummy>` switches the error from `Invalid account ID header` to
  `{"code":"invalid_token","message":"invalid access token"}` — i.e. the request is routed into the
  token-auth branch. Every other dummy variant (raw value, `ldso=`-shaped value in `Authorization` or
  `Cookie`, both together, `LD-API-Version: beta`) leaves the account-header error unchanged, on both
  `/api/v2/*` and `/internal/*`.
* Why it could matter: a retained legacy fallback is where weaker validation usually survives.
* Verification: needs a real token to compare legacy vs modern validation, i.e. an account. Unauth work
  is exhausted — the differential above is the whole of what can be learned without credentials.
* Note: this is also the answer to the long-running "what is the account ID header?" question — see
  `findings/log.md`: the header name was never recoverable from bundles or by brute force, and run 4
  shows the gate is not satisfied by any dummy-valued header/cookie, so it is derived from the session
  (`ldso`) server-side or from a header the SPA sets only after login.

## L6 — OAuth dynamic client registration enabled (`enable-o-auth-dcr = true`, `enable-oauth-dcr = true`)

* Disclosed alongside: `enable-modernized-oauth-applications-endpoint = true`,
  `enable-oauth-multi-account-redirect = true`, `enable-oauth-refresh-token-echo = false`,
  `enable-vercel-marketplace-oauth-sign-up = true`, `enable-aws-marketplace-signup = true`,
  `enable-observability-vega-github-csrf-enforcement = true`, `vega-agentcore-gonfalon-auth-header = false`.
  Public API surface: `/api/v2/oauth/clients` (GET/POST), `/api/v2/oauth/clients/{clientId}`
  (GET/PATCH/DELETE), `/api/v2/tokens*` (`openapi-paths.txt`).
* Why it could matter: DCR plus a multi-account redirect is the usual recipe for open-redirect /
  client-registration abuse in OAuth flows.
* Verification: read the OpenAPI definition of `createOAuth2Client` (redirect-URI validation rules) and
  the SPA's OAuth code; any live test would create an OAuth client (a write) — needs an account and
  explicit go-ahead.

## L7 — Auth-flow endpoints enumerated from the bundles (NOT probed — excluded by design)

`/internal/account/login`, `/login2`, `/signupv2`, `/signup/complete/{token}`,
`/signup/{token}/pending-invites`, `/signup/facilitated-trial/{token}`,
`/signup/facilitated-trial/{token}/validate`, `/verify-code`, `/resend-verification`,
`/session`, `/session/escalate`, `/session/mfa`, `/session/mfa-recovery`, `/revoke-sessions`,
`/account/join`, `/account/owner`, `/account/saml`, `/account/saml-app-details`, `/account/scim`,
`/account/scim/managed-teams`, `/account/suggest-invites`, `/account/tokens`.

These are auth-flow and/or mutating paths and are **excluded from all CI probing by design**
(`tools/ci-internal-probe.sh` header). Listed for completeness: invite/facilitated-trial tokens in
paths are the kind of thing worth reviewing *by reading the bundle code*, not by probing.

---

## Rule for this file

Nothing here gets reported on the strength of a flag value. An item graduates to `findings/F-00x-*.md`
only when there is either (a) an executable PoC against real code (as with F-002 and F-003), or (b) an
observed server response that demonstrates the behaviour on an in-scope host, using only our own
account/data.
