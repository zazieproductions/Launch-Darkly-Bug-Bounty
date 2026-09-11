# Test Plan — LaunchDarkly Bug Bounty

Prioritized hypotheses. **H = high value**, M = medium, L = lower. Phases:
- **P0** = doable without an account (passive / unauth'd, from browser)
- **P1** = needs the `@bugcrowdninja` account (create → full-access org → access token in `.env`)
- **P2** = needs second account or org member with different role (for authz contrast)

Guardrails: production environment. Own-tenant data only. Minimal volumes. No DoS. Stop &
report on any destructive potential. SSRF reports need proof-of-reach + metadata.

---

## Phase 0 — Unauthenticated surface (no account)

| # | Hypothesis | Steps | If true |
|---|-----------|-------|---------|
| H4 | **Announcements "public" API is unauthenticated** | `GET https://app.launchdarkly.com/api/v2/announcements`; try POST/PATCH/DELETE without auth | Unauth read (info) / unauth write (P2/P3) |
| P0-1 | Unauth behavior of internal-only surface | GET `/api/v2/private/` (probe for route listing / error diff), `/api/v2/caller-identity` (expect 401 JSON), `/internal/` | Program: improper `/private/` access = "worthy of note" |
| P0-2 | Unauth'd SDK-route responses on in-scope hosts | On `stream.launchdarkly.com`: `GET /all`, `/eval/contexts`, `/msdk`, `/meval`, `/msdk/bulk`, `/bulk_eval/contexts`, `/ping/anything`, `/sdk/evalx/x/contexts/AAAA`. On `events.launchdarkly.com`: `GET/POST /events/identify` etc. | 404 vs 401 diffs = route existence map; any 2xx/400 with details = finding |
| P0-3 | CORS + cookie-origin check (read side) | From a page you control (e.g. `file://` or a pastebin host) fire `fetch('https://app.launchdarkly.com/api/v2/caller-identity', {credentials:'include'})` with a bogus Origin — observe whether session auth is rejected and what error body leaks | If origin check is weak/absent: cross-origin session API read (P1/P2) |
| P0-4 | Docs search reflection | `docs.launchdarkly.com` / `launchdarkly.com/docs` search with `xss` probes in query; inspect raw HTML (not markdown) for reflected values | Reflected XSS (docs site, P3/P2) |
| P0-5 | `openapi.json` public | `GET /api/v2/openapi.json` with `Authorization: anything` | Confirms public (already documented; skip as finding) |
| P0-6 | `app.launchdarkly.com` as SDK polling fallback | `GET /sdk/evalx/x/contexts/AAAA` and `/msdk/evalx/contexts/AAAA` on app host | Route existence (feeds P1 streamer testing) |

## Phase 1 — Account setup

1. Sign up at `app.launchdarkly.com/signup` with `zazieproductions@bugcrowdninja.com`.
2. Verify org gets full-feature access (all plans).
3. Create a **personal access token** (Account → Authorization), scope = full. Store in `.env`
   (`LD_TOKEN=...`) — gitignored. Also capture the `ldso` cookie for cookie-auth tests.
4. `GET /api/v2/caller-identity` → record role/permissions (required in every report).
5. Create a **second, low-privilege identity** if the org allows (member invite flow) — or use a
   second `+bugcrowd` email. Authz testing needs role contrast (admin vs member vs token-scope).
6. Inventory the org: projects, environments, existing keys (SDK key, mobile key, client-side ID,
   relay proxy config) — these are the tokens for streamer/events testing.

## Phase 2 — Access control & IDOR (focus area: improper authN/authZ, privilege escalation)

IDOR matrix — for each resource type, swap the key/ID with one from a project/environment you
don't own (create ≥2 projects; invite a low-priv member):

| Resource | Endpoints | Checks |
|---|---|---|
| Feature flags | get/patch/copy/delete flag, flag-status-across-environments | cross-project key; member patch; token with read-only scope writing |
| Segments (incl. **big segments**) | get/patch, **membership-for-context / membership-for-user**, bulk target updates | cross-env segment key; membership oracle for contexts you don't own |
| **Contexts** ⭐ | context kinds CRUD, context instances, **search contexts/instances**, **attribute names/values**, **evaluate-context-instance**, context flag settings | can member read attribute *values* of another project's contexts? eval endpoint: does it accept cross-project context kind + key? kind archive/restore races |
| Teams & roles | teams, team-members, team-roles, **custom roles** CRUD, members patch (bulk) | self-role-elevation via PATCH members (role assignment not in role's permissions); custom-role action injection (add actions not assignable) |
| Environments | get/patch, **reset SDK/mobile key** | reset another env's keys (denial of access for tenant); project-member acting on env they don't manage |
| Experiments ⭐ | get-experiments, **get-experiments-any-env**, iterations, settings | `any-env` cross-project read; experiment metrics tampered via events (chain w/ P4) |
| Approvals / scheduled changes / releases | apply approval, review, phase status | apply/review with non-approver role; race: approve+apply atomicity |
| Relay proxy configs | get/list, reset key | config body containing **environment SDK keys** returned to non-maintainer? |
| SDK keys Beta | get sdk-keys (env/project), patch, **put-sdk-key-views** | project-scope token reading env keys; view assignment to wrong env |
| OAuth2 clients | create/patch/get, client-by-id | create OAuth client (credential minting!) with restricted role |
| Access tokens | list/get/patch/reset own & others' tokens | read/reset other members' tokens |
| Audit log | list/search/count | non-admin reading audit entries (who did what, when) |
| Data export | destinations, **generate trust policy / key pair / setup script** | reading another tenant's trust policies; setup scripts embedding secrets |
| IP allowlist | CRUD entries | non-admin modifying (lock-in vector) |
| Insights | deployments, PRs, repos association | cross-project repo/PR data |

Cross-cutting API tricks (run the interesting ones under each role):
- **H3 — version pinning:** replay the same mutating/reading call with `LD-API-Version: 20160426,
  20191212, 20210729, 20220603, 20240415, beta`. Old versions had different filtering/pagination
  (e.g. 20191212 list-flags returns targeting by default pre-summary behavior). Look for
  version-gated authz gaps.
- **H2 — method override:** `POST` + `X-HTTP-Method-Override: PATCH/DELETE/PUT` to (a) unauth'd
  routes, (b) routes with weaker check, (c) with cookie auth + foreign Origin.
- **H1 — Origin validation on cookie auth:** authenticated with `ldso` cookie from a malicious
  Origin (should 4xx). Test: exact match, `null`, `https://app.launchdarkly.com.evil.com`,
  subdomain, trailing dot, case, multiple Origin headers, missing Origin, Origin vs Referer
  mismatch. CORS echoes any origin, so a bypass = cross-origin read+write of session API.
- **`expand=` abuse:** `expand=<anything>` on list endpoints — undocumented expansions leaking
  fields (e.g. expand secret-ish fields on relay configs, tokens, integrations).
- **Semantic patch:** `instructions` with unknown `kind`, duplicated kinds, out-of-order ops,
  `test` ops that mutate? Atomicity: verify partial-failure really changes nothing.
- **Pagination edge:** `limit=0/-1/100000`, `offset` negative, `limit>max` → OOM-ish (note, no DoS),
  off-by-one leaking items across pages.
- **`/private/` with session cookie:** probe a few plausible private routes with cookie auth.
- **Cookie flags:** `ldso` missing HttpOnly/Secure is explicitly eligible.
- **New-action PCE sweep:** for every action in the "Recently added actions" table in
  `recon/app-features.md` (2025-09 → 2026-09): hit its endpoint with a role lacking the action
  (stale preset roles + minimal custom roles). Also: custom-role **wildcard action injection**
  (`*`, `update*` globs in `POST /custom-roles`), `bypassRequiredSegmentApproval` flow,
  `revokeSessions` date edge, `viewSdkKey` gating on SDK Keys Beta list/get (key material in
  response?), `updateAccessTokenExpiry` on other members' tokens.

## Phase 3 — XSS / SSRF in user input (focus area)

XSS: stored content is rendered in React (escapes by default) — hunt for **unescaped sinks**:
- Flag descriptions/names (especially **code references** rendering, `_site` links), tag labels,
  team/role names, announcement bodies (rendered in-app banner!), **audit log comments**
  (comments appear in webhooks + audit log — rendered?), experiment/metric names, context
  **attribute names & values** (new focus area: rendered in context UI, targeting UI,
  **client-side SDK payloads** — if a context attribute value lands in an SDK payload and a
  customer app renders it, that's the customer's app issue, not ours — but the *admin UI*
  rendering is ours), error messages reflecting input (server-side), **search result rendering**
  (server-side context/user search POSTs), CSV/JSON export preview pages, release notes,
  approval comments.
- Docs-site search (P0-4) is the only docs-site user input; app.search fields (flags, contexts,
  users, audit) are React but check raw fetch of the underlying search API for reflected HTML
  (some endpoints return HTML for emails — emails excluded, but API HTML is not).

SSRF (must include proof of reach + metadata — use a **request-capturing endpoint** like
`httpbin`/interactsh-style service you control, and capture response metadata):
- **Webhooks**: create with `url` = your captor; fire trigger; capture response headers/body the
  webhook delivery included. Also: internal URL schemes (`file://`, `gopher://`), redirect from
  your captor to internal host, URL with credentials, IPv6/mapped IPv4, DNS-rebinding.
- **Flag import configurations** (Beta): external source URL + `trigger import run` — server
  fetches your URL (SSRF + possible file read via returned flags).
- **Data export destinations**: warehouse/S3/BigQuery/Snowflake configs + "complete setup" /
  "generate setup script" — server-side connectivity checks?
- **Integration configurations / delivery configurations**: `validate delivery configuration`
  endpoint likely makes server-side calls.
- **Persistent store integrations** (big segment store): store URLs.
- **Code references repositories**: repo URL field.
- **Relay proxy configs**: proxy endpoint?
- **IP allowlist** entries with non-IP strings (parsing edge).
- Webhook event payloads: does delivery include **other tenants' data** on misconfigured webhook?
  (single-tenant webhooks, so cross-tenant unlikely — verify scope.)

## Phase 4 — Streamer & Events (focus: improper flag-data retrieval, event mechanism abuse)

Setup: SDK key + mobile key + client-side ID from your org (UI → environment → SDK keys).
Plus the two-environment (secure-mode on/off) setup from Phase 4a.

Streamer (`stream.launchdarkly.com`, in scope; client routes on `clientstream.*` are out of scope
but the same Go service likely handles them — test what's reachable on the in-scope host):
- **Client-side payload integrity**: fetch with client-side ID + context:
  - Are targeting rules / user-targets **absent** (documented)? Any `withReasons=true` leaking
    rule names / clause details client-side? (client shouldn't get reasons detail that reveals rules)
  - `filter=<viewKey>` from another environment/project — accepted? (views = filtered payloads, new)
  - `h=` secure-mode hash: send valid hash for your context key with **mutated context attributes**
    (body/path mismatch) — does server use path context or body? Which wins?
  - Context edge cases: multi-kind context in path; unicode; 8KB+ context (truncation → does a
    truncated base64 decode to a *different* context that maps to a victim?); base64 with
    ambiguous padding; `+`/`/` variants (non-urlsafe) in path.
  - **Key/ID confusion**: mobile key on `/all`? client-side ID on `/all`? server key on `/msdk*`?
    Cross-type auth should 401/403 — look for one type accepted on another's routes with reduced
    data filtering.
  - **ETag/reconnect**: stale `last-etag` from another env (if etags are globally unique?),
    `Retry:` handling, huge `since` values.
  - **`/all` response for a key whose env was deleted/archived** — stale payload cache?
  - Rate/abuse: none (SDKs exempt) — keep volume tiny anyway.
- **Bulk eval** (`/bulk_eval/contexts`, `/msdk/bulk` — if reachable on in-scope host): batch
  context eval — cross-env contexts in one batch?

Events (`events.launchdarkly.com`):
- **Cross-env/cross-account event injection**: send identify/feature/custom events with
  (a) your key but **another context** (fine), (b) `key` field in event body differing from
  Authorization key — which wins? (c) events referencing **another environment's flag key +
  your key**? Can you record metric events against flags you don't own? (experimentation
  tampering — chain with focus area)
- **Experimentation logic**: create an experiment (focus area), feed crafted events:
  - duplicate identify for same context (dedup?),
  - events with negative metric values / huge values / wrong types,
  - events for iterations that don't match the flag's targeting (does analysis accept?),
  - cross-flag experiment events (iteration of flag A on flag B's flag key),
  - timestamp manipulation (future/past) — sample-size & result integrity.
- **Data exfil via events?** Events are sink-only (no response data) — confirm.
- **Event size/field overflow**: oversized event bodies, deeply nested JSON (server recursion),
  unicode in all fields, array where object expected.
- **Diagnostic events**: what's sent for SDK key type errors (diagnostic event with key value?).
- `events.launchdarkly.us`/EU: out of scope — skip active.

## Phase 4a — Client-side oracle, secure mode, private attrs, views (H5–H7) ⭐

Setup additions: create **two** environments in your org — `env-plain` (secure mode OFF) and
`env-secure` (secure mode ON). Grab client-side IDs + (optionally) mobile keys for each.
Details & documented baseline: `recon/sdk-docs.md`.

**H5 — Client-side context evaluation oracle / secure mode bypasses (P1/P2 candidate if bypassed)**
Documented: without secure mode, a public client-side ID can evaluate any context (disclosed,
mitigate-by-config). With secure mode, unsigned-context evals must be rejected.
1. `env-plain`: `GET https://app.launchdarkly.com/sdk/evalx/{clientId}/contexts/{b64url(context)}?withReasons=true`
   with guessed/arbitrary context keys (in-scope host! polling fallback). Record: values returned,
   reason kinds (`TARGET_MATCH`? `RULE_MATCH`+ruleId? `PREREQUISITE_FAILED`+prerequisiteKey?).
   **The reasons are the reportable surface**, not the raw oracle.
2. Same via streaming: `GET /eval/{clientId}/{b64url(context)}` on `clientstream.launchdarkly.com`
   (out of scope — for comparison only) vs. whether the same client routes exist on
   `stream.launchdarkly.com` (in scope) — error diffs.
3. `env-secure`: no `h` → error? wrong `h` → error? `h` for context A, path context B → reject?
4. **canonicalKey collisions** (hash is over canonicalKey only): multi-kind contexts, kind case
   variants, unicode casefold, anonymous kind, extra attributes with same key, **permuted
   multi-context kind order** — does one signed hash authorize a *different* context's
   evaluation (attribute-level oracle)?
5. **Route coverage of `h` enforcement**: poll, stream, ping, REPORT, bulk — all reject without it?
6. **Credential mixing in secure-mode env**: client-side ID on `/msdk*`, mobile key on `/eval*`,
   server SDK key in `Authorization` + `h` absent — expected rejections; anything 2xx = finding.
7. `withReasons=true` with valid `h` — do reasons still expose ruleIds/prerequisiteKeys?
   (Secure mode documents variation privacy; reasons = targeting structure.)

**H6 — Private attribute leakage (privacy, P2/P3)**
Mark attrs private (client SDK `privateAttributes`, incl. `/path/ptr` variants). Client SDK sends
them for eval; server must not store/echo them. Check every surface:
- `/evalx` + `withReasons` response, stream payload,
- events accepted at `events.launchdarkly.com` (no echo expected, but check response + what's
  stored: view via Contexts UI/API),
- **REST API**: `GET context attribute names` / `attribute values`, `search-contexts`,
  `search-context-instances`, `get-context-instances`, `evaluate-context-instance`, context detail
  page's backing API — values under `_meta` in JSON?
- audit log entries (context create/update bodies, comments),
- legacy users endpoints (user flag settings / user search),
- Live events / Data Export payloads if enabled.
Fuzz privacy stripping: pointer `..`, `*`, ``, duplicate/conflicting paths, built-in attrs
(`email`, `name`, `anonymizeKey`) marked private (docs say key/kind can't be private — test).

**H7 — Views / filtered SDK payloads (beta; cross-key filter) (P2/P3)**
- Create 2 SDK keys in env: key-F (filtered by view V), key-P (plain). Create view V with 1 flag.
- key-F + `filter=<V>` → only V's resources (baseline).
- key-P + `filter=<V>` → does an unfiltered key honor the param (over-filtering = bug, low) or
  ignore it (expected)? key-F + `filter=<otherView>` → cross-view read (P3).
- key-F's `filter` pointing at a view in **another project** (create 2 projects) → cross-project?
- Views Beta API authz: `get-linked-resources`, `link-resource` with member role / project-scope
  token — linking arbitrary resources (flags in other projects) via views?

## Phase 4b — Event-driven tampering (H8–H9) ⭐ (focus: experimentation)

Setup: experiment on a flag in `env-plain` (frequentist + Bayesian), guarded rollout if available,
a flag with detailed tracking enabled.

**H8 — Context creation/attribute tampering via `index`/`identify` events (P2/P3)**
- `identify` with a NEW context key → creates context instance (documented). Fine.
- `identify` with an EXISTING context key + **different attributes** → attributes overwritten?
  (re-identify flow) If yes: targeted users' attributes can be mutated via events → targeting
  changes for them (business logic + privacy). Check who's allowed (any client-side ID of the env?
  mobile? server key of ANOTHER env in same project?).
- `index` vs `identify` differences (kind, merge semantics, multi-kind).
- Private attrs in identify payload (pair with H6).
- Attribute volume/depth: 100KB attribute values, 1000 attrs, nested depth 50 — robustness
  (note errors; no volume attacks).
- Anonymous contexts: force anon via events? usage-counting manipulation (low).

**H9 — Experimentation / guarded-rollout tampering via `feature`/`custom` events (P2 candidate)**
- `feature` events for the experiment flag with: wrong `variation` index, `inExperiment` true on a
  flag not in the experiment, iteration key of flag B on flag A, negative/`Number.MAX_VALUE`
  metric values, wrong types, far-future/past `creationDate`, duplicate events (dedup key
  behavior), custom event `data` with injection chars (reflected in analysis UI?).
- Guarded rollouts: they "use [feature] events to monitor variation performance, detect
  regressions" — craft regression-free events for a broken variation (bypass auto-block?) or
  fake regressions for a good one (availability for the tenant — report as logic bug, don't
  trigger destructive actions on other tenants' data — use own flags only).
- Sample-size / experiment completion: can you make an experiment "complete" early / stall
  forever via event volume? (own experiments only)
- Holdouts: prerequisite-flag events required for holdouts — craft events to break holdout
  assignment for your contexts (logic).
- **Guarded rollouts (trial available on all accounts)** — mechanics in `recon/app-features.md`:
  (a) min-context gate: N feature events from ONE context vs N distinct contexts — which advances
  the rollout? (b) one extreme metric value triggering auto-rollback (trivially gameable
  safety control), (c) offsetting values masking a real regression, (d) future-dated events
  skipping step windows, (e) exclusivity rule (guarded rollout + experiment on same flag)
  enforcement.
- Traffic-assignment verification (server-side checks vs event claims): does the analysis
  pipeline re-derive a context's variation from seed+key+bucket, or trust the `variation`/
  `inExperiment` fields on incoming events? If trusted → H9's cross-variation events are the
  finding (results integrity).

## Phase 5 — Business logic (contexts ⭐ & experimentation ⭐)

Contexts (new user model, "1:1 replacement users → contexts" — replacement bugs are gold):
- Legacy **user** endpoints vs new **context** endpoints: same data, different authz? (user
  flag settings vs context flag settings)
- Context kind lifecycle: create kind → use in flag/segment/experiment → **archive** kind →
  what happens to existing flags/segments/evals? Restore races? Delete instances in use?
- **Anonymous contexts**: usage counting, key rules (anonymous key `anonymous`), can you force
  anonymous contexts to be counted/targeted as regular?
- **Bulk targeting** export/import: export = data egress (CSV excluded unless LD-specific —
  but *access control* on export is in scope); import: does it replace or merge? race with
  concurrent edit?
- **Auto context-kind creation via SDK eval** (evalx/identify with novel kind): tenant project
  mutation by a client-side ID — kind-name edge cases (case, unicode, reserved, `multi`,
  empty, `/`, 512 chars), count limits.
- **Multi-context canonicalKey** (feeds H5-4): permute kind order in `{kind:"multi",…}`, add
  redundant kinds — same canonicalKey with different attribute surface?
- **Context instance versions** (per-source-app/SDK records): same context identified via
  server key + client ID → two versions; private-attr state leaking across versions (H6).
- Kind archive/restore with live flags/segments/experiments referencing it (dangling refs, eval
  behavior, restore race with concurrent eval).
- **Context settings** (per-context overrides): override for context you don't own? expiry
  handling (expiring targets endpoints) — override past-dated expiries?
- **Evaluate-context-instance** API: server-side eval returns values for any context you pass —
  including contexts with attributes you could craft to match another tenant's targeting?
  (Your env's flags only, but: cross-project within same account for low-priv roles.)

Experimentation (2022 refresh):
- Audience allocation: overlap between experiments/holdouts — can a context be in two
  experiments' audiences (double counting)?
- **get-experiments-any-env** (see Phase 2) + metric group access by key (cross-project?).
- Bayesian vs frequentist result computation inputs: can events shift results beyond what
  targeting implies (e.g. record success events for the *other* variation)?
- Sample size calculator (new in-app, 2026-09-01): client or server? If server-side, fuzz inputs.
- Iteration creation while experiment running (mid-flight changes, baseline shifts).
- Traffic-assignment logic per docs (`recon/app-features.md`): "Edit design" vs Stop+restart
  reshuffle paths via API (patch-experiment vs create-iteration) — behavior matches docs?
  allocation increase when untracked buckets insufficient (reshuffle off → error or silent
  misallocation?), layer snapshot integrity after layer mutation, holdout/experiment
  randomization-unit mismatch handling.
- Seed exposure check: iteration seed absent from client payloads (client can't compute
  assignments locally without it — pair with H5).

## Phase 6 — Odds & ends

- **OAuth2 clients** (Phase 2) — if a restricted role can create one, that's credential minting.
- **Webhook secrets**: rotation, timing, included in list/get responses?
- **Search endpoints** (server-side, POST): query injection into the search engine (Elasticsearch
  tag on app) — stored XSS via search term reflected in audit/UI; also **search-based data
  leakage** across projects (search index scoping!). ← high value, app has Elasticsearch tag.
- **Audit log search**: same.
- **Announcements**: unauth read (H4); stored XSS in announcement body (rendered in-app banner for
  all orgs? or per-org?).
- **Email flows** (mostly excluded): HTML injection in emails excluded; but **email links**
  (verify/reset) — token entropy, URL leakage in logs. Password-reset-link email-change non-expiry
  is excluded (listed).
- **`demo.app.launchdarkly.com`**: study feature behavior safely (in-scope subdomain of app host)
  — e.g. watch how context kind archive behaves live without risking your org data.
- **JS bundles** on app.launchdarkly.com: pull the main bundle, grep for internal API paths,
  feature flags, endpoint names not in the OpenAPI spec (undocumented endpoints = access-control
  goldmine). ← concrete next step once egress works.
- **ldso cookie**: flags (eligible), path, rotation on role change, logout invalidation.

## Sequencing (recommended)

1. P0 batch (half a day, from your browser — all read-only).
2. Account setup + org inventory (1h).
3. Phase 2 IDOR matrix with 2 roles (the classic LD findings; 31 known issues suggests triage
   is tight on basics — differentiate with: version-pinning, semantic-patch, search scoping,
   contexts/eval endpoints).
4. Phase 3 SSRF (webhooks + flag import) — program explicitly asks for SSRF with proof.
5. Phase 4a client-side oracle + secure mode (H5) — the program's explicit "flag info meant for
   other users" ask — then 4b event tampering (H8/H9), then the rest of Phase 4 (streamer/events).
6. Phase 5 business logic (focus areas = triage goodwill).
7. Picking through Phase 6 while waiting on triage.

## Report hygiene (per program)

- One vuln per report; same vuln across endpoints = one report (list endpoints).
- Include: **role used**, impact, **reliable** repro (token scopes, exact headers incl.
  `LD-API-Version` when relevant), PoC video/captures, evidence files.
- SSRF: captor metadata (request headers, IP seen, response snippet) **required**.
- Stop testing on any path to data destruction/modification of others' data; report as-is.
