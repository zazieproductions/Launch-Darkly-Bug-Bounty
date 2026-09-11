# REST API Endpoint Inventory

Source: official docs index `https://launchdarkly.com/docs/api/llms.txt` (fetched 2026-09-11) +
OpenAPI overview. Raw OpenAPI spec: `https://app.launchdarkly.com/api/v2/openapi.json`
(public; any string accepted in `Authorization` per docs "Play" note) and
`https://launchdarkly.com/docs/api/openapi.json` / `.yaml`.

Base URL: `https://app.launchdarkly.com` (federal: `https://app.launchdarkly.us` — out of scope).

## API mechanics relevant to testing

- **Auth:** access token (`Authorization: <token>`) or `ldso` session cookie.
  - Session-cookie auth **requires `Origin: https://app.launchdarkly.com`** (mismatch → error).
  - Token auth does **not** require origin matching.
- **CORS:** API echoes any `Origin` as allowed (`Access-Control-Allow-Origin: <origin>` or `*`).
  → Combined with session-cookie auth this is only safe *because of* the Origin check. **Test the
  Origin check hard** (see test-plan H1).
- **Method override:** `X-HTTP-Method-Override: DELETE|PATCH|PUT` lets POST tunnel mutating verbs.
  → Check override on unauth'd routes, on routes with different authz, and with cookie auth from
  non-`app.launchdarkly.com` origins (see H2).
- **API versioning:** per-token default version + `LD-API-Version: <yyyymmdd>` header per request.
  Known versions: `20240415` (current), `20220603` (EOL 2025-04-15), `20210729`, `20191212`,
  `20160426`. → Version-pin/differential testing (see H3).
- **Beta resources:** require `LD-API-Version: beta` header else `403`.
- **Patches:** JSON patch, JSON merge patch, and **semantic patch**
  (`Content-Type: application/json; domain-model=launchdarkly.semanticpatch`,
  body `{comment?, environmentKey?, instructions:[{kind, ...}]}`). Semantic patches are atomic.
- **Pagination:** `limit`/`offset` (current version); `_links` first/last/next/prev.
- **Errors:** JSON `{code, message, id}`; statuses 400/401/403/404/405/409/422/429.
- **Rate limits:** global (per account /10s), route-level (/10s), per-token (/10s), IP-based
  (`Retry-After`). Headers: `X-Ratelimit-*`. SDK endpoints are NOT rate limited.
- **`expand=` query param** on many GETs (e.g. `expand=members,maintainers`).

## Public (no meaningful auth) endpoints

| Endpoint | Notes |
|---|---|
| `GET /api/v2/openapi.json` | Full spec; any Authorization string accepted |
| `GET /api/v2/ips` | Public IP list |
| `GET /api/v2/caller-identity` | Identify caller; **contains `bountyEligible`** for LD-controlled accounts |
| `GET /api/v2` (root resource) | API root |
| `GET/POST/PATCH/DELETE /api/v2/announcements` ("…-public" endpoints) | **Verify whether truly unauthenticated** (see H4) |

## Full endpoint inventory (group → endpoints)

Format: `Method /path` — doc page. Paths reconstructed from doc slugs; verify exact paths in the
OpenAPI spec before scripting.

### Access Tokens (`/api/v2/tokens`)
- POST /token, DELETE /token/{token}, GET /token/{token}, GET /tokens (paginated, default 25),
  PATCH /token/{token}, POST /token/{token}/reset (legacy)

### Account Members
- POST /members/{memberId}/teams (add to teams), DELETE /members/{memberId},
  GET /members/{memberId}, POST /members (invite), GET /members (list),
  PATCH /members (bulk modify), PATCH /members/{memberId}

### Account Usage Beta
- GET usage: ai-runs, contexts-clientside, contexts-serverside, contexts-total, data-export-events,
  evaluations, events, experimentation-events, experimentation-keys, mau-clientside, mau-sdks-by-type,
  mau-total, mau-by-category, observability-{errors,logs,metrics,sessions,traces},
  sdk-versions-details, sdk-all-versions, service-connections, stream, stream-by-sdk-version,
  stream-sdk-versions, vega-ai, warehouse-export

### Adaptive Triggers
- POST/DELETE/GET/PATCH adaptive-trigger; POST disable/enable; GET list

### Agent Control (new, large surface)
- AI configs: POST/DELETE/GET/PATCH ai-config; get/patch targeting; get metrics (+by variation);
  get quick stats; create/delete/get/patch AI Config variation
- Agent graphs: POST/DELETE/GET/PATCH agent-graph
- Prompt snippets: POST/DELETE/GET/PATCH prompt-snippet; list references/versions
- Agent skills: POST/DELETE/GET/PATCH agent-skill; list references/versions
- Agent optimization: POST/DELETE/GET/PATCH; create optimization result; list runs;
  list results (by run / all versions / latest per run); delete run
- AI model configs: POST/DELETE/GET/PATCH model-config; list versions
- AI tools: POST/DELETE/GET/PATCH ai-tool; list references/versions
- Restricted models: POST /restricted-models (add), DELETE /restricted-models (remove)

### Announcements
- POST /announcements (create-public), DELETE (delete-public), GET (get-public), PATCH (update-public)

### Applications Beta
- DELETE/GET/GET-versions/PATCH application & application-version

### Approvals
- POST approval-request (create / apply / apply-for-flag / for-flag / flag-copy-config),
  DELETE (± for-flag), GET (± for-flag), GET list (± for-flag), POST review (± for-flag)

### Approvals Beta
- GET/PUT approval-request-settings; PATCH approval-request / flag-config-approval-request

### Audit Log
- GET entry; POST entry-counts; GET entries (list); POST search entries

### Code References
- POST/DELETE extinction; POST/DELETE repository; DELETE branches; GET branch / statistics /
  root-statistic / repository; GET branches / extinctions / repositories (list);
  PATCH repository; PUT branch (upsert)

### Contexts ⭐ focus area
- PUT /context-kinds (create or update context kind)
- DELETE context instances
- POST/GET **evaluate flags for context instance** ← interesting: server-side eval API
- GET context attribute names
- GET context attribute values ← potential data-disclosure surface
- GET context instances
- GET context kinds by project key
- GET contexts
- POST search context instances; POST search contexts

### Context Settings
- PUT flag setting for context (per-context overrides)

### Custom Roles
- POST/DELETE/GET/PATCH custom-role; GET list

### Data Export Destinations
- POST complete-warehouse-destination-setup, POST/DELETE/GET/PATCH destination,
  POST generate-snowflake-destination-key-pair, POST generate-trust-policy,
  POST generate-warehouse-destination-setup-script, GET destinations

### Environments
- POST/DELETE/GET environment; GET environments-by-project;
  POST reset-environment-mobile-key; POST reset-environment-sdk-key; PATCH environment

### Experiments ⭐ focus area
- POST experiment; POST iteration; GET experiment; GET experimentation-settings;
  GET experiments; **GET experiments-any-env** (name suggests cross-env access — check authz!);
  PATCH experiment; PUT experimentation-settings

### Feature Flags
- POST copy-feature-flag; POST feature-flag (create); DELETE;
  GET expiring-context-targets; GET expiring-user-targets; GET feature-flag;
  GET feature-flag-status; GET **feature-flag-status-across-environments**;
  GET feature-flag-statuses; POST migration-safety-issues; GET feature-flags (list);
  PATCH expiring-targets; PATCH expiring-user-targets; PATCH feature-flag

### Feature Flags Beta
- GET dependent-flags; GET dependent-flags-by-env

### Flag Import Configurations Beta (external source URLs → SSRF candidate)
- POST/DELETE/GET/PATCH flag-import-configuration; POST **trigger flag import run** (server fetches external source)

### Flag Links Beta
- POST/DELETE/GET/PATCH flag-link

### Flag Triggers
- POST/DELETE/GET/PATCH trigger-workflow; GET trigger-workflow-by-id; GET trigger-workflows (list)

### Follow Flags
- PUT flag-follower; GET flag-followers; GET followers-by-proj-env; DELETE flag-follower

### Holdouts
- POST/DELETE/PATCH holdout; GET all/holdout/holdout-by-id

### Insights (all Beta)
- Charts: GET deployment-frequency / flag-status / lead-time / release-frequency / stale-flags chart data
- Deployments: POST/GET/GET-list/PATCH deployment event
- Flag events: GET flag-events
- Pull requests: GET pull-requests
- Repositories: POST associate-repositories-and-projects; GET repositories; DELETE repository-project
- Scores: POST/DELETE/GET/PATCH insight-group; GET insight-scores; GET insight-groups

### Integration Audit Log Subscriptions
- POST/DELETE/GET/PATCH subscription; GET subscription-by-id; GET subscriptions (by integration)

### Integration Delivery Configurations Beta
- POST/DELETE/GET/PATCH delivery-configuration; GET by-id; GET by-environment; GET list;
  POST **validate delivery configuration**

### Integrations Beta
- POST/DELETE/GET/PATCH integration-configuration; GET all-configurations

### IP Allowlist Beta
- POST/DELETE/GET/PATCH ip-allowlist entry; GET ip-allowlist; PATCH ip-allowlist-config

### Layers
- POST/GET/PATCH layer; GET layers

### Metrics
- POST/DELETE/GET/PATCH metric; GET metrics (list)

### Metrics Beta
- POST/DELETE/GET/PATCH metric-group; GET metric-groups

### OAuth2 Clients
- POST/DELETE/GET/PATCH o-auth-2-client; GET client-by-id; GET o-auth-clients

### Persistent Store Integrations Beta (big segment store)
- POST/DELETE/GET/PATCH big-segment-store-integration; GET by-id; GET list

### Projects
- PUT flag-defaults-by-project; POST/DELETE/GET/PATCH project; GET flag-defaults-by-project;
  GET projects (list); PATCH flag-defaults-by-project

### Relay Proxy Configurations
- POST/DELETE/GET/PATCH relay-auto-config; GET relay-proxy-configs (list);
  POST reset-relay-auto-config  ← **config holds environment keys; check what gets returned**

### Release Pipelines Beta
- POST/DELETE/GET/PATCH-put release-pipeline; GET by-key; GET release-progressions

### Release Policies Beta
- POST/DELETE/GET/PATCH-put release-policy; GET by-key; GET list; POST release-policies-order

### Releases Beta
- POST/DELETE/GET/PATCH release-by-flag-key; POST update-phase-status

### Scheduled Changes
- POST/DELETE/GET/PATCH flag-config-scheduled-change(s)

### SDK Keys Beta
- POST/DELETE/GET/PATCH sdk-key; GET sdk-keys (env); GET project-sdk-keys; PUT sdk-key-views

### Segments
- POST big-segment-export / big-segment-import; POST/DELETE/GET/PATCH segment;
  GET big-segment-export/import; GET **segment-membership-for-context**;
  GET **segment-membership-for-user**; GET expiring-targets-for-segment;
  GET expiring-user-targets-for-segment; GET segments (list);
  PATCH expiring-targets-for-segment; PATCH expiring-user-targets-for-segment;
  PATCH update-big-segment-context-targets; PATCH update-big-segment-targets

### Tags
- GET tags (list)

### Teams
- POST/DELETE/GET/PATCH team; POST team-members (bulk add); GET team-roles;
  GET team-maintainers; GET teams (list)

### Teams Beta
- PATCH teams (bulk)

### Users
- GET search-users; GET user; GET users (list)

### User Settings (legacy user model)
- GET expiring-flags-for-user; GET user-flag-setting; GET user-flag-settings;
  PATCH expiring-flags-for-user; PUT flag-setting

### Views Beta
- POST/DELETE/GET/PATCH view; GET linked-resources; GET linked-views; GET views (list);
  POST link-resource; DELETE unlink-resource

### Webhooks
- POST/DELETE/GET/PATCH webhook; GET all-webhooks  ← **SSRF candidate (URL field)**

### Workflows
- POST/DELETE/GET/PATCH workflow; GET custom-workflow; GET workflows (list)

### Workflow Templates
- POST/DELETE/GET/PATCH workflow-template

### Other
- GET /versions; GET /openapi.json; GET /ips; GET /caller-identity; GET / (root)

## Testing angles derived from this inventory

1. **Authz matrix** per group: member vs admin vs project-scope vs token-scope.
   Especially: Approvals, Custom Roles, Environments (reset SDK keys!), OAuth2 Clients,
   Relay Proxy Configs, Experiments any-env, Contexts eval + attribute values, Audit Log,
   Data Export (trust policies, key pairs), SDK Keys Beta.
2. **IDOR by key swap:** flags/segments/contexts/teams use human keys — swap keys across
   projects/environments you don't own.
3. **`expand=` abuse:** request expansions not documented for your role.
4. **Version pinning:** same call under `20160426`…`20240415` + `beta`.
5. **Semantic patch instruction injection:** unexpected `kind` values / extra params.
6. **SSRF:** webhooks, flag-import configurations (external fetch on trigger), data export
   destinations, integration configurations.
