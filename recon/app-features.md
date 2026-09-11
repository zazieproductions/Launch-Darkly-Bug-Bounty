# Product Feature Notes — focus-area internals (for logic/authz testing)

Source: official product docs (`launchdarkly.com/docs/home`), fetched 2026-09-11.

## Guarded rollouts (`home/releases/guarded-rollouts`) — NEW, event-driven, auto-acting

- Enterprise + Guardian add-on; **all accounts get a limited trial** (our bounty account can use it).
- Attached to a new flag/AgentControl-config variation; progressively ramps traffic while
  monitoring metrics; regression = statistically significant negative impact (sequential
  testing, **absolute difference** — legacy relative difference removed).
- On regression: notify + **automatic rollback** (if enabled).
- **Minimum context requirement:** each rollout step requires the new variation to be evaluated
  by a *minimum number of contexts*; if not met, LD **automatically rolls back** the change.
- One guarded rollout per flag at a time (excludes other guarded rollouts, progressive rollouts,
  experiments on that flag; not on migration flags).
- Metrics sources: integrations, **metric import API**, SDK custom events, OTel autogen metrics.

**Attack surface (H9 refinement):**
1. **Unique-context counting**: does the min-context gate count *distinct context keys* or
   event count? Send N feature events for ONE context → if it advances the rollout, the gate is
   bypassable (logic; also means you can force progression of a rollout with no real users).
2. **Force regression → auto-rollback**: feed fake negative metric values (custom events) to
   trigger auto-rollback of a rollout in your own org (demo the control; report as logic bug if
   trivially gameable, or if rollback triggers on *any* event pattern — e.g. one extreme value).
3. **Suppress regression**: feed offsetting positive values to mask a real regression (integrity).
4. Step timing: advance/rollback decisions per step window — event timestamps (future-dated) to
   skip/extend steps.
5. Interaction exclusivity: guarded rollout + experiment on same flag — enforcement of the
   exclusivity rule (create both → which wins / error handling).
6. `updateAutomatedRolloutConfig` (project action, Aug 2026) — authz: can a project member
   without it modify rollout config via API?

## Experiment traffic assignment (`home/experimentation/traffic-assignment`) — NEW doc (2026-09-09)

- Iteration **seed** (generated at iteration start) + context key → hash → **100,000 buckets**.
  Deterministic; **no stored assignment** — recalculated every evaluation.
- Randomization unit = context kind (`user`, `organization`, …) — uses that kind's key.
- Tracked buckets = experiment variations (analyzed); untracked = control (excluded from results).
- Traffic increase: takes untracked buckets first (existing contexts keep variations); if not
  enough untracked buckets: **reshuffle = new seed** (if allowed) else cannot satisfy allocation.
- Traffic decrease: tracked → untracked (those contexts get control, leave results).
  Increase again after decrease may re-assign differently even without reshuffling.
- Stopping an experiment **always reshuffles** on next iteration; "Edit design" avoids it.
- **Layers**: shared seed; mutually exclusive experiments via disjoint bucket sets; small
  scattered blocks per variation; stopping an iteration stores a **layer snapshot**.
- **Holdouts**: change *eligibility*, not split; randomization unit must match all contained
  experiments.
- "Your SDKs perform the assignment calculation locally **or receive the result from
  LaunchDarkly**" (client-side evalx).

**Attack surface (Phase 5 refinement):**
- Seed exposure: is the seed in the flag payload (server key holders can precompute buckets —
  by design); client-side payloads must NOT contain seeds (client can't compute without seed —
  verify seeds/rule details absent from client payloads; pair with H5).
- Reshuffle edge cases: allocation changes at iteration boundaries; "Edit design" vs Stop paths
  (API: patch-experiment vs create-iteration) — do both behave per docs (logic)?
- Layer snapshot integrity: stop iteration, mutate layer, view old results — snapshot honored?
- Holdout/experiment randomization-unit mismatch handling (API validation vs eval-time).
- Cross-variation event mapping: events must map to the bucket's variation (H9 event tampering —
  does the analysis server verify variation vs assignment, or trust the event's claim?).

## SDK credentials (`home/account/environment/keys`)

- **SDK keys**: prefix `sdk-`, secret, server/AI SDKs, rotatable (create new + delete old).
- **Mobile keys**: prefix `mob-`, not secret, client/mobile SDKs, rotatable.
- **Client-side IDs**: alphanumeric, no dashes, not secret, **cannot be created/rotated** (one
  per env).
- **Multiple SDK keys + multiple mobile keys per environment** (all plans) → key-per-app
  isolation; **view-scoped keys** (H7) cannot be used by Relay Proxy (rejected; needs unscoped).
- Key **expiry** can be set at any time; env must always retain ≥1 active SDK key + mobile key.
- Default key per env (auto-generated); filtered (view) keys can't be default.
- REST API: SDK Keys Beta (post/patch/delete/get by key, get all env, get all project,
  put-sdk-key-views).

**Attack surface:**
- Authz on SDK Keys Beta endpoints (pair with `viewSdkKey`/`updateSdkKey`/`createSdkKey`/
  `deleteSdkKey` actions, Apr 2026): does **list/get** return the actual key material, and to
  which roles? A role with project-scoped read on flags but no `viewSdkKey` fetching env SDK
  keys = secret disclosure (P1/P2).
- Expiry manipulation: `updateAccessTokenExpiry`-style actions on SDK keys? Expired key edge
  (eval returns fallbacks — availability).
- Key reuse protection: "You cannot reuse these, even if the old key is deleted" — enforce
  client-side ID / key string reuse across envs (confusion: same key value in two envs?).
- Multiple keys: per-key payload filtering independent (H7); key A's views must not apply to B.

## Role actions (`home/account/roles/role-actions`) — full reference, 11 pages

Actions are scoped to resource types (`proj/*:env/*:flag/*`, `member/*:token/*`, `acct`, …);
advanced editor allows **glob/wildcard actions** (`update*`).

**"Recently added actions" table (the authz-gap hunting list):**

| Date | Resource | New actions |
|---|---|---|
| 2026-09 | `proj/*:trace/*` | `updateTraceAnnotation` |
| 2026-08 | `acct` | `updateAccountTokenLimit` (daily AI-eval token limit) |
| 2026-08 | `ip-allowlist` | `createIpAllowlistEntry`, `deleteIpAllowlistEntry`, `updateIpAllowlistEnabled`, `updateIpAllowlistEntry`, `viewIpAllowlist` |
| 2026-08 | `member/*:token/*`, `service-token/*` | `updateAccessTokenExpiry` |
| 2026-08 | `proj/*` | `updateAutomatedRolloutConfig`, `updateViewAssociationRequirements` |
| 2026-08 | `proj/*:env/*:flag/*` | `updateVariationJsonSchema` |
| 2026-08 | `proj/*:metric/*` | `updateMetricDenominator`, `updateWindowOffset` |
| 2026-08 | `proj/*:env/*:sdk-key/*` | `updateSdkKeyPayload` |
| 2026-08 | `proj/*:agent-optimization/*` | `createAgentOptimization`, `createAgentOptimizationRun`, `deleteAgentOptimization`, `updateAgentOptimization`, `updateAgentOptimizationRun` |
| 2026-07 | `proj/*:env/*:aiconfig/*` | `createTriggers`, `deleteTriggers`, `updateTriggers` |
| 2026-07 | `proj/*:alert/*` | `createJiraIssue` (Jira = 3rd-party integration → target the gate, not Jira) |
| 2026-07 | `proj/*:env/*:segment/*` | `bypassRequiredSegmentApproval` |
| 2026-07 | `proj/*:ai-model-config/*` | `updateAIModelConfig` |
| 2026-07 | `proj/*` | `updateTeamMaintainerRequirements` |
| 2026-06 | `proj/*:metric/*` | `updateMetricWinsorization` |
| 2026-05 | `proj/*:view/*` | `linkAIConfigToView`, `unlinkAIConfigFromView` |
| 2026-05 | `proj/*:metric/*` | `updateTraceQuery`, `updateTraceValueLocation` |
| 2026-04 | `proj/*:env/*:sdk-key/*` | `createSdkKey`, `deleteSdkKey`, `updateSdkKey`, `viewSdkKey` |
| 2026-04 | `proj/*:observability-settings/*` | 5 observability actions |
| 2026-04 | `proj/*:ai-dataset/*`, `proj/*:ai-evaluation/*` | 6 AI dataset/eval actions |
| 2026-02 | `acct` | `disableIdPManagingTeams`, `enableIdPManagingTeams` (SCIM team sync) |
| 2026-02 | `proj/*:agent-graph/*` | `createAgentGraph`, `updateAgentGraph`, `deleteAgentGraph` |
| 2026-02 | `proj/*:env/*:notification-subscription/*` | `createNotificationSubscription`, `deleteNotificationSubscription` |
| 2026-01 | `proj/*:metric/*` | `updateAnalysisType` |
| 2025-12 | `proj/*` | `updateObservabilitySettings`, `updateLifecycleSettings` |
| 2025-12 | traces/logs/errors/sessions/alerts/dashboards/metric-data-sources | ~18 observability actions (`viewTrace`, `viewLog`, `updateErrorStatus`, `viewSession`, alert CRUD, dashboard CRUD, `createMetricDataSource`…) |
| 2025-10 | `proj/*:view/*` | `linkSegmentToView`, `unlinkSegmentFromView` |
| 2025-10 | `proj/*:metric/*` | `updateArchived` |
| 2025-09 | `proj/*:release-policy/*` | release policy CRUD + rank |

Account actions also include: `createAnnouncement`/`updateAnnouncement`/`deleteAnnouncement`
(ties to H4 public announcements API), `createOAuthClient`, `createSamlConfig`, `createScimConfig`,
`revokeSessions` ("revoke sessions issued before a specified date"), `updateAccountToken`
(legacy reset), `deleteSubscription` (plan cancel!), `updateBillingContact`.

**PCE strategy (Phase 2 add-on):**
1. Create custom roles: (a) read-only project member, (b) each "new action" granted minimally,
   (c) preset Member/Release Manager/etc. un-updated ("you can choose when to update your preset
   roles" — **stale preset roles may lack checks for new endpoints**; conversely, preset roles
   updated to latest may now include actions members didn't consciously grant).
2. For every recently-added action: hit its API endpoint with a role that does NOT have the
   action. 2xx = missing authz check (P1/P2 depending on action).
3. Wildcard action injection: create custom role via API (`POST /custom-roles`) with action
   specifiers using globs/wildcards that match more than intended (`*`, `update*`, `*Secret*`)
   — does the server store/expand them as given? (role-action injection = persistent PCE.)
4. `bypassRequiredSegmentApproval`: segment approval flow — who's gated, which API path
   bypasses (approval-request apply endpoints).
5. `revokeSessions`: date-parameter edge (future date = revoke all? past = none?) + authz.

## Context model (`home/flags/contexts/intro`)

- Contexts = upgraded "users"; kinds (user/organization/device/…custom), **multi-contexts**
  (`{kind:"multi", user:{…}, organization:{…}, device:{…}}`).
- **Context instances** = unique combination of associated contexts; **context instance
  versions** = instance as recorded from a unique source app/SDK (per-SDK-instance records).
- Built-in attributes: `kind`, `key`, `name`, `anonymous` (+ custom attributes; `email` is
  custom for contexts, unlike legacy users).
- Context kinds can be created in UI **or automatically when evaluating via SDK** with a new
  kind (evalx/identify with unseen kind → auto-create).
- Segments target contexts (incl. big segments).

**Attack surface (Phase 5 refinement):**
- **Auto kind creation via SDK eval**: client-side ID + novel `kind` in evalx → kind created in
  tenant project? Rate/limit of kind creation (name collisions, unicode names, reserved names,
  case-insensitivity `User` vs `user`).
- **Multi-context canonicalKey** (feeds H5 secure-mode hash): what exactly is the canonicalKey
  of a multi-context (concatenation order? kind order independence)? Craft multi-contexts with
  permuted kind order / redundant kinds → same canonicalKey, different attribute surface.
- **Instance versions**: per-SDK records — identify events from two SDKs (server key + client
  ID) for same context → two versions; does one version's private-attr setting leak into the
  other's record (H6)?
- Context kinds archive/restore (context-kinds-archive) with flags/segments/experiments
  referencing the kind (dangling references, eval behavior, restore race).
- `anonymous` built-in attribute: force `anonymous:true` in events → usage counting exclusion
  (billing-adjacent logic, low).
