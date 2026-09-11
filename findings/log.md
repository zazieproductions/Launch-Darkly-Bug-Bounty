# Research Log

## 2026-09-11 — Setup + passive recon (agent-assisted)

**Environment:** agent sandbox egress is GitHub-only; LaunchDarkly hosts not directly reachable.
Passive recon via docs proxy + GitHub source. Active testing must run from researcher's machine.

**Docs / API surface (from `launchdarkly.com/docs`):**
- Full REST API endpoint inventory captured → `recon/api-endpoints.md` (~60 resource groups).
- API mechanics noted: CORS echoes any Origin (session auth relies on Origin check),
  `X-HTTP-Method-Override` for POST→PATCH/PUT/DELETE, `LD-API-Version` per-request versioning
  (20160426→20240415 + `beta`), semantic patches, `expand=`, JSON error format, rate-limit headers.
- Public endpoints: `/api/v2/openapi.json` (any auth string accepted), `/api/v2/ips`,
  `/api/v2/caller-identity` (has `bountyEligible`), root.
- "Announcements" API has *`-public`* endpoint names → hypothesis H4 (unauth?).
- `docs.launchdarkly.com` now redirects to `launchdarkly.com/docs` (Fern docs; `llms.txt`/`.md`
  conventions + MCP server for agents).
- SDK "Domain list" captured → `recon/domains-and-instances.md`. Only
  `stream.launchdarkly.com` + `events.launchdarkly.com` in scope among SDK hosts; EU/federal
  instances out of scope.

**SDK source review (cloned → `sdk/`, gitignored):**
- `launchdarkly/js-core` (current browser/server-node/react/vue/svelte/RN/edge/openfeature SDKs)
  + `launchdarkly/react-client-sdk` (v5).
- Wire format + new features documented → `recon/sdk-wire-format.md`:
  context base64url in URL path; `REPORT` HTTP verb option; `withReasons`, `h` (secure-mode
  HMAC-SHA256(sdkKey, canonicalKey)), `filter` (views — new Aug 2026); FDv2 processors;
  React Server Components support (new); no XSS primitives in React SDK (grep clean).
- No obvious client-side SDK vulns from passive review; real targets are server-side handler
  behaviors driven by these formats (see test-plan Phase 4).

**Hypotheses written** → `plans/test-plan.md` (P0 unauth batch first: announcements, /private,
SDK routes on in-scope hosts, CORS+Origin, docs search reflection, app-host SDK polling paths).

## 2026-09-11 (cont.) — SDK docs deep-dive (`launchdarkly.com/docs/sdk`)

- Full SDK docs index + security-critical pages read → new file `recon/sdk-docs.md`.
- **Secure mode page confirms the client-side oracle threat model verbatim**: without secure
  mode, a public client-side ID can identify another user's flag values by evaluating their
  context keys; secure mode = HMAC-SHA256(sdkKey, canonicalKey) sent as `h`, per-env opt-in.
  → Wrote **H5** (oracle + bypass matrix: canonicalKey collisions, route coverage, credential
  mixing, reasons leakage with valid hash).
- **Private attributes**: client SDKs send private attrs for eval; LD must not store/echo.
  → Wrote **H6** (leakage matrix across evalx/stream/events/REST context APIs/audit/legacy
  users endpoints; JSON-pointer fuzz of the privacy stripper).
- **Filtered payloads/views** (beta): per-key view filter, `filter=` param, 10 views/key.
  → Wrote **H7** (cross-key/cross-project view filter abuse + Views Beta authz).
- **Events**: `index`/`identify` create/overwrite context instances; `feature` events power
  Experimentation + new **Guarded rollouts**. → Wrote **H8** (attribute tampering via re-identify)
  and **H9** (experiment/guarded-rollout metric tampering — focus area).
- Local storage caching = per-browser only → documented, not reportable (time-saver).
- Test plan updated: new Phases 4a/4b inserted; sequencing re-ordered.

## 2026-09-11 (cont. 2) — Product docs deep-dive (`launchdarkly.com/docs/home`)

- Read focus-area feature docs → new file `recon/app-features.md`:
  - **Guarded rollouts** (new, trial on all accounts): sequential-testing regression → auto
    rollback; **minimum-context gate per step**. Attack: unique-context counting, gameable
    rollback, masked regressions, step timing, exclusivity enforcement → H9 extended.
  - **Experiment traffic assignment** (new doc 2026-09-09): seed+key → 100k buckets,
    deterministic, no stored assignments; tracked/untracked; layers (shared seed, snapshots);
    holdouts. Attack: seed exposure in client payloads, reshuffle path behavior (Edit design vs
    Stop), analysis pipeline trusting event claims vs re-deriving assignments → Phase 5 + H9.
  - **SDK credentials**: `sdk-` (secret) / `mob-` / client-side ID (alphanumeric, uncreatable);
    multiple keys per env; expiry; view-scoped keys rejected by Relay Proxy. Attack: `viewSdkKey`
    gating on SDK Keys Beta list/get (key material disclosure), key-reuse protection.
  - **Role actions**: captured the full "Recently added actions" table (2025-09 → 2026-09, ~60
    actions) incl. `bypassRequiredSegmentApproval`, `updateAccessTokenExpiry` (member + service
    tokens), `updateAccountTokenLimit`, `revokeSessions`, IP allowlist actions, SDK-key CRUD
    actions. Strategy: new-action PCE sweep (endpoints with roles lacking the action; stale
    preset roles; wildcard action injection in custom roles) → Phase 2 extended.
  - **Context model**: kinds/instances/**instance versions** (per source SDK), multi-contexts,
    built-in attrs (kind/key/name/anonymous), **auto kind creation via SDK eval**. Attack: kind
    creation edge cases, multi-context canonicalKey permutation (H5-4), instance-version
    private-attr leakage (H6) → Phase 5 extended.
- All three doc sections (api / sdk / home) now mined for the security-relevant surface.
  Remaining unread: per-language SDK references, full static action reference (strategy covers
  it), guides pages.

**Next (needs researcher):**
1. Run P0 batch from browser (all read-only).
2. Create `zazieproductions@bugcrowdninja.com` account → token → `.env`.
3. Proceed per `plans/test-plan.md` sequencing (P0 → account → Phase 2 IDOR + new-action PCE
   sweep → Phase 3 SSRF → Phase 4a H5 oracle/secure-mode → 4b event/guarded-rollout tampering).
