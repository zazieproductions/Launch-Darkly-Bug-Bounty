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

**Next (needs researcher):**
1. Run P0 batch from browser (all read-only).
2. Create `zazieproductions@bugcrowdninja.com` account → token → `.env`.
3. Proceed per `plans/test-plan.md` sequencing.
