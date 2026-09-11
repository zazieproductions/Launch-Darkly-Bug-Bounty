# SDK Wire Format & Source Review

Source: `launchdarkly/js-core` (monorepo, main branch, cloned 2026-09-11) — contains the current
browser, server-node, react, vue, svelte, react-native, edge (Cloudflare/Fastly/Akamai/Vercel/
Shopify), and openfeature SDKs + shared code. Also `launchdarkly/react-client-sdk` (v5, standalone
repo, still maintained). Older standalone repos (`js-client-sdk`, `node-server-sdk`) are
renamed/legacy — future work lives in js-core.

Note on scope: only **SDK repos** count for SDK findings (program excludes non-`-sdk` repos and
scan results). `js-core` is the canonical SDK repo; frame any SDK finding against it.

## Request format (from source)

### Headers (all SDKs) — `packages/shared/common/src/utils/http.ts`
```
authorization: <sdkKey>              # server & mobile keys; NOT sent by browser SDK
user-agent: <SDKBase>/<version>      # or x-launchdarkly-user-agent for edge SDKs
x-launchdarkly-wrapper: <name>/<v>   # if wrapper (framework) present
x-launchdarkly-tags: <value>         # if applicationTags configured
x-launchdarkly-instance-id: <v4 GUID># server SDKs, once per instance (spec 1.1)
```
Client-side IDs travel **in the URL path**, not in a header.

### Client-side (browser) routes — `packages/shared/sdk-client/src/datasource/Endpoints.ts`
FDv1 (client-side ID `X`):
- Polling (on `clientsdk.launchdarkly.com` / `app.launchdarkly.com`):
  - GET `/sdk/evalx/{X}/contexts/{base64url(contextJSON)}`
  - POST/REPORT `/sdk/evalx/{X}/context` (context in JSON body)
- Streaming (on `clientstream.launchdarkly.com`):
  - GET `/eval/{X}/{base64url(contextJSON)}` (SSE)
  - GET `/ping/{X}`
Mobile-key FDv1: `/msdk/evalx/contexts/{...}` (poll), `/meval/{...}` (stream), `/mping`.
- Query params: `withReasons=true` (if configured), `h=<secureModeHash>`, `filter=<payloadFilterKey>` (views).
- **`REPORT` HTTP method** is a real feature: `useReport: true` → `REPORT` verb with
  `content-type: application/json` + context in body (poll & SSE).

### Server-side routes
- GET `/all` (stream SSE, auth = SDK key header)
- Polling variants via `getPollingUri` on `sdk.launchdarkly.com`/`app.launchdarkly.com`
- FDv2 processors (`OneShotInitializerFDv2`, `PollingProcessorFDv2`, `StreamingProcessorFDv2`,
  `createPayloadListenerFDv2`) — newer flag-data protocol; watch for protocol edge cases.

### Events recorder
- `getEventsUri(serviceEndpoints, analyticsEventPath)` → `{events}/...`
  (standard: `/events/identify`, `/events/summary`, `/events/feature`, `/events/debug`);
  diagnostic events via `diagnosticEventsPath`. Context PII goes in POST bodies.

### Context encoding — the interesting bit
- Context → `JSON.stringify(LDContext)` → `base64UrlEncode` = `btoa` + `+/→-_` + strip `=`
  → placed **in the URL path segment**.
- `canonicalizePath`: strips leading `/` and trailing `?`.
- Browser `btoa` wrapper handles unicode (UTF-8 → binary string) — so unicode context keys do NOT
  break encoding, but note the output is a single path segment: **no `/` can appear in the
  base64url output**, so path-injection via context keys needs server-side decode handling, not
  client splitting. The real question is **server-side** decode behavior for:
  - oversized context strings (URL length limits → truncation → which context gets served?)
  - duplicate/ambiguous base64 (padding-agnostic decoding — do two contexts collide?)
  - malformed base64 segments (error handling / does it fall back to a default context?)
- `secureModeHash` (new GA): server SDK `client.secureModeHash(context)` =
  **HMAC-SHA256(key = sdkKey, data = context.canonicalKey)** hex. Browser: developer passes
  `hash` in `identify(context, {hash})` → sent as `?h=`.
  - Questions for server testing: is `h` validated against the *full* context or just key?
    (impl hashes only `canonicalKey` — if the server only checks the key-hash, an attacker with
    the same key could target any context with that key? unlikely — keys are unique per context —
    but the hash domain being only the canonicalKey is worth probing: can a crafted context
    produce the same canonicalKey as a victim context? e.g. different attribute sets,
    multi-kind contexts, key case-sensitivity.)
- `Context.canonicalKey` — check normalization (case, unicode) in `js-server-sdk-common` Context.

### Browser SDK behavior — `packages/sdk/browser/src`
- `identify(context, {hash, bootstrap})`: loads flags from localStorage cache first, then
  one-shot poll (`_requestPayload`, 3 retries), then starts SSE; reuses connection params.
  - **Race window:** during identify, stale cached flags for the *previous* context may be served
    until poll completes → user enumeration? (cache is per-browser; low impact but document.)
- localStorage: caches flags per context (keyed how? check cache key construction — if keyed by
  context kind only, context switch could read another context's cached flags locally).
- `BrowserStateDetector`, `LDClient` (SSR/evaluateExisting), goals/GoalTracker (legacy goals API
  still in-tree), `useReport` option.
- Events: identify/feature/summary/custom events; `sendEvents: false` supported; `flushEventsInterval`.

### React SDK — `packages/sdk/react/src` (+ standalone react-client-sdk v5)
- No `dangerouslySetInnerHTML`/`innerHTML`/`eval` anywhere (grep clean).
- New: **React Server Components** support — `createLDServerSession` per-request eval scope
  (server/); client hydration via context provider + `getFlagsProxy` (a Proxy over the flags
  object — check `getFlagsProxy` invariant traps).
- `useFlags`/`withLDConsumer`/`asyncWithLDProvider` — async provider = hydration mismatch surface
  (functional, not security).

## Source-review conclusions (passive)

1. No obvious client-side XSS primitives (SDKs render nothing; React SDK confirmed clean).
2. Robustness notes (not reportable as-is, useful for server-side hunting):
   - `btoa` polyfill assumptions; unicode context keys fine.
   - URL-length behavior on very large contexts is a **server** question.
   - `REPORT` verb handling is unusual — server must allow a non-standard verb on SSE endpoints.
3. Real value of this review: **exact routes/headers/params to fuzz on the in-scope Go services**
   (stream, events, app-as-polling-fallback) and knowledge of the new features (FDv2, secure-mode
   hash, views `filter=`, RSC) to target "new GA" logic bugs.
4. Non-JS SDKs (Java/Python/Go/.NET/etc.) — same wire protocol per cross-SDK contract tests;
   contract-tests dirs in js-core show the shared spec (SCMP references in comments).

## Open questions for authenticated testing

- [ ] Unauth'd responses on `stream.launchdarkly.com` for client routes: `/msdk`, `/meval`,
      `/eval/{id}`, `/ping/{id}`, `/msdk/bulk`, `/bulk_eval/contexts` — do they 404, 401, or leak?
- [ ] Does `stream.launchdarkly.com` serve client-side payloads (rules stripped) for a
      client-side ID, and does `withReasons=true` leak rule names/eval detail client-side?
- [ ] `h=` (secure mode hash): does the server accept it alone (no Authorization) for mobile keys?
- [ ] `filter=<viewKey>`: can a client pass another env's view key? (views = filtered SDK payloads,
      new Aug-2026 feature)
- [ ] Events: can events for context A be recorded under env B's key? Cross-env metric pollution
      → experimentation logic impact (focus area).
- [ ] Polling fallback on `app.launchdarkly.com`: which SDK paths exist there (`/sdk/...`,
      `/msdk/...`)? (in-scope host)
