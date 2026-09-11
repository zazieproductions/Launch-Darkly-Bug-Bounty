# SDK Docs — Documented Security Model (baseline for "unexpected data" findings)

Source: official SDK docs (`launchdarkly.com/docs/sdk`), fetched 2026-09-11.
The program's streamer focus: *"client-side SDKs are specifically meant to prevent attackers from
accessing things such as flag evaluation rules… any improper handling/exposure of this data may be
considered noteworthy."* This file is the documented baseline; deviations = findings.

## Key model (sdk/concepts/client-side-server-side)

| SDK type | Credential | May receive rules? | Where it runs |
|---|---|---|---|
| Client-side (JS, Electron, .NET client, C++ client) | **client-side ID** (public by design) | **NO** — "client-side SDKs depend on LaunchDarkly's servers to safely store flag rules" | Untrusted device |
| Mobile (Android/iOS/Flutter/RN/Roku/.NET) | **mobile key** (semi-public) | NO (client payload) | Untrusted device |
| Server-side / AI / OpenFeature | **SDK key** (secret) | YES — full rulesets | Trusted infra |
| Edge (Akamai/Cloudflare/Fastly/Vercel) | client-side ID + CDN integration | YES (written into customer's edge DB) | CDN |
| Observability | plugin on client/server SDK | n/a | — |

- "SDKs are designed to work with one LaunchDarkly environment at a time" (mobile: multi-env).
- Client JS: initial **poll**, then optional **streaming**; "Client-side SDKs receive flag value
  changes **for a specific context**."
- Client payload = flag values only; rules & PII stay server-side. **Verify per test plan H5.**

## Evaluation reasons (sdk/concepts/evaluation-reasons)

Reason object kinds: `OFF`, `FALLTHROUGH`, `TARGET_MATCH`, `RULE_MATCH` (+`ruleIndex`,
`ruleId`), `PREREQUISITE_FAILED` (+`prerequisiteKey`), `ERROR` (+`errorKind`), optional
`inExperiment`. Detail methods also emit a `reason` into analytics events (`debug` events shown
with full `context` object incl. custom attributes — Sandy example).

**Exposure questions:**
- Client-side: are `withReasons` results (ruleId/ruleIndex/prerequisiteKey) returned to the
  browser? RULE_MATCH rule IDs + prerequisite flag keys = partial targeting structure leak.
- `TARGET_MATCH` on client eval = "this context key is in individual targets" → enumeration.
- Data Export / Live events `reason` + full context = check access control of those views.

## ⭐ Secure mode (sdk/features/secure-mode) — the confirmed threat model

> "Secure mode ensures that customers' feature flag evaluations are kept private in web browser
> environments, and that **one end user cannot inspect the variations for another end user**. On an
> insecure device, a malicious end user could use a context or user key to **identify what flag
> values another end user receives by analyzing the results of multiple flag evaluations**. Secure
> mode prevents you from doing an evaluation for a context or user key that hasn't been signed on
> the backend."

Mechanics (from docs + js-core source):
- Per-**environment** opt-in setting (Environments list → edit env → secure mode).
- Hash = **HMAC-SHA256 keyed with the environment SDK key**, over the **canonical context key**
  (source: `LDClientImpl.secureModeHash` → `hmac(createHmac('sha256', sdkKey), context.canonicalKey)`).
- Computed by a backend SDK (`client.secureModeHash(context)`) or manually; passed to the JS front
  end; JS SDK sends context + `h` param. "If the hash doesn't match, LaunchDarkly returns an error."
- Applies to: Electron, JavaScript, Node.js (client-side), React Web. "Not necessary for
  server-side SDKs." Non-JS SDKs are unaffected by the setting.
- Resetting the environment SDK key invalidates hashes.

**Test implications (H5 in test plan):**
1. Env WITHOUT secure mode: client-side ID + arbitrary context in `/sdk/evalx/{id}/contexts/{b64}`
   (poll, on `app.launchdarkly.com` — in scope) and `/eval/{id}/{b64}` (stream) returns that
   context's variation. This is *documented known behavior* (mitigate by enabling secure mode) —
   report only if something beyond the docs leaks (reasons, rule data, cross-env).
2. Env WITH secure mode:
   - Missing `h` → expect error. Wrong `h` → error.
   - `h` signed for context A, request context B (same env) → must reject.
   - **canonicalKey collisions**: multi-kind contexts, case/unicode variants, `kind` casing,
     anon contexts — craft two contexts with equal canonicalKey but different attribute sets;
     does a hash for one authorize the other? (attribute-level info is then readable via the eval)
   - **Route coverage**: is `h` enforced on polling, streaming, ping, REPORT, bulk eval — on all?
   - **Credential mixing in secure-mode env**: mobile key on `/msdk*` (secure mode is documented
     JS-only — confirm mobile paths remain open, i.e. BY DESIGN not a bypass; but check whether a
     *client-side ID* works on `/msdk*` or a *mobile key* on `/eval*`).
   - `withReasons=true` alongside valid `h` — does the signed context still get full reason
     detail (ruleIds etc.)? (documented scope of secure mode = variations only)
   - `h` param ignored when also sending `Authorization` header with a server SDK key?
3. **The oracle itself** (pre-secure-mode environments): value enumeration across guessed context
   keys (keys are often emails/names — see `context attribute values` API + contexts list for the
   key space if you have tenant access). If `TARGET_MATCH`/`RULE_MATCH` are observable, the
   attacker maps who is targeted — beyond the documented mitigation, which only addresses
   *variations*, not necessarily *reasons*. Frame any report around **reasons leaking
   targeting structure client-side** rather than the raw oracle (which is disclosed).

## Private attributes (sdk/features/private-attributes)

- Configurable per SDK (`allAttributesPrivate`, `privateAttributes([...])`, per-context
  `.Private("attr")`), incl. JSON-pointer paths like `/address/street`.
- **Server/AI SDK: private attrs are not sent at all.**
- **Client SDK: private attrs ARE sent for evaluation** (server needs them), but:
  - not sent in events,
  - "LaunchDarkly won't store the private attribute",
  - "will not appear on the Contexts list or on the detail page".
- **The context key and kind are always sent, never private.**
- Quirk: once marked private while the context is in the Contexts list, LD keeps treating it as
  private even if you remove the designation (until context deleted + re-evaluated).
- Context detail page shows private attrs under `_meta` with values hidden.

**Test implications (H6):** with a client-side context containing private attrs, check server
surfaces for the values:
- `/evalx` + `withReasons` (reasons must not include them),
- events (`identify`/`feature`/`debug` accepted at events.launchdarkly.com — request echo?),
- **REST API**: `GET context attribute names/values`, `search contexts/instances`,
  `evaluate-context-instance`, context detail endpoints — does JSON contain values under `_meta`?
- Audit log entries for context creation (does the comment/entry include the context body?)
- Legacy user endpoints (users API + user flag settings) — do they expose the same data?
- JSON-pointer fuzz: `/..`, `..`, `*`, empty, duplicate paths — misconfigured privacy stripping?

## Filtered SDK payloads / views (sdk/concepts/payload-filtering) — BETA, Enterprise

- Up to **10 views per SDK/mobile key**; filtered key receives only resources in the views.
- Default SDK/mobile keys can't be filtered; filtered keys can't be promoted to default.
- Requires role action `updateSdkKeyPayload` (Owner/Admin or custom role with that action).
- Relay Proxy ≥9.0, not auto-config.
- API: SDK Keys Beta (`post/patch sdk-key` incl. views) + Views Beta (`link-resource` etc.).

**Test implications (H7):**
- `filter=<viewKey>` query param on stream/poll (js-core sends `endpoints.payloadFilterKey`):
  can key A pass key B's view key? Can an unfiltered key pass a `filter` param at all?
  (Expected: server ties filter to the key; verify — a bug = payload of another app's view,
  or full payload bypass of filtering.)
- Views = generic resource links (Views Beta API): cross-project linking? `get-linked-resources`
  authz for non-maintainers?
- Filtered payload correctness: does a filtered key ever receive resources OUTSIDE its views
  (e.g. segments referenced by an in-view flag)?

## Analytics events (sdk/concepts/events)

Kinds: `summary`, `feature` (Experimentation + detailed tracking + **guarded rollouts**),
`debug`, `migration_op`, `index`, `identify`, `page view`, `click`, `custom` (track*,
observability web vitals).
Features that depend on events: **Contexts list**, "Target with flags", flag statuses, Live
events, Data Export, Experimentation, Guarded rollouts, Observability, migration metrics.
- `index`/`identify` **push context data to LaunchDarkly** (creates/updates context instances —
  see H8: context creation/attribute tampering via events).
- Anonymous contexts can be omitted from index/identify (server SDKs).
- Client SDKs also send summary/debug/feature for **prerequisite** flags (holdouts depend on it).
- Flush intervals: server ~seconds, mobile ~30s; `sendEvents: false` for testing.

**Test implications (H8/H9):**
- `identify` with arbitrary context key/attributes (your env): creates context record → can you
  **overwrite attributes of an existing context** (re-identify with different attrs → changes
  targeting for that user! business logic, P2/P3)?
- `feature` events with mismatched variation/iteration/flag (experimentation tampering — focus
  area); negative/huge metric values; cross-flag iteration ids; `inExperiment` on non-experiment
  flags.
- Event key vs Authorization key mismatch — which context/key wins?
- `migration_op` events — migration flag metrics tampering (new feature: Migrations).
- Private attrs in events (must be absent — pair with H6).
- Page view/click events (JS SDK experimentation): attribute limits, PII in props.

## Local storage caching (sdk/features/local-storage)

- JS v4 (default on), iOS, Android, Flutter, RN, React Web, Vue: cache flag values per unique
  context; `maxCachedContexts` default **5**, LRU eviction on `identify()`.
- `maxCachedContexts: 0` clears; `disableCache: true` keeps existing data.
- "unique key that is based on the user properties" (Electron).
- **Note:** cache key derivation is client-side; cross-context bleed would be per-browser only
  (local privacy, low value) — check `BrowserFlagCache`/cache-key code in js-core if curious,
  but this is the customer's browser, not LD's server → likely non-reportable. Documented here to
  avoid wasting time.

## Other relevant pages (not yet read — grab if the line of attack needs them)

- `sdk/features/aliasing-users` (user aliasing → identity-merging logic)
- `sdk/features/anonymous` (anonymous contexts: key rules, usage)
- `sdk/features/identify` (context switch semantics)
- `sdk/features/migration-config` + `home/flags/migration-metrics` (Migrations — new)
- `home/releases/guarded-rollouts` (Guarded rollouts — new, event-dependent)
- `sdk/features/experimentation` (client-side experimentation setup)
- `sdk/concepts/flag-evaluation-rules` (server-side eval algorithm — for SDK logic findings)
- `sdk/concepts/big-segments` (big segment membership via persistent store)
- `home/flags/private-context-attributes` (UI side of H6)
- `home/experimentation/*` (traffic assignment, allocation, sample size — focus area)
- `home/flags/contexts/*` (context kinds, archiving — focus area)
