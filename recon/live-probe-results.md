# Live Unauthenticated Probe Results

Everything here was observed **live** against production on **2026-09-11** from the agent
sandbox via the docs fetch proxy (GET only — the proxy cannot set headers, cannot send
bodies, and does **not** surface HTTP status codes). Status codes/headers for the same
probes come from CI — see `ci-results/run-*/route-matrix.txt`.

## Capability note (important for how this research is run)

| Channel | Can reach LaunchDarkly? | Limits |
|---|---|---|
| sandbox `curl` | ❌ blocked (SSL_ERROR_SYSCALL) | — |
| sandbox `fetch_page` proxy | ✅ yes | GET only; no custom headers; no status codes; body rendered as text/markdown; empty bodies show as `<!doctype html><html><head></head><body></body></html>` |
| GitHub Actions runner | ✅ yes (full) | results must be **committed back** to the branch — Actions logs (`results-receiver.actions.githubusercontent.com`) and artifacts (`*.blob.core.windows.net`) are both unreachable from the sandbox |
| researcher's browser/machine | ✅ yes | header/body/status tests that need a session |

## Observations

### O1 — `GET /api/v2/announcements` (unauth) requires an UNDOCUMENTED account-ID header ⭐

```
GET https://app.launchdarkly.com/api/v2/announcements        (no auth, no headers)
→ {"code":"unauthorized","message":"Invalid account ID header"}
```

Compare with the standard auth failure on a normal endpoint:

```
GET https://app.launchdarkly.com/api/v2/caller-identity      (no auth)
→ {"code":"unauthorized","message":"invalid access token"}
```

Two different auth code paths. The announcements handler is not rejecting a missing/invalid
*access token* — it is rejecting a missing/invalid **account ID header**.

The official docs page for this operation (`/docs/api/announcements/get-announcements-public`)
documents only:
- `Authorization` (string, "API Key authentication via header")
- query params `status` (`active|inactive|scheduled`), `limit`, `offset`

No account-ID header is documented. Neither is it in the generated API clients
(`launchdarkly/api-client-java` → `AnnouncementsApi.java` builds the call with only
`Accept`/`Content-Type` headers and `ApiKey` auth). So the header is **enforced by the server
but absent from the public contract** — i.e. this endpoint is called by LD's own frontend with
a header that customers/SDKs never send.

**Why this matters (H4 refined):**
1. If the header is attacker-supplied and unauthenticated, `GET /api/v2/announcements` becomes
   an **unauthenticated, account-scoped read** — and the account ID is attacker-chosen, so the
   natural follow-ups are cross-account read + **account enumeration** (valid vs invalid ID
   error differential).
2. The response schema discloses authorization-policy internals. From
   `AnnouncementResponse` / `AnnouncementAccessRep` (api-client-java models):
   - `access.allowed[]` / `access.denied[]` → each entry has `resources[]`, `notResources[]`,
     `actions[]`, `notActions[]`, `effect` (`allow|deny`), **`roleName`**
   - plus `id`, `title`, `message`, `severity` (`info|warning|critical`),
     `status` (`active|inactive|scheduled`), `startTime`/`endTime` (ms), `isDismissible`
   So a successful unauth read leaks **role names and resource-specifier strings** used in LD's
   own policy language, and any `critical`/scheduled announcements before they're public.
3. **Writes on this endpoint are deliberately NOT tested.** `POST/PATCH/DELETE /api/v2/announcements`
   are the `createAnnouncementPublic` / `updateAnnouncementPublic` / `deleteAnnouncementPublic`
   operations, and announcements are rendered as in-app banners (with `critical` severity and
   scheduling). An unauthenticated write here would be visible to **every LaunchDarkly customer**
   — that is exactly the "compromises other users / destructive" case the program says to stop on
   and report instead. If unauth read is confirmed, the report states the write risk as
   *unexercised* and lets LD evaluate it. The old `--include-announcement-write` flag in
   `tools/run-session1.sh` has been removed for this reason.

**Next step (CI):** `tools/ci-route-matrix.sh` §5 brute-forces ~21 plausible header names
(`LD-Account-Id`, `X-Account-Id`, `LD-Tenant-Id`, …) × 2 dummy values + 4 query-param variants,
and §7b/§7c greps the app's JS bundles for account-ish header names and for the code that calls
`announcements`. Any response differing from the baseline error = the gate is found.

### O2 — SDK client-side polling routes are live on the in-scope app host ⭐

```
GET https://app.launchdarkly.com/sdk/evalx/thisidshouldnotexist/contexts/AAAA
→ {"code":"invalid_request","message":"couldn't parse user JSON: expected value at line 1 column 1"}
```

- `AAAA` is not valid base64url-JSON. The handler **decoded and JSON-parsed the context before
  doing anything about the client-side ID** — the route exists on `app.launchdarkly.com`
  (documented polling fallback, and an in-scope host), and its error path reveals handler
  ordering plus the internal name of the parser ("user JSON" — the legacy *users* code path still
  serves the contexts route; relevant to the "users → contexts is a 1:1 replacement" focus area).
- With a **well-formed** context (`eyJraW5kIjoidXNlciIsImtleSI6InRlc3QifQ` = `{"kind":"user","key":"test"}`)
  the same bogus-ID URL returns an **empty body** — no error JSON at all. Status code unknown via
  the proxy; CI §1 records it. If that is `200` with an empty payload, then key validation is
  silent and the endpoint is a usable oracle surface for H5 testing from any host (no CORS
  involved, since it's not an `/api/v2/` route).
- `GET /msdk/evalx/contexts/{ctx}` (mobile route, ID in a different position) → also empty body.
  CI §1 tests both `/msdk/evalx/contexts/{ctx}` and `/msdk/evalx/{id}/contexts/{ctx}` shapes.

Pre-computed contexts for reuse (base64url, no padding):

| context | JSON | b64url |
|---|---|---|
| user_test | `{"kind":"user","key":"test"}` | `eyJraW5kIjoidXNlciIsImtleSI6InRlc3QifQ` |
| multi (user,org) | `{"kind":"multi","user":{"key":"u1"},"org":{"key":"o1"}}` | `eyJraW5kIjoibXVsdGkiLCJ1c2VyIjp7ImtleSI6InUxIn0sIm9yZyI6eyJrZXkiOiJvMSJ9fQ` |
| multi permuted (org,user) | `{"kind":"multi","org":{"key":"o1"},"user":{"key":"u1"}}` | `eyJraW5kIjoibXVsdGkiLCJvcmciOnsia2V5IjoibzEifSwidXNlciI6eyJrZXkiOiJ1MSJ9fQ` |
| empty object | `{}` | `e30` |
| no kind | `{"key":"test"}` | `eyJrZXkiOiJ0ZXN0In0` |

The two `multi` rows are the **canonicalKey-permutation pair for H5-4** (same kinds/keys,
different JSON order) — if a secure-mode `h` computed over one authorizes the other, that is the
secure-mode bypass the program asks about.

### O3 — `GET /api/v2/ips` returns the app 404 page

```
GET https://app.launchdarkly.com/api/v2/ips
→ 404 "Lost in space" (HTML app 404 page, not a JSON API error)
```

The recon notes (from docs) list `/api/v2/ips` as a public endpoint. It 404s now, and returns the
**SPA HTML 404**, not the JSON `{code,message}` API error — so this path is handled by the app
front-controller, not the API router. Either the endpoint moved (CI §6e greps the live OpenAPI
spec for `ips`-ish paths) or it was removed. Not a finding on its own (version/path disclosure is
excluded), but it is a useful reminder that **path-vs-router behavior differs** between
`/api/v2/*` API routes and app routes — relevant when probing `/internal/` and `/private/`
(HTML 404 = "no such app route", JSON error = "API route exists").

### O4 — `stream.launchdarkly.com/all` reachable, empty body

`GET https://stream.launchdarkly.com/all` (no auth) → empty body via the proxy (expected for an
SSE endpoint that never sends an event without a valid SDK key). CI §2 records status codes +
headers for the whole streamer route set, which is what actually maps route existence there
(`404` = no route, `401/400` = route + auth check).

### O5 — `/internal/` answers UNAUTHENTICATED with a resource index, and its children share the account-ID gate ⭐⭐

```
GET https://app.launchdarkly.com/internal/            (no auth, no headers)
→ {"_links":{"account":{"href":"/internal/account","type":"application/json"},
             "actions":{"href":"/internal/actions","type":"application/json"},
             "self":{"href":"/internal/","type":"application/json"}}}

GET https://app.launchdarkly.com/internal/account        → {"code":"unauthorized","message":"Invalid account ID header"}
GET https://app.launchdarkly.com/internal/actions        → {"code":"unauthorized","message":"Invalid account ID header"}
GET https://app.launchdarkly.com/internal/announcements  → {"code":"unauthorized","message":"Invalid account ID header"}
GET https://app.launchdarkly.com/internal/members        → HTML 404 "Lost in space" (no such route)
GET https://app.launchdarkly.com/private/                → HTML 404 "Lost in space" (no such route)
```

Three things follow:

1. **The `/internal/` API root is reachable with zero credentials** and happily describes itself.
   The program states `/internal/` is "customer-facing … require[s] either a valid `ldso` session
   cookie or an access token". The root index requires **neither**. That alone is an
   unauthenticated-access observation on an in-scope API subroute (focus area: "Unauthenticated/
   unauthorized access to APIs"), and it is the map for everything below it.
2. **`/api/v2/announcements` is the same machinery as `/internal/announcements`** — identical
   gate, identical error string. So "Invalid account ID header" is the **internal-API family's**
   auth check, and the public `/api/v2/announcements` route is an internal-API endpoint exposed on
   the public API path. That reframes H4: this is not "a public endpoint missing auth", it is
   "an internal endpoint whose only credential is an account identifier supplied in a header".
   → **If the header alone (no cookie, no token) authorizes the request, an attacker who can
   supply or guess another account's ID reads that account's internal data.** That is the
   cross-tenant/unauth finding; the account-ID error differential is also an enumeration oracle.
3. **A reliable router fingerprint** for mapping the rest of the surface without credentials:
   HTML "Lost in space" = no route at all; JSON `Invalid account ID header` = real gated internal
   route; JSON `invalid access token` = real `/api/v2/` route; JSON `_links` index = route that
   answers unauthenticated. CI §4/§4b applies this across ~50 candidate paths and classifies each.

Note `/internal/actions` — combined with `AnnouncementAccessAllowedReason` (`actions[]`,
`resources[]`, `effect`, `roleName`), an unauthenticated or header-only read of `/internal/actions`
would disclose LD's **role-action vocabulary** as deployed (directly useful for the new-action PCE
sweep in Phase 2, and a disclosure finding in its own right).

### O6 — correct path for the public IP list

`GET /api/v2/ips` → 404 HTML; the unauthenticated API root index (`GET /api/v2/`) shows the real
href is **`/api/v2/public-ip-list`**, which returns the full egress CIDR list with no auth
(expected/documented — not a finding). The root index is itself unauthenticated and lists
`account`, `flag-statuses`, `flags`, `integrations`, `members`, `projects`, `public-ip-list`,
`segments`, `tokens`, `webhooks` — worth remembering that **`GET /api/v2/` is an unauth'd
route-discovery oracle** for the public API, and the reconstructed doc slugs in
`recon/api-endpoints.md` need correcting against it (CI §6 produces the exact inventory).

## Probe coverage status

| Probe | Via proxy (GET, no status) | Via CI (status + headers) |
|---|---|---|
| announcements unauth error | ✅ O1 | ✅ §5 header brute force |
| caller-identity unauth | ✅ O1 | ✅ §4 |
| `/api/v2/ips` | ✅ O3 | ✅ §4 (+ `public-ips` variant) |
| app-host SDK poll routes | ✅ O2 | ✅ §1 (10 shapes) |
| streamer routes | ✅ O4 (partial) | ✅ §2 (14 shapes) |
| events routes | — | ✅ §3 (8 GET + 2 empty POSTs) |
| `/internal/`, `/private/` | — | ✅ §4 |
| OpenAPI header params / no-auth ops | — | ✅ §6 (spec is public) |
| bundle mining for internal paths + account header | — | ✅ §7 |
| CORS/Origin behaviour (H1) | ❌ needs headers | ✅ `ci-extra-unauth.sh` X2/X3 (unauth side); session side needs Part B secrets |
