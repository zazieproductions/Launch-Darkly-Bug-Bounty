# SDK Service Domains & Instances

Source: official docs "Domain list" (`https://launchdarkly.com/docs/sdk/concepts/domain-list`),
fetched 2026-09-11. Scope implications in **bold**.

## Commercial (default)

| Service | Server-side SDKs | Client-side JS SDKs | Mobile SDKs |
|---|---|---|---|
| Streaming | `stream.launchdarkly.com` **← IN SCOPE** | `clientstream.launchdarkly.com` (out of scope, unlisted) | `clientstream.launchdarkly.com` (out of scope) |
| Polling | `sdk.launchdarkly.com` or `app.launchdarkly.com` (unlisted / in scope) | `clientsdk.launchdarkly.com` or `app.launchdarkly.com` | `clientsdk.launchdarkly.com` or `app.launchdarkly.com` |
| Events | `events.launchdarkly.com` **← IN SCOPE** | `events.launchdarkly.com` **← IN SCOPE** | `mobile.launchdarkly.com` (out of scope) |
| Observability | — | `otel.observability.app.launchdarkly.com`, `pub.observability.app.launchdarkly.com` (ambiguous — subdomain of in-scope host) | same |

## Federal (`.us`) — separate instance, OUT OF SCOPE

`stream.launchdarkly.us`, `sdk.launchdarkly.us` / `app.launchdarkly.us`, `events.launchdarkly.us`,
`clientstream.launchdarkly.us`, `clientsdk.launchdarkly.us`

## EU (`.eu`) — separate instance, OUT OF SCOPE

`stream.eu.launchdarkly.com`, `sdk.eu.launchdarkly.com` / `app.eu.launchdarkly.com`,
`events.eu.launchdarkly.com`, `clientstream.eu.launchdarkly.com`, `clientsdk.eu.launchdarkly.com`

Other references:
- Relay Proxy replaces all of the above (customer-controlled; its config is managed via API)
- Public IP list: docs `/home/infrastructure/ip-list` and `GET /api/v2/ips`
- SDKs are **never rate limited**; streaming uses SSE + global CDN

## Testing implications

- Only **`stream.launchdarkly.com`** and **`events.launchdarkly.com`** may be actively tested
  among SDK hosts. Client-side stream/poll flows go to `clientstream/clientsdk.*` (unlisted) —
  so for in-scope client-side streamer testing use the **server-side** SDK key + routes, and for
  client-side-ID behavior note the host mismatch and report findings against stream.launchdarkly.com
  behavior where reachable (client routes may exist on the same Go service — verify unauth'd
  error responses on stream.launchdarkly.com for `/msdk`, `/meval`, `/eval/*`, `/ping/*`).
- EU/federal instances: passive comparison only (if anything, error-response diffs).
- `app.launchdarkly.com` itself is a documented polling fallback — so SDK polling behavior can be
  tested on the in-scope app host (e.g. `GET /sdk/...` style paths on app).
