# LaunchDarkly Bug Bounty — Research Workspace

Working repo for the [LaunchDarkly Bugcrowd program](https://bugcrowd.com/launchdarkly).

## Program snapshot

- **Reward tiers (CVSS-based, may be modified for likelihood/impact, appeal possible):**
  | Priority | Reward |
  |---|---|
  | P1 | $6,500–$7,500 |
  | P2 | $2,500 |
  | P3 | $1,250 |
  | P4 | $150 |
- **Test account:** use the `@bugcrowdninja.com` email (see `email`):
  `zazieproductions@bugcrowdninja.com` (accounts get full access to all features)
- **Key rules that shape strategy:**
  - Reports must show **original analysis + human input** (no low-effort/AI-generated content).
  - **One vulnerability per report**; multi-endpoint findings of the same vuln = duplicate.
  - Every report needs: **role used**, clear explanation, security impact, **reliable repro steps**.
  - SSRF reports **must include proof the target endpoint was reached + its metadata**.
  - Production testing: no DoS, no touching other users' data, no destructive post-exploitation.
  - `@bugcrowdninja` substring required in any account used.

## In-scope targets (short list — details in [scope.md](scope.md))

| Target | What it is |
|---|---|
| `app.launchdarkly.com` | Main web app (React) — authN/authZ, XSS/SSRF in user input |
| `app.launchdarkly.com/api/v2/` (+ `/internal/`) | Customer REST API — token or `ldso` session cookie |
| `/private/` subroute | Internal APIs — access = finding ("worthy of note") |
| LaunchDarkly SDKs (open source, repos ending `-sdk` / js-core) | Logic bugs, handler logic, SDK↔server comms |
| `stream.launchdarkly.com` | SSE/polling flag data for SDKs |
| `events.launchdarkly.com` | Event recorder (metrics/experimentation data) |
| `docs.launchdarkly.com` (+ `launchdarkly.com/docs`) | Static docs; user input fields (search) + cross-origin calls to app → CSRF noteworthy |

Out of scope (highlights): all other subdomains, third-party integrations, DoS/rate-limit-bypass,
client-side SDK keys being public, open redirects w/o extra impact, scan/dependency results,
HTML injection in app/email text fields (listed as excluded), and more — see [scope.md](scope.md).

## Focus areas (program call-outs)

1. **Custom Contexts** (new user model: users → custom contexts) — new infra/UI, business-logic errors
2. **Experimentation** — flags + events, analysis logic
3. app: improper authN/authZ, privilege escalation, XSS/SSRF in user input
4. API: unauth/unauthorized access, unexpected data returned, handler logic errors
5. SDKs: dig into open-source code (beyond scans)

## Repo layout

```
README.md            ← you are here
scope.md             ← scope matrix, gray zones, compliance notes
info, target         ← raw program page copies (pre-existing)
email                ← bugcrowdninja account email
vulnerability-rating-taxonomy.json ← Bugcrowd VRT reference
recon/
  api-endpoints.md   ← full REST API endpoint inventory (from official OpenAPI index)
  domains-and-instances.md ← SDK service domains per region (US/EU/federal)
  sdk-wire-format.md ← endpoints/headers/params the real SDKs send (from js-core source)
plans/
  test-plan.md       ← prioritized hypotheses, pre/post-auth phases
findings/
  TEMPLATE.md        ← report template matching program report guidelines
  log.md             ← research activity log
sdk/                 ← gitignored clones (js-core, react-client-sdk)
```

## Environment notes (this sandbox)

- Direct egress from this sandbox is restricted: `curl`/`git` reach **GitHub only**; LaunchDarkly
  domains are NOT directly reachable. Passive recon here goes through the docs fetch proxy.
- Active testing (authenticated API/UI, streamer, events) must be run **from the researcher's
  browser/machine**. Everything in `plans/test-plan.md` is written as actionable steps for that.

## Workflow

1. Keep `findings/log.md` current (dates, what was tried, what was observed).
2. Each real finding → copy `findings/TEMPLATE.md`, fill it out, link evidence.
3. Credentials live in `.env` / `credentials*` (gitignored) — never in tracked files.
