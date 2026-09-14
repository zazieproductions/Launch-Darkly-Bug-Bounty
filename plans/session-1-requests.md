# Session 1 — Request Sheet (copy-paste ready)

Run these from your own machine/browser (this sandbox can't reach LaunchDarkly hosts).
Replace `{proj}`/`{env}` with your org's keys once the account exists.
Paste the raw responses back to the agent — especially the ⭐ ones.

## Part A — Unauthenticated (no account needed)

```bash
# A1 ⭐ — Announcements "public" endpoints (H4: are they really unauth?)
curl -sS -i 'https://app.launchdarkly.com/api/v2/announcements'

# A2 — DO NOT RUN. Unauth announcement writes were removed from the plan on 2026-09-11.
# Live probing showed the unauth GET is gated by an undocumented "account ID header"
# (see recon/live-probe-results.md O1). Announcements render as in-app banners for ALL
# customers with severity=critical and scheduling support, so an unauthenticated POST is a
# service-wide content change — the program says stop and report, not exercise. If unauth
# READ is confirmed, report it and describe the write risk without testing it.

# A3 — caller identity, no auth (expect 401 JSON; record error shape)
curl -sS -i 'https://app.launchdarkly.com/api/v2/caller-identity'

# A4 — public IP list (expect 200)
curl -sS -i 'https://app.launchdarkly.com/api/v2/ips'

# A5 ⭐ — streamer route existence (404 = no route, 401 = route + auth check).
for p in all eval/contexts msdk msdk/bulk bulk_eval/contexts eval/thisidshouldnotexist ping/x meval/AAAA mping; do
  printf '%-28s ' "/$p"
  curl -sS -o /dev/null -w '%{http_code}\n' --max-time 5 "https://stream.launchdarkly.com/$p"
done

# A6 ⭐ — app host as documented SDK polling fallback (in-scope host!)
curl -sS -i 'https://app.launchdarkly.com/sdk/evalx/thisidshouldnotexist/contexts/AAAA'
curl -sS -i 'https://app.launchdarkly.com/msdk/evalx/contexts/AAAA'

# A7 — events recorder (empty batch = no-op; safe)
curl -sS -i 'https://events.launchdarkly.com/events/identify'
curl -sS -i -X POST 'https://events.launchdarkly.com/events/identify' \
  -H 'Content-Type: application/json' -d '[]'
```

**A8 — CORS + Origin/session check (browser).** Do it TWICE: while logged OUT, then while
logged IN to app.launchdarkly.com. Each time: open a page on a non-LD origin (e.g.
`https://example.com`), F12 console, paste:

```js
(async () => {
  try {
    const r = await fetch('https://app.launchdarkly.com/api/v2/caller-identity',
                          {credentials: 'include'});
    console.log('status:', r.status);
    console.log('ACAO:', r.headers.get('access-control-allow-origin'));
    console.log('body:', await r.text());
  } catch (e) { console.log('FETCH THREW (CORS/NET):', e.message); }
})();
```
Record: status, ACAO header value, body (or the CORS error text). This is the read-side of
H1 (CORS echoes any origin; session auth must be rejected by the Origin check).

**A9 — docs search reflection.** Navigate to
`https://launchdarkly.com/docs/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` →
View Source (Ctrl+U) → search for `onerror`. Same on `docs.launchdarkly.com`. If absent from
raw HTML → client-side rendered (Algolia) → note "no SSR reflection" and move on.

## Part B — Account + token (UI)

1. Sign up: `https://app.launchdarkly.com/signup` with `zazieproductions@bugcrowdninja.com`.
2. Verify full-feature access (Experimentation, AgentControl, Observability, Guarded rollouts
   trial, Release management should all be present).
3. Gear icon → **Authorization / API access tokens** → New **personal** token,
   name `bugcrowd-agent`, role **Owner** (needed for the authz matrix + `showAll`).
   Copy the value immediately (shown once). → send it to the agent (stored in gitignored `.env`)
   OR just run Part C yourself and paste responses.
4. Note from the UI: org name, project key, environment key (they're in the URL bars).

## Part C — Authenticated baseline (all GETs — safe)

```bash
LD='https://app.launchdarkly.com'
H='Authorization: <paste-your-lpat-token>'
P='{proj}'; E='{env}'

# C1 ⭐ — who am I (role/scopes/tokenKind — required in every report)
curl -sS -H "$H" "$LD/api/v2/caller-identity"

# C2 ⭐ — org inventory; expanded environments include the REAL sdk-/mob- key
# values AND the secureMode flag per environment (feeds H5 setup)
curl -sS -H "$H" "$LD/api/v2/projects?expand=environments"

# C3 — flags + segments in the env
curl -sS -H "$H" "$LD/api/v2/projects/$P/environments/$E/features"
curl -sS -H "$H" "$LD/api/v2/projects/$P/environments/$E/segments"

# C4 ⭐ — context kinds (focus area)
curl -sS -H "$H" "$LD/api/v2/projects/$P/context-kinds?expand=environmentObservations"

# C5 ⭐ — SDK keys (beta endpoint; response contains full key values —
# note which roles later can/can't see these)
curl -sS -H "$H" -H 'LD-API-Version: beta' \
  "$LD/api/v2/projects/$P/environments/$E/sdk-keys"

# C6 ⭐ — tokens list (should show only last-4 of each token;
# if full values appear for others' tokens -> finding)
curl -sS -H "$H" "$LD/api/v2/tokens"
curl -sS -H "$H" "$LD/api/v2/tokens?showAll=true"

# C7 ⭐ — relay proxy configs (docs say list includes `fullKey` — the config key value)
curl -sS -H "$H" "$LD/api/v2/account/relay-auto-configs"

# C8 ⭐ — webhooks list (docs say items include `secret` — confirm what's returned)
curl -sS -H "$H" "$LD/api/v2/webhooks"

# C9 ⭐ — experiments (focus area)
curl -sS -H "$H" "$LD/api/v2/projects/$P/environments/$E/experiments"

# C10 — recent audit entries (limit 1..20 only)
curl -sS -H "$H" "$LD/api/v2/auditlog?limit=20"

# C11 — announcements WITH auth (compare vs A1)
curl -sS -H "$H" "$LD/api/v2/announcements"

# C12 — teams + custom roles (authz baseline)
curl -sS -H "$H" "$LD/api/v2/teams"
curl -sS -H "$H" "$LD/api/v2/custom-roles"

# C13 ⭐ — version-pinning sanity: same call on the oldest API version
curl -sS -H "$H" -H 'LD-API-Version: 20160426' "$LD/api/v2/projects"
```

## Paste back (priority order)

1. A1 + A2 (announcements behavior) — H4 may already be a finding.
2. A5/A6 status-code table + one full response from A6 (error shape per route).
3. A8 outputs (both runs) — H1 read side.
4. C1, C2 (env keys + `secureMode` per env), C4, C5–C8, C13.
5. Anything that looks odd (unexpected 2xx, fields you didn't expect, errors with detail).

Then the agent plans Session 2: IDOR matrix + new-action PCE sweep + H5 secure-mode/oracle.
