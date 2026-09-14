#!/usr/bin/env bash
# Session 1 recon runner for the LaunchDarkly bug bounty.
#
# SAFE BY DEFAULT: unauthenticated Part A reads + authenticated Part C GETs only.
# The ONE write (A2, unauth POST to announcements) is OFF unless you pass
# --include-announcement-write, and is clearly marked for deletion.
#
# Usage:
#   LD_TOKEN='api-...' bash tools/run-session1.sh
#   LD_TOKEN='api-...' bash tools/run-session1.sh --include-announcement-write
#
# Output: scratch/responses/<timestamp>/  (gitignored) — paste the printed
# summary + interesting files back to the agent.
set -uo pipefail

LD='https://app.launchdarkly.com'
STREAM='https://stream.launchdarkly.com'
EVENTS='https://events.launchdarkly.com'
OUT="scratch/responses/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

INCLUDE_WRITE=0
[ "${1:-}" = "--include-announcement-write" ] && INCLUDE_WRITE=1

j() { python3 -c "import sys,json;d=json.load(sys.stdin);print(json.dumps(d,indent=1))" 2>/dev/null; }

echo "### Session 1 run — output in $OUT"
echo

echo "== Part A: unauthenticated =="
echo "-- A1 announcements (unauth) --"
curl -sS -i --max-time 15 "$LD/api/v2/announcements" > "$OUT/A1_announcements_unauth.txt" || true
head -3 "$OUT/A1_announcements_unauth.txt"

if [ "$INCLUDE_WRITE" -eq 1 ]; then
  # A2 REMOVED ON PURPOSE (2026-09-11).
  #
  # Live probing showed unauth GET /api/v2/announcements answers
  #   {"code":"unauthorized","message":"Invalid account ID header"}
  # i.e. this route is gated by an undocumented account-ID header, not by the normal
  # access-token path. Its write siblings (createAnnouncementPublic / updateAnnouncementPublic /
  # deleteAnnouncementPublic) create announcements that are rendered as in-app banners with
  # severity=info|warning|critical and start/end scheduling -- for EVERY customer, not just our
  # own tenant. An unauthenticated POST here is therefore a potential service-wide content change:
  # exactly the "compromises other users / destructive post-exploitation" case the program says to
  # STOP on and report instead of exercising. See recon/live-probe-results.md O1.
  #
  # If unauth READ is ever confirmed, report it and describe the write risk as unexercised.
  echo "-- A2 permanently disabled: unauth announcement writes could affect all customers --"
  echo "   (program rule: stop and report rather than perform destructive/wide-blast-radius writes)"
fi

echo "-- A3 caller-identity (unauth) --"
curl -sS -i --max-time 15 "$LD/api/v2/caller-identity" > "$OUT/A3_caller_unauth.txt" || true
head -3 "$OUT/A3_caller_unauth.txt"

echo "-- A4 ips (public) --"
curl -sS -o "$OUT/A4_ips.txt" -w 'code=%{http_code}\n' --max-time 15 "$LD/api/v2/ips" || true

echo "-- A5 stream.launchdarkly.com route sweep --"
: > "$OUT/A5_stream_routes.txt"
for p in all eval/contexts msdk msdk/bulk bulk_eval/contexts eval/thisidshouldnotexist ping/x meval/AAAA mping; do
  CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$STREAM/$p" 2>/dev/null || echo ERR)
  echo "/$p -> $CODE" | tee -a "$OUT/A5_stream_routes.txt"
done

echo "-- A6 app host SDK polling fallback routes --"
: > "$OUT/A6_app_sdk_routes.txt"
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$LD/sdk/evalx/thisidshouldnotexist/contexts/AAAA" 2>/dev/null || echo ERR)
echo "GET /sdk/evalx/{id}/contexts/AAAA -> $CODE" | tee -a "$OUT/A6_app_sdk_routes.txt"
CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$LD/msdk/evalx/contexts/AAAA" 2>/dev/null || echo ERR)
echo "GET /msdk/evalx/contexts/AAAA -> $CODE" | tee -a "$OUT/A6_app_sdk_routes.txt"

echo "-- A7 events.launchdarkly.com --"
curl -sS -i --max-time 10 "$EVENTS/events/identify" > "$OUT/A7_events_get.txt" || true
curl -sS -i --max-time 10 -X POST "$EVENTS/events/identify" \
  -H 'Content-Type: application/json' -d '[]' > "$OUT/A7_events_post_empty.txt" || true
head -1 "$OUT/A7_events_get.txt"
echo "    (A8 CORS/Origin + A9 docs-search are browser-only — see plans/session-1-requests.md)"

echo
if [ -z "${LD_TOKEN:-}" ]; then
  echo "!! No LD_TOKEN set — skipping Part C. Re-run with: LD_TOKEN='api-...' bash tools/run-session1.sh"
  echo
  echo "Files: $(ls "$OUT" | tr '\n' ' ')"
  exit 0
fi
H="Authorization: $LD_TOKEN"

echo "== Part C: authenticated (GETs only) =="
echo "-- C1 caller-identity --"
curl -sS --max-time 15 -H "$H" "$LD/api/v2/caller-identity" | j > "$OUT/C1_caller.json" || true
head -20 "$OUT/C1_caller.json"

echo "-- C2 projects?expand=environments --"
curl -sS --max-time 20 -H "$H" "$LD/api/v2/projects?expand=environments" | j > "$OUT/C2_projects.json" || true
P=$(python3 -c "
import json
d=json.load(open('$OUT/C2_projects.json'))
items=d.get('items',[])
print(items[0]['key'] if items else '')" 2>/dev/null)
E=$(python3 -c "
import json
d=json.load(open('$OUT/C2_projects.json'))
items=d.get('items',[])
envs=(items[0].get('environments') or {}).get('items',[]) if items else []
print(envs[0]['key'] if envs else '')" 2>/dev/null)
echo "    first project=$P env=$E"
python3 - "$OUT/C2_projects.json" <<'EOF' 2>/dev/null | tee -a "$OUT/C2_summary.txt"
import json,sys
d=json.load(open(sys.argv[1]))
print("env key material + secureMode per environment (from expand=environments):")
for pr in d.get('items',[]):
    for e in (pr.get('environments') or {}).get('items',[]):
        print(f"  {pr['key']}/{e['key']}: sdk={e.get('apiKey','?')[:9]}… mob={e.get('mobileKey','?')[:9]}… secureMode={e.get('secureMode')}")
EOF

echo "-- C3 flags + segments --"
[ -n "${P:-}" ] && [ -n "${E:-}" ] || { echo "    (skipped — no project/env found)"; }
[ -n "${P:-}" ] && [ -n "${E:-}" ] && curl -sS --max-time 20 -H "$H" "$LD/api/v2/projects/$P/environments/$E/features" | j > "$OUT/C3_features.json" || true
[ -n "${P:-}" ] && [ -n "${E:-}" ] && curl -sS --max-time 20 -H "$H" "$LD/api/v2/projects/$P/environments/$E/segments" | j > "$OUT/C3_segments.json" || true
echo "    features: $(python3 -c "import json;print(len(json.load(open('$OUT/C3_features.json')).get('items',[])))" 2>/dev/null || echo '?')  segments: $(python3 -c "import json;print(len(json.load(open('$OUT/C3_segments.json')).get('items',[])))" 2>/dev/null || echo '?')"

echo "-- C4 context-kinds --"
[ -n "${P:-}" ] && curl -sS --max-time 20 -H "$H" "$LD/api/v2/projects/$P/context-kinds?expand=environmentObservations" | j > "$OUT/C4_context_kinds.json" || true
echo "    $(head -5 "$OUT/C4_context_kinds.json" 2>/dev/null | tr '\n' ' ')"

echo "-- C5 sdk-keys (beta) --"
[ -n "${P:-}" ] && [ -n "${E:-}" ] && curl -sS --max-time 20 -H "$H" -H 'LD-API-Version: beta' \
  "$LD/api/v2/projects/$P/environments/$E/sdk-keys" | j > "$OUT/C5_sdk_keys.json" || true
echo "    (full key values are in the file — don't paste that file verbatim to chat)"

echo "-- C6 tokens (own + showAll) --"
curl -sS --max-time 20 -H "$H" "$LD/api/v2/tokens" | j > "$OUT/C6_tokens.json" || true
curl -sS --max-time 20 -H "$H" "$LD/api/v2/tokens?showAll=true" | j > "$OUT/C6_tokens_showall.json" || true
echo "    token-value check: $(grep -c '"token":' "$OUT/C6_tokens.json" 2>/dev/null) entries; any full (long) values? -> inspect file"

echo "-- C7 relay-auto-configs --"
curl -sS --max-time 20 -H "$H" "$LD/api/v2/account/relay-auto-configs" | j > "$OUT/C7_relay.json" || true

echo "-- C8 webhooks --"
curl -sS --max-time 20 -H "$H" "$LD/api/v2/webhooks" | j > "$OUT/C8_webhooks.json" || true
echo "    secret field present? $(grep -c '"secret"' "$OUT/C8_webhooks.json" 2>/dev/null || true)"

echo "-- C9 experiments --"
[ -n "${P:-}" ] && [ -n "${E:-}" ] && curl -sS --max-time 20 -H "$H" "$LD/api/v2/projects/$P/environments/$E/experiments" | j > "$OUT/C9_experiments.json" || true

echo "-- C10 auditlog (limit 20) --"
curl -sS --max-time 20 -H "$H" "$LD/api/v2/auditlog?limit=20" | j > "$OUT/C10_auditlog.json" || true

echo "-- C11 announcements (auth) --"
curl -sS --max-time 15 -H "$H" "$LD/api/v2/announcements" | j > "$OUT/C11_announcements_auth.json" || true

echo "-- C12 teams + custom-roles --"
curl -sS --max-time 20 -H "$H" "$LD/api/v2/teams" | j > "$OUT/C12_teams.json" || true
curl -sS --max-time 20 -H "$H" "$LD/api/v2/custom-roles" | j > "$OUT/C12_custom_roles.json" || true

echo "-- C13 projects on LD-API-Version 20160426 --"
curl -sS --max-time 20 -H "$H" -H 'LD-API-Version: 20160426' "$LD/api/v2/projects" | j > "$OUT/C13_projects_oldver.json" || true
echo "    code: $(head -3 "$OUT/C13_projects_oldver.json" | tr '\n' ' ')"

echo
echo "### DONE. Files:"
ls -la "$OUT"
echo
echo "Paste back to the agent: the summary printed above + A1, A5, A6, A7, C1, C2, C6 (redact long token values), C8 (secret field), C10 (first entries), C13."
