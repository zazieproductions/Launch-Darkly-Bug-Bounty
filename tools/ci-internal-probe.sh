#!/usr/bin/env bash
# Internal-API probe: the 142 /internal/* paths mined out of the app's JS bundles
# (ci-results/run-2/bundle-api-paths.txt) plus the internal header names found alongside them.
#
# SAFETY POLICY FOR THIS SCRIPT (deliberate, please don't loosen it):
#   * GET only. No POST/PUT/PATCH/DELETE anywhere.
#   * EXCLUDED BY DESIGN — never probed, because they are mutating, credential-bearing, or
#     generate email/tickets for real people (program excludes support-team interfaces, email
#     bombing, and anything that compromises other users):
#       /internal/account/{login,login2,signup*,signupv2,join,forgot,verify-code,
#                          resend-verification,revoke-sessions,card,accrued-invoices,owner,
#                          saml*,scim*,tokens,subscription,suggest-invites,session*}
#       /internal/profile/{password,mfa/*,resend-verification,cancel-verification}
#       /internal/reset/{passwordResetToken}          (password-reset token; do not enumerate)
#       /internal/invite/{token}[, /mfa]              (invite token; do not enumerate)
#       /internal/login/mfa/confirm, /internal/forgot, /internal/contact-us/**
#       anything with bulk-version-update, /cancel, /probe, /upload-url, /completion (mutating or
#       server-side side effects — documented as targets for AUTHENTICATED, owner-tenant testing
#       in plans/test-plan.md, not for unauth blind probing)
#   * Dummy identifiers only. We never point a request at another customer's project/account.
#   * ~90 requests total, 0.2s apart. No volume/rate-limit testing (out of scope).
set -uo pipefail

LD='https://app.launchdarkly.com'
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36'
OUT="${CI_RESULTS_DIR:-ci-results/local}"
mkdir -p "$OUT/raw2"
RES="$OUT/internal-probe.txt"
HITS="$OUT/internal-probe-hits.txt"
: > "$RES"; : > "$HITS"

# Optional: a REAL account id (ours) makes the ld-account header test meaningful.
# Without it we still learn which endpoints answer unauthenticated.
ACC="${LD_ACCOUNT_ID:-}"

get() { # get <label> <path> [curl args...]
  local label="$1" path="$2"; shift 2
  local tag; tag=$(echo "$label" | tr -c 'a-zA-Z0-9._-' '_')
  local code
  code=$(curl -sS -D "$OUT/raw2/$tag.hdr" -o "$OUT/raw2/$tag.body" -w '%{http_code}' \
         --max-time 15 -A "$UA" "$@" "$LD$path" 2>"$OUT/raw2/$tag.err" || echo ERR)
  local size; size=$(wc -c < "$OUT/raw2/$tag.body" 2>/dev/null | tr -d ' ')
  local body; body=$(head -c 400 "$OUT/raw2/$tag.body" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
  printf '%-62s %-4s %8sB  %s\n' "$label" "$code" "$size" "$body" | tee -a "$RES"
  case "$code" in
    2*|3*) echo "*** $label -> $code  $body" | tee -a "$HITS"
           sed 's/^/    HDR /' "$OUT/raw2/$tag.hdr" 2>/dev/null | head -15 | tee -a "$HITS"
           echo "    BODY(first 4k):" | tee -a "$HITS"
           head -c 4096 "$OUT/raw2/$tag.body" 2>/dev/null | tee -a "$HITS"; echo | tee -a "$HITS";;
  esac
  sleep 0.2
}

echo "=== 1. read-only internal endpoints, NO credentials ===" | tee -a "$RES"
for p in \
  "/internal/" \
  "/internal/config/anonymous" \
  "/internal/config/authenticated" \
  "/internal/plans" \
  "/internal/billingv2/plans" \
  "/internal/billingv2/plans/enterprise/limits" \
  "/internal/role-presets-bundle" \
  "/internal/accesses" \
  "/internal/entitlements/ai-configs" \
  "/internal/entitlements/release-guardian" \
  "/internal/metric-data-sources" \
  "/internal/usage/sdk-active" \
  "/internal/warehouse-integrations-health" \
  "/internal/unauthenticated-members/organization-verifications" \
  "/internal/account" \
  "/internal/actions" \
  "/internal/announcements" \
  "/internal/projects" \
  "/internal/projects/flag-count" \
  "/internal/profile" \
  "/internal/profile/context" \
  "/internal/profile/following" \
  "/internal/profile/notification-settings" \
  "/internal/account/subscription" \
  "/internal/billingv2/account/subscription" \
  "/internal/billingv2/account/subscription/usage" \
  "/internal/billingv2/account/subscription/usage-status" \
  "/internal/billingv2/account/subscription/trial-extension/eligibility" \
  "/internal/billingv2/account/subscription/opportunity/enterprise-seats" \
  "/internal/billingv2/account/subscription/campaigns" \
  "/internal/flags/thisprojectshouldnotexist" \
  "/internal/ai/evaluations/providers" \
  "/internal/projects/thisprojectshouldnotexist/flag-templates" \
  "/internal/projects/thisprojectshouldnotexist/flags/search" \
  "/internal/projects/thisprojectshouldnotexist/playgrounds" \
  "/internal/projects/thisprojectshouldnotexist/datasets" \
  "/internal/projects/thisprojectshouldnotexist/evaluations" \
  "/internal/projects/thisprojectshouldnotexist/metric-data-sources" \
  "/internal/projects/thisprojectshouldnotexist/applications" \
  "/internal/projects/thisprojectshouldnotexist/assignment-data-sources" \
  ; do
  get "GET $p" "$p"
done

echo | tee -a "$RES"
echo "=== 2. authorization access-check oracle (GET, dummy service names) ===" | tee -a "$RES"
for s in flags projects members account nonexistent-service; do
  get "GET /internal/authorization/access-check/$s/bulk" "/internal/authorization/access-check/$s/bulk"
done

echo | tee -a "$RES"
echo "=== 3. ld-account header with a real account id (needs LD_ACCOUNT_ID) ===" | tee -a "$RES"
if [ -n "$ACC" ]; then
  for p in "/internal/account" "/internal/actions" "/internal/announcements" \
           "/internal/config/authenticated" "/internal/role-presets-bundle" \
           "/internal/projects" "/internal/profile" "/internal/accesses" \
           "/api/v2/announcements" "/internal/unauthenticated-members/organization-verifications"; do
    get "GET $p [ld-account]" "$p" -H "ld-account: $ACC"
    get "GET $p [LD-Account-Id]" "$p" -H "LD-Account-Id: $ACC"
  done
else
  echo "  skipped: LD_ACCOUNT_ID not set (our own account id, from /api/v2/caller-identity" | tee -a "$RES"
  echo "  '_links.self.href' or any /api/v2/account/{id}/... URL in the browser)" | tee -a "$RES"
fi

echo | tee -a "$RES"
echo "=== 4. internal LD headers found in the bundles (behavioural diff vs baseline) ===" | tee -a "$RES"
# ld-flag-override / ld-gonfalon-overrides are LD's own dogfooding flag system (gonfalon).
# If the app honours them from a client request, that is client-controlled internal feature
# gating. Read-only probes on a benign endpoint only.
for hspec in \
  'ld-flag-override: showAll=true' \
  'ld-gonfalon-overrides: {}' \
  'ld-bypass-ua-tracking: true' \
  'ld-data-source: test' \
  'ld-observability: true' \
  'x-ld-project-id: thisprojectshouldnotexist' \
  'x-ld-envid: thisenvshouldnotexist' \
  'ld-account-id-verification-for-salesforce: test' ; do
  for p in "/internal/config/anonymous" "/internal/plans" "/internal/role-presets-bundle"; do
    tagh=$(echo "$hspec" | tr -c 'a-zA-Z0-9' '_')
    get "GET $p [$tagh]" "$p" -H "$hspec"
  done
done

echo | tee -a "$RES"
echo "=== 5. baseline comparison: same endpoints WITHOUT the header ===" | tee -a "$RES"
for p in "/internal/config/anonymous" "/internal/plans" "/internal/role-presets-bundle"; do
  get "GET $p [baseline]" "$p"
done

echo | tee -a "$RES"
echo "=== 6. bundle grep: how the internal headers are actually set ===" | tee -a "$RES"
# ci-route-matrix.sh §7f extracts these (it deletes the raw bundles to keep the commit small).
found=0
for f in "$OUT"/bundle-ctx-*.txt ci-results/*/bundle-ctx-*.txt; do
  [ -s "$f" ] || continue
  found=1
  echo "--- $(basename "$f") ---" | tee -a "$RES"
  head -c 2500 "$f" | tee -a "$RES"; echo | tee -a "$RES"
done
[ "$found" -eq 1 ] || echo "  (no bundle-ctx-*.txt present; run tools/ci-route-matrix.sh first)" | tee -a "$RES"

echo | tee -a "$RES"
echo "=== 7. undocumented /api/v2 paths: bundle strings vs public OpenAPI spec ===" | tee -a "$RES"
if [ -f "$OUT/bundle-api-paths.txt" ] && [ -f "$OUT/openapi-paths.txt" ]; then
  grep -E '^/api/v2/' "$OUT/bundle-api-paths.txt" | sed 's/\${[^}]*}/{x}/g; s/{[^}]*}/{x}/g' | sort -u \
    > "$OUT/tmp-bundle-v2.txt"
  awk '{print $2}' "$OUT/openapi-paths.txt" | sed 's/{[^}]*}/{x}/g' | sort -u > "$OUT/tmp-spec-v2.txt"
  comm -23 "$OUT/tmp-bundle-v2.txt" "$OUT/tmp-spec-v2.txt" > "$OUT/undocumented-api-v2-paths.txt"
  echo "  bundle-only /api/v2 paths (not in the public spec): $(wc -l < "$OUT/undocumented-api-v2-paths.txt")" | tee -a "$RES"
  head -60 "$OUT/undocumented-api-v2-paths.txt" | tee -a "$RES"
  rm -f "$OUT/tmp-bundle-v2.txt" "$OUT/tmp-spec-v2.txt"
else
  echo "  (needs bundle-api-paths.txt + openapi-paths.txt from ci-route-matrix.sh in the same dir)" | tee -a "$RES"
fi

echo | tee -a "$RES"
echo "=== 8. deep dive: /internal/config/anonymous (unauthenticated config dump) ===" | tee -a "$RES"
# Confirmed live 2026-09-11: this endpoint answers with NO credentials and returns LD's own
# dogfood config + internal client-side feature flags. Capture it fully and characterise it.
CFG="$OUT/internal-config-anonymous.json"
curl -sS --compressed --max-time 30 -A "$UA" -D "$OUT/raw2/cfg_anon.hdr" \
  "$LD/internal/config/anonymous" -o "$CFG" 2>/dev/null || true
echo "  size: $(wc -c < "$CFG" 2>/dev/null | tr -d ' ') bytes" | tee -a "$RES"
echo "  response headers:" | tee -a "$RES"
sed 's/^/    /' "$OUT/raw2/cfg_anon.hdr" 2>/dev/null | head -20 | tee -a "$RES"

# Second fetch: is the dogfood context / secure-mode hash per-request random or stable?
CFG2="$OUT/raw2/cfg_anon_2.json"
sleep 1
curl -sS --compressed --max-time 30 -A "$UA" "$LD/internal/config/anonymous" -o "$CFG2" 2>/dev/null || true
# Third fetch: does a client-supplied cookie/param change the signed context? (read-only GETs)
CFG3="$OUT/raw2/cfg_anon_cookie.json"
curl -sS --compressed --max-time 30 -A "$UA" \
  -H 'Cookie: ld_anonymous_id=bugcrowd-test-0001; sandboxVisitorAccountId=bugcrowd-test-0001' \
  "$LD/internal/config/anonymous?contextKey=bugcrowd-test-0002" -o "$CFG3" 2>/dev/null || true

python3 - "$CFG" "$CFG2" "$CFG3" <<'PY' | tee -a "$RES"
import json, sys, re
def load(p):
    try:
        return json.load(open(p, errors='ignore'))
    except Exception:
        return None
a, b, c = (load(p) for p in sys.argv[1:4])
def summary(d, label):
    if not isinstance(d, dict):
        print(f"  {label}: <not JSON / unavailable>")
        return
    ctx = d.get('dogfoodContext') or {}
    sess = (ctx.get('session') or {}).get('key')
    user = (ctx.get('user') or {}).get('key')
    flags = d.get('allClientSideFlags') or {}
    print(f"  {label}: clientSideId={d.get('clientSideId')}")
    print(f"        dogfoodBaseUri={d.get('dogfoodBaseUri')}")
    print(f"        dogfoodStreamUri={d.get('dogfoodStreamUri')}")
    print(f"        dogfoodEventsUri={d.get('dogfoodClientSideEventsUri')}  sendEvents={d.get('dogfoodSendEvents')}")
    print(f"        dogfoodContext.session.key={sess}")
    print(f"        dogfoodContext.user.key={user}  user.attrs={ {k:v for k,v in (ctx.get('user') or {}).items() if k not in ('key',)} }")
    print(f"        secureModeContextHash={d.get('secureModeContextHash')}")
    print(f"        top-level keys={sorted(d.keys())}")
    print(f"        allClientSideFlags: {len(flags)} entries; $valid={flags.get('$valid')}")
summary(a, 'fetch#1')
summary(b, 'fetch#2')
summary(c, 'fetch#3 (cookie+param supplied)')

if isinstance(a, dict) and isinstance(b, dict):
    ha, hb = a.get('secureModeContextHash'), b.get('secureModeContextHash')
    ka = ((a.get('dogfoodContext') or {}).get('session') or {}).get('key')
    kb = ((b.get('dogfoodContext') or {}).get('session') or {}).get('key')
    print(f"  --> secureModeContextHash stable across requests? {ha == hb}")
    print(f"  --> dogfood session key stable across requests?   {ka == kb}")
    if ha == hb and ka == kb:
        print("      STABLE: the signed context is not per-visitor -> check what it is derived from")
    else:
        print("      PER-REQUEST: server signs a fresh anonymous context each call")
if isinstance(a, dict) and isinstance(c, dict):
    kc = ((c.get('dogfoodContext') or {}).get('session') or {}).get('key')
    ka = ((a.get('dogfoodContext') or {}).get('session') or {}).get('key')
    print(f"  --> attacker-supplied cookie/param changed the signed context key? {kc != ka} (fetch#3 key={kc})")
    if kc and 'bugcrowd-test' in str(kc):
        print("      *** CONTEXT IS ATTACKER-CONTROLLED -> the server will sign an arbitrary context")
        print("          key with a valid secure-mode hash => secure-mode bypass primitive (H5). ***")

# inventory the disclosed flags + confidential-looking strings
if isinstance(a, dict):
    flags = a.get('allClientSideFlags') or {}
    open(sys.argv[1] + '.flagnames.txt', 'w').write('\n'.join(sorted(flags)) + '\n')
    print(f"  --> flag names written to internal-config-anonymous.json.flagnames.txt ({len(flags)})")
    blob = json.dumps(a)
    jira = sorted(set(re.findall(r'\b[A-Z]{3,8}-\d{2,6}\b', blob)))
    print(f"  --> internal ticket refs disclosed: {len(jira)} -> {jira[:25]}")
    hosts = sorted(set(re.findall(r'https?://[a-zA-Z0-9._-]+', blob)))
    print(f"  --> hosts referenced: {hosts[:25]}")
    for needle in ('not yet built', 'not planned', 'Q3 2026', 'legacy Airflow', 'junk-country',
                   'federal', 'commit '):
        n = blob.lower().count(needle.lower())
        if n:
            print(f"  --> confidential-roadmap phrase {needle!r}: {n} occurrence(s)")
PY

# keep the full config (public data, no customer secrets) but bound everything else
cp "$CFG" "$OUT/internal-config-anonymous-fetch1.json" 2>/dev/null || true
find "$OUT/raw2" -type f -size +256k -delete 2>/dev/null || true
echo "internal-probe done -> $OUT (hits: $(grep -c '^\*\*\*' "$HITS" 2>/dev/null || echo 0))" | tee -a "$RES"
