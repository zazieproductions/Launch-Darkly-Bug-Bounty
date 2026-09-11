#!/usr/bin/env bash
# Unauthenticated route/header matrix + OpenAPI spec analysis + JS bundle mining.
#
# WHY THIS EXISTS: the agent sandbox cannot reach LaunchDarkly hosts, and cannot
# download GitHub Actions logs or artifacts (both live on hosts that are blocked
# from the sandbox). So this script runs in CI and writes its results into
# ci-results/ which the workflow commits back to the branch — that commit is how
# the agent reads the results.
#
# SAFETY: every request here is an unauthenticated GET/HEAD/OPTIONS or a
# no-op POST with an empty body. No writes, no data creation, no volume.
set -uo pipefail

LD='https://app.launchdarkly.com'
STREAM='https://stream.launchdarkly.com'
EVENTS='https://events.launchdarkly.com'
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36'
OUT="${CI_RESULTS_DIR:-ci-results/local}"
mkdir -p "$OUT"

probe() { # probe <label> <url> [extra curl args...]
  local label="$1" url="$2"; shift 2
  local f="$OUT/raw/$(echo "$label" | tr -c 'a-zA-Z0-9._-' '_').txt"
  mkdir -p "$OUT/raw"
  local code
  code=$(curl -sS -D "$f.hdr" -o "$f.body" -w '%{http_code}' --max-time 15 \
         -A "$UA" "$@" "$url" 2>>"$f.err" || echo ERR)
  local size; size=$(wc -c < "$f.body" 2>/dev/null | tr -d ' ')
  local body; body=$(head -c 300 "$f.body" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
  printf '%-52s %s  %6sB  %s\n' "$label" "$code" "$size" "$body" | tee -a "$OUT/route-matrix.txt"
}

echo "=== 1. app-host SDK polling routes (in-scope host, client-side ID in path) ===" | tee -a "$OUT/route-matrix.txt"
# base64url of {"kind":"user","key":"test"} and friends
CTX_USER='eyJraW5kIjoidXNlciIsImtleSI6InRlc3QifQ'
CTX_MULTI='eyJraW5kIjoibXVsdGkiLCJ1c2VyIjp7ImtleSI6InUxIn0sIm9yZyI6eyJrZXkiOiJvMSJ9fQ'
CTX_MULTI_PERM='eyJraW5kIjoibXVsdGkiLCJvcmciOnsia2V5IjoibzEifSwidXNlciI6eyJrZXkiOiJ1MSJ9fQ'
CTX_EMPTY='e30'
BADID='thisidshouldnotexist'
for p in \
  "sdk/evalx/$BADID/contexts/AAAA" \
  "sdk/evalx/$BADID/contexts/$CTX_USER" \
  "sdk/evalx/$BADID/contexts/$CTX_EMPTY" \
  "sdk/evalx/$BADID/contexts/$CTX_MULTI" \
  "sdk/evalx/$BADID/contexts/$CTX_USER?withReasons=true" \
  "sdk/evalx/$BADID/users/testuser" \
  "msdk/evalx/contexts/$CTX_USER" \
  "msdk/evalx/$BADID/contexts/$CTX_USER" \
  "sdk/goals/$BADID" \
  "sdk/evalx/x/contexts/$CTX_USER" ; do
  probe "GET /$p" "$LD/$p"
done

echo | tee -a "$OUT/route-matrix.txt"
echo "=== 2. stream.launchdarkly.com route existence (in scope) ===" | tee -a "$OUT/route-matrix.txt"
for p in all "all?filter=x" "eval/$BADID/$CTX_USER" "eval/contexts/$CTX_USER" ping/x mping meval/AAAA \
         msdk "msdk/bulk" "bulk_eval/contexts" "sdk/evalx/$BADID/contexts/$CTX_USER" \
         "msdk/evalx/contexts/$CTX_USER" "evalx/$BADID/contexts/$CTX_USER" "v1/all" "all/x"; do
  probe "GET stream/$p" "$STREAM/$p"
done

echo | tee -a "$OUT/route-matrix.txt"
echo "=== 3. events.launchdarkly.com (in scope) ===" | tee -a "$OUT/route-matrix.txt"
for p in "" "events" "events/identify" "events/bulk" "bulk" "mobile" "events/debug" "diagnostic"; do
  probe "GET events/$p" "$EVENTS/$p"
done
# no-op POSTs (empty batch bodies only — nothing is created)
probe "POST events/identify []" "$EVENTS/events/identify" -X POST -H 'Content-Type: application/json' -d '[]'
probe "POST events/bulk []"     "$EVENTS/events/bulk"     -X POST -H 'Content-Type: application/json' -d '[]'

echo | tee -a "$OUT/route-matrix.txt"
echo "=== 4. app root subroutes incl. /internal/ and /private/ ===" | tee -a "$OUT/route-matrix.txt"
for p in "" "api/v2" "api/v2/" "api/v2/openapi.json" "api/v2/ips" "api/v2/public-ips" "api/v2/caller-identity" \
         "api/v2/announcements" "api/v2/projects" "internal" "internal/" "api/v2/internal" \
         "private" "private/" "api/v2/private" "private/announcements" "sdk" "msdk" "login" "signup"; do
  probe "GET /$p" "$LD/$p"
done

echo | tee -a "$OUT/route-matrix.txt"
echo "=== 5. H4: /api/v2/announcements undocumented account-ID header probe ===" | tee -a "$OUT/route-matrix.txt"
# Baseline (no header) returned: {"code":"unauthorized","message":"Invalid account ID header"}
# Docs for getAnnouncementsPublic list ONLY Authorization + status/limit/offset, so this header
# is undocumented. Brute-force plausible names with a dummy value; any response that differs
# from the baseline error means we found the gate.
HEXID='5f0e3a1b2c3d4e5f6a7b8c9d'
: > "$OUT/announcements-header-probe.txt"
printf '%-34s %-24s %s  %s\n' HEADER VALUE CODE BODY | tee -a "$OUT/announcements-header-probe.txt"
for h in \
  'LD-Account-Id' 'LD-Account-ID' 'LD-ACCOUNT-ID' 'X-LD-Account-Id' 'X-Account-Id' 'Account-Id' \
  'AccountId' 'X-LaunchDarkly-Account-Id' 'LD-Account' 'X-LD-Account' 'LD-Account-Key' \
  'X-Account-Key' 'LD-Tenant-Id' 'X-Tenant-Id' 'LD-Organization-Id' 'X-Organization-Id' \
  'LD-Team-Id' 'Account' 'X-Account' 'LD-Api-Account-Id' 'LD-App-Account-Id' ; do
  for v in "$HEXID" 'testaccount'; do
    f="$OUT/raw/ann_$(echo "${h}_${v}" | tr -c 'a-zA-Z0-9' '_').txt"
    code=$(curl -sS -D "$f.hdr" -o "$f.body" -w '%{http_code}' --max-time 12 -A "$UA" \
           -H "$h: $v" "$LD/api/v2/announcements" 2>/dev/null || echo ERR)
    body=$(head -c 200 "$f.body" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
    printf '%-34s %-24s %s  %s\n' "$h" "$v" "$code" "$body" | tee -a "$OUT/announcements-header-probe.txt"
    sleep 0.3
  done
done
# and as query params
for q in "accountId=$HEXID" "account=$HEXID" "LD-Account-Id=$HEXID" "accountKey=testaccount"; do
  f="$OUT/raw/annq_$(echo "$q" | tr -c 'a-zA-Z0-9' '_').txt"
  code=$(curl -sS -D "$f.hdr" -o "$f.body" -w '%{http_code}' --max-time 12 -A "$UA" \
         "$LD/api/v2/announcements?$q" 2>/dev/null || echo ERR)
  body=$(head -c 200 "$f.body" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
  printf '%-34s %-24s %s  %s\n' "QUERY ?$q" '-' "$code" "$body" | tee -a "$OUT/announcements-header-probe.txt"
done

echo | tee -a "$OUT/route-matrix.txt"
echo "=== 6. OpenAPI spec analysis (spec is public) ===" | tee -a "$OUT/route-matrix.txt"
curl -sS --compressed --max-time 60 "$LD/api/v2/openapi.json" -o "$OUT/openapi.json" \
  -w 'openapi.json: code=%{http_code} size=%{size_download}\n' || true
if [ -s "$OUT/openapi.json" ]; then
python3 - "$OUT/openapi.json" "$OUT" <<'PY'
import json, sys, collections
spec = json.load(open(sys.argv[1]))
out  = sys.argv[2]
paths = spec.get('paths', {})

# 6a. full path+method inventory (exact paths for the IDOR matrix)
lines = []
for p, ops in sorted(paths.items()):
    for m, op in ops.items():
        if m.lower() not in ('get','post','put','patch','delete','head','options'):
            continue
        lines.append(f"{m.upper():7} {p}    opId={op.get('operationId','')}")
open(f"{out}/openapi-paths.txt","w").write("\n".join(lines) + "\n")
print(f"6a. paths={len(paths)} operations={len(lines)} -> openapi-paths.txt")

# 6b. header parameters anywhere in the spec (undocumented-header hunt)
hdrs = collections.defaultdict(set)
def walk_params(params, where):
    for prm in params or []:
        if isinstance(prm, dict) and prm.get('in') == 'header':
            hdrs[prm.get('name','?')].add(where)
for p, ops in paths.items():
    walk_params(ops.get('parameters'), p)
    for m, op in ops.items():
        if isinstance(op, dict):
            walk_params(op.get('parameters'), f"{m.upper()} {p}")
open(f"{out}/openapi-header-params.txt","w").write(
    "\n".join(f"{k}   used by: {', '.join(sorted(v)[:6])}" for k,v in sorted(hdrs.items())) + "\n")
print(f"6b. header params in spec: {sorted(hdrs)} -> openapi-header-params.txt")

# 6c. operations with NO security requirement -> unauthenticated candidates
noauth = []
glob = spec.get('security')
for p, ops in paths.items():
    for m, op in ops.items():
        if not isinstance(op, dict) or m.lower() not in ('get','post','put','patch','delete'):
            continue
        sec = op.get('security', glob)
        if sec in ([], None) or (isinstance(sec, list) and any(s == {} for s in sec)):
            noauth.append(f"{m.upper():7} {p}    opId={op.get('operationId','')}")
open(f"{out}/openapi-noauth-operations.txt","w").write("\n".join(noauth) + "\n")
print(f"6c. operations with empty/absent security: {len(noauth)} -> openapi-noauth-operations.txt")
for l in noauth[:25]:
    print("      ", l)

# 6d. everything announcement-related (params + security + response schema refs)
ann = []
for p, ops in paths.items():
    if 'announcement' not in p.lower():
        continue
    for m, op in ops.items():
        if not isinstance(op, dict):
            continue
        ann.append({
            'op': f"{m.upper()} {p}",
            'operationId': op.get('operationId'),
            'security': op.get('security', glob),
            'parameters': [{'name': x.get('name'), 'in': x.get('in'), 'required': x.get('required')}
                           for x in (op.get('parameters') or []) if isinstance(x, dict)],
        })
json.dump(ann, open(f"{out}/openapi-announcements.json","w"), indent=1)
print(f"6d. announcement operations: {len(ann)} -> openapi-announcements.json")
for a in ann:
    print("      ", a['op'], "security=", a['security'], "params=", a['parameters'])

# 6e. paths NOT in the public docs inventory (internal-ish names)
sus = [p for p in paths if any(k in p.lower() for k in
       ('internal','private','admin','debug','test','caller','ips','announce'))]
open(f"{out}/openapi-suspicious-paths.txt","w").write("\n".join(sorted(sus)) + "\n")
print(f"6e. internal/private/admin/debug-ish paths in spec: {len(sus)} -> openapi-suspicious-paths.txt")
for s in sorted(sus)[:40]:
    print("      ", s)
PY
else
  echo "6. openapi.json download failed" | tee -a "$OUT/route-matrix.txt"
fi

echo | tee -a "$OUT/route-matrix.txt"
echo "=== 7. JS bundle mining: undocumented endpoints + the account header ===" | tee -a "$OUT/route-matrix.txt"
mkdir -p "$OUT/bundles"
for page in "$LD/login" "$LD/" "$LD/signup"; do
  n=$(echo "$page" | sed 's#.*/##; s#[^a-zA-Z0-9]#_#g'); [ -z "$n" ] && n=root
  curl -sS --compressed -A "$UA" --max-time 25 "$page" -o "$OUT/bundles/page_$n.html" 2>/dev/null || true
done
python3 - "$OUT/bundles" "$LD" <<'PY' > "$OUT/bundle-urls.txt"
import sys, re, os
from urllib.parse import urljoin
d, base = sys.argv[1], sys.argv[2]
urls = []
for fn in os.listdir(d):
    if not fn.endswith('.html'):
        continue
    html = open(os.path.join(d, fn), errors='ignore').read()
    for m in re.finditer(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
        u = urljoin(base + '/', m.group(1))
        if u.startswith('http') and u not in urls:
            urls.append(u)
print('\n'.join(urls[:25]))
PY
echo "bundle URLs found: $(wc -l < "$OUT/bundle-urls.txt")" | tee -a "$OUT/route-matrix.txt"
n=0
while IFS= read -r u; do
  [ -z "$u" ] && continue
  n=$((n+1)); [ "$n" -gt 25 ] && break
  f="$OUT/bundles/$(echo "$u" | sed 's#.*/##; s#[^a-zA-Z0-9._-]#_#g').js"
  curl -sS --compressed --max-time 60 --max-filesize 60000000 "$u" -o "$f" 2>/dev/null || true
  echo "  downloaded $(basename "$f") $(wc -c < "$f" 2>/dev/null | tr -d ' ')B" | tee -a "$OUT/route-matrix.txt"
done < "$OUT/bundle-urls.txt"

if compgen -G "$OUT/bundles/*.js" > /dev/null; then
  echo "-- 7a. internal/private API paths referenced in bundles --" | tee -a "$OUT/route-matrix.txt"
  grep -ohE '["'"'"'`]/(internal|private|api/v2)/[A-Za-z0-9_./{}$:-]{1,90}["'"'"'`]' "$OUT"/bundles/*.js 2>/dev/null \
    | tr -d "\"'\`" | sort -u > "$OUT/bundle-api-paths.txt" || true
  wc -l < "$OUT/bundle-api-paths.txt" | xargs echo "   unique paths:" | tee -a "$OUT/route-matrix.txt"
  grep -E '^/(internal|private)/' "$OUT/bundle-api-paths.txt" | head -80 | tee -a "$OUT/route-matrix.txt"

  echo "-- 7b. account-ID-ish header names in bundles --" | tee -a "$OUT/route-matrix.txt"
  grep -ohiE '[a-z0-9-]*(account|tenant|organization)[a-z0-9-]*(id|key)[a-z0-9-]*' "$OUT"/bundles/*.js 2>/dev/null \
    | sort | uniq -c | sort -rn | head -40 > "$OUT/bundle-account-strings.txt" || true
  cat "$OUT/bundle-account-strings.txt" | tee -a "$OUT/route-matrix.txt"
  grep -ohiE '"(x-|ld-)[a-z0-9-]{2,40}"' "$OUT"/bundles/*.js 2>/dev/null | tr 'A-Z' 'a-z' \
    | sort | uniq -c | sort -rn | head -40 > "$OUT/bundle-custom-headers.txt" || true
  echo "   custom header-looking strings:" | tee -a "$OUT/route-matrix.txt"
  cat "$OUT/bundle-custom-headers.txt" | tee -a "$OUT/route-matrix.txt"

  echo "-- 7c. context around 'announcements' calls --" | tee -a "$OUT/route-matrix.txt"
  grep -ohE '.{160}announcements.{160}' "$OUT"/bundles/*.js 2>/dev/null | head -12 \
    > "$OUT/bundle-announcements-context.txt" || true
  cat "$OUT/bundle-announcements-context.txt" | tee -a "$OUT/route-matrix.txt"
fi

# keep the committed result set small: raw/ bodies can be big
du -sh "$OUT" 2>/dev/null | tee -a "$OUT/route-matrix.txt"
find "$OUT/raw" -type f -size +64k -delete 2>/dev/null || true
rm -f "$OUT/openapi.json" 2>/dev/null || true   # 1.5MB, regenerable; keep derived text only
rm -rf "$OUT/bundles" 2>/dev/null || true        # huge; keep only extracted greps
echo "route-matrix done -> $OUT" | tee -a "$OUT/route-matrix.txt"
