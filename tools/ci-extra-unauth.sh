#!/usr/bin/env bash
# Extra unauthenticated recon — no credentials needed. Safe for CI and local runs.
# Output: scratch/responses/<timestamp>-X/  (gitignored)
set -uo pipefail

LD='https://app.launchdarkly.com'
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36'
OUT="scratch/responses/$(date +%Y%m%d-%H%M%S)-X"
mkdir -p "$OUT"

echo "== X1: live OpenAPI spec =="
curl -sS --compressed --max-time 30 "$LD/api/v2/openapi.json" \
  -o "$OUT/X1_openapi.json" -w 'code=%{http_code} size=%{size_download}\n' || true

echo "== X2: CORS echo matrix (unauth) =="
for EP in ips projects; do
  for O in NONE https://app.launchdarkly.com https://evil-cors-test.example; do
    if [ "$O" = NONE ]; then ARGS=(-H 'Accept: application/json'); else ARGS=(-H 'Accept: application/json' -H "Origin: $O"); fi
    F="$OUT/X2_${EP}_$(echo "$O" | tr -c 'a-zA-Z0-9' '_').txt"
    curl -sS -i --max-time 15 "${ARGS[@]}" "$LD/api/v2/$EP" -o "$F" 2>/dev/null || true
    {
      echo "GET /api/v2/$EP   Origin: $O"
      grep -iE '^HTTP|^access-control' "$F" 2>/dev/null | tr -d '\r' | sed 's/^/  /'
      echo
    } | tee -a "$OUT/X2_cors_matrix.txt"
  done
done

echo "== X3: OPTIONS preflight on /api/v2/projects =="
for O in https://app.launchdarkly.com https://evil-cors-test.example; do
  F="$OUT/X3_preflight_$(echo "$O" | tr -c 'a-zA-Z0-9' '_').txt"
  curl -sS -i --max-time 15 -X OPTIONS "$LD/api/v2/projects" \
    -H "Origin: $O" \
    -H 'Access-Control-Request-Method: GET' \
    -H 'Access-Control-Request-Headers: authorization' \
    -o "$F" 2>/dev/null || true
  echo "preflight Origin: $O"
  grep -iE '^HTTP|^access-control|^allow' "$F" 2>/dev/null | tr -d '\r' | sed 's/^/  /'
done

echo "== X4: root subroute probes (unauth, status codes) =="
for p in api/v2 api/v2/ internal internal/ private private/ sdk msdk; do
  read -r CODE LOC < <(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 "$LD/$p" 2>/dev/null || echo ERR)
  echo "/$p -> $CODE redirect=${LOC:--}" | tee -a "$OUT/X4_roots.txt"
done

echo "== X5: login page + app root shells (unauth) =="
curl -sS --compressed -A "$UA" --max-time 20 "$LD/login" \
  -o "$OUT/X5_login.html" -w 'login: code=%{http_code} size=%{size_download}\n' || true
curl -sS --compressed -A "$UA" --max-time 20 "$LD/" \
  -o "$OUT/X6_app_root_unauth.html" -w 'root:  code=%{http_code} size=%{size_download}\n' || true

echo "== X7: download referenced JS bundles (SPA surface for /internal/ discovery) =="
mkdir -p "$OUT/X7_bundles"
python3 - "$OUT/X5_login.html" "$OUT/X6_app_root_unauth.html" "$OUT/X7_bundles" "$LD" <<'EOF' > "$OUT/X7_urls.txt"
import sys, re, os
from urllib.parse import urljoin
outdir, base = sys.argv[3], sys.argv[4]
urls = []
for p in sys.argv[1:3]:
    if os.path.exists(p) and os.path.getsize(p) > 0:
        html = open(p, errors='ignore').read()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            urls.append(urljoin(base + '/', m.group(1)))
        for m in re.finditer(r'<link[^>]+(?:href=["\']([^"\']+\.js)["\'])', html, re.I):
            urls.append(urljoin(base + '/', m.group(1)))
seen, final = set(), []
for u in urls:
    if u not in seen and u.startswith('http'):
        seen.add(u)
        final.append(u)
print('\n'.join(final[:15]))
EOF
n=0
while IFS= read -r u; do
  [ -z "$u" ] && continue
  n=$((n+1)); [ "$n" -gt 15 ] && break
  f="$OUT/X7_bundles/$(echo "$u" | sed 's#.*/##; s#[^a-zA-Z0-9._-]#_#g')"
  curl -sS --compressed --max-time 40 --max-filesize 40000000 "$u" \
    -o "$f" -w "bundle $(basename "$f") code=%{http_code} size=%{size_download}\n" || true
done < "$OUT/X7_urls.txt"

echo "X-part done. Output in $OUT"
