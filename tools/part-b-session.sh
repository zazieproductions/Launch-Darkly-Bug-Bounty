#!/usr/bin/env bash
# Part B: session-cookie (ldso) tests via burner login.
#
# Requires: LD_LOGIN_EMAIL + LD_LOGIN_PASSWORD (env or GitHub Actions secrets).
# SAFETY: exactly ONE login POST attempt per run (avoid lockout/captcha).
#         Read-only after login. Session values redacted from outputs at the end.
# Output: scratch/responses/<timestamp>-B/  (gitignored)
set -uo pipefail

LD='https://app.launchdarkly.com'
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36'
OUT="scratch/responses/$(date +%Y%m%d-%H%M%S)-B"
mkdir -p "$OUT"

if [ -z "${LD_LOGIN_EMAIL:-}" ] || [ -z "${LD_LOGIN_PASSWORD:-}" ]; then
  echo "-- Part B skipped: LD_LOGIN_EMAIL / LD_LOGIN_PASSWORD not set --"
  exit 0
fi

JAR="$OUT/jar.txt"

echo "== B1: GET /login (capture form/CSRF + initial cookies) =="
curl -sS --compressed -c "$JAR" -A "$UA" --max-time 20 "$LD/login" \
  -o "$OUT/B1_login.html" -w 'code=%{http_code} size=%{size_download}\n' || true
python3 - "$OUT/B1_login.html" <<'EOF' 2>/dev/null | tee "$OUT/B1_form.txt" || true
import sys, re
html = open(sys.argv[1], errors='ignore').read()
for m in re.finditer(r'<form\b[^>]*>', html, re.I):
    print('FORM:', m.group(0))
for m in re.finditer(r'<input\b[^>]*>', html, re.I):
    tag = m.group(0)
    if re.search(r'hidden', tag, re.I) or re.search(r'name=', tag):
        print('INPUT:', tag)
for m in re.finditer(r'<meta[^>]*csrf[^>]*>', html, re.I):
    print('META:', m.group(0))
EOF

# Build login POST body: hidden form fields (CSRF etc.) + email/password.
BODY=$(python3 - "$OUT/B1_login.html" <<'EOF' 2>/dev/null || true
import os, re, sys, urllib.parse
fields = {}
try:
    html = open(sys.argv[1], errors='ignore').read()
    for m in re.finditer(r'<input[^>]*hidden[^>]*>', html, re.I):
        tag = m.group(0)
        n = re.search(r'name=["\']([^"\']+)', tag)
        v = re.search(r'value=["\']([^"\']*)', tag)
        if n:
            fields[n.group(1)] = v.group(1) if v else ''
except Exception:
    pass
fields['email'] = os.environ['LD_LOGIN_EMAIL']
fields['password'] = os.environ['LD_LOGIN_PASSWORD']
print(urllib.parse.urlencode(fields))
EOF
)
CSRF=$(python3 - "$OUT/B1_login.html" <<'EOF' 2>/dev/null || true
import re, sys
try:
    html = open(sys.argv[1], errors='ignore').read()
    m = re.search(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', html, re.I) \
        or re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']', html, re.I)
    print(m.group(1) if m else '')
except Exception:
    print('')
EOF
)
CSRF_HDR=()
[ -n "${CSRF:-}" ] && CSRF_HDR=(-H "X-CSRF-Token: $CSRF")

echo "== B2: login POST (single attempt) =="
curl -sS -i -c "$JAR" -b "$JAR" -A "$UA" --max-time 20 \
  -X POST "$LD/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "Origin: $LD" -H 'Referer: https://app.launchdarkly.com/login' -H 'X-Requested-With: XMLHttpRequest' \
  "${CSRF_HDR[@]}" \
  --data "$BODY" \
  -o "$OUT/B2_login_post.txt" -w 'code=%{http_code} redirect=%{redirect_url}\n' || true

echo "  Set-Cookie names+flags (values redacted):"
grep -i '^set-cookie' "$OUT/B2_login_post.txt" 2>/dev/null | tr -d '\r' | while IFS= read -r l; do
  rest="${l#*[Ss]et-[Cc]ookie: }"
  nv="${rest%%;*}"
  attrs="${rest#*;}"
  echo "  ${nv%%=*}=<redacted>; $attrs"
done | tee "$OUT/B2_cookie_flags.txt"

if ! grep -q 'ldso' "$JAR" 2>/dev/null; then
  echo "  !! no ldso cookie after login — stopping Part B here."
  echo "  (inspect B1_login.html + B2_login_post.txt; refine the login endpoint next run)"
  exit 0
fi
echo "  ldso cookie acquired."

echo "== B3: caller-identity via session cookie =="
curl -sS -b "$JAR" -A "$UA" --max-time 15 "$LD/api/v2/caller-identity" \
  -o "$OUT/B3_caller.json" -w 'code=%{http_code}\n' || true
head -c 600 "$OUT/B3_caller.json" 2>/dev/null; echo

echo "== B4: Origin-check matrix via session cookie (GET /api/v2/projects) =="
for O in NONE https://app.launchdarkly.com https://evil-origin-test.example; do
  if [ "$O" = NONE ]; then ARGS=(); else ARGS=(-H "Origin: $O"); fi
  F="$OUT/B4_$(echo "$O" | tr -c 'a-zA-Z0-9' '_').txt"
  curl -sS -i -b "$JAR" -A "$UA" --max-time 15 "${ARGS[@]}" "$LD/api/v2/projects" -o "$F" 2>/dev/null || true
  echo "Origin: $O"
  grep -iE '^HTTP|^access-control' "$F" 2>/dev/null | tr -d '\r' | sed 's/^/  /'
done | tee "$OUT/B4_origin_matrix.txt"

echo "== B5: /private/ probes with session cookie =="
for p in private private/ private/user private/flags private/summary; do
  read -r CODE LOC < <(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' -b "$JAR" -A "$UA" --max-time 10 "$LD/$p" 2>/dev/null || echo ERR)
  echo "/$p -> $CODE redirect=${LOC:--}"
done | tee "$OUT/B5_private.txt"

echo "== B6: authenticated app shell + bundles =="
curl -sS --compressed -b "$JAR" -A "$UA" --max-time 20 "$LD/" \
  -o "$OUT/B6_app_root.html" -w 'code=%{http_code} size=%{size_download}\n' || true
mkdir -p "$OUT/B6_bundles"
python3 - "$OUT/B6_app_root.html" "$OUT/B6_bundles" "$LD" <<'EOF' > "$OUT/B6_urls.txt"
import sys, re, os
from urllib.parse import urljoin
page, outdir, base = sys.argv[1:4]
urls = []
if os.path.exists(page) and os.path.getsize(page) > 0:
    html = open(page, errors='ignore').read()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
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
  f="$OUT/B6_bundles/$(echo "$u" | sed 's#.*/##; s#[^a-zA-Z0-9._-]#_#g')"
  curl -sS --compressed --max-time 40 --max-filesize 40000000 "$u" \
    -o "$f" -w "bundle $(basename "$f") code=%{http_code} size=%{size_download}\n" || true
done < "$OUT/B6_urls.txt"

echo "== B7: redact session values before artifact upload =="
sed -i -E 's/(ldso=)[^;"\\ ]+/\1<redacted>/g' "$OUT/B2_login_post.txt" 2>/dev/null || true
: > "$JAR"
echo "Part B done. Output in $OUT"
