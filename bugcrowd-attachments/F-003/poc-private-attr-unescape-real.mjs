#!/usr/bin/env node
/**
 * PoC (v2, REAL-CODE-BOTH-SIDES) — private context attribute references that begin with '/' or '~'
 * are never redacted by js-core, the shared core of every current LaunchDarkly client-side SDK.
 *
 * WHAT CHANGED vs v1
 *   v1 transcribed js-core's redaction loop from ContextFilter.ts. This version executes the
 *   vendor's ACTUAL ContextFilter.ts, Context.ts and AttributeReference.ts, unmodified, through
 *   Node's built-in TypeScript transform. The only substitution is a stub for the `src/api/context`
 *   *interface* subtree, which is proven to contain no executable code at all (see
 *   tools/ts-stub-api-types.mjs). So the reported leak is produced by LaunchDarkly's own code path:
 *   Context.filter -> ContextFilter.filter -> cloneWithRedactions -> AttributeReference.
 *
 * ROOT CAUSE — js-core/packages/shared/common/src/AttributeReference.ts:18
 *     function unescape(ref: string): string {
 *       return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
 *     }
 *   String.prototype.indexOf returns an INDEX and is used here as a truthiness test. When '~' is
 *   the FIRST character of a path component indexOf returns 0 -> falsy -> the component is returned
 *   WITHOUT being unescaped. Per the attribute-reference spec '~1' encodes a literal '/' and '~0'
 *   encodes a literal '~', so an attribute whose name begins with '/' or '~' can never be addressed
 *   and therefore can never be redacted.
 *
 *   The same helper is implemented correctly in every other LaunchDarkly SDK:
 *     node-server-sdk/attribute_reference.js:18      component.indexOf('~') >= 0 ? ...
 *     python-server-sdk/ldclient/impl/model/attribute_ref.py   unconditional .replace(...)
 *     ruby-server-sdk lib/ldclient-rb/reference.rb    path.include? '~'
 *     go-sdk-common ldattr/ref.go                     strings.Contains(path, "~")
 *   -> an isolated js-core regression, not a specification choice.
 *
 * IMPACT
 *   A customer who marks an attribute such as "/ssn", "~secret" or a nested "/pii" private gets NO
 *   redaction: the raw value is sent to LaunchDarkly in identify/index/debug events (and on to any
 *   configured Data Export destination - webhook, S3, Splunk, Segment, ...) and
 *   `_meta.redactedAttributes` does not list it, so the failure is completely silent.
 *
 * Usage: node tools/poc-private-attr-unescape-real.mjs [outDir]
 * No network, no credentials, nothing is sent to LaunchDarkly.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.dirname(HERE);
const SDK = path.join(REPO, 'sdk');
const OUT = path.resolve(process.argv[2] || path.join(REPO, 'out'));

// ---------------------------------------------------------------- self re-exec with TS support
// The real js-core sources are TypeScript, so this script needs Node's transform + our resolver
// hook. Re-exec once with the right flags rather than requiring the caller to remember them.
if (!process.execArgv.some((a) => a.includes('transform-types'))) {
  const args = [
    '--experimental-transform-types',
    '--import',
    path.join(HERE, 'ts-register.mjs'),
    fileURLToPath(import.meta.url),
    ...process.argv.slice(2),
  ];
  process.stdout.write(execFileSync(process.execPath, args, { encoding: 'utf8', maxBuffer: 64 << 20 }));
  process.exit(0);
}

const log = [];
const say = (s = '') => {
  log.push(s);
  console.log(s);
};
const j = (v) => JSON.stringify(v);

const need = [
  path.join(SDK, 'js-core/packages/shared/common/src/AttributeReference.ts'),
  path.join(SDK, 'js-core/packages/shared/common/src/ContextFilter.ts'),
  path.join(SDK, 'js-core/packages/shared/common/src/Context.ts'),
  path.join(SDK, 'node-server-sdk/attribute_reference.js'),
  path.join(SDK, 'node-server-sdk/context_filter.js'),
];
for (const p of need) {
  if (!fs.existsSync(p)) {
    console.error(`missing ${p}\n  git clone --depth 1 https://github.com/launchdarkly/js-core sdk/js-core`);
    console.error('  git clone --depth 1 https://github.com/launchdarkly/node-server-sdk sdk/node-server-sdk');
    process.exit(1);
  }
}

const require = createRequire(import.meta.url);
const COMMON = path.join(SDK, 'js-core/packages/shared/common/src');

// ---------------------------------------------------------------- REAL js-core (unmodified .ts)
const JSCoreAR = (await import(path.join(COMMON, 'AttributeReference.ts'))).default;
const JSCoreContextFilter = (await import(path.join(COMMON, 'ContextFilter.ts'))).default;
const JSCoreContext = (await import(path.join(COMMON, 'Context.ts'))).default;

// ---------------------------------------------------------------- REAL node-server-sdk v7
const NodeAR = require(path.join(SDK, 'node-server-sdk/attribute_reference.js'));
const NodeContextFilter = require(path.join(SDK, 'node-server-sdk/context_filter.js'));

const head = (await import('node:child_process'))
  .execFileSync('git', ['-C', path.join(SDK, 'js-core'), 'log', '-1', '--format=%h %ad %s', '--date=short'], { encoding: 'utf8' })
  .trim();

say('# F-003 PoC v2 — private attributes starting with "/" or "~" are never redacted by js-core');
say('');
say(`  js-core HEAD under test : ${head}`);
say('  Code executed           : vendor sources, UNMODIFIED, loaded through Node --experimental-transform-types');
say('                            - packages/shared/common/src/AttributeReference.ts  (real)');
say('                            - packages/shared/common/src/ContextFilter.ts       (real)');
say('                            - packages/shared/common/src/Context.ts             (real)');
say('                            - node-server-sdk/attribute_reference.js            (real)');
say('                            - node-server-sdk/context_filter.js                 (real)');
say('  Sole substitution       : tools/ts-stub-api-types.mjs replaces the `src/api/context` interface');
say('                            subtree, which contains NO executable code (grep-verified). No vendor');
say('                            logic is replaced.');
say('');

// ---------------------------------------------------------------- 1. root cause, from vendor state
say('## 1. Root cause, read straight out of the vendor objects');
say('');
say('  js-core AttributeReference (REAL) parsing of private-attribute references:');
say('');
say('    reference          _components (real object state)   expected per spec');
const refObjs = {};
for (const [ref] of [['/~1ssn'], ['/~0secret'], ['/a~1b'], ['/profile/~1ssn']]) {
  refObjs[ref] = new JSCoreAR(ref);
  const comps = j(refObjs[ref].components);
  const expected = {
    '/~1ssn': '["/ssn"]',
    '/~0secret': '["~secret"]',
    '/a~1b': '["a/b"]',
    '/profile/~1ssn': '["profile","/ssn"]',
  }[ref];
  const ok = comps === expected;
  say(`    ${ref.padEnd(18)} ${comps.padEnd(35)} ${expected.padEnd(26)} ${ok ? 'OK' : '<-- WRONG'}`);
}
say('');
say('  Why: unescape() uses `ref.indexOf(\'~\')` as a boolean, and indexOf returns 0 when "~" is the');
say('  first character of the component -> falsy -> no unescaping. Components whose "~" is NOT first');
say('  ("a~1b") work, which is why the bug is easy to miss in casual testing.');
say('');
say('  Secondary defect in the same file, validate(): the character class is written [^0|^1], i.e. a');
say('  negated class containing a LITERAL "|" and "^", not an alternation. So "~" followed by a');
say('  character other than 0/1 is wrongly accepted:');
say(`    js-core       isValidReference("/a~|b") = ${new JSCoreAR('/a~|b').isValid}`);
say(`    node-sdk v7   isValidReference("/a~|b") = ${NodeAR.isValidReference('/a~|b')}`);
say('  (Go/Ruby/Python all reject it.) A typo\'d private reference is silently accepted and then');
say('  silently never redacts, instead of being surfaced as invalid.');
say('');

// ---------------------------------------------------------------- 2. end-to-end through real filters
say('## 2. End-to-end: does the private attribute actually get redacted?');
say('');

const CTX = {
  kind: 'user',
  key: 'u-123',
  email: 'user@example.com',
  '/ssn': '123-45-6789',
  '~secret': 'tilde-value',
  'a/b': 'slash-in-middle',
  profile: { '/ssn': '987-65-4321', city: 'Asheville' },
  _meta: { privateAttributes: ['/~1ssn', '/~0secret', '/a~1b', '/profile/~1ssn'] },
};
say(`  context : ${j(CTX)}`);
say('');

// --- real js-core path: Context.fromLDContext -> ContextFilter.filter
const jsRefs = CTX._meta.privateAttributes.map((r) => new JSCoreAR(r));
const jsCtx = JSCoreContext.fromLDContext(CTX);
if (!jsCtx.valid) throw new Error('js-core rejected the context');
const jsOut = new JSCoreContextFilter(false, jsRefs).filter(jsCtx);

// --- real node-server-sdk v7 path
const nodeOut = new NodeContextFilter(false, CTX._meta.privateAttributes).filter(CTX);

say('  js-core (REAL ContextFilter.filter) output:');
say(`    ${j(jsOut)}`);
say('');
say('  node-server-sdk v7 (REAL context_filter.js) output:');
say(`    ${j(nodeOut)}`);
say('');

const CHECKS = [
  ['"/ssn" (top level)', '/~1ssn', (o) => o['/ssn']],
  ['"~secret"', '/~0secret', (o) => o['~secret']],
  ['"a/b" (~ not first char)', '/a~1b', (o) => o['a/b']],
  ['profile."/ssn" (nested)', '/profile/~1ssn', (o) => (o.profile || {})['/ssn']],
];

say('  per-attribute result:');
say(`    ${'attribute'.padEnd(28)} ${'reference'.padEnd(20)} ${'js-core'.padEnd(12)} node-server-sdk v7`);
const leaked = [];
for (const [label, ref, get] of CHECKS) {
  const a = get(jsOut);
  const b = get(nodeOut);
  const jsVerdict = a === undefined ? 'REDACTED' : 'LEAKED';
  const nodeVerdict = b === undefined ? 'REDACTED' : 'LEAKED';
  if (a !== undefined) leaked.push(label);
  say(
    `    ${label.padEnd(28)} ${ref.padEnd(20)} ${(jsVerdict + (a === undefined ? '' : ` -> ${j(a)}`)).padEnd(24)} ${nodeVerdict}`,
  );
}
say('');

say('## 3. Why the failure is silent');
say(`  js-core          _meta.redactedAttributes : ${j((jsOut._meta || {}).redactedAttributes || [])}`);
say(`  node-sdk v7      _meta.redactedAttributes : ${j((nodeOut._meta || {}).redactedAttributes || [])}`);
say('  js-core claims it redacted 1 of 4, so the customer gets no signal that their');
say('  private-attribute configuration is not taking effect.');
say('');

say('## 4. Affected SDKs (everything built on @launchdarkly/js-sdk-common)');
say('  browser-sdk, react-client-sdk, vue-client-sdk, angular-client-sdk, node-client-sdk,');
say('  react-native-sdk, js-client-sdk and the edge/serverless SDKs packaged from');
say('  packages/shared/sdk-server - i.e. every current LaunchDarkly SDK that formats contexts');
say('  into events.');
say('');

say('## 5. Fix');
say("  AttributeReference.ts:18 ->  return ref.indexOf('~') >= 0 ? ... : ref;");
say("  (or ref.includes('~')), matching node-server-sdk/attribute_reference.js:18; and");
say('  validate(): [^0|^1] -> [^01].');
say('');

const RESULT = `RESULT: ${leaked.length} of ${CHECKS.length} private attributes LEAKED by real js-core code: ${j(leaked)}`;
say(RESULT);

fs.mkdirSync(OUT, { recursive: true });
fs.writeFileSync(path.join(OUT, 'poc-output-v2-real.txt'), log.join('\n') + '\n');
fs.writeFileSync(
  path.join(OUT, 'filtered-contexts-v2-real.json'),
  JSON.stringify({ input: CTX, 'js-core': jsOut, 'node-server-sdk-v7': nodeOut }, null, 2) + '\n',
);
say(`written: ${path.join(OUT, 'poc-output-v2-real.txt')}`);
say(`written: ${path.join(OUT, 'filtered-contexts-v2-real.json')}`);

// non-zero exit if the vendor code redacts everything (i.e. the bug is fixed)
process.exit(leaked.length === 0 ? 2 : 0);
