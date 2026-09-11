#!/usr/bin/env node
/**
 * PoC — private-attribute references that start with '/' or '~' are never redacted by js-core
 *        (the shared core of every current LaunchDarkly client-side SDK)
 *
 * ROOT CAUSE (js-core/packages/shared/common/src/AttributeReference.ts:18)
 *   function unescape(ref) {
 *     return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
 *   }
 * `String.prototype.indexOf` returns an INDEX, used here as a truthiness test. When '~' is the
 * FIRST character of a path component, indexOf returns 0 -> falsy -> the component is returned
 * WITHOUT unescaping. Per the attribute-reference spec, "~1" means a literal '/' and "~0" means a
 * literal '~', so any attribute whose name begins with '/' or '~' can never be addressed, and
 * therefore can never be redacted.
 *
 * The legacy node-server-sdk (v7) implements the same helper correctly:
 *   node-server-sdk/attribute_reference.js:18
 *     component.indexOf('~') >= 0 ? component.replace(...) : component
 * as do python-server-sdk (impl/model/attribute_ref.py), ruby-server-sdk (reference.rb:
 * `return path, nil unless path.include? '~'`) and go-sdk-common (ldattr/ref.go:
 * `if !strings.Contains(path, "~")`). So this is an isolated regression in js-core.
 *
 * WHAT THIS SCRIPT EXECUTES
 *   * js-core's REAL AttributeReference.ts, byte-identical except that its single TYPE-ONLY import
 *     line is replaced by a local type alias (documented below). Run through Node's built-in
 *     TypeScript type stripping (Node >= 22.6) - no build step, no npm, no network.
 *   * node-server-sdk v7's REAL attribute_reference.js and context_filter.js (plain CommonJS).
 *   * js-core's ContextFilter redaction loop, transcribed verbatim from
 *     js-core/packages/shared/common/src/ContextFilter.ts (compare/protectedAttributes/
 *     cloneWithRedactions), driven by the REAL js-core AttributeReference.
 *
 * IMPACT
 *   A customer who marks an attribute such as "/ssn", "~secret" or a nested "/pii" private gets NO
 *   redaction: the raw value is sent to LaunchDarkly in identify/index/debug events (and on to any
 *   configured Data Export destination), and `_meta.redactedAttributes` does not list it, so the
 *   misconfiguration is silent.
 *
 * Usage: node tools/poc-private-attr-unescape.mjs [outDir]
 * No network. No credentials.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..');
const SDK = path.join(REPO, 'sdk');
const OUT = process.argv[2] || path.join(REPO, 'findings', 'F-003-private-attr-unescape');
fs.mkdirSync(OUT, { recursive: true });

const SRC_TS = path.join(SDK, 'js-core/packages/shared/common/src/AttributeReference.ts');
const NODE_AR = path.join(SDK, 'node-server-sdk/attribute_reference.js');
const NODE_CF = path.join(SDK, 'node-server-sdk/context_filter.js');
for (const p of [SRC_TS, NODE_AR, NODE_CF]) {
  if (!fs.existsSync(p)) {
    console.error(`missing ${p}\n  git clone --depth 1 https://github.com/launchdarkly/js-core sdk/js-core`);
    console.error('  git clone --depth 1 https://github.com/launchdarkly/node-server-sdk sdk/node-server-sdk');
    process.exit(2);
  }
}

// ---- prepare a runnable copy of js-core's REAL AttributeReference.ts -------------------------
const RUNDIR = path.join(SDK, '.tsrun');
fs.mkdirSync(RUNDIR, { recursive: true });
fs.writeFileSync(path.join(RUNDIR, 'package.json'), '{"type":"module"}\n');
const tsSrc = fs.readFileSync(SRC_TS, 'utf8');
const TYPE_IMPORT = "import { LDContextCommon } from './api/context/LDContextCommon';";
if (!tsSrc.includes(TYPE_IMPORT)) throw new Error('expected type-only import line not found in AttributeReference.ts');
const patched = tsSrc.replace(
  TYPE_IMPORT,
  '// PoC harness: the line above in the original file was a TYPE-ONLY import.\n' +
  '// It is replaced by a local alias so the file can run under Node type-stripping.\n' +
  '// Zero runtime effect; all remaining bytes are verbatim from js-core.\n' +
  'type LDContextCommon = Record<string, any>;',
);
const TS_COPY = path.join(RUNDIR, 'AttributeReference.ts');
fs.writeFileSync(TS_COPY, patched);

const { default: JSCoreAttributeReference } = await import(TS_COPY);
const NodeAR = require(NODE_AR);
const NodeContextFilter = require(NODE_CF);

// ---- js-core ContextFilter logic, transcribed verbatim (ContextFilter.ts) --------------------
const protectedAttributes = ['key', 'kind', '_meta', 'anonymous'].map(
  (str) => new JSCoreAttributeReference(str, true),
);
function compare(a, b) {
  return a.depth === b.length && b.every((value, index) => value === a.getComponent(index));
}
function cloneWithRedactions(target, references) {
  const stack = [];
  const cloned = {};
  const excluded = [];
  stack.push(
    ...Object.keys(target).map((key) => ({ key, ptr: [key], source: target, parent: cloned, visited: [target] })),
  );
  while (stack.length) {
    const item = stack.pop();
    const redactRef = references.find((ref) => compare(ref, item.ptr));
    if (!redactRef) {
      const value = item.source[item.key];
      if (value === null) item.parent[item.key] = value;
      else if (Array.isArray(value)) item.parent[item.key] = [...value];
      else if (typeof value === 'object') {
        if (!item.visited.includes(value)) {
          item.parent[item.key] = {};
          stack.push(
            ...Object.keys(value).map((key) => ({
              key, ptr: [...item.ptr, key], source: value,
              parent: item.parent[item.key], visited: [...item.visited, value],
            })),
          );
        }
      } else item.parent[item.key] = value;
    } else excluded.push(redactRef.redactionName);
  }
  return { cloned, excluded: excluded.sort() };
}
// mirrors ContextFilter._filterSingleKind for a single-kind context
function jsCoreFilterSingleKind(single, privateRefs) {
  const refs = privateRefs.filter(
    (attr) => !protectedAttributes.some((p) => p.compare(attr)),
  );
  const { cloned, excluded } = cloneWithRedactions(single, refs);
  if (excluded.length) {
    if (!cloned._meta) cloned._meta = {};
    cloned._meta.redactedAttributes = excluded;
  }
  if (cloned._meta) {
    delete cloned._meta.privateAttributes;
    if (Object.keys(cloned._meta).length === 0) delete cloned._meta;
  }
  return cloned;
}

// ---- report ---------------------------------------------------------------------------------
const log = [];
const say = (s = '') => { log.push(s); console.log(s); };

say('# PoC — js-core fails to redact private attributes whose name starts with "/" or "~"');
say(`js-core source : ${path.relative(REPO, SRC_TS)} (run through Node type-stripping, ${process.version})`);
say(`node-server-sdk: ${path.relative(REPO, NODE_AR)} + ${path.relative(REPO, NODE_CF)} (v7, real code)`);
say('');

const jstr = (v) => (v === undefined ? 'undefined' : JSON.stringify(v));
say('## 1. The parsing divergence (both are the REAL implementations)');
const target = { '/ssn': 'V1', '~secret': 'V2', 'a/b': 'V3', email: 'V5', profile: { '/ssn': 'V4' } };
say('  Does the reference resolve the attribute it names?');
say('  reference            js-core .get(target)   node-server-sdk get(target,ref)  agree?');
for (const r of ['/~1ssn', '/~0secret', '/a~1b', '/profile/~1ssn', 'email']) {
  const jc = new JSCoreAttributeReference(r).get(target);
  const nd = NodeAR.get(target, r);
  say(`  ${r.padEnd(20)} ${jstr(jc).padEnd(22)} ${jstr(nd).padEnd(32)} ${jc === nd}`);
}
say('');
say('  js-core parsed components (real code):');
for (const r of ['/~1ssn', '/~0secret', '/a~1b', '/profile/~1ssn']) {
  say(`    ${r.padEnd(20)} -> ${JSON.stringify(new JSCoreAttributeReference(r).components)}`);
}
say('    (expected for /~1ssn: ["/ssn"];  for /profile/~1ssn: ["profile","/ssn"])');
say('');
say('  js-core isValidReference("/a~|b") : ' + new JSCoreAttributeReference('/a~|b').isValid +
    '   (spec: "~" followed by anything other than 0/1 is INVALID)');
say('  node-server-sdk isValidReference("/a~|b") : ' + NodeAR.isValidReference('/a~|b'));
say('  -> both JS SDKs accept an invalid escape because the char class is written [^0|^1]');
say('     (a literal "|" and "^" inside a negated class); Go/Ruby/Python reject it.');
say('');

say('## 2. End-to-end: is the private attribute actually redacted?');
say('  Context: a user with a nested attribute literally named "/ssn" plus a control attribute.');
const ctx = {
  kind: 'user',
  key: 'u-123',
  email: 'user@example.com',
  '/ssn': '123-45-6789',
  '~secret': 'tilde-value',
  'a/b': 'slash-in-middle',
  profile: { '/ssn': '987-65-4321', city: 'Asheville' },
  _meta: { privateAttributes: ['/~1ssn', '/~0secret', '/a~1b', '/profile/~1ssn'] },
};
say('  context            : ' + JSON.stringify(ctx));
say('  private references : ' + JSON.stringify(ctx._meta.privateAttributes));
say('');

// node-server-sdk v7 (correct implementation), real code end-to-end
const nodeFiltered = NodeContextFilter({ allAttributesPrivate: false, privateAttributes: [] }).filter(JSON.parse(JSON.stringify(ctx)));
say('  node-server-sdk v7 (real ContextFilter) output:');
say('    ' + JSON.stringify(nodeFiltered));
say('');

// js-core path: real AttributeReference + verbatim ContextFilter loop
const jsRefs = ctx._meta.privateAttributes.map((r) => new JSCoreAttributeReference(r));
const jsFiltered = jsCoreFilterSingleKind(JSON.parse(JSON.stringify(ctx)), jsRefs);
say('  js-core (real AttributeReference + verbatim ContextFilter loop) output:');
say('    ' + JSON.stringify(jsFiltered));
say('');

const leaks = [];
const check = (label, pathStr, obj, keyPath) => {
  const v = keyPath.reduce((o, k) => (o == null ? o : o[k]), obj);
  say(`    ${label.padEnd(34)} ${pathStr.padEnd(24)} ${v === undefined ? 'REDACTED' : 'LEAKED -> ' + jstr(v)}`);
  if (v !== undefined) leaks.push(label);
};
say('  per-attribute result:');
say('    attribute                        private reference          js-core');
check('"/ssn" (top level)', '/~1ssn', jsFiltered, ['/ssn']);
check('"~secret"', '/~0secret', jsFiltered, ['~secret']);
check('"a/b" (~ not first char)', '/a~1b', jsFiltered, ['a/b']);
check('profile."/ssn" (nested)', '/profile/~1ssn', jsFiltered, ['profile', '/ssn']);
say('');
say('  same attributes through node-server-sdk v7:');
say('    attribute                        private reference          node-server-sdk');
const ncheck = (label, ref, obj, keyPath) => {
  const v = keyPath.reduce((o, k) => (o == null ? o : o[k]), obj);
  say(`    ${label.padEnd(34)} ${ref.padEnd(24)} ${v === undefined ? 'REDACTED' : 'LEAKED -> ' + jstr(v)}`);
};
ncheck('"/ssn" (top level)', '/~1ssn', nodeFiltered, ['/ssn']);
ncheck('"~secret"', '/~0secret', nodeFiltered, ['~secret']);
ncheck('"a/b" (~ not first char)', '/a~1b', nodeFiltered, ['a/b']);
ncheck('profile."/ssn" (nested)', '/profile/~1ssn', nodeFiltered, ['profile', '/ssn']);
say('');

say('  note: node-server-sdk v7 redacts by comparing the ESCAPED pointer path of each attribute');
say('        (join(ptr, processEscapeCharacters(key))) with the reference string, so it is immune');
say('        to the unescape bug; js-core compares UNESCAPED components, so it depends on unescape().');
say('');
say('## 3. Why it is silent');
say(`  js-core _meta.redactedAttributes      : ${JSON.stringify(jsFiltered._meta && jsFiltered._meta.redactedAttributes)}`);
say(`  node-server-sdk _meta.redactedAttributes: ${JSON.stringify(nodeFiltered._meta && nodeFiltered._meta.redactedAttributes)}`);
say('  js-core reports nothing redacted, so the customer sees no hint that their private-attribute');
say('  configuration is not taking effect; the raw values travel in identify/index/debug events.');
say('');

say('## 4. Affected SDKs (all consume js-core @launchdarkly/js-sdk-common)');
say('  browser, react-client-sdk, vue-client-sdk, angular-client-sdk, node-client-sdk,');
say('  react-native-sdk, js-client-sdk and the edge/serverless SDKs packaged from js-core');
say('  (packages/shared/sdk-server), i.e. every SDK that formats contexts into events.');
say('');

say('## 5. Fix');
say("  AttributeReference.ts:18  ->  return ref.indexOf('~') >= 0 ? ... : ref;");
say("  (or `ref.includes('~')`), matching node-server-sdk/attribute_reference.js:18,");
say('  python-server-sdk/ldclient/impl/model/attribute_ref.py:96, ruby-server-sdk reference.rb and');
say('  go-sdk-common/ldattr/ref.go:252. Also tighten the validation char class [^0|^1] -> [^01].');

say('');
say(`RESULT: ${leaks.length} of 4 attributes LEAKED through js-core: ${JSON.stringify(leaks)}`);

fs.writeFileSync(path.join(OUT, 'poc-output.txt'), log.join('\n') + '\n');
fs.writeFileSync(path.join(OUT, 'filtered-contexts.json'),
  JSON.stringify({ input: ctx, js_core: jsFiltered, node_server_sdk_v7: nodeFiltered }, null, 1));
say(`written: ${path.join(OUT, 'poc-output.txt')}`);
say(`written: ${path.join(OUT, 'filtered-contexts.json')}`);
