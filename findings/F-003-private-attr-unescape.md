# F-003 — js-core never redacts private context attributes whose name starts with `/` or `~` (index used as a boolean)

- **Status:** CONFIRMED with executable proof that runs **real, unmodified vendor code on both sides**.
  Re-verified **2026-09-13** against `launchdarkly/js-core` HEAD `6d92d5b` (2026-09-11) — the defect
  is present in the current default branch, not a stale snapshot. No account, no network, nothing is
  sent to LaunchDarkly; this is a deterministic SDK logic bug.
- **Defective file:** `launchdarkly/js-core` → `packages/shared/common/src/AttributeReference.ts`,
  line 18, published as npm `@launchdarkly/js-sdk-common`.
- **Scope position (verified, not assumed) — see §0:** the defective file lives in the `js-core`
  monorepo, whose name does not end in `-sdk`. It is nevertheless unambiguously *the* LaunchDarkly
  client/server SDK code: `js-core` publishes **33** npm packages, the large majority named
  `@launchdarkly/*-sdk` (incl. `js-client-sdk`, `node-server-sdk`, `react-sdk`, `vue-client-sdk`,
  `electron-client-sdk`, `react-native-client-sdk`, `svelte-client-sdk`, `cloudflare-server-sdk`,
  `vercel-server-sdk`, `fastly-server-sdk`, `akamai-server-edgekv-sdk`, `server-sdk-ai`…), all of
  which inherit the buggy file through `@launchdarkly/js-sdk-common`. The program exclusion targets
  *non-SDK* repos (tooling/docs), and this is not one.
- **Report against:** the published SDK packages above. Concretely verified dependency chain:
  `@launchdarkly/js-client-sdk` → `@launchdarkly/js-client-sdk-common@1.32.0` →
  `@launchdarkly/js-sdk-common@2.26.0` (contains both `AttributeReference.ts` and `ContextFilter.ts`).
- **CWE:** CWE-697 (Incorrect Comparison) → CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
- **Suggested severity:** **P3** (CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = 5.3). Fallback **P4** if triage treats the leaked data as staying inside the vendor's own pipeline (see §6).
- **Duplicate risk:** scope notes "5 known issues" for SDK repos; I could not enumerate them. This is an isolated one-character regression in one file, distinct from the canonicalKey defect in F-002.

---

## 0. Verification record (2026-09-13) and scope evidence

### 0.1 The PoC now executes the vendor's actual redaction code, on both sides

The original PoC transcribed js-core's redaction loop from `ContextFilter.ts`. That transcription has
been removed. `tools/poc-private-attr-unescape-real.mjs` loads and runs, **unmodified**, through
Node 22's built-in TypeScript transform (`--experimental-transform-types`):

| File | Status |
|---|---|
| `packages/shared/common/src/AttributeReference.ts` | real vendor source (the defect) |
| `packages/shared/common/src/ContextFilter.ts` | real vendor source (the redaction algorithm) |
| `packages/shared/common/src/Context.ts` | real vendor source (`Context.fromLDContext`, `canonicalKey`) |
| `node-server-sdk/attribute_reference.js` | real vendor source (correct control) |
| `node-server-sdk/context_filter.js` | real vendor source (correct control) |

The **only** substitution is `tools/ts-stub-api-types.mjs`, which stands in for the
`packages/shared/common/src/api/context/**` interface subtree. That is provably runtime-neutral:
`grep -rnE '^\s*(export\s+)?(abstract\s+)?(class|function|const|let|var|enum)\s' src/api/context/`
returns **no matches** — the subtree contains interfaces and type aliases only, so there is no
executable code to replace. Its complete export set is six type names, all used in type positions
only. No vendor logic is substituted anywhere.

Why the stub is needed at all: `AttributeReference.ts:1` and `ContextFilter.ts:4` import a *type*
with a bare `import { LDContextCommon } from './api…'` instead of `import type`, so Node's transform
cannot erase the binding and module instantiation fails on nested type-only imports.

### 0.2 Result (real code, current HEAD)

```
js-core HEAD under test : 6d92d5b 2026-09-11

  reference          _components (real object state)   expected per spec
  /~1ssn             ["~1ssn"]                         ["/ssn"]            <-- WRONG
  /~0secret          ["~0secret"]                      ["~secret"]         <-- WRONG
  /a~1b              ["a/b"]                           ["a/b"]             OK
  /profile/~1ssn     ["profile","~1ssn"]               ["profile","/ssn"]  <-- WRONG

  attribute                    reference            js-core                      node-server-sdk v7
  "/ssn" (top level)           /~1ssn               LEAKED -> "123-45-6789"      REDACTED
  "~secret"                    /~0secret            LEAKED -> "tilde-value"      REDACTED
  "a/b" (~ not first char)     /a~1b                REDACTED                     REDACTED
  profile."/ssn" (nested)      /profile/~1ssn       LEAKED -> "987-65-4321"      REDACTED

RESULT: 3 of 4 private attributes LEAKED by real js-core code
```

`_components: ["~1ssn"]` is read straight out of the vendor's own `AttributeReference` object — the
parser itself is holding the wrong attribute name, which is the root cause made visible.

Reproduce:

```bash
git clone --depth 1 https://github.com/launchdarkly/js-core sdk/js-core
git clone --depth 1 https://github.com/launchdarkly/node-server-sdk sdk/node-server-sdk
node tools/poc-private-attr-unescape-real.mjs        # re-execs itself with the TS flags
```

Artifacts: `findings/F-003-private-attr-unescape/poc-output-v2-real.txt`,
`filtered-contexts-v2-real.json` (v1 artifacts retained for history).

### 0.3 The un-redacted value is what goes on the wire

`ContextFilter` is not advisory — it is instantiated by the real event pipeline and its output *is*
the event's `context` field:

```ts
// packages/shared/common/src/internal/events/EventProcessor.ts:156
this._contextFilter = new ContextFilter(
  _config.allAttributesPrivate,
  _config.privateAttributes.map((ref) => new AttributeReference(ref)),
);

// packages/shared/common/src/internal/events/EventProcessor.ts:333 (_makeOutputEvent)
context: this._contextFilter.filter(event.context, !debug),
```

So the object printed in §0.2 is byte-for-byte the `context` that `identify` / `index` / `debug`
events carry to `events.launchdarkly.com` and on to the customer's Data Export destinations.

*Honest limitation:* I did not execute `EventProcessor` end to end. Doing so requires importing
`src/api/subsystem/**`, which — unlike `src/api/context/**` — contains real runtime constructs
(`DataSourceState`, `LDEventType`, `LDDeliveryStatus` enums, `CallbackHandler` class). Stubbing those
would mean substituting vendor logic, so I cited the call site instead. The claim therefore rests on
the executed `ContextFilter.filter` output plus these two source lines.

### 0.4 Cross-SDK survey — js-core is the only wrong implementation

Every other LaunchDarkly SDK implements the same helper correctly. Verified by reading current
default-branch source (2026-09-13):

| SDK | implementation | result |
|---|---|---|
| `js-core` (`@launchdarkly/js-sdk-common`) | `ref.indexOf('~') ? … : ref` | **BUG** (index 0 is falsy) |
| `node-server-sdk` v7 | `component.indexOf('~') >= 0 ? … : component` | correct |
| `python-server-sdk` | `ldclient/impl/model/attribute_ref.py` — unconditional `replace` | correct |
| `php-server-sdk` | `Types/AttributeReference.php` — `preg_match('/(~[^01]\|~$)/')` then unconditional `str_replace` | correct |
| `flutter-client-sdk` | `attribute_reference.dart:30` — `if (ref.contains('~'))` | correct |
| `ruby-server-sdk` | `lib/ldclient-rb/reference.rb` — `path.include? '~'` | correct |
| `go-sdk-common` (`go-server-sdk`) | `ldattr/ref.go` — `strings.Contains(path, "~")` | correct |

Note that PHP is the instructive control: `strpos` has the *same* "0 is falsy" hazard as JS
`indexOf`, and the PHP SDK avoids it by not using a position test at all. This is an isolated js-core
regression, not a specification choice — which also means the fix is uncontroversial.

### 0.5 Scope, stated plainly

The program excludes "findings related to non-SDK repositories (i.e. repos not ending in `-sdk`)".
`launchdarkly/js-core` does not end in `-sdk`. The finding is nevertheless about LaunchDarkly's
client and server SDKs, because `js-core` *is* where they are built — it publishes 33 npm packages
(`for f in packages/*/*/package.json; do jq -r .name $f; done`), the majority named
`@launchdarkly/*-sdk`. If triage reads the rule strictly by repository name, the fallback is to file
against the published SDK packages that ship the code (e.g. `@launchdarkly/js-client-sdk`,
`@launchdarkly/node-server-sdk`), which is the same defect and the same fix.

---

## 1. Summary

Private context attributes are the customer-facing control for keeping PII out of LaunchDarkly events.
A reference such as `/~1ssn` means "the attribute literally named `/ssn`" (`~1` → `/`, `~0` → `~`).

In js-core the unescaping helper is:

```ts
// js-core/packages/shared/common/src/AttributeReference.ts:17-19
function unescape(ref: string): string {
  return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
}
```

`String.prototype.indexOf` returns an **index**, and it is used here as a **truthiness test**. When `~`
is the first character of a path component, `indexOf` returns `0` → falsy → the component is returned
**without being unescaped**. The parsed reference therefore points at an attribute named `~1ssn`
instead of `/ssn`, never matches the real attribute, and the attribute is **not redacted**.

Consequence: **any context attribute whose name begins with `/` or `~` cannot be made private.** Its
raw value is sent to LaunchDarkly in identify / index / debug events (and from there to any
configured Data Export destination — webhooks, S3, Splunk, Segment, etc.), and because the value was
never matched, `_meta.redactedAttributes` does not list it: the failure is completely silent.

## 2. Every other SDK gets this right — this is an isolated js-core regression

See the verified seven-SDK survey in **§0.4** (`js-core` is the only wrong implementation; PHP is the
instructive control because `strpos` shares the "0 is falsy" hazard and still gets it right).

The bug is also *self-inconsistent* within js-core: the escaping direction is fine
(`toRefString`: `value.replace(/~/g,'~0').replace(/\//g,'~1')`), so js-core can **produce** a correct
reference it cannot itself **parse**.

## 3. Executable proof (`tools/poc-private-attr-unescape-real.mjs`)

The PoC runs **real code on both sides** (details and the proof that nothing is substituted: §0.1):

* js-core's actual `AttributeReference.ts`, `ContextFilter.ts` and `Context.ts`, **unmodified**,
  executed through Node ≥ 22.6's built-in TypeScript transform (`--experimental-transform-types`)
  with a resolver hook for js-core's extensionless relative imports — no build step, no npm, no
  network. The earlier version of this PoC patched the type-only import line and transcribed the
  redaction loop; both workarounds are gone.
* `node-server-sdk` v7's actual `attribute_reference.js` **and** `context_filter.js`, end to end.

Input context (a user with an attribute literally named `/ssn`, plus controls):

```json
{"kind":"user","key":"u-123","email":"user@example.com",
 "/ssn":"123-45-6789","~secret":"tilde-value","a/b":"slash-in-middle",
 "profile":{"/ssn":"987-65-4321","city":"Asheville"},
 "_meta":{"privateAttributes":["/~1ssn","/~0secret","/a~1b","/profile/~1ssn"]}}
```

Reference parsing (both real implementations):

```
reference            js-core components      expected
/~1ssn               ["~1ssn"]               ["/ssn"]
/~0secret            ["~0secret"]            ["~secret"]
/a~1b                ["a/b"]                 ["a/b"]      <- correct: '~' is not at index 0
/profile/~1ssn       ["profile","~1ssn"]     ["profile","/ssn"]
```

End-to-end filtered output (what actually goes into the event):

```
node-server-sdk v7 (correct):
  {"_meta":{"redactedAttributes":["/a~1b","/profile/~1ssn","/~0secret","/~1ssn"]},
   "profile":{"city":"Asheville"},"email":"user@example.com","key":"u-123","kind":"user"}

js-core (defective):
  {"_meta":{"redactedAttributes":["/a~1b"]},
   "profile":{"city":"Asheville","/ssn":"987-65-4321"},
   "~secret":"tilde-value","/ssn":"123-45-6789",
   "email":"user@example.com","key":"u-123","kind":"user"}

per-attribute            js-core                  node-server-sdk v7
"/ssn" (top level)       LEAKED "123-45-6789"     REDACTED
"~secret"                LEAKED "tilde-value"     REDACTED
"a/b" (~ not first char) REDACTED                 REDACTED
profile."/ssn" (nested)  LEAKED "987-65-4321"     REDACTED
```

Full output: `findings/F-003-private-attr-unescape/poc-output.txt`, both filtered contexts in
`filtered-contexts.json`. Reproduce with:

```bash
git clone --depth 1 https://github.com/launchdarkly/js-core sdk/js-core
git clone --depth 1 https://github.com/launchdarkly/node-server-sdk sdk/node-server-sdk
node tools/poc-private-attr-unescape.mjs
```

Why node-server-sdk v7 is immune: it redacts by comparing the **escaped** pointer path of each
attribute (`join(ptr, processEscapeCharacters(key))`) with the reference string, so it never depends
on `unescape()`. js-core compares **unescaped components**, which is exactly where the bug bites.

## 4. Who is affected, and how it is reached

* Any customer of a js-core-based SDK (browser, React, Vue, Angular, Node client-side, React Native,
  the edge/serverless SDKs built on `packages/shared/sdk-server`) who has a context attribute whose
  name starts with `/` or `~` and marks it private — either through SDK configuration
  (`privateAttributes: ['/~1ssn']`) or per-context (`_meta.privateAttributes`).
* Names like this are not exotic: they appear when contexts are built from JSON-Pointer-ish keys,
  namespaced/qualified attribute names (`/pii/email`, `~internal`), migration shims that prefix keys,
  or when data is flattened from a nested payload whose keys contain slashes.
* The value that leaks is the customer's own end-user data, sent in clear to LaunchDarkly's event
  pipeline and then to whatever Data Export destinations the customer configured. The customer's
  stated intent ("do not send this attribute") is silently violated, and nothing in the event
  (`_meta.redactedAttributes`) reveals it.

## 5. Secondary defect in the same function (same fix location)

```ts
function validate(reference: string): boolean {
  return !reference.match(/\/\/|(^\/.*~[^0|^1])|~$/);
}
```
`[^0|^1]` is a **character class containing a literal `|` and `^`**, not an alternation. So
`/a~|b` and `/a~^b` are accepted as valid references even though `~` followed by anything other than
`0`/`1` is invalid per the spec — Go (`ldattr/ref.go` returns `ok=false`), Ruby and Python all reject
them. Verified in the PoC: `isValidReference("/a~|b")` → `true` in **both** JS SDKs. Effect: a
typo'd private-attribute reference is silently accepted and then silently never redacts, instead of
being rejected and surfaced. Same file, same fix, listed for completeness (not a separate report).

## 6. Severity reasoning, honestly

* `C:L`, not `C:H`: what is exposed is the customer's own context attribute data, to LaunchDarkly
  (their processor) and to destinations the customer themselves configured. It is not remote code
  execution and not another tenant's data.
* `AC:L`, `PR:N`: no preconditions beyond an attribute name that begins with `/` or `~`; the failure
  is deterministic and requires no attacker action at all — the "attack" is that the privacy control
  does not work.
* Argued **P3** because it defeats a documented compliance/privacy control across the entire
  client-side SDK family, silently, with no signal to the customer; regulated customers rely on
  private attributes for GDPR/HIPAA-style minimisation. **P4** is the fair fallback if triage weighs
  the data as staying within the vendor relationship.
* Not claimed: no server-side behaviour is implicated, no credentials involved, no other customer's
  data touched, nothing was sent to LaunchDarkly while demonstrating this (the PoC is entirely local).

## 7. Fix

```ts
// js-core/packages/shared/common/src/AttributeReference.ts:18
- return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
+ return ref.includes('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
```
(equivalently `ref.indexOf('~') >= 0`, which is what `node-server-sdk/attribute_reference.js:18`
already does), plus `[^0|^1]` → `[^01]` in `validate()`. Add regression tests for references whose
component begins with `~1` / `~0`, including the nested case, and a cross-SDK contract-test case so
the shared `sdk-test-harness` suite catches any future divergence.

## 8. Artifacts

```
tools/poc-private-attr-unescape-real.mjs                  PoC v2 — runs REAL vendor code, both sides
tools/ts-register.mjs / tools/ts-resolve-hook.mjs         Node TS loader: resolves js-core's
                                                          extensionless .ts imports (no patching)
tools/ts-stub-api-types.mjs                               type-only stub for src/api/context
                                                          (grep-proven to contain no executable code)
findings/F-003-private-attr-unescape/poc-output-v2-real.txt        v2 output (current HEAD)
findings/F-003-private-attr-unescape/filtered-contexts-v2-real.json  v2 input + both filtered outputs
tools/poc-private-attr-unescape.mjs                       PoC v1 (retained for history)
findings/F-003-private-attr-unescape/poc-output.txt       v1 output
findings/F-003-private-attr-unescape/filtered-contexts.json        v1 outputs
sdk/js-core, sdk/node-server-sdk                          cloned sources (gitignored)
```
