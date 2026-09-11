# F-003 — js-core never redacts private context attributes whose name starts with `/` or `~` (index used as a boolean)

- **Status:** CONFIRMED locally with executable proof against the **real, unmodified SDK code** (both sides). No account or network access needed — this is a deterministic client-side/SDK logic bug.
- **Report against (scope requires a repo ending `-sdk`):** `launchdarkly/react-client-sdk` (and identically `launchdarkly/js-client-sdk`, `launchdarkly/node-server-sdk` v6+, `vue-client-sdk`, `angular-client-sdk`, `node-client-sdk`, `react-native-sdk`, plus the edge/serverless SDKs) — all of which format contexts into events through the shared core.
- **Defective file:** `launchdarkly/js-core` → `packages/shared/common/src/AttributeReference.ts`, line 18 (published as `@launchdarkly/js-sdk-common`, consumed by every SDK listed above).
- **CWE:** CWE-697 (Incorrect Comparison) → CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
- **Suggested severity:** **P3** (CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = 5.3). Fallback **P4** if triage treats the leaked data as staying inside the vendor's own pipeline (see §6).
- **Duplicate risk:** scope notes "5 known issues" for SDK repos; I could not enumerate them. This is an isolated one-character regression in one file, distinct from the canonicalKey defect in F-002.

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

| SDK | implementation | result |
|---|---|---|
| `js-core` (`@launchdarkly/js-sdk-common`) | `ref.indexOf('~') ? … : ref` | **BUG** (index 0 is falsy) |
| `node-server-sdk` v7 | `node-server-sdk/attribute_reference.js:18` → `component.indexOf('~') >= 0 ? … : component` | correct |
| `python-server-sdk` | `ldclient/impl/model/attribute_ref.py:96` → `s.replace("~1","/").replace("~0","~")` (unconditional) | correct |
| `ruby-server-sdk` | `lib/ldclient-rb/reference.rb` → `return path, nil unless path.include? '~'` | correct |
| `go-sdk-common` (used by `go-server-sdk`) | `ldattr/ref.go:252` → `if !strings.Contains(path, "~") { return path, true }` | correct |

The bug is also *self-inconsistent* within js-core: the escaping direction is fine
(`toRefString`: `value.replace(/~/g,'~0').replace(/\//g,'~1')`), so js-core can **produce** a correct
reference it cannot itself **parse**.

## 3. Executable proof (`tools/poc-private-attr-unescape.mjs`)

The PoC runs **real code on both sides**:

* js-core's actual `AttributeReference.ts`, byte-identical except that its single **type-only** import
  line is replaced with a local type alias, executed through Node ≥ 22.6's built-in TypeScript type
  stripping — no build step, no npm, no network;
* `node-server-sdk` v7's actual `attribute_reference.js` **and** `context_filter.js`, end to end;
* js-core's redaction loop transcribed verbatim from `ContextFilter.ts`
  (`protectedAttributes`, `compare`, `cloneWithRedactions`), driven by the real `AttributeReference`.

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
tools/poc-private-attr-unescape.mjs                     the PoC (runs real code from both SDKs)
findings/F-003-private-attr-unescape/poc-output.txt     full output above
findings/F-003-private-attr-unescape/filtered-contexts.json   input + both filtered outputs
sdk/js-core, sdk/node-server-sdk                        cloned sources (gitignored)
```
