# F-003 — Private attributes starting with `/` or `~` are not redacted (js-core)

**Target:** `LaunchDarkly Open Source SDKs`
**URL / Location:** `https://github.com/launchdarkly/js-core/blob/main/packages/shared/common/src/AttributeReference.ts#L18` — published as `@launchdarkly/js-sdk-common` (consumed by `js-client-sdk`, `react-client-sdk`, `vue-client-sdk`, `react-native-client-sdk`, etc.)
**VRT:** `Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure` (CWE-359, CWE-697)
**Severity:** P3 — CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)
**Tested on:** `js-core` HEAD `6d92d5b` (2026-09-11) and latest `main` on 2026-09-13. Node.js 22. Local reproduction only — no account, no network calls to LaunchDarkly. All source is public on GitHub.

## Summary

`js-core` is the shared core for all current LaunchDarkly browser and client-side SDKs. Its `AttributeReference` helper fails to unescape private-attribute references when the escaped sequence appears at the start of a path component. An attribute literally named `/ssn` is referenced as `/~1ssn` (`~1` → `/`). The code checks `ref.indexOf('~')` as a boolean, so `0` (found at index 0) is treated as falsy and the replacement never runs. The filter then looks for `~1ssn` instead of `/ssn`, misses, and sends the raw value to LaunchDarkly in `identify`/`index` events. The failure is silent — `redactedAttributes` does not include the missed field.

## Impact

* A customer who marks an attribute such as `/ssn`, `~secret`, or `profile./ssn` as private expects it to be stripped before events leave the browser. With this bug the value is delivered to `events.launchdarkly.com` and to any Data Export destinations (S3, Segment, Splunk, webhook) the customer has configured.
* The customer's `redactedAttributes` list omits the field, so there is no indication the setting is ineffective. This undermines GDPR / data-minimisation controls that depend on `privateAttributes`.
* The defect affects every SDK built on `@launchdarkly/js-sdk-common`. No attacker interaction is required — normal use with a leading `/` or `~` in an attribute name is sufficient.

Scope is limited to the customer's own PII being sent to their own configured pipeline, not another tenant's data or RCE. P3 is appropriate; I am not claiming P1/P2.

## Steps to Reproduce

Prerequisites: Node.js ≥22.6, no `npm install` required. The attached PoC runs the vendor's real source via Node's `--experimental-transform-types` and uses only public GitHub repositories.

1. Clone public sources:

```bash
git clone --depth 1 https://github.com/launchdarkly/js-core
git clone --depth 1 https://github.com/launchdarkly/node-server-sdk
```

2. Run the attached PoC (also reproduced below as a minimal check):

```bash
node poc-private-attr-unescape-real.mjs
# Attached file. Loads AttributeReference.ts, ContextFilter.ts, and Context.ts
# unmodified from js-core and attribute_reference.js / context_filter.js from
# node-server-sdk v7 as a control. The only stub is for src/api/context
# type-only interfaces (six type names, no runtime code).
```

Minimal inline verification without the full harness:

```js
// Directly shows the parsing bug on public source:
function unescape_buggy(ref){ return ref.indexOf('~') ? ref.replace(/~1/g,'/').replace(/~0/g,'~') : ref; }
console.log(unescape_buggy('~1ssn')); // " ~1ssn" — wrong, should be "/ssn"
console.log(unescape_buggy('a~1b'));  // "a/b" — happens to work, why bug is missed
```

3. Or inspect the source directly:

```
https://github.com/launchdarkly/js-core/blob/main/packages/shared/common/src/AttributeReference.ts#L18
return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
```

Expected: all four test private attributes are redacted and listed in `redactedAttributes`.
Observed with `js-core`: three leak, one redacted (see Evidence).

## Technical Details

Defective code:

```ts
// packages/shared/common/src/AttributeReference.ts:17-19
function unescape(ref: string): string {
  return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
}
```

`indexOf` returns `0` when `~` is the first character of the component (`/~1ssn` → component `~1ssn`), so the ternary takes the falsy branch and returns the raw component.

Concretely:

* `new AttributeReference('/~1ssn').components` → `["~1ssn"]` (should be `["/ssn"]`)
* `/a~1b` → `["a/b"]` correct — `~` is not at index 0, so the bug is missed in casual testing

End-to-end `ContextFilter` output on this context:

```json
{
  "kind": "user", "key": "u-123", "email": "user@example.com",
  "/ssn": "123-45-6789", "~secret": "tilde-value",
  "a/b": "slash-in-middle", "profile": { "/ssn": "987-65-4321", "city": "Asheville" },
  "_meta": { "privateAttributes": ["/~1ssn","/~0secret","/a~1b","/profile/~1ssn"] }
}
```

* `node-server-sdk v7` (correct): `{"profile":{"city":"Asheville"},"redactedAttributes":["/a~1b","/profile/~1ssn","/~0secret","/~1ssn"]}` — all four redacted
* `js-core`: `{"profile":{"city":"Asheville","/ssn":"987-65-4321"},"~secret":"tilde-value","/ssn":"123-45-6789","redactedAttributes":["/a~1b"]}` — three values leaked, only one listed

Cross-SDK check on 2026-09-13 HEAD (all correct except `js-core`):

* `node-server-sdk` uses `indexOf('~') >= 0`
* `python-server-sdk` uses unconditional `replace`
* `php-server-sdk` uses `preg_match` + `str_replace` (notably avoids the same `strpos` 0-is-falsy pitfall)
* `flutter`, `ruby`, `go` use `contains` / `include?` / `strings.Contains`

The filtered object is the wire payload. In `src/internal/events/EventProcessor.ts:156` the filter is constructed from `privateAttributes`, and at `:333` the result of `filter()` is assigned to `context` on the outgoing event. No additional stripping occurs after this point. I did not run `EventProcessor` end-to-end (it requires subsystem enums/classes); the claim rests on the executed `ContextFilter` output plus those two call sites.

A secondary issue in the same function is `validate()` using `[^0|^1]` — a negated class containing literal `|` and `^` — so `~` followed by `|` or `^` is incorrectly accepted. Same file, same fix.

## Evidence (all attached, no private repo required)

* `poc-private-attr-unescape-real.mjs` — PoC that runs real vendor code on both sides (ATTACHED)
* `poc-output-v2-real.txt` — full run log showing `3 of 4 LEAKED` vs `4/4 REDACTED` control (ATTACHED)
* `filtered-contexts-v2-real.json` — input and both filtered outputs, byte-for-byte wire payloads (ATTACHED)

You can also verify without the PoC by opening the two GitHub links above — the buggy `indexOf('~')` vs correct `indexOf('~') >= 0` is a one-character difference visible in the browser. No requests were sent to LaunchDarkly; reproduction is offline.

## Remediation

```diff
- return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
+ return ref.includes('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
```

or `indexOf('~') >= 0` to match `node-server-sdk`. Also fix `[^0|^1]` → `[^01]` in `validate()` and add regression tests for `~1`/`~0` at component start, including nested case `/profile/~1ssn`.

## Notes on Scope and Testing

* This was tested offline against public GitHub source. No production system was stressed, no other user's data was accessed, and no credentials were used.
* The finding is filed against the published SDK packages (`@launchdarkly/js-sdk-common` and dependants) which are explicitly in scope as SDKs. `js-core` is the monorepo that publishes them. This is not a dependency-scan result — it was found by reading the source and reproduced by executing the real filter.
* Role used: no LaunchDarkly account. If a role is required by the form, use `Unauthenticated / SDK consumer — offline reproduction`.

---
Researcher: zazieproductions@bugcrowdninja.com
