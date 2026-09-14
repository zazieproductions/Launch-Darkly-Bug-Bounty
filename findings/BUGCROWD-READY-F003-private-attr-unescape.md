# Sensitive Data Exposure in LaunchDarkly js-core AttributeReference allows private attributes starting with '/' or '~' to leak to event pipeline

## Summary

`launchdarkly/js-core` powers all current browser and client-side SDKs (`@launchdarkly/js-sdk-common` → `js-client-sdk`, `react-client-sdk`, `vue-client-sdk`, etc.). Its `AttributeReference` unescapes `~1` → `/` and `~0` → `~` using `ref.indexOf('~')` as a boolean. When `~` is at index 0 (exactly the case for an attribute literally named `/ssn` referenced as `/~1ssn`), the check is falsy and the replacement is skipped. The filter then looks for the wrong name, never redacts it, and the raw value is sent to `events.launchdarkly.com` and to any configured Data Export destinations. Anyone can reproduce this locally — no LaunchDarkly account is required.

## Affected asset

- **URL / endpoint:** `https://github.com/launchdarkly/js-core/blob/main/packages/shared/common/src/AttributeReference.ts#L18` — published as `npm @launchdarkly/js-sdk-common` (shared by all `js-core` SDKs)
- **HTTP method:** N/A — offline SDK logic, exercised via `ContextFilter.filter()` which populates `context` on `identify`/`index` events sent to `events.launchdarkly.com`
- **Parameter or field:** `privateAttributes` entry and `_meta.privateAttributes` (JSON Pointer style, e.g., `/~1ssn`, `/~0secret`, `/profile/~1ssn`)
- **Account role required:** None — offline reproduction against public source
- **Environment:** `js-core` HEAD `6d92d5b` (2026-09-11), re-checked on `main` 2026-09-13, Node.js 22
- **Date tested:** 2026-09-13

## Preconditions

- Node.js ≥22.6 (uses built-in TypeScript transform; no `npm install`)
- Two public repositories cloned read-only:
  ```bash
  git clone --depth 1 https://github.com/launchdarkly/js-core
  git clone --depth 1 https://github.com/launchdarkly/node-server-sdk
  ```
- The attached PoC `poc-private-attr-unescape-real.mjs` (also reproducible with the 3-line inline snippet below)
- No LaunchDarkly account, no API key, no network calls to LaunchDarkly are needed

## Steps to reproduce

1. Clone the two public repositories as above.
2. Save the attached PoC as `poc-private-attr-unescape-real.mjs` in the same parent directory (or use the minimal inline check in step 2a).
   2a. Minimal inline check (no harness):
   ```js
   function unescape_buggy(ref){ return ref.indexOf('~') ? ref.replace(/~1/g,'/').replace(/~0/g,'~') : ref; }
   console.log(unescape_buggy('~1ssn')); // observed: "~1ssn" — expected "/ssn"
   console.log(unescape_buggy('a~1b'));  // observed: "a/b"  — correct, so casual tests miss the bug
   ```
3. Run the full harness:
   ```bash
   node poc-private-attr-unescape-real.mjs
   ```
   The script loads `AttributeReference.ts`, `ContextFilter.ts`, and `Context.ts` unmodified from `js-core` via `--experimental-transform-types`, and `attribute_reference.js` / `context_filter.js` unmodified from `node-server-sdk` v7 as a control. The only stub is for `src/api/context` type-only interfaces (six type names, no runtime code).

4. Observe the output section `1. The parsing divergence`:
   - `/~1ssn` → `["~1ssn"]` (should be `["/ssn"]`) — **WRONG**
   - `/~0secret` → `["~0secret"]` (should be `["~secret"]`) — **WRONG**
   - `/a~1b` → `["a/b"]` — correct (bug hidden when `~` is not at index 0)

5. Observe section `2. End-to-end: is the private attribute actually redacted?` using this input context:
   ```json
   {
     "kind": "user", "key": "u-123", "email": "user@example.com",
     "/ssn": "123-45-6789", "~secret": "tilde-value",
     "a/b": "slash-in-middle", "profile": { "/ssn": "987-65-4321", "city": "Asheville" },
     "_meta": { "privateAttributes": ["/~1ssn","/~0secret","/a~1b","/profile/~1ssn"] }
   }
   ```

6. Compare outputs:
   - **Expected:** `redactedAttributes` contains all four references; none of the four values appear in the filtered context.
   - **Observed with js-core:** `redactedAttributes: ["/a~1b"]` — only one redacted; `"/ssn"`, `"~secret"`, and `profile."/ssn"` remain with raw values.
   - **Observed with node-server-sdk v7 control:** `redactedAttributes: ["/a~1b","/profile/~1ssn","/~0secret","/~1ssn"]` — all four redacted.

## Proof of concept

**Defective code (public link):**
```ts
// https://github.com/launchdarkly/js-core/blob/main/packages/shared/common/src/AttributeReference.ts#L18
function unescape(ref: string): string {
  return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
}
```
Correct implementation for reference: `https://github.com/launchdarkly/node-server-sdk/blob/main/attribute_reference.js#L18` — `component.indexOf('~') >= 0 ? ...`

**Attached evidence (no private repo needed):**
- `poc-private-attr-unescape-real.mjs` — runs real vendor code on both sides (ATTACHED)
- `poc-output-v2-real.txt` — full run log showing `3 of 4 LEAKED` for js-core vs `4/4 REDACTED` for control (ATTACHED)
- `filtered-contexts-v2-real.json` — input and both filtered outputs, byte-for-byte wire payloads (ATTACHED)

Excerpt from `poc-output-v2-real.txt`:

```
reference            js-core .get(target)   node-server-sdk get(target,ref)
  /~1ssn               undefined              "V1"                             false
  /~0secret            undefined              "V2"                             false
  /a~1b                "V3"                   "V3"                             true
  /profile/~1ssn       undefined              "V4"                             false

js-core filtered context:
{"_meta":{"redactedAttributes":["/a~1b"]},"profile":{"city":"Asheville","/ssn":"987-65-4321"},"~secret":"tilde-value","/ssn":"123-45-6789",...}
node-server-sdk filtered context:
{"_meta":{"redactedAttributes":["/a~1b","/profile/~1ssn","/~0secret","/~1ssn"]},"profile":{"city":"Asheville"},...}
```

**Wire path:** In `js-core` the filtered object is the event payload. `src/internal/events/EventProcessor.ts:156` constructs `ContextFilter` from `privateAttributes`; `:333` assigns `context: this._contextFilter.filter(event.context, !debug)` to the outgoing event. No further stripping occurs.

No requests were sent to LaunchDarkly during this reproduction; no customer data was accessed.

## Impact

A customer who configures `privateAttributes: ["/~1ssn"]` to keep an attribute named `/ssn` out of LaunchDarkly would have that value delivered to LaunchDarkly and forwarded to any Data Export destinations they configured (S3, Segment, Splunk, webhook). The `_meta.redactedAttributes` list omits the field, so the dashboard gives no indication the setting is ineffective.

This affects every SDK built on `@launchdarkly/js-sdk-common` and requires only an attribute name beginning with `/` or `~` — a normal pattern for namespaced or JSON-Pointer-style keys. The scope is the customer's own PII to their own pipeline (not another tenant's data or RCE), so I am claiming P3 (CVSS:3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3) and not P1/P2.

## Suggested remediation

```diff
- return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
+ return ref.includes('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
```

or `indexOf('~') >= 0` to match `node-server-sdk`. Also fix `validate()` regex `[^0|^1]` → `[^01]` in the same function, and add regression tests for `~1`/`~0` at component start, including the nested case `/profile/~1ssn` and a cross-SDK contract test in `sdk-test-harness`.

---
**Researcher:** zazieproductions@bugcrowdninja.com — offline SDK consumer, no LaunchDarkly account used (if the form requires a role, use `Unauthenticated`)
**VRT:** `Sensitive Data Exposure > Disclosure of Secrets > PII Leakage/Exposure` (CWE-359, CWE-697)
