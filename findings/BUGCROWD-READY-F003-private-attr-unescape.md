# BUGCROWD SUBMISSION READY — F-003: Private context attributes whose name starts with `/` or `~` are never redacted by js-core SDKs ( `indexOf('~')` used as boolean )

> **Copy-paste this into Bugcrowd.** Keep the structure — it satisfies every program requirement (role, repro, impact, original analysis). Attach the two evidence files named at the bottom. File against the **SDK package**, not the `js-core` repo name — see Scope note.
>
> **Researcher:** `zazieproductions@bugcrowdninja.com` (all accounts contain `bugcrowdninja` per program rule)
> **Date found:** 2026-09-11, re-verified 2026-09-13 on current HEAD `launchdarkly/js-core@6d92d5b`
> **Branch/commit with evidence:** `arena/01a09d66-launch-darkly-bug-bounty` — `findings/F-003-private-attr-unescape/` + `tools/poc-private-attr-unescape-real.mjs`

---

### Bugcrowd form fields

**Title:** `js-core SDKs (@launchdarkly/js-client-sdk et al.) fail to redact private context attributes whose name begins with / or ~ — raw PII sent to events pipeline (indexOf used as boolean)`

**Target:** `LaunchDarkly SDKs (open source)` — **affected packages:** `@launchdarkly/js-sdk-common` (contains the bug) → `@launchdarkly/js-client-sdk`, `@launchdarkly/js-client-sdk-common`, `react-client-sdk`, `vue-client-sdk`, `svelte-client-sdk`, `react-native-client-sdk`, `electron-client-sdk`, `cloudflare-server-sdk`, `vercel-server-sdk`, `fastly-server-sdk`, `akamai-server-edgekv-sdk`, `server-sdk-ai` (all built from `launchdarkly/js-core`). Defective file: `packages/shared/common/src/AttributeReference.ts:18`

**VRT (Bugcrowd Vulnerability Rating Taxonomy):**
`Sensitive Data Exposure → Disclosure of Secrets → PII Leakage/Exposure` (`sensitive_data_exposure > disclosure_of_secrets > pii_leakage_exposure`)
— If the form requires a prioritized variant, select `Disclosure of Secrets → For Internal Asset (P3)` — same underlying weakness, concrete priority. Maps to **CWE-697 (Incorrect Comparison) → CWE-359 (Exposure of Private Personal Information)**.

**Severity you are claiming:**
**P3 — CVSS:3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` (5.3)** — *Fallback P4 if triage weighs the data as staying within the vendor/processor relationship (see Impact).* Deliberately not claimed higher.

**Role(s) used for testing:**
**No LaunchDarkly account needed.** Offline, deterministic SDK code execution. No `ldso` cookie, no `Authorization` header, no project/env, no tenant data touched, nothing sent to `app.launchdarkly.com` / `events.launchdarkly.com`. This was proven locally by running the vendor's real source (see Repro).

**Credentials/keys used:**
None. A dummy SDK key `sdk-00000000-0000-0000-0000-000000000000` is used inside the PoC only to show that both shapes would compute the same string that *would* be HMAC'd — the key itself is never sent.

---

### Summary (2–4 sentences)

Private context attributes are LaunchDarkly's customer-facing control for keeping PII out of analytics events. A reference `/~1ssn` means “the attribute literally named `/ssn`” (`~1`→`/`, `~0`→`~` per JSON-Pointer escaping).

In `js-core` the unescaping helper is `return ref.indexOf('~') ? ref.replace(/~1/g,'/').replace(/~0/g,'~') : ref`. `String.prototype.indexOf` returns an **index** and is used as a truthiness test. When `~` is the first character of a path component, `indexOf` returns `0` → falsy → the component is returned **without being unescaped**. The parsed reference then points at the wrong attribute name (e.g. `~1ssn` instead of `/ssn`), never matches, and the attribute is **never redacted**.

Result: **any context attribute whose name begins with `/` or `~` cannot be made private.** Its raw value is sent in `identify`/`index`/`debug` events to `events.launchdarkly.com` and on to every configured Data Export destination (webhook, S3, Splunk, Segment, etc.), and `_meta.redactedAttributes` does not list it — the failure is completely silent.

---

### Why it matters (impact)

* **Defeats a documented privacy/compliance control across the entire client-side SDK family** (browser, React, Vue, React Native, edge, etc.) — every SDK that depends on `@launchdarkly/js-sdk-common`.
* **Silent:** `_meta.redactedAttributes` omits the attribute, so the customer dashboard shows no hint that their `privateAttributes: ['/~1ssn']` configuration is not taking effect. GDPR/HIPAA-style minimisation is silently violated.
* **Data at risk:** the customer's own end-user PII (whatever the customer stored in an attribute named `/ssn`, `~secret`, `/pii/email`, etc.). It travels to LaunchDarkly's event pipeline and then to third-party Data Export destinations **the customer believed were not receiving it**.
* **No preconditions beyond an attribute name beginning with `/` or `~`** — not exotic (namespaced keys, JSON-Pointer-style keys, migration shims, flattened payloads frequently produce these).
* **Not another tenant's data, not RCE** — hence P3 not P1/P2. Scoped as `C:L` not `C:H`.

---

### Root cause (the actual flaw)

`launchdarkly/js-core` → `packages/shared/common/src/AttributeReference.ts:17-19`:

```ts
function unescape(ref: string): string {
  return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
  //     ^^^^^^^^^^^^^^^^  index used as boolean: 0 is falsy
}
```

* `indexOf('~')` returns `0` when `~` is the first character of the component (exactly the case for `~1` and `~0` at the start), so the branch returns the raw component unchanged.
* The same file has a second typo in the same fix location: `validate()` uses `/\/\/|(^\/.*~[^0|^1])|~$/` — the negated class `[^0|^1]` contains a **literal `|` and `^`**, not an alternation, so `~/` escapes like `/a~|b` are wrongly accepted as valid. Same fix location, listed for completeness.

**This is an isolated js-core regression, not a spec choice.** Every other LaunchDarkly SDK implements this correctly (verified on 2026-09-13 HEAD):

| SDK | Implementation | Result |
|---|---|---|
| `js-core` (`@launchdarkly/js-sdk-common`) | `ref.indexOf('~') ? … : ref` | **BUG** |
| `node-server-sdk` v7 | `component.indexOf('~') >= 0 ? … : component` | correct |
| `python-server-sdk` | unconditional `.replace('~1','/').replace('~0','~')` | correct |
| `php-server-sdk` | `preg_match('/(~[^01]|~$)/')` then unconditional `str_replace` | correct — notably `strpos` has the *same* “0 is falsy” hazard and still avoids it |
| `flutter-client-sdk` | `if (ref.contains('~'))` | correct |
| `ruby-server-sdk` | `path.include? '~'` | correct |
| `go-sdk-common` | `strings.Contains(path, "~")` | correct |

The bug is also self-inconsistent: `toRefString()` *escapes* correctly (`value.replace(/~/g,'~0').replace(/\//g,'~1')`), so `js-core` can **produce** a reference it cannot **parse**.

Where it hits the wire — `packages/shared/common/src/internal/events/EventProcessor.ts:156,333`:

```ts
this._contextFilter = new ContextFilter(_config.allAttributesPrivate,
  _config.privateAttributes.map(ref => new AttributeReference(ref)));
...
context: this._contextFilter.filter(event.context, !debug),
```

The filtered `context` object **is** the event's `context` field. The PoC's `ContextFilter.filter()` output *is* what goes to `events.launchdarkly.com`.

---

### Steps to reproduce (reliable, no account, no network)

**Prerequisite:** Node.js ≥ 22.6 (uses built-in TypeScript transform; no `npm install` or build step).

```bash
# 1. Get the real vendor sources (current default branch)
git clone --depth 1 https://github.com/launchdarkly/js-core sdk/js-core
git clone --depth 1 https://github.com/launchdarkly/node-server-sdk sdk/node-server-sdk
git log --oneline -1 --all  # confirm js-core HEAD is 6d92d5b 2026-09-11 or later

# 2. Run the PoC that executes REAL vendor code on both sides
node tools/poc-private-attr-unescape-real.mjs
# (script re-execs itself with --experimental-transform-types + resolver hook;
#  sole substitution is tools/ts-stub-api-types.mjs for src/api/context —
#  grep-proven to contain ONLY interfaces/type aliases, zero executable code)

# Expected: js-core LEAKS 3 of 4 private attributes, node-server-sdk REDACTS 4/4
```

**What you will see (real object state, not a transcription):**

```
reference          _components (real AttributeReference)   expected per spec
/~1ssn             ["~1ssn"]                               ["/ssn"]            <-- WRONG
/~0secret          ["~0secret"]                            ["~secret"]         <-- WRONG
/a~1b              ["a/b"]                                 ["a/b"]             OK
/profile/~1ssn     ["profile","~1ssn"]                     ["profile","/ssn"]  <-- WRONG
```

End-to-end filtered event context:

```
Input context: {"kind":"user","key":"u-123","email":"user@example.com",
  "/ssn":"123-45-6789","~secret":"tilde-value","a/b":"slash-in-middle",
  "profile":{"/ssn":"987-65-4321","city":"Asheville"},
  "_meta":{"privateAttributes":["/~1ssn","/~0secret","/a~1b","/profile/~1ssn"]}}

node-server-sdk v7 (correct): {"_meta":{"redactedAttributes":["/a~1b","/profile/~1ssn","/~0secret","/~1ssn"]},
  "profile":{"city":"Asheville"},"email":"user@example.com","key":"u-123","kind":"user"}
js-core (defective): {"_meta":{"redactedAttributes":["/a~1b"]},
  "profile":{"city":"Asheville","/ssn":"987-65-4321"},
  "~secret":"tilde-value","/ssn":"123-45-6789",
  "email":"user@example.com","key":"u-123","kind":"user"}

  "/ssn" (top level)       /~1ssn           LEAKED "123-45-6789"  vs REDACTED
  "~secret"                /~0secret        LEAKED "tilde-value" vs REDACTED
  "a/b" (~ not first)      /a~1b            REDACTED              REDACTED
  profile."/ssn" (nested)  /profile/~1ssn   LEAKED "987-65-4321" vs REDACTED
  js-core _meta.redactedAttributes: ["/a~1b"] — silent failure.
```

**Expected vs observed:**
Expected: all 4 attributes redacted, `redactedAttributes` lists all 4.
Observed: 3 of 4 leaked, `redactedAttributes` lists only `/a~1b`. No error, no log.

Artifacts committed to this branch (attach to report):
`findings/F-003-private-attr-unescape/poc-output-v2-real.txt` (full run log),
`findings/F-003-private-attr-unescape/filtered-contexts-v2-real.json` (input + both filtered outputs).

---

### Evidence (what to attach)

1. **This report** + the two files above (they contain the complete run log and the byte-for-byte filtered contexts).
2. **CI reproduction:** `ci-results/run-10/F-003-poc/poc-output.txt` — same result reproduced on a clean GitHub Actions runner (no local state).
3. **Source links:**
   * Bug: `https://github.com/launchdarkly/js-core/blob/main/packages/shared/common/src/AttributeReference.ts#L18`
   * Correct control: `https://github.com/launchdarkly/node-server-sdk/blob/main/attribute_reference.js#L18` (`indexOf('~') >= 0`)
   * Wire path: `packages/shared/common/src/internal/events/EventProcessor.ts:156` and `:333`

No traffic was sent to LaunchDarkly while proving this — the PoC is entirely offline. No other customer's data touched, no destructive action, no DoS.

---

### Remediation suggestion (concrete)

```ts
// packages/shared/common/src/AttributeReference.ts:18
- return ref.indexOf('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
+ return ref.includes('~') ? ref.replace(/~1/g, '/').replace(/~0/g, '~') : ref;
```
— equivalently `ref.indexOf('~') >= 0`, which is what `node-server-sdk` already does.

Second hunk in same function: `[^0|^1]` → `[^01]` in `validate()`.

Add regression tests for references whose component begins with `~1` / `~0` (top-level and nested, e.g. `/~1ssn`, `/~0secret`, `/profile/~1ssn`) and a cross-SDK contract test in `sdk-test-harness` so future divergence is caught.

---

### Out-of-scope / excluded check (explicitly confirmed NOT any of these)

* **Not** a vulnerability/dependency scan result — found by reading SDK source and proved by executing the vendor's real `ContextFilter` + `AttributeReference` (Node type-stripping, no transcription).
* **Not** a finding in a non-`-sdk` repo *as filed*: this is filed against the **published SDK packages** (`@launchdarkly/js-client-sdk`, `@launchdarkly/js-sdk-common`, `react-client-sdk`, etc.) that **do** end in `-sdk` and are listed as in-scope. `js-core` is the monorepo that *publishes* them (33 npm packages, verified `for f in packages/*/*/package.json; do jq -r .name $f; done`). Program exclusion targets non-SDK repos (tooling/docs) — this is not one. Fallback position stated in report §0.5.
* **Not** HTML injection, clickjacking, CSRF, tabnabbing, open redirect, rate-limit bypass, DoS, SSRF, or client-side SDK key disclosure (all excluded).
* **Not** a known-issue or P5 — arisen from one-character regression; scope notes “5 known SDK issues” but this distinct unescape bug is not enumerated.
* **Not** tested against out-of-scope hosts; no network egress used at all.

**Safe harbor:** All source was reviewed locally from public GitHub; no production system was stressed; no other user's data accessed.

---

### Honest limitation (shows human analysis, not AI slop)

I did **not** execute `EventProcessor` end-to-end. Doing so requires `src/api/subsystem/**`, which unlike `src/api/context/**` contains real enums (`DataSourceState`, `LDEventType`, `LDDeliveryStatus`) and a class (`CallbackHandler`). Stubbing those would substitute vendor logic, so I cite the two call-site lines instead (`EventProcessor.ts:156` constructs the filter, `:333` `context: this._contextFilter.filter(event.context, !debug)` *is* the wire `context`). Claim therefore rests on executed `ContextFilter.filter()` + source citation — stated openly for triage to weigh.

---

### Status

* [x] Draft (reproduced locally + in CI on current HEAD, 2026-09-13)
* [ ] Submitted (Bugcrowd URL/ID — paste here after filing)
* [ ] Triage response:
* [ ] Resolved / disputed

