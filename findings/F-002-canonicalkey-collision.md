# F-002 — Context `canonicalKey` is not injective: a secure-mode hash signed for one context validates for a *different* context

- **Status:** SDK-level flaw **CONFIRMED by executable PoC against the real, unmodified SDK code** (`node-server-sdk`, `python-server-sdk`; plus `js-core` and `go-sdk-common` by source). The *server-side* leg was attempted unauthenticated (CI run 7) and came back **INCONCLUSIVE** — see §7: the baseline probe was rejected because LaunchDarkly's published dogfooding client-side ID is served by an out-of-scope relay, not by the app-host eval route. The definitive server-side test is §H of `tools/ci-authenticated-phase.sh`, run against **our own** environment once `LD_TOKEN` exists. **Do not submit the server-side claim until that runs.**
- **Affected components (all `-sdk` repos, i.e. in the program's SDK scope):**
  - `launchdarkly/python-server-sdk` — `ldclient/context.py` (`_escape_key_for_fully_qualified_key`, `Context.__init__`)
  - `launchdarkly/node-server-sdk` — `context.js` (`encodeKey`, `getCanonicalKey`)
  - `launchdarkly/js-core` (shared by `js-client-sdk`, `react-client-sdk`, browser/node-client SDKs) — `packages/shared/common/src/Context.ts` (`encodeKey`, `canonicalKey` getter); consequences in `packages/shared/sdk-client/src/storage/namespaceUtils.ts` and `packages/shared/sdk-server/src/events/ContextDeduplicator.ts`
  - `launchdarkly/go-server-sdk` via `launchdarkly/go-sdk-common` — `ldcontext/builder_simple.go` (`makeFullyQualifiedKeySingleKind`)
  - and the LaunchDarkly service itself, which must compute the same value to verify the client-side `h` parameter
- **Root cause class:** non-injective identifier used as the input to a MAC (secure mode) and as a cache/dedup key
- **Suggested severity:** **P3** (CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N` = 6.8). Claim rests on defeating the *secure mode* control; see §6 for the honest caveat on attack complexity and for the P4 fallback.
- **Program alignment:** scope lists the SDK repos and the client-side/streaming surface; "Client-side SDKs are specifically meant to prevent attackers from accessing things such as flag evaluation rules due to the untrusted nature of client devices, so any improper handling/exposure of this data may be considered noteworthy." Custom Contexts are an explicitly highlighted feature area.

---

## 1. Summary

Secure mode works by having the customer's backend compute
`h = HMAC-SHA256(environmentSdkKey, canonicalKey(context))` and the client sending `h` alongside the
context. The service re-derives `canonicalKey` from the submitted context and compares.

`canonicalKey` **collides across differently-shaped contexts**:

* a single-kind `user` context returns its key **raw, with no escaping**;
* every other kind, and every kind inside a multi-context, has `:` → `%3A` and `%` → `%25` escaped
  and is prefixed with `kind:`.

Therefore a `user` context whose key is literally `org:o1:user:u1` and the multi-context
`{org:{key:"o1"}, user:{key:"u1"}}` produce the **identical** canonical key — and hence the
**identical secure-mode hash**. A signature the backend legitimately issued for one context is
accepted for the other.

The same non-injective value is also used as (a) the browser SDK's localStorage namespace for cached
flag payloads and (b) the server SDKs' context-deduplication key, so the collision additionally
causes cross-context flag-cache reuse and suppressed context/identify events.

## 2. Root cause, quoted from the SDKs

`python-server-sdk/ldclient/context.py`
```python
def _escape_key_for_fully_qualified_key(key: str) -> str:
    # When building a fully-qualified key, ':' and '%' are percent-escaped ...
    return key.replace('%', '%25').replace(':', '%3A')
...
# multi-context:
full_key += c.kind + ':' + _escape_key_for_fully_qualified_key(c.key)   # kinds sorted, joined by ':'
...
# single context:
self.__full_key = key if kind == Context.DEFAULT_KIND else '%s:%s' % (kind, _escape_key_for_fully_qualified_key(key))
#               ^^^ escape() is SKIPPED exactly when kind == 'user'
```

`node-server-sdk/context.js`
```js
function encodeKey(key) {
  if (key.includes('%') || key.includes(':')) return key.replace(/%/g, '%25').replace(/:/g, '%3A');
  return key;
}
function getCanonicalKey(context) {
  if ((context.kind === undefined || context.kind === null || context.kind === 'user') && context.key)
    return context.key;                                       // <-- RAW
  else if (context.kind !== 'multi' && context.key)
    return `${context.kind}:${encodeKey(context.key)}`;
  else if (context.kind === 'multi')
    return Object.keys(context).sort().filter(k => k !== 'kind')
      .map(k => `${k}:${encodeKey(context[k].key)}`).join(':');
}
```

`js-core/packages/shared/common/src/Context.ts` (identical logic; same `encodeKey`)
```ts
public get canonicalKey(): string {
  if (this._isUser) return this._context!.key;                 // <-- RAW
  if (this._isMulti) return Object.keys(this._contexts).sort()
    .map((key) => `${key}:${encodeKey(this._contexts[key].key)}`).join(':');
  return `${this.kind}:${encodeKey(this._context!.key)}`;
}
```

`go-sdk-common/ldcontext/builder_simple.go` — the comment states this is the *specification*, not an
implementation slip:
```go
// Per the users-to-contexts specification, the fully-qualified key for a single context is:
// - equal to the regular "key" property, if the kind is "user" (a.k.a. DefaultKind)
// - or, for any other kind, it's the kind plus ":" plus the result of partially URL-encoding the
//   "key" property (':' and '%' are percent-escaped ...)
if omitDefaultKind && kind == DefaultKind { return key }       // <-- RAW
escapedKey := strings.ReplaceAll(strings.ReplaceAll(key, "%", "%25"), ":", "%3A")
return fmt.Sprintf("%s:%s", kind, escapedKey)
```

Context **keys are free-form strings** (only *kind* names are validated —
`_INVALID_KIND_REGEX = re.compile('[^-a-zA-Z0-9._]')`), so nothing stops a key from containing `:`.

## 3. Executable proof

Two PoCs run the **real, unmodified SDK code** (no transcription) and are committed to this repo:

| PoC | SDK under test | Result |
|---|---|---|
| `tools/poc-canonicalkey-collision.js` | `node-server-sdk/context.js` (+ `js-core` logic) | headline collision true; **2688 colliding pairs out of 5880 generated contexts**; **0 disagreements** between the two JS implementations |
| `tools/poc-canonicalkey-collision.py` | `python-server-sdk/ldclient/context.py` | **4/4 collisions**, incl. 2-kind and 3-kind multi-contexts; identical HMAC-SHA256 for both shapes |

Representative output (`findings/F-002-canonicalkey-collision/poc-output*.txt`):
```
A = single-kind user context   key='org:o1:team:t1:user:u1'
B = multi-context              {"org": "o1", "team": "t1", "user": "u1"}
   A.fully_qualified_key = 'org:o1:team:t1:user:u1'
   B.fully_qualified_key = 'org:o1:team:t1:user:u1'
   COLLISION = True   identical secure-mode HMAC = True
   hmac = ba57ea45c956b257cbc5652b7030353f7de569c67c34d3e9074b1b373fafdc64
```
Both PoCs are local, offline, credential-free and deterministic; they use a **dummy** SDK key
(`sdk-0000…`) purely to show the two HMACs are equal.

## 4. Primary impact — secure-mode hash transplant

Secure mode's documented guarantee: *"one end user cannot inspect the variations or the reasons for
variations of a feature flag for another end user"*. Because the MAC covers only `canonicalKey`, and
`canonicalKey` is not injective, the binding between a signature and a context is ambiguous:

1. A customer app asks its backend to sign a context whose key the requester influences — a very
   common pattern: username/handle, tenant or organisation slug, device id, session id, email local
   part, an id copied from a webhook or a URL.
2. The attacker arranges for that key to be `org:<victimOrg>:user:<victimUser>` (or any other
   `<kind>:<key>:<kind>:<key>…` shape) and receives a valid `h`.
3. The attacker calls the client-side evaluation route directly with a **different context** that
   shares the canonical key — e.g. the multi-context
   `{"kind":"multi","org":{"key":"<victimOrg>"},"user":{"key":"<victimUser>"}}` — plus the `h` from
   step 2:
   `GET https://app.launchdarkly.com/sdk/evalx/{clientSideId}/contexts/{b64url(context)}?h={h}&withReasons=true`
4. The service re-derives the same canonical key, the MAC matches, and the request is evaluated as
   the victim's multi-context: the attacker receives that context's flag values and (with
   `withReasons=true`) the targeting rules that produced them — the exact data secure mode exists to
   protect. The reverse direction works too (multi → user).

This is not a client-side bug only: the *service* must compute canonicalKey identically to accept
`h`, so the ambiguity is in the shared contract. §7 verifies that server-side behaviour.

## 5. Secondary impacts of the same root cause

**(a) Browser flag-cache collision (client-side, no account needed).**
`js-core/packages/shared/sdk-client/src/storage/namespaceUtils.ts`:
```ts
export async function namespaceForContextData(crypto, environmentNamespace, context) {
  return concatNamespacesAndValues([
    { value: environmentNamespace, transform: noop },
    { value: context.canonicalKey, transform: hashAndBase64Encode(crypto) }, // <-- storage key
  ]);
}
```
`FlagPersistence._storeCache`/`loadCached` use that value as the localStorage key, and the legacy
migration path even calls `storage.clear(context.canonicalKey)`. Two colliding contexts therefore
**share one cache slot**: on a shared/kiosk device, or wherever a second user's context collides with
the first, the SDK can serve the other context's cached flag payload (and overwrite/evict it via the
`ContextIndex` pruning logic). Integrity of client-side evaluation is affected even when the network
response later corrects it.

**(a2) The context-binding guard on incoming flag updates is defeated too.**
`js-core/packages/shared/sdk-client/src/flag-manager/FlagUpdater.ts`:
```ts
upsert(context: Context, key: string, item: ItemDescriptor): boolean {
  if (activeContext?.canonicalKey !== context.canonicalKey) {
    logger.warn('Received an update for an inactive context.');
    return false;                       // guard meant to stop cross-context payload application
  }
```
Because the guard compares `canonicalKey`, an update carrying a colliding context passes the check and
is applied to the active context's flag store — the guard that exists to keep one context's payload
out of another's evaluation does not hold for colliding shapes. (`CacheInitializer.ts` in the FDv2
datasource keys on `canonicalKey` the same way.)

**(b) Event / context deduplication collision (server SDKs).**
`js-core/.../events/ContextDeduplicator.ts` and `node-server-sdk/event_processor.js` key their LRU on
`canonicalKey`:
```ts
public processContext(context: Context): boolean {
  const { canonicalKey } = context;
  const inCache = this._contextKeysCache.get(canonicalKey);
  this._contextKeysCache.set(canonicalKey, true);
  return !inCache;   // second, DIFFERENT context is treated as already seen -> event dropped
}
```
A colliding context suppresses the other's index/identify events, corrupting context discovery and
the analytics/experimentation denominators (exposure counts, MAU/MTU-style metrics) for the affected
window. This is a data-integrity impact on the Experimentation feature area.

Both are consequences of the same defect and are fixed by the same change; they are listed for
triage completeness, not as separate reports.

## 6. Severity reasoning and honest caveats

* **Attack complexity is real.** Step 2 above requires the customer's backend to sign a
  context key the attacker can shape, and to use secure mode. Many apps do (any user-chosen
  handle/slug/device/session id passed through to the LD context), but not all. Hence `AC:H`.
* **What is *not* claimed:** no other tenant's data was accessed; no SDK key was obtained or
  brute-forced; the MAC algorithm itself is sound; and the client-side ID used in §7 is one that
  LaunchDarkly itself publishes to every anonymous visitor and documents as safe to embed in
  untrusted contexts (the program excludes client-side-key secrecy findings — this finding does not
  rely on that key being secret, only on it being a real environment with secure mode enabled).
* **Confidentiality `C:H`** is claimed for the primary impact because a successful transplant yields
  the full client-side flag payload plus, with `withReasons=true`, the targeting rules — for a
  context the attacker is not entitled to evaluate. **`I:L`** covers the cache/dedup corruption.
* If triage views the required backend-signing precondition as reducing impact rather than
  likelihood, the fallback rating is **P4**. The defect is nevertheless in LaunchDarkly's own
  published specification and every SDK that implements it, and the fix is small (see §8).
* **Contingency, stated plainly:** the P3 rating depends on the service verifying `h` with the same
  non-injective canonical key (§7 result is inconclusive so far). If §H shows the service distinguishes
  the two context shapes, the secure-mode claim collapses and what remains is still a real defect but
  rated lower — the client-side flag-cache collision (§5a), the defeated context-binding guard in
  `FlagUpdater.upsert` (§5a2) and the event-deduplication collision (§5b), which are P4/P5-class
  integrity issues that do not depend on server behaviour at all. The report should be filed only after
  §H has run, with the rating adjusted to whichever branch is true.

## 7. Server-side verification (in flight)

`tools/ci-securemode-collision.sh` needs **no account**: LaunchDarkly's own unauthenticated
`GET /internal/config/anonymous` publishes, for its **own dogfooding environment**, a `clientSideId`,
the multi-context it signs, and `secureModeContextHash`. The script:

1. fetches that response once;
2. computes the signed context's canonical key locally (spec-exact) and builds the colliding
   single-kind `user` context `{"kind":"user","key":"<that canonical key>"}`, plus an unrelated
   control context;
3. issues ≤ 9 GETs to the documented client-side route on the in-scope app host:
   signed-context+`h`, colliding-context+`h`, control+`h`, colliding+`withReasons`, and the
   no-`h`/bad-`h` controls that establish whether secure mode is enforced at all;
4. records only status code, byte length and a 160-char excerpt — **flag payloads are not committed**
   (stored bodies are truncated to 400 B).

Decision rule baked into the script:

| observation | conclusion |
|---|---|
| no-`h` → 2xx | secure mode not enforced for that env → **inconclusive**, re-run on our own env |
| no-`h` → 4xx, control+`h` → 4xx, collision+`h` → 2xx | **confirmed**: hash accepted for a different context shape |
| no-`h` → 4xx, control+`h` → 4xx, collision+`h` → 4xx | service distinguishes the shapes → not vulnerable server-side (SDK-only finding) |

Safety: in-scope host only, LaunchDarkly's own dogfood environment only, read-only, tiny volume, no
other customer's tenant touched.

### Result — CI run 7 (`ci-results/run-7/securemode-collision.txt`): INCONCLUSIVE

```
canonicalKey(signed multi-context)      : session:fac2c19b-…:user:fac2c19b-…
canonicalKey(colliding single-kind user): session:fac2c19b-…:user:fac2c19b-…
COLLISION (local)                       : True

orig (with h) BASELINE   401   0B      <-- the signed context with its OWN valid hash
collision (with h)       401   0B
control (with h)         401   0B
orig (NO h)              401   0B
```

The **baseline failed**, so nothing can be concluded in either direction: the route never accepted the
context it was given a valid signature for. `401` with a `0`-byte body is exactly what this route
returns for a client-side ID it does not know (`ci-results/run-2/route-matrix.txt`:
`GET /sdk/evalx/thisidshouldnotexist/contexts/{valid ctx}` → `401 0B`), and the same config response
points LaunchDarkly's own SDK at `relay-fdv2-prod.ld.catamorphic.com` — a host that is **out of scope**
and is **not** contacted by this script. In other words: the dogfooding environment's flags are not
served by `app.launchdarkly.com/sdk/evalx/`, so this route cannot be used to test their hash
validation without an account.

The script was then changed to fail fast (baseline first, two requests instead of eight) and to report
`INCONCLUSIVE` rather than a false negative; the earlier version's "NOT VULNERABLE server-side" line
was an artefact of checking only the collision probe, and is withdrawn.

**What still stands:** the SDK-level defect is proven with executable PoCs (§3) against four
implementations, including the two that LaunchDarkly ships and supports today, and it is documented in
`go-sdk-common` as the *specification*. What is unproven is whether the service's own `h` verification
reproduces the same non-injective canonical key. §H of `tools/ci-authenticated-phase.sh` settles it on
our own tenant: it reads our own environment's `clientSideId` and SDK key with our own token, computes
`h(A)` and `h(B)` locally, and probes A+h(A), **B+h(A)** (the collision), C+h(A) (control), and A/B
without `h`. Secure mode must be enabled on that environment (UI toggle, or
`LD_ALLOW_ENV_PATCH=true`). The SDK key is held in memory only and never written to an artifact.

## 8. Suggested remediation

1. **Make the encoding injective.** Apply the same escaping to `user`-kind keys as to every other
   kind (`%` → `%25`, `:` → `%3A`), i.e. never emit an unescaped key. Keep back-compat by accepting
   both forms during verification, or version the scheme (`LD-API-Version`-style / `ckv=2`).
2. **Or bind the MAC to the whole context identity**, not just the key: e.g.
   `HMAC(sdkKey, canonicalJSON({kind(s), key(s)}))` or a length-prefixed encoding
   (`<nKinds>:<kind1>:<len>:<key1>:…`) that cannot be re-parsed as another shape.
3. **Defence in depth on the service:** when secure mode is enabled, reject an `h` whose context
   shape (set of kinds) differs from the shape the hash was issued for, and consider rejecting
   `user`-kind keys that parse as `<kind>:<key>[:<kind>:<key>]…`.
4. **Fix the derived key consumers** (localStorage namespace, dedup LRU) to use an encoding that
   includes the kind set, so distinct contexts can never share a cache slot or an event key.

## 9. Artifacts

```
tools/poc-canonicalkey-collision.js          node PoC (real node-server-sdk code + js-core logic)
tools/poc-canonicalkey-collision.py          python PoC (real python-server-sdk Context class)
tools/ci-securemode-collision.sh             live, account-free server-side verification
findings/F-002-canonicalkey-collision/       poc-output.txt, poc-output-python.txt, collision-examples.json
sdk/                                         cloned SDK sources (gitignored)
```

## 10. Report hygiene

One vulnerability per report: this submission is the non-injective `canonicalKey` / secure-mode hash
transplant. F-001 (unauthenticated `/internal/config/anonymous` disclosure) is a separate report with
a different root cause and fix, even though it supplies the dogfooding material used in §7.
