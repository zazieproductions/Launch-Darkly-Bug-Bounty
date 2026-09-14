# Account-setup runbook — activating the authenticated phase

Everything so far has been unauthenticated. `tools/ci-authenticated-phase.sh` is written, tested for
syntax and **inert**: with no `LD_TOKEN` secret it prints `SKIPPED` and exits 0. This runbook is the
exact, minimum set of actions needed to switch it on. All of them are yours to perform — I cannot set
repo secrets (`gh secret list` returns 403 in this sandbox), and I will never ask for a password,
token or 2FA code in chat.

Estimated effort: ~15 minutes. Nothing here is destructive, and every test stays inside our own account.

---

## 1. Create the LaunchDarkly account

1. Sign up at `https://app.launchdarkly.com/signup` using **`zazieproductions@bugcrowdninja.com`** —
   the program requires the `@bugcrowdninja.com` address so submissions are attributable.
2. Verify the email, then start the self-serve trial. Signup is open
   (`disallowSignups=false` in the disclosed config) and the disclosed
   `pql-signup-junk-country-list` does not include the US, so a US signup is not blocked.
3. Note the **account id**: it is the 24-hex string in the URL after login —
   `https://app.launchdarkly.com/account/<24-hex>/settings`.

## 2. Create a second project (needed for the authz matrix)

The most valuable test available without touching another customer's data is *scope enforcement
inside our own account*: a token restricted to project 1 must not be able to read project 2.
So create two projects, each with one environment:

* project `bb-project-1` (environment `production`)
* project `bb-project-2` (environment `production`)

Optionally add 1–2 flags to each so read tests return content.

## 3. Create two API tokens (Reader only — never Admin/Writer)

Account Settings → Authorization → API access tokens:

| token | scope | secret name |
|---|---|---|
| #1 | **Reader** on the whole account | `LD_TOKEN` |
| #2 | **Reader** on `bb-project-1` only | `LD_TOKEN_SCOPED` |

Token #2 is what makes §D of the harness meaningful: if it can read `bb-project-2`, that is broken
scope enforcement (a P2-class finding) proved entirely with our own data.

## 4. Add the secrets to this repo

Repo → Settings → Secrets and variables → Actions → New repository secret:

| secret | required? | what it unlocks |
|---|---|---|
| `LD_TOKEN` | **yes** | activates the whole harness (§A–§H) |
| `LD_TOKEN_SCOPED` | recommended | §D scoped-token / privilege-escalation matrix |
| `LD_ACCOUNT_ID` | optional | §B account-ID-header resolution with a real value (the harness also tries to derive it) |
| `LD_SSRF_CAPTOR` | optional | §I only — a request-interaction URL **you** control (Burp Collaborator / webhook.site). The program requires captor metadata for any SSRF claim, so without it those endpoints are not touched at all |
| `LD_ALLOW_ENV_PATCH` | optional (`true`) | §H lets the harness `PATCH` **our own** environment to turn **secure mode** on — needed for the definitive F-002 proof if you don't want to click the toggle in the UI. Reversible |
| `LD_ALLOW_RESOURCE_CREATION` | optional (`true`) | currently unused by the read-only harness; reserved |
| `LD_ALLOW_ORG_VERIFICATION` | optional (`true`) | POSTs `/internal/unauthenticated-members/organization-verifications`, which may create state. Default off |
| `LD_ALLOW_LOGIN` / `LD_LOGIN_EMAIL` / `LD_LOGIN_PASSWORD` | **leave unset** | the cookie/session path is deliberately *not* automated — a password should not live in CI. If we ever need the `ldso` cookie path, do it manually in a browser |

## 5. Enable secure mode on one environment (for the definitive F-002 test)

F-002's live proof needs an environment with **secure mode ON**: Environment Settings → Secure mode →
enable, for `bb-project-1/production`. (Or set `LD_ALLOW_ENV_PATCH=true` and let the harness do it.)
§H then reads our own `clientSideId` and SDK key with our own token, computes both HMACs locally, and
probes:

```
A = {"kind":"user","key":"org:K:user:K"}                     + h(A)
B = {"kind":"multi","org":{"key":"K"},"user":{"key":"K"}}    + h(A)   <-- the collision
C = {"kind":"user","key":"bugcrowd-unrelated-control"}       + h(A)   <-- must be rejected
A, B without h                                                        <-- shows secure mode is enforced
```

`secure mode enforced` + `C rejected` + `B accepted with A's hash` = F-002 confirmed on our own
tenant, which is the version of the proof that survives triage. The SDK key is held in memory only and
never written to any artifact; a redaction sweep runs before anything is committed.

## 6. What the harness will and will not do

**Will:** GET our own account's projects, environments, members, teams, roles, tokens, context kinds,
applications, destinations, webhooks, usage, entitlements, plans, `/internal/` read endpoints; POST the
two read-only-by-semantics endpoints (`flags/search`, `access-check/{service}/bulk`); compare
nonexistent vs random-valid ids for enumeration; run the F-002 collision probes on our own env.

**Will not:** touch another tenant's data (no other account's ids are ever used — the one customer
account id disclosed by `/internal/config/anonymous` is explicitly *not* used, per program rules);
create, modify or delete anything unless an opt-in switch is set; send a password; run any
auth-flow mutation; POST `organization-verifications`; contact an SSRF target without a captor;
rate-limit or stress anything (every request has a 300 ms gap and the totals are in the tens).

To stop it at any time: delete the `LD_TOKEN` secret. The next run prints `SKIPPED` and exits.

## 7. Where results land

`ci-results/run-N/auth-phase/authenticated-phase.txt` (plus truncated, redacted bodies in
`auth-phase/raw/`) on branch `arena/01a09299-launch-darkly-bug-bounty`. Pull with:

```bash
git pull --rebase origin arena/01a09299-launch-darkly-bug-bounty
```

## 8. Bugcrowd side (parallel track)

* Register/confirm the Bugcrowd account with the same `@bugcrowdninja.com` address.
* One vulnerability per report: F-002 and F-003 are separate reports (different files, different root
  causes, different fixes); F-001 is a third.
* Both F-002 and F-003 ship with executable PoCs that run the vendors' real code — no speculation, no
  scanner output, nothing AI-padded. The leads in `plans/auth-posture-leads.md` stay unfiled until
  verified.
