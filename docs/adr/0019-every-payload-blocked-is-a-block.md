# 19. A CVE whose every payload was refused is blocked, not partially blocked

Date: 2026-08-20

## Status

Accepted. Refines the buckets defined in
[ADR 3](0003-report-per-cve-and-separate-upstream-errors.md).

## Context

"Partially blocked" is a claim: some of this CVE's attacks got through. Reading the request
sequences of all 641 partially blocked CVEs at PL4 on run 32369626239 shows that for most of
them nothing did.

| | count |
| --- | --- |
| every payload-carrying request was refused | **413** |
| a payload really did get through | 173 |
| the CVE's class means a bare request can be the attack | 36 |
| the only refusal was the template's own sign-in | 18 |

Two shapes account for the 413. **290** send reconnaissance first — a plugin directory, a
version file — and then the attack, which is refused. **109** are the reverse, and were the
surprise: the attack is refused and the template then checks for the artefact it would have
created.

```
POST /wp-admin/admin.php?page=html2wp-settings   403
GET  /wp-content/uploads/html2wp/3IBEVk...php    200
```

That 200 is the mock answering for a webshell the blocked upload never wrote. Counting it as
the WAF letting something through is backwards.

## Decision

A CVE with a mixed verdict reads as blocked when all three hold:

1. no request carrying a payload came back as anything other than 403,
2. something other than a plain sign-in was refused,
3. the CVE's class is not one where a bare request can itself be the attack.

A request carries a payload if it uses a method other than `GET` or `HEAD`, has a query
string, has a body, contains an encoded character or a traversal sequence, or names a system
file outright. Everything else is a plain fetch.

Condition 2 exists because a WAF that refuses `POST /wp-login.php` has refused an ordinary
login, which says nothing about the exploit that login was leading to — crediting it would
reward a false positive. A request to an auth path *with* a query string is not a sign-in:
`/wp-login.php?login-error=<script>` is an XSS payload aimed at the login page.

Condition 3 covers the classes from [ADR 18](0018-count-access-control-cves-separately.md)
plus `CWE-200`, `CWE-538` and `CWE-548`. `CVE-2023-2734` is why: it sends
`/?rest_route=/wp/v2/users`, which CRS refuses, and then the bare `/wp-json/wp/v2/users`,
which it does not — and the bare one is the exploit. Without this condition the CVE would
report as fully blocked while its attack succeeded.

## Consequences

- The published rate rises about ten points at every level. Run 32369626239: PL1 42.0% →
  50.0%, PL2 48.6% → 57.5%, PL3 56.2% → 66.4%, PL4 60.7% → 71.2%. Nothing about the WAF
  changed; the previous number counted reconnaissance as a failed defence.
- `cves_partially_blocked` now means what it says. At PL4 it falls from 641 to 227, and those
  227 are CVEs where a payload demonstrably got through — a list worth reading, which 641 was
  not.
- The next run-to-run diff shows a large jump, and the churn floor will need re-measuring
  again.
- This is a heuristic over request shape, and its failure mode is flattering: a payload the
  shape test misses would let a CVE read as blocked. The three conditions are what keep that
  narrow, and each is covered by a test that fails when the condition is removed.
- A CVE can still be "partially blocked" and mean it. 173 at PL4 do.

## Alternatives considered

- **Report it alongside instead**, as ADR 18 does for access-control classes. Rejected
  because that ADR answers a different question: those CVEs are correctly bucketed and the
  extra figure says how much of the result a ruleset could ever influence. Here the bucket
  itself was wrong.
- **Decide from the template rather than the trace**, matching each request to the step that
  declared it. More faithful, and it needs variable interpolation to be reversed to work at
  all.
- **Treat any unblocked plain GET as reconnaissance**, without conditions 2 and 3. Simpler,
  and it would have reported `CVE-2023-2734` as defended while its exploit succeeded.
