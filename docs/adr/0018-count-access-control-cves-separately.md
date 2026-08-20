# 18. Count access-control CVEs separately

Date: 2026-08-20

## Status

Accepted.

## Context

Breaking the misses down by CWE rather than by request shape puts the same four classes at
the top every time, measured at PL4 on run 32369626239:

| CWE | | missed | of | rate |
| --- | --- | --- | --- | --- |
| CWE-862 | missing authorization | 48 | 74 | 65% |
| CWE-306 | missing authentication for a critical function | 47 | 83 | 57% |
| CWE-287 | improper authentication | 57 | 107 | 53% |
| CWE-284 | improper access control | 17 | 29 | 59% |

For contrast, CWE-79 and CWE-89 do not appear until far down that list; the ruleset is doing
what it is built for. What these four have in common is that **the malicious request is, byte
for byte, one a legitimate user could send**. `GET /mifs/aad/api/v2/ping` is an attack when an
unauthenticated caller makes it and a health check when the operator does. Whether it is an
attack depends on who sent it and what they are entitled to, which the application knows and
a WAF does not.

Reporting those beside injection classes says the ruleset failed at something it is not
attempting. A generic rule covering them would have to guess at authorisation, and guessing
wrong denies real users — which is the more expensive error. Virtual patches can cover a
specific application, but they need context this project does not have and cannot generate
safely.

Simply dropping them is also wrong: CRS blocks 127 of the 390 outright. Those blocks are real
— usually because the template's request happens to carry something a rule recognises — and
deleting the class would delete them from the numerator too.

## Decision

Keep them in the buckets they earned, and report a second figure beside the first.

`seaweed` reads `info.classification.cwe-id` from the templates, the same walk that already
tells a gated template from a finished one, and counts how many CVEs in each of the three
verdict buckets belong to an access-control class. The report gains
`cves_access_control` and `block_rate_addressable`, the latter being the block rate with
those CVEs removed from both halves of the fraction. The Slack message carries both.

Run 32369626239 at PL4: 390 access-control CVEs reached a verdict, 127 blocked, 35 partial,
228 not blocked. The headline rate is 60.7%; without them it is 63.8%.

The seven classes are `CWE-862`, `CWE-863`, `CWE-306`, `CWE-287`, `CWE-284`, `CWE-639` and
`CWE-425`. `CWE-200`, exposure of sensitive information, is deliberately not among them: some
of it is reachable — CRS blocks a request for `/.env` or `/.git/config` through
`restricted-files.data` — so it is a mixed class rather than a blind one, and it stays in the
headline.

## Consequences

- The published number no longer has to carry a question no ruleset can answer. The gap
  between the two rates, 3.1 points at PL4, is the size of that question.
- A CVE is now counted in two places at once. That is a second view of the same CVEs, not a
  sixth bucket, and the buckets still sum to `cves_tested`.
- The classification is only as good as the corpus. 3789 of 4149 templates declare a
  `cwe-id`; the rest are counted in the headline, which is the pessimistic reading. A
  template naming several CWEs writes them as one comma-separated scalar rather than a YAML
  list, and any one access-control entry among them is enough — reading only the first would
  have missed 45 of the 390.
- Templates can be mislabelled, and this now moves a number when they are. Nothing here
  reclassifies a *verdict*; the worst case is a CVE counted in the wrong supplementary
  figure.

## Alternatives considered

- **A sixth bucket.** Would remove them from the verdict counts, deleting 127 real blocks and
  making the buckets no longer describe what the WAF answered.
- **Drop the CVEs from the scan.** Cheaper to report and worse to know: whether CRS happens
  to block an access-control CVE is worth measuring, and 127 of them are blocked today.
- **Include CWE-200.** It is the largest single miss class at 55%, so including it would move
  the addressable rate furthest, which is exactly why it needs the stricter test. Part of that
  class is ordinary file-exposure that CRS already covers.
