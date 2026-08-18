# 14. Run a current CRS

- Status: Accepted
- Date: 2026-08-17

## Context

Calibrating the false positive measurement from
[ADR 13](0013-measure-false-positives-against-the-crs-suite.md) meant running go-ftw, the
reference implementation, against the same stack. Doing so turned up something larger.

go-ftw needs a log marker to delimit each test's output, which the CRS image provides as
`CRS_ENABLE_TEST_MARKER=1` — a first-class switch in `activate-rules.sh`, not a
hand-rolled test rule. With it enabled, three runs answered the question:

| stack | tool | false positives |
| --- | --- | --- |
| CRS's own reference stack | go-ftw | **0** |
| ours | go-ftw | 100 |
| ours | `seaweed false-positives` | 97 |

The 97 were a strict subset of go-ftw's 100, so the tool was sound: 100% precision, and
the three it missed are `920100-4`, which CRS's own overrides mark as a broken test, and
two Content-Type stages it declines to replay.

That left the stacks to explain the difference, and the reason was in the image pin:

```
our WAF:                CRS 4.1.0   (owasp/modsecurity-crs:4-apache-202404131004)
CRS's reference stack:  CRS 4.30.0
our test corpus:        v4.28.0
our Nuclei templates:   v10.4.7
```

**Every number this project has published described CRS 4.1.0**, roughly 27 releases and
sixteen months behind, measured against a current corpus. Renovate never bumped it because
`4-apache-202404131004` is not a version-shaped tag; it did bump `nginx:1.29-alpine` in
#147, so the mechanism works when the tag is legible.

## Decision

Pin `owasp/modsecurity-crs:4.28.0-apache-202608131208`, by digest, on a version-shaped tag
that Renovate can read.

## Consequences

The false positive count is the headline. Against a matched corpus, on both paranoia
levels tested:

| | CRS 4.1.0 | CRS 4.28.0 |
| --- | --- | --- |
| false positives at PL1 | 72 | **0** |
| false positives at PL4 | 97 | **0** |

All 97 were an artifact of testing a v4.28.0 corpus against a 4.1.0 ruleset. Matched, our
stack now agrees exactly with CRS's own reference stack, which also reports 0. The
measurement from ADR 13 is calibrated, and the false positive rate is publishable: it is
currently **0%**.

The blocking curve barely moved, which is worth saying plainly because it was not what I
expected:

| paranoia | CRS 4.1.0 | CRS 4.28.0 |
| --- | --- | --- |
| PL1 | 52% | 54% |
| PL2 | 58% | 58% |
| PL3 | 59% | 60% |
| PL4 | 63% | 64% |

Twenty-seven releases moved CVE blocking by one or two points. The stale ruleset mattered
enormously for false positives and hardly at all for blocking, so the CVE numbers reported
so far were approximately right for the wrong reason.

- Renovate will now keep the WAF current, and a bump will move the numbers, which is what
  the run-to-run diff from [ADR 10](0010-compare-each-run-with-the-previous-one.md) exists
  to surface.
- Nothing else in the stack changed: the healthcheck, the marker round-trip and the four
  paranoia scans all behave as before on the new image.
- The false positive pass is not yet part of the weekly run. Now that it produces a
  trustworthy number, wiring it in is worth doing on its own.

## Alternatives considered

- **`4.25.1-apache-lts`.** The long-term support line, and a defensible choice for a
  project measuring what most people deploy. Rejected for now because the corpus this is
  measured against tracks the current release; testing an LTS ruleset against current tests
  reintroduces exactly the mismatch this ADR removes.
- **Leave the pin and subtract a known-failure baseline.** Would have hidden a real problem
  behind a constant.
