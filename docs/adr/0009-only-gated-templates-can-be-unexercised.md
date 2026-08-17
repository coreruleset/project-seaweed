# 9. Only a gated template can be "not exercised"

- Status: Accepted
- Date: 2026-08-16

## Context

[ADR 6](0006-separate-rejected-and-unexercised-from-not-blocked.md) called a CVE "not
exercised" when its whole trace was a bare `GET /`, on the reasoning that a flow gate had
failed and the payload step never ran. It works, but the test is a proxy for the real
question and it catches the wrong templates too.

Splitting the 142 CVEs the bucket held, by whether their template actually has a gate:

| count | template | outcome |
| --- | --- | --- |
| 66 | gated | `200` — the gate saw the page and still did not match |
| 45 | **no gate** | `200` |
| 20 | **no gate** | `403` |
| 7 | gated | `403` — the WAF blocked the detection request |
| 4 | either | other |

The 66 with no gate are not untested at all. Their template has no flow, so it sends
everything it has, and `GET /` was the whole attack — a version probe, or an
unauthenticated endpoint check. Twenty of them were **blocked by the WAF**, which the
report was hiding in a bucket that says the opposite.

## Decision

A CVE is "not exercised" only if its template declares a `flow` *and* the trace shows
nothing but a bare `GET /`.

`seaweed` reads the templates to know which ids are gated, defaulting to
`nuclei-templates/` where `scripts/fetch-templates.sh` puts them, overridable with
`--templates`. When they cannot be read it logs and keeps the old pessimistic reading,
rather than silently reclassifying on missing evidence.

The template parsing moves out of `cmd` into `internal/templates`, shared with
`gen-mock`, which already walked the same tree for the same reason. `gen-mock` produces a
byte-identical page after the move.

## Consequences

On the run this was measured against:

| | before | after |
| --- | --- | --- |
| CVEs not exercised | 142 | **76** |
| CVEs blocked | 1593 | **1613** |
| CVEs not blocked | 512 | 557 |

Twenty WAF blocks stop being reported as untested.

- The reporter now depends on the templates, which is a new input for a tool that
  previously read only trace files. It degrades to the previous behaviour without them.
- 76 CVEs remain genuinely gated-and-unmatched, and their gates want things a body cannot
  give: `status_code`, `content_type`, `compare_versions`. That is what is left of #162.
- A gated template whose detection request the WAF *blocked* is still filed as not
  exercised. Arguably CRS stopping the reconnaissance is a result worth counting, but it
  is a different question from "did the payload get blocked", and only 7 CVEs sit there.

## Alternatives considered

- **Serve the header fingerprints too**, which was the obvious next lever after ADR 8.
  Built it, measured it, threw it away: only 3 of the 142 unexercised CVEs gate on a
  response header, so it moved the number by 3 — inside the run-to-run noise — in exchange
  for a generated nginx snippet, a mount, an include and another staleness surface.
- **Count the requests a template intends to send** and compare with the trace. More
  precise, and it means interpreting `flow` expressions rather than just noticing one.
