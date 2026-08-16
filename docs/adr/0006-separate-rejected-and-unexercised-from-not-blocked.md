# 6. Separate rejected and unexercised CVEs from "not blocked"

- Status: Accepted
- Date: 2026-08-16

## Context

The first full run on the finished pipeline
([31958312324](https://github.com/coreruleset/project-seaweed/actions/runs/31958312324)) reported
789 of 2710 CVEs as not blocked. Reading the trace files against the newly collected
ModSecurity audit log showed that most of those were not WAF failures:

| count | what actually happened |
| --- | --- |
| 155 CVEs | the whole trace is a single `GET /` — the detection step never matched, so no payload was ever sent |
| 136 requests | Apache answered `400` or `404` before the backend saw them |
| ~500 CVEs | reached the backend, and CRS found nothing to block |
| 7 CVEs | an attack rule fired but the score stayed under the threshold |

The `400`/`404` group is the sharpest: **all 62 of the `404`s carry `Server: Apache`, and
61 of them contain `%2f`**. Apache's default `AllowEncodedSlashes Off` rejects encoded
slashes during URI translation, which happens before ModSecurity's phase 2 blocking rule
runs. Several of those requests had already accumulated an anomaly score of 5, 7 or 10 —
enough to block — and were counted as the WAF letting an attack through.

The unexercised group is the other half of the same problem, from
[ADR 1](0001-generate-mock-backend-fingerprints.md): flow-gated templates whose gate the
mock cannot satisfy send nothing but their detection request. Reporting them as "not
blocked" blames the WAF for an attack nobody sent, and hides the number that actually
matters for the mock — how many templates still do not get past their gate.

## Decision

Two more categories, neither of which is a verdict about the WAF:

- **rejected** — `400`, `404`, `405`. The bundled mock answers `200` on every path and
  method, so under `docker compose up` anything else came from Apache rather than the
  application.
- **not exercised** — a CVE whose every request is a bare `GET /`, with no path and no
  query string. Its payload step never ran.

Rejected requests join errored ones outside the verdict count, so they affect neither the
per-CVE bucket nor the block rate. A CVE with no verdicts at all is now `no verdict`
rather than `errored`, since it can get there by rejection as well as by error.

## Consequences

Re-running the same artifact through the new classification:

| | before | after |
| --- | --- | --- |
| CVEs not blocked | 789 | **533** |
| CVEs not exercised | — | 194 |
| CVEs with no verdict | 2 | 100 |
| requests rejected | — | 136 |
| block rate | 64% | **66%** |

- "Not blocked" is now a list worth reading. 256 CVEs left it, none of them because the
  WAF got better.
- `cves_not_exercised` is a direct measure of how much of the corpus the mock still cannot
  unlock — the metric ADR 1 was missing.
- The output keys changed again: `total_rejected` and `cves_not_exercised` are new, and
  `cves_errored` became `cves_no_verdict`.
- The `404` assumption is specific to the bundled backend. Against a real application,
  where `404` is an ordinary answer, this over-counts rejections. Documented in the README;
  it would need the audit log to resolve properly.
- Header-only attacks against `/` are misfiled as not exercised. Nothing in the trace
  distinguishes them from a benign root probe without parsing the request headers.

## Alternatives considered

- **Detect rejections by the response body marker** rather than by status code. The mock
  serves `seaweed-mock-ok` in every response, so its absence proves the request never
  reached the backend — precise, and immune to the `404` ambiguity. Rejected because it
  silently misclassifies everything when pointed at any other backend, and papering that
  over needs a mode switch.
- **Use the `Server` response header** to tell the WAF's answers from the backend's. Works
  for this stack, hardcodes nginx-versus-Apache into the reporter.
- **Ask the audit log whether ModSecurity blocked**, instead of inferring from the status.
  This is the right long-term answer and would settle both the `404` ambiguity and
  CRS-block-versus-any-403. It needs the reporter to read the audit log and join it to the
  traces, which is a bigger change than this one.
