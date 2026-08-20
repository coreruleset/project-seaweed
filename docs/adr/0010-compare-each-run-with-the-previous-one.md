# 10. Compare each run with the previous one

- Status: Accepted
- Date: 2026-08-16

## Context

"Report comparison — TBD" has been in the README since the project started. Aggregate
counts answer "how is CRS doing" vaguely; the signal a weekly job should produce is
"CVE-X was blocked last week and is not now".

The obstacle is noise. Two runs of the same templates against the same CRS disagree on
about **48 of 2710 CVEs**, measured by diffing two consecutive scheduled runs. The causes
split:

| | count | cause |
| --- | --- | --- |
| identical request, different verdict | 34 | nuclei randomises the User-Agent per request |
| different request | 14 | randomised payloads: `{{randstr}}`, oast hostnames |

> **Amended 2026-08-20.** The User-Agent is now pinned ([ADR 20](0020-pin-the-user-agent.md)),
> which removes the 34 and most of the floor with it: two identical runs measured 2 changes,
> and `expectedChurn` is 6 rather than 48. The remaining churn is templates randomising their
> own payloads.

Removing the User-Agent noise at its source was tried first and does not work. Nuclei
v3.8 has no `-random-agent` flag, no equivalent key in its config file, and ignores
`-H "User-Agent: ..."` at scale — **6 of 3841 requests** used the pinned agent, with 885
distinct agents still appearing. On a small tag set it looked like it worked, which is
worth knowing before someone else tries it.

So the churn is a property of the tool being driven, and the comparison has to absorb it.

## Decision

`seaweed diff previous.json current.json` compares two JSON reports. It prints the bucket
totals side by side with their change, then the CVEs that were blocked and no longer are,
and it says on every run how much churn is ordinary.

The order is the design. **Totals first, names second**: a bucket total moving is signal,
a handful of individual CVEs moving is not. Nothing exits non-zero — a regression is
information for a human, not a broken build.

The scheduled workflow runs the diff against the previous successful run's report and
writes it to the job summary. The report is uploaded as its own small artifact, separate
from the traces, and the comparison happens *before* that upload so it always finds the
previous run rather than this one. A missing or unreadable previous report is not a
failure: the step is `continue-on-error` and says why.

## Consequences

- The regression signal exists for the first time, and reads honestly rather than
  claiming more precision than the data supports.
- The job needs `actions: read` to fetch the previous artifact.
- 48 changes a week will show up in the listing. Reading it well means checking whether
  the totals moved, which is what the output leads with.
- Both noise sources are also mis-attribution, not just churn. Some CVEs are recorded as
  blocked because the random User-Agent tripped CRS rather than the payload: 932237 scores
  5 on `(SS; Linux x86_64)` all by itself, which is the whole blocking threshold. Reported
  upstream as coreruleset/coreruleset#4761.
- A template version bump will move CVEs wholesale, and the diff has no way to know that
  happened. The pinned version is in `scripts/fetch-templates.sh`, so it is visible in the
  commit that caused it.

## Alternatives considered

- **Require a change to persist across two runs before reporting it.** Removes most of the
  noise, at a week of latency on every real regression. Worth revisiting once there is
  enough history to know how often real changes appear.
- **Fail the build on a regression.** With 48 noisy changes a week that is an alert nobody
  would keep listening to.
- **Put the diff in the Slack message.** The job summary renders a table and a list
  properly; Slack would need the whole comparison threaded through a job output.
