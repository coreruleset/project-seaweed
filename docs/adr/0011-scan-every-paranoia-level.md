# 11. Scan every paranoia level

- Status: Accepted
- Date: 2026-08-17

## Context

Every run so far has been at `BLOCKING_PARANOIA: 4`, the most aggressive setting. That is
one point on a curve, and it is not the point most CRS installs run at — PL1 is the
default. The interesting question for CRS is how much more the ruleset blocks at each
level, which the documentation describes qualitatively and nobody had measured here.

## Decision

The scan runs once per paranoia level. `docker-compose.yml` takes `SEAWEED_PARANOIA` and
`SEAWEED_OUTPUT`, both defaulted, so a level and a place to put its traces are the only
things that vary; the workflow loops 1 to 4 and the reporter runs over each output
directory.

Paranoia 4 stays the headline: it is what the notification sends and what the run-to-run
diff from [ADR 10](0010-compare-each-run-with-the-previous-one.md) compares, so the
history stays continuous. The other three levels exist as the curve, written to the job
summary.

## Consequences

Measured over four full local runs against the pinned templates:

| paranoia | blocked | partially | not blocked | not exercised | block rate |
| --- | --- | --- | --- | --- | --- |
| PL1 | 1319 | 356 | 851 | 77 | **52.2%** |
| PL2 | 1460 | 364 | 707 | 77 | 57.7% |
| PL3 | 1494 | 369 | 667 | 79 | 59.1% |
| PL4 | 1606 | 362 | 562 | 79 | **63.5%** |

CRS blocks about half of these CVE payloads in its default configuration, and about two
thirds at maximum paranoia. The largest single step is PL1 to PL2, at +5.5 points.

- Four scans instead of one: about 40 seconds of scanning each, so a few minutes of extra
  wall clock, most of it container startup.
- The artifact grows from roughly 34 MB of traces to 136 MB before compression. Retention
  is the thing to watch if that becomes a problem.
- **The curve shows only the benefit side.** Higher paranoia costs false positives and
  seaweed does not measure them yet, so a rising rate is not on its own an argument for
  raising the level. That is
  [issue #164](https://github.com/coreruleset/project-seaweed/issues/164), and this ADR is
  half a result without it.
- A confound worth naming: rule 932237 is PL3 and fires on nuclei's randomised
  User-Agent, so a few blocks at PL3 and PL4 belong to the agent rather than the payload.
  Counting traces where a bare `GET /` was blocked, at most 13 of the 287 additional
  blocks between PL1 and PL4 could come from this — about 5%, so the shape holds. See
  coreruleset/coreruleset#4761.

## Alternatives considered

- **A GitHub matrix job per level.** Parallel, so no extra wall clock, but it multiplies
  the single job that ADR 4 deliberately collapsed: four sets of outputs, four Slack
  payloads, and a collector job to assemble the curve. The sequential loop keeps one job
  and costs minutes on a weekly schedule.
- **Report the curve in Slack.** The job summary renders a table; Slack would need the
  whole thing threaded through a job output for a number nobody acts on weekly.
- **Sweep only PL1 and PL4.** Cheaper, and it would have missed that PL1 to PL2 is the
  biggest step.
