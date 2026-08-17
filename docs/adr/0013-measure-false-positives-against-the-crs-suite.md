# 13. Measure false positives against the CRS regression suite

- Status: Accepted, but the number is not yet trustworthy
- Date: 2026-08-17

## Context

[ADR 11](0011-scan-every-paranoia-level.md) measured blocking across paranoia levels: 52%
at PL1 rising to 64% at PL4. It says nothing about what those twelve points cost, and the
maximum score on that metric is to block everything. Without a false positive rate the
curve cannot be acted on.

CRS carries its own corpus. Its regression suite has 940 stages (at v4.28.0) whose
expectation is `no_expect_ids` — particular rules must **not** match this request. Those
assertions are written by the people who maintain the rules, which is a better definition
of a false positive than anything this project could invent.

## Decision

`scripts/fetch-crs-tests.sh` downloads a pinned CRS release's regression suite.
`seaweed false-positives <host:port> --audit-log <file>` reads every stage that forbids a
rule, replays it, and then checks the audit log for whether a forbidden rule matched
anyway.

Each replayed request carries `X-Seaweed-Case: <n>`. That makes the join to the audit log
**exact**, which is the thing
[issue #161](https://github.com/coreruleset/project-seaweed/issues/161) could not achieve
for Nuclei traffic: there the requests are the templates' to make, here they are ours to
label.

The replayer supplies `Host`, `Content-Length` and `Content-Type` only when a stage leaves
them out, matching what the suite's own runner must do. Without `Content-Type` a request
with a body trips 920340, a paranoia-1 rule, and the stage fails for a reason the replay
invented.

## Consequences

Measured locally against the pinned suite:

| paranoia | benign requests | blocked | assertions broken | rate |
| --- | --- | --- | --- | --- |
| PL1 | 931 | 183 | 72 | 7.7% |
| PL4 | 931 | 572 | 97 | 10.4% |

**The absolute numbers are not trustworthy, and nothing is wired into the notification.**
This stack is not the harness CRS runs its suite on, and there is no reference run to
separate "CRS false positive" from "this replay differs from go-ftw". A 7.7% failure rate
at PL1 against a suite that passes in CRS's own CI almost certainly measures the difference
between the two setups, not 72 defects.

Calibrating means running go-ftw itself against this stack and comparing its failure count
with this tool's. That needs go-ftw to read the audit log live, which is the container
ownership problem from [ADR 7](0007-decide-delivery-by-the-backend-marker.md) again.

Until then the tool is a capability, not a published metric. The relative movement between
levels — 7.7% to 10.4% — is the more defensible reading, because both sides share whatever
the stack difference is.

## Two wrong turns, recorded so they are not repeated

**Counting blocked requests is not a false positive measurement.** The first version did
exactly that, and reported a 62.7% "false positive rate" at PL4. `no_expect_ids` does not
mean "must not be blocked"; it means "must not trip *this* rule". Those stages live in the
test files of attack rules and include payloads like `arg=%0acat%20/etc/passwd;`, which CRS
is right to block through some neighbouring rule. Blocking is still reported, as
`benign_blocked`, because it is interesting — but it is not the measurement.

**The implausible number is what exposed it.** Adding `Content-Type` — a correctness fix,
since 920340 is paranoia 1 — made the reported rate go *up*, from 14.5% to 19.7%. A fix
that makes a metric worse means the metric is measuring the wrong thing.

## Alternatives considered

- **Run go-ftw directly.** The reference implementation, and the right calibration tool.
  It needs live access to the audit log to make its assertions, and it cannot filter to
  only the stages that forbid a rule, so the whole suite's pass rate mixes false positives
  with false negatives.
- **Author a benign corpus in this repo.** Fully controlled and deterministic, and only as
  good as the requests chosen — a self-authored corpus measures the author's imagination.
- **Use nuclei's `http/technologies` templates as benign traffic.** Ordinary paths, but
  scanner-shaped, and nuclei's randomised User-Agent trips CRS on its own
  (coreruleset/coreruleset#4761), so the corpus would carry the confound with it.
