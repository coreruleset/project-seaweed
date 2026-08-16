# 4. Verify on pull requests, and alert when the weekly run fails

- Status: Accepted
- Date: 2026-08-16

## Context

Two gaps showed up on the same day.

Nothing verified changes on the way in. The repository had a single workflow, on a weekly
schedule, and no PR CI. The unit tests added in
[ADR 3](0003-report-per-cve-and-separate-upstream-errors.md) ran on a laptop and nowhere
else, and a Renovate PR bumping nginx and a Go dependency merged with nothing checking
either.

Nothing reported failures. The first dispatch on the new pipeline failed: Nuclei creates
its trace directory as root with mode `0700`, the runner could not read it, and `zip -qq`
skipped it silently, so the artifact was 310 bytes and the report found no trace files.
The error gate worked exactly as designed — the job failed rather than reporting zero
blocks as a WAF result — but `slack-notification` had `needs: process-artifacts` and no
`if:`, so a failed report meant no message at all. The failure was found by accident,
while looking at something else.

A weekly job that goes quiet on failure is indistinguishable from a weekly job nobody
scheduled.

## Decision

**A CI workflow runs on every pull request**: `go test -race`, `golangci-lint`,
`actionlint` and `zizmor`, in one job. `actionlint` also shellchecks the `run:` blocks,
which is where this repository's workflow logic now lives. `zizmor` runs without the
code-scanning upload, so the workflow keeps `contents: read`.

**The scheduled workflow notifies either way.** Success sends the summary it always sent.
Failure sends an alert linking to the run. A cancelled run stays silent, because someone
stopped it deliberately.

**Scan and report are one job.** The report job used to download the artifact the scan job
had just uploaded, after its own checkout and Go setup, to read files the first job
already had on disk. The artifact upload stays — it is the evidence — but it is no longer
round-tripped, and it now happens before the report runs so the traces survive a failed
report.

The scan job gets `timeout-minutes: 30`. It takes about a minute; the limit is a backstop
against a hung container burning six hours of runner time.

## Consequences

- Test and lint failures surface on the PR instead of after the merge.
- A broken week is visible in Slack rather than silent.
- One less job, one less artifact round-trip, one less checkout and Go setup. It also
  removes the seam the `0700` bug lived in.
- Re-running just the report now means re-running the scan too. That is about a minute.
- CI does not run the pipeline, so it would not have caught the `0700` bug. What catches
  that class of failure is the guard in the scan job that fails when no trace files were
  produced. Linting the workflow and running the pipeline are different kinds of
  verification, and this ADR only adds the first.
- `golangci-lint` runs on defaults. A `.golangci.yml` would surface a pile of new
  findings and belongs in its own change.

## Alternatives considered

- **Separate jobs per linter.** Four runner spin-ups for about a minute of actual work.
- **Keeping the scan and report jobs separate** so the report can be re-run against a
  stored artifact. Real, but it costs a job on every run to save a minute on the rare
  re-run, and the round-trip is where the last bug hid.
- **`if: always()` on a single Slack step, with the colour computed from
  `needs.scan.result`.** One step instead of two, but the payload then has to carry
  metric fields that are empty strings on failure. Two steps with plain payloads read
  better.
- **Uploading zizmor's SARIF to code scanning.** Nicer findings UI, at the cost of
  `security-events: write` on the workflow. Worth revisiting; not worth the permission
  today.
