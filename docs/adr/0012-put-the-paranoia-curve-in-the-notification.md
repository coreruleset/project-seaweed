# 12. Put the paranoia curve in the notification

- Status: Accepted
- Date: 2026-08-17

## Context

[ADR 11](0011-scan-every-paranoia-level.md) made the run sweep every paranoia level, but
only the job summary got the curve. Slack still received a single number from PL4, which
is the least representative level — PL1 is what most CRS installs run. The most
informative thing the project produces was reachable only by opening the run.

The curve was also built by a `jq` loop in the workflow, which is presentation logic in
YAML with nothing testing it.

## Decision

`seaweed sweep <dir>` reads each immediate subdirectory as one paranoia level, named after
the directory, and reports them together. It renders fixed-width rows — rate, a bar, and
the counts behind them — for `text`, and Block Kit with that table inside a code block for
`slack`. Slack only aligns columns inside a code block, so the rows are padded to a
constant width and there is a test asserting that.

The headline stays the highest level, now named in the text ("64% of CVEs blocked at PL4"),
for continuity with the single number this project reported before it swept anything. The
run-to-run diff still compares PL4 alone.

This replaces the `jq` loop, so the workflow no longer formats anything.

Using a subcommand rather than teaching `-o` to take several directories keeps the
single-level path unchanged: `-o` means one run's output, and merging across runs is the
mistake [ADR 11's implementation actually made](https://github.com/coreruleset/project-seaweed/pull/171).

## Consequences

- The notification carries the curve, so the number a reader acts on is the one for their
  own paranoia level.
- One less shell loop and one less `jq` dependency in the workflow.
- **Fixed on the way past**: Cobra's `Print` helpers write to stderr unless told otherwise,
  so `seaweed diff` had been writing its table to stderr since
  [ADR 10](0010-compare-each-run-with-the-previous-one.md). The workflow redirects stdout
  into the job summary, so the summary got the code fences and nothing between them, while
  the text still appeared in the step log — which is why it looked like it worked.
  `NewRootCommand` now sets stdout explicitly, with a test that fails if it is pointed
  anywhere else.
- `sweep` labels levels by directory name, so the layout `output/pl1` … `output/pl4` is
  now load-bearing. A renamed directory changes the labels rather than breaking anything.
- Four `javascript`-protocol traces per level carry no CVE id in their header and are
  skipped with a warning, as they were before. That is 4 CVEs of roughly 2700, unchanged
  by this ADR but worth writing down.

## Alternatives considered

- **Append a block to the payload with `jq` in the workflow.** Fewer lines of Go, but it
  puts the layout back in YAML, untested, which is what
  [ADR 10's](0010-compare-each-run-with-the-previous-one.md) reasoning rejected.
- **Make `-o` repeatable.** Then the headline level is either implicit in the ordering or
  needs a second flag, and `-o` stops meaning one thing.
- **A Block Kit table.** Slack's rich tables are not dependable through an incoming
  webhook; a monospace code block is what actually renders everywhere.
