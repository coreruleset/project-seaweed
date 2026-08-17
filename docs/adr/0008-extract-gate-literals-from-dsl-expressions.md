# 8. Extract gate literals from dsl expressions too

- Status: Accepted
- Date: 2026-08-16

## Context

`cves_not_exercised`, added in [ADR 6](0006-separate-rejected-and-unexercised-from-not-blocked.md),
put a number on how much of the corpus never gets tested: **190 CVEs** whose flow gate
never matched, so their payload step never ran and the WAF was never asked about them.

Breaking those 190 down by what their gate actually wants:

| count | gate |
| --- | --- |
| 102 | `dsl` on the body |
| 66 | no flow gate at all — the template only ever sends `GET /` |
| 30 | `word` on the body |
| 9 | a flow, but no internal matcher |
| 8 | `word`/`regex`/`status` on other parts |

The `dsl` group is the interesting one, because of what those expressions say:

```yaml
- contains(body,"/wp-content/plugins/tom-m8te/")
- contains(tolower(body), "altenergy power control software")
- contains_all(body,"Navis","Tags:")
```

That is a word matcher written differently. The generator ignored them only because it
filtered on `type: word`. Across all flow-gated templates there are 674 internal `dsl`
gates, and two thirds mention the body; the commonest companion clause is
`status_code == 200`, which the mock already satisfies.

## Decision

`seaweed gen-mock` also collects string literals from internal `dsl` expressions that
mention `body` (or `body_1`, `body_2`, …). The page goes from 376 fingerprints to 870.

Literals are taken from the whole expression, not just its `contains(body, ...)` clause.
An expression like `contains(body,"wp-content") && contains(header,"text/html")`
contributes both. Over-serving is the safe direction here: a string the gate did not
strictly need only risks letting a payload through to the WAF, which is the entire point
of the exercise, while missing one loses the CVE from the measurement completely.

## Consequences

Two full local runs, back to back, same machine, same pinned templates, only the page
different:

| | 376 fingerprints | 870 fingerprints |
| --- | --- | --- |
| CVEs not exercised | 190 | **145** |
| CVEs partially blocked | 292 | 362 |
| CVEs not blocked | 537 | 510 |
| requests sent | 3774 | 3867 |

45 CVEs now reach their payload step, and 93 more requests get put to the WAF. For
context, the run-to-run noise measured on this bucket is about 5 CVEs, so the change is
well clear of it.

- The generated page is bigger, and every response the mock serves carries all of it. It
  is still one file of a few kilobytes, and CRS's outbound rules pass it unchanged.
- Nothing here helps the 66 templates that only ever send `GET /`. Those have no gate to
  satisfy: they are misfiled by the `Exercised` heuristic, which cannot see an attack
  carried in headers. That is a separate problem.
- The remaining `dsl` gates want things a body cannot provide — `contains(header, ...)`
  appears 100 times, `contains(content_type, ...)` 71 times, `compare_versions` 39.
  Response headers are the next lever.

## Alternatives considered

- **Evaluate the dsl expressions properly** rather than scraping literals out of them.
  Correct, and it means implementing Nuclei's expression language. The scrape gets most of
  the value for a regex and a loop.
- **Only take literals from `contains(body, ...)` clauses**, ignoring mixed expressions.
  Tighter, and it would have dropped 232 of the 267 body-mentioning gates on the floor,
  for a purity that does not matter when over-serving is harmless.
