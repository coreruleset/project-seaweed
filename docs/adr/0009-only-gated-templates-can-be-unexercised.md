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

> **Amended 2026-08-18.** "A bare `GET /`" originally meant any request to `/`, because
> the reader matched the path and discarded the method. Templates that aim their payload
> at the root path and carry it in the body — `flow: http(1) || http(2)` POSTing an RCE
> blob, for one — were therefore read as probes. The test is now the method as well: `GET`
> and `HEAD` to `/` are probes, anything else is an attack. Measured on run 32088128453,
> this reclaims 5 CVEs at PL4 (47 unexercised → 42), 3 of them blocks the report was
> discarding, and 4 at PL1 (43 → 39).

> **Amended 2026-08-20.** A bare `GET /` is not the only request that tests nothing. The most
> common single request in a run is `GET /wp-content/plugins/<slug>/readme.txt`: 58 of the 60
> templates that stop there extract a version from the readme and run it through
> `compare_versions`, and 43 of them gate a payload behind that comparison which never fires
> against a mock backend. Fetching a file that describes the application is reconnaissance,
> so a trace of nothing but those is not exercised either — whether or not the template
> declares a `flow`, because an ungated one sent everything it has and everything it has is a
> file fetch.
>
> The list is deliberately five entries (`readme.txt`, `readme.md`, `changelog.txt`,
> `changelog.md`, `license.txt`) and every one has to be a file a browser never requests while
> rendering a page. That excludes `wp-content/themes/<name>/style.css`, which five templates
> also fingerprint through and which is the theme stylesheet on every page view. A request
> carrying a query string, an encoded character or a traversal sequence is not treated as a
> probe, since the path is then doing more than naming the file.
>
> One exception, which cost a bug before the tests caught it: a WAF that *refuses* the
> enumeration has answered, and that answer has to survive. A blocked probe stays a block
> rather than falling through to the gated reading, which would have discarded 5 of them at
> PL4.
>
> Measured on run 32184771851, 56 CVEs move out of `cves_not_blocked` at PL4 and 57 at PL1.
> `cves_blocked` does not change at any level. The block rate rises about a point — PL1
> 41.4% → 42.0%, PL4 60.1% → 61.0% — because the denominator loses CVEs that were never
> tested, not because anything new was blocked.

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
