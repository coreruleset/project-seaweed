# 7. Decide delivery by the backend marker, not the status code

- Status: Accepted
- Date: 2026-08-16

## Context

[ADR 6](0006-separate-rejected-and-unexercised-from-not-blocked.md) split requests the
server refused out of "not blocked", using a hardcoded list of statuses: `400`, `404`,
`405`. It named its own weakness — an application's own `404` is an ordinary answer, and
the list cannot tell it from Apache refusing an encoded slash.

[Issue #161](https://github.com/coreruleset/project-seaweed/issues/161) proposed settling
this by reading the ModSecurity audit log. That turns out to be the harder way round. The
audit log has no key to join on: trace files carry no transaction id, and the obvious
key — the request line — is shared, because `GET /` is sent by hundreds of templates.
Joining on it naively lets a benign root probe inherit another template's anomaly score,
which is exactly the artifact that produced a phantom "169 CVEs scored 68 and were not
blocked" during the analysis in #160.

The trace files already hold the answer, in the response body. The mock serves
`seaweed-mock-ok` on every path and every method, so the marker's presence is proof the
request reached the application. Measured over a full run:

| status | carried the marker | did not |
| --- | --- | --- |
| 200 | 1244 | 1 |
| 400 | 0 | 74 |
| 403 | 0 | 2394 |
| 404 | 0 | 62 |
| 408 | 0 | 2 |

The single `200` without it is Apache answering `OK` to a request it handled itself, which
is correctly *not* a delivery.

## Decision

Classification reads the body, not a status list:

- **delivered** — the response carries the marker, or its status is below `400`. The
  payload reached the application, so the WAF let it through, whatever the application
  then answered.
- **blocked** — not delivered, status `403`.
- **errored** — not delivered, `408`/`500`/`502`/`503`/`504`.
- **rejected** — not delivered, anything else.

The success-or-redirect clause is what keeps this honest against a backend that carries no
marker: a `2xx` is never a refusal. Point seaweed at some other target and the
classification degrades to roughly what it did before this change, rather than declaring
every response a rejection.

`BackendMarker` moves into `internal/reader` and `seaweed gen-mock` uses it, so the string
the generator writes and the string the reporter looks for cannot drift apart.

## Consequences

- The numbers on the run this was developed against are **identical**, because the mock
  never returns a delivered `4xx`. The change is in the basis, not the result: it is now
  derived from evidence in the trace rather than from an assumption about the backend.
- An application `404` is now classified correctly, which the status list could not do.
- The reader keeps one response of state while scanning, to pair a status with the body
  that follows it. There is a test that a marker in one body does not leak onto the next
  response's verdict.
- Nothing here needs the audit log. #161 is narrowed to what still does need it: naming
  the rule behind a block, and reporting near-misses.
- The reader now depends on the bundled mock's marker for its best answers. That coupling
  is real, and it is why the constant is shared rather than written twice.

## Alternatives considered

- **Join the audit log to the traces by request line.** The original plan. No usable join
  key, and the failure mode is silent misattribution rather than a visible error.
- **Detect the marker's absence across the whole run and fall back.** An implicit mode
  switch. The success-or-redirect clause achieves the same graceful degradation without
  one.
- **Have ModSecurity stamp a response header on block.** Would name the blocker directly,
  at the cost of a custom rule in the bundled config that does not exist upstream, making
  the stack less like the thing under test.
