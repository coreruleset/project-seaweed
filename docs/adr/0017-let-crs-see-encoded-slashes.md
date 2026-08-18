# 17. Let CRS see encoded slashes

Date: 2026-08-18

## Status

Accepted.

## Context

At paranoia 4, 104 of the CVEs in a run get no verdict at all: every one of their requests
was refused before the WAF reached a conclusion. Splitting that bucket by cause:

| CVEs | what the request looked like | who answered |
| --- | --- | --- |
| 56 | encoded traversal, `..%2F..%2F..%2Fetc%2Fpasswd` | Apache, 404 |
| 45 | raw traversal, `/../../../etc/passwd` | Apache, 400 |
| 2 | a literal `#` in the request line | Apache, 400 |
| 1 | slow response | 408 |

The 56 are the interesting ones, and they were being lost to a default. Apache decodes
`%2F` during URI translation and, finding a path outside the document root, answers 404 —
in phase 1, before ModSecurity's blocking rule in phase 2 ever runs. So the ruleset was
never asked. Encoded-slash traversal is precisely what CRS rules 930100 and 930110 exist
to catch, and the scan could not tell whether they worked.

The other 45 cannot be recovered. Apache rejects a request line whose path escapes the
document root before any module sees it, and no directive changes that; verified still 400
with the fix below in place. They are honestly reported as no verdict.

## Decision

Set `AllowEncodedSlashes NoDecode` on the CRS vhost, so the path reaches the rule engine
as sent.

Measured on the same requests that produced the 404s:

```
/api/file/temp/..%2F..%2F..%2F..%2Fetc%2Fpasswd    404 -> 403
/plugins/..%2F..%2Fetc%2Fpasswd                    404 -> 403
/x%2Fy                                             404 -> 200 (reaches the backend)
```

Two details cost time and are worth recording.

**It has to be inside the `<VirtualHost>`.** The directive's context is server config *and*
virtual host, and a vhost does not inherit the server-level value. Appending it to
`httpd.conf` parses cleanly, applies to nothing, and leaves every 404 exactly where it was.

**The image builds that file at start-up**, so the directive is patched in by the
container's command rather than mounted. A mounted `httpd-vhosts.conf` would have to
reproduce the whole proxy configuration and would drift on every CRS bump — the failure
this project keeps meeting.

Patching by pattern can silently stop matching, which is the same class of silent failure.
So the readiness gate from [ADR 2](0002-single-compose-environment-with-readiness-gate.md)
now asks for one more thing: an encoded slash must round-trip to the backend and come back
carrying the marker. If a future CRS image renames or restructures that file, the WAF never
reports healthy and the scan stops. Verified by breaking the pattern on purpose: the
container stays unhealthy and `nuclei` never starts.

## Consequences

- 56 CVEs a run move from "no verdict" to a real one, and CRS blocks them, so the block
  rate rises. Like any coverage change, the run it lands in is not comparable with the one
  before it.
- Apache is no longer normalising away part of the attack surface the ruleset is
  responsible for. What the report says about traversal rules is now about the rules.
- Benign traffic is unaffected: the CRS regression corpus replays identically with and
  without the directive, 931 requests and 540 blocked either way at PL4.
- The scan's environment now differs from a stock CRS container in one documented respect.
  It is an httpd setting rather than a ruleset one, and without it the ruleset cannot be
  measured — but a deployment that leaves it at the default really is protected by Apache
  here, and this report no longer reflects that.

## Alternatives considered

- **Ask upstream for an env var** in `coreruleset/modsecurity-crs-docker`, the way `PORT`
  and `BACKEND` work today. The right long-term shape, and worth opening; it does not
  measure anything this week.
- **Mount a replacement `httpd-vhosts.conf`.** Reproduces the proxy, websocket and header
  configuration to add one line, and silently goes stale against the image it copies.
- **Leave it and report the 56 as a known blind spot.** Honest, and the blind spot covers
  exactly the rules most associated with path traversal.
