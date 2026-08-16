# 5. Pin the templates, and collect the WAF's logs instead of printing them

- Status: Accepted
- Date: 2026-08-16

## Context

**Templates were fetched at run time.** Nuclei installed whatever was current when the job
started — `nuclei-templates are not installed, installing...` in every log. A weekly
regression job whose corpus changes underneath it cannot answer the question it exists to
ask, because a change in the numbers can always be a change in the templates.

It had already gone wrong quietly. `mock/fingerprints.html` was generated from a local
snapshot with 114 flow-gated templates. The version the scan actually ran, v10.4.7, has
**841**. Measured against v10.4.7's flow-gated templates with word gates:

| fingerprint page | templates whose gate the mock satisfies |
| --- | --- |
| committed (109 fingerprints, from the snapshot) | 102 of 264 |
| regenerated from v10.4.7 (376 fingerprints) | 264 of 264 |

The mock had been silently drifting away from the templates since the day it was
generated, and nothing could notice.

**The WAF's error log went to the console.** `ERRORLOG` defaults to stderr in the CRS
image, so every rule match — several per request, kilobytes each — was streamed into the
job log by `docker compose up`. The log was tens of megabytes and unreadable. Meanwhile
the JSON audit log, which carries the rule ids behind each block, was written inside the
container and thrown away when it exited.

The compose file also set `MODSEC_ERROR_LOG`, which the CRS image does not use. It was a
no-op.

## Decision

**The template version is pinned in `scripts/fetch-templates.sh`**, which downloads that
version's release tarball into `nuclei-templates/`. The scan bind-mounts the directory
read-only at `/templates` and runs with `-duc`, so nothing updates behind it. The version
lives in the script rather than a `.env`, because compose does not need it — only the
fetch does — and a committed `.env` invites someone to put a secret in it later.

One directory serves both the scan and `seaweed gen-mock`, so the fingerprint page cannot
be generated from a different corpus than the scan uses. **CI enforces it**: it fetches
the pinned templates, regenerates the page, and fails on any diff.

**The WAF's logs go to files.** `ERRORLOG` and the audit log point into
`/var/log/apache2` inside the container, and are copied out with `docker compose cp` after
the run and archived alongside the traces. That directory is deliberately *not*
bind-mounted: the CRS image runs as uid 999, and a host directory mounted there belongs to
the host user, so ModSecurity cannot create its audit log and Apache dies at config parse.
Docker Desktop remaps bind-mount ownership, so this only fails on Linux.
The audit log switches from `concurrent` to `Serial` — one JSON object per transaction in
one file, rather than thousands of files — and its parts are trimmed to `ABHZ`:
transaction, request headers, rule messages, terminator. The default also stores request
and response bodies, and the mock returns the same page every time.

## Consequences

- Week-to-week numbers are comparable, and a change in them means a change in the WAF or
  in the templates, deliberately, on a commit.
- 264 flow-gated templates now get past their detection step instead of 102, because the
  fingerprint page finally matches the templates being run.
- The console output of a run went from tens of megabytes to about 15 KB, with no
  ModSecurity lines in it at all. The error log is still there, as an artifact.
- The audit log now carries the rule ids: a `fileupload`-tagged run recorded 55 distinct
  CRS rules, led by 949110 and 920273. That is the input the report needs to tell a CRS
  block from any other 403 — the work ADR 3 deferred.
- Roughly 45 MB of logs per full weekly run, which compresses to a few MB in the artifact.
- The logs are only available after the run, via `docker compose cp`, rather than
  streaming to the host as they are written.
- Renovate has to bump the pinned version, and that bump is now a reviewable
  change that moves the numbers, which is the point. CI will fail it until the
  fingerprint page is regenerated in the same PR.
- `docker compose up` no longer works from a fresh clone on its own; the fetch script has
  to run first. It fails loudly when the directory is empty.

## Alternatives considered

- **A one-shot init container fetching templates into a named volume**, keeping
  `docker compose up` self-contained. Tried it, and it breaks the run: `--exit-code-from`
  implies `--abort-on-container-exit`, so the init container completing tore down CRS
  three seconds into the scan. The scan reported 50 errors across 48 of 91 requests.
  Working around it needs profiles, or detached mode plus `docker compose wait`, and the
  named volume is still not readable by `gen-mock` on the host.
- **Folding the fetch into the nuclei service's entrypoint.** The nuclei image has `wget`
  but no `tar`.
- **A nuclei flag to pin the template version.** There is none. `-ut` updates to latest
  and `-ud` only changes where they are installed.
- **Keeping the audit log's default parts.** 30 MB per run of mostly repeated copies of
  the mock's response body.
