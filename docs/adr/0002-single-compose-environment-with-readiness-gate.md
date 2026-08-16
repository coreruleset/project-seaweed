# 2. One compose environment, gated on readiness

- Status: Accepted
- Date: 2026-08-16

## Context

The test environment was defined twice: in `docker-compose.yml` for local runs, and again
in a `services:` block in `.github/workflows/scheduled_job.yaml` for CI. The two had
drifted:

- CI pointed the WAF at `http://dummyhttp:80`. dummyhttp listens on 8080. The backend was
  unreachable for every scheduled run.
- CI omitted the JSON audit log settings that compose sets.
- Compose passed `-sresp` without `-srd`, so trace files were written inside the container
  instead of the mounted `./output`.

Nothing checked that the environment worked before the scan started, and nothing checked
afterwards that the results were plausible. Both failure modes are silent, because a WAF
that cannot reach its backend answers `503`, and Seaweed counts every non-`403` response
as "the WAF let it through".

In the archived run in `output/`, 1158 of 7752 responses are `503` and 1151 are `404`.
That is 30% of the run scored as WAF failures caused by a backend that was not serving.
The job still exited 0 and still sent a Slack summary.

This is not hypothetical timing paranoia: while reproducing the setup for
[ADR 1](0001-generate-mock-backend-fingerprints.md), Nuclei started before Apache
finished booting and produced 25 traces instead of 114, with exit code 0.

## Decision

`docker-compose.yml` is the only definition of the test environment. CI checks out the
repository and runs `docker compose up --exit-code-from nuclei`; the `services:` block is
gone.

Both backing services declare a healthcheck, and each dependent service waits on
`condition: service_healthy`:

- `mock` is healthy when it serves the `seaweed-mock-ok` marker.
- `crs` is healthy when that same marker round-trips *through the WAF*. Checking that
  Apache is listening is not enough — that is true while the backend is down.
- `nuclei` does not start until `crs` is healthy.

The healthcheck sends a browser User-Agent, because CRS at paranoia level 4 blocks curl's
own.

The tag list moved into the compose command as `${SEAWEED_TAGS:-...}`, so local and CI
runs scan the same thing by default and either can override it.

## Consequences

- A broken environment fails the job. `docker compose up` exits non-zero when a
  dependency never becomes healthy, instead of producing a report built from 503s.
- Local and CI runs are the same run. Changing the environment means changing one file.
- `docker compose up` locally now writes trace files to `./output` as documented, because
  `-srd /output` was added.
- CI no longer uses `projectdiscovery/nuclei-action`, so the pinned `NUCLEI_VERSION` is
  gone; the Nuclei version is the digest-pinned image in compose, which Renovate already
  tracks.
- Startup is slower than the previous `services:` block, since compose pulls and waits for
  healthchecks. Seconds, against a scan that takes minutes.
- The 503 problem is contained, not solved. Infrastructure responses (502, 503, 504, 408)
  are still counted as "not blocked" by the reporter. Bucketing them separately, and
  failing a run whose infrastructure-error rate is too high, is the next change.
- `-jle output.json` was dropped: it wrote Nuclei's findings to the container's working
  directory, where nothing collected them, and Seaweed reads trace files rather than
  findings.

## Alternatives considered

- **Keep the `services:` block and just fix the port.** One line, and the two definitions
  drift again on the next change. It also cannot mount `mock/fingerprints.html`, since
  service containers start before the repository is checked out.
- **Retry or poll for readiness in a workflow step.** Reimplements healthchecks in shell,
  and only helps CI, not local runs.
- **Assert on the results instead of the environment** (for example, fail if more than
  n% of responses are 5xx). Worth having as well, but it detects the failure after
  spending the whole scan on it, and it belongs in the reporter.
