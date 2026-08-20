# Path traversal: the `....//` form and 930120's target list

**Status:** measured, not filed. The gap is real and reproducible, but no CVE in the corpus
exercises it, and the cost of the obvious fix is unmeasured. See
[Why this was not filed](#why-this-was-not-filed).

**Date:** 2026-08-19 · **Measured against:** CRS 4.28.0 on Apache 2.4.68, PL4 · **Rules read
from:** `coreruleset` `main` at v4.29.0 · **Corpus:** nuclei-templates v10.4.7

Sibling findings from the same analysis were filed as coreruleset/coreruleset#4765
(WordPress metadata enumeration), #4766 (management endpoints) and #4767 (XXE). This one was
held back.

## The finding in one line

A four-dot traversal in the **request path** aimed at a Unix file is undetected, while the
identical shape aimed at a Windows file is blocked — because `win.ini` is in
`restricted-files.data`, which is matched against the path, and `etc/passwd` is only in
`lfi-os-files.data`, which is not.

| request | status | rules |
| --- | --- | --- |
| `GET /x/....//....//etc/passwd` | 200 | none |
| `GET /x/....//....//windows/win.ini` | 403 | 920440, 930130 |
| `GET /x/etc/passwd` | 200 | none |
| `GET /x/windows/win.ini` | 403 | 920440, 930130 |
| `GET /x?f=....//....//etc/passwd` | 403 | 920273, 930120, 932160, 932236, 942460 |
| `GET /x?f=....//....//windows/win.ini` | 403 | 920273, 930120, 942460 |

The traversal syntax is incidental to the last four rows: `/x/etc/passwd` with no traversal
at all is equally undetected, and the parameter rows are caught by `930120` matching the
filename, not the dots.

## Two independent mechanisms

### 1. The dot run is bounded at three

`930100` and `930110` (both PL1, CRITICAL) bound it between separators:

```
930110: (?:^|[/;\x5c])\.{2,3}[/;\x5c]
```

Four dots between separators match neither alternative, and the engine cannot restart
mid-run because the character before the second dot is a dot rather than a separator.
`grep -E '\.\.\.\.'` over `rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf` returns nothing.

Requesting `/x/<form><form>etc/passwd`. "Reached" means the origin's marker came back in the
body, so the request was delivered rather than merely unblocked.

| form | after one removal of `../` | equals `../` | status | reached | score | rules |
| --- | --- | --- | --- | --- | --- | --- |
| `../` | — | no | 400 | no | 0 | none — Apache rejects during URI translation |
| `.../` | `.` | no | 403 | no | 15 | 930100, 930110 |
| `..../` | `..` | no | 200 | yes | 0 | none |
| `...../` | `...` | no | 200 | yes | 0 | none |
| `....//` | `../` | **yes** | 200 | yes | 0 | none |
| `.....//` | `.../` | no | 200 | yes | 0 | none |
| `......//` | `..../` | no | 200 | yes | 0 | none |
| `........//` | `....../` | no | 200 | yes | 0 | none |
| `..././` | `../` | **yes** | 403 | no | 15 | 930100, 930110 |
| `..;/` | — | no | 403 | no | 10 | 930110 |
| `..%2f` | — | no | 403 | no | 15 | 930100, 930110 |
| `%2e%2e/` | — | no | 400 | no | 0 | none — Apache decodes, then rejects |

Dot count is not the distinction. Of the two forms a single-pass `../` sanitiser converts
into `../`, CRS matches `..././` and misses `....//`. Five, six and eight dots are equally
unmatched but do not collapse to `../` in one pass, so nothing is lost there.

`....//` is not traversal by itself: `posixpath.normpath("/x/....//....//etc/passwd")`
returns `/x/..../..../etc/passwd`, so `....` resolves as an ordinary directory name. It
matters only against a backend that removes `../` occurrences without looping.

### 2. `lfi-os-files.data` is never matched against the URI

Targets in the 930 family at v4.29.0:

| rule | target | data |
| --- | --- | --- |
| 930100, 930110 | `REQUEST_URI_RAW\|ARGS\|REQUEST_HEADERS\|!REQUEST_HEADERS:Referer\|FILES\|XML:/*\|XML://@*` | inline regex |
| 930120 | `REQUEST_COOKIES\|REQUEST_COOKIES_NAMES\|ARGS_NAMES\|ARGS\|XML:/*\|XML://@*` | `lfi-os-files.data` |
| 930130 | `REQUEST_FILENAME` | `restricted-files.data` |
| 930140 | `REQUEST_FILENAME` | `ai-critical-artifacts.data` |
| PL2 rule, line 198 | `REQUEST_HEADERS:Referer\|REQUEST_HEADERS:User-Agent` | `lfi-os-files.data` |

So the path is inspected for traversal *syntax* and for `restricted-files.data` names, but
never for `lfi-os-files.data` names. Where the two lists overlap the path is covered; where
they do not, it is not:

| entry | restricted-files.data | lfi-os-files.data | caught in the path |
| --- | --- | --- | --- |
| `win.ini` | line 463 | line 373 | yes |
| `etc/passwd` | absent | line 650 | no |

## Corpus evidence

Nine templates in v10.4.7 use a four-dot form. Seven are outside `http/cves` and therefore
outside this project's scan:

```
fuzzing/linux-lfi-fuzzing.yaml            ....//....//etc/passwd
vulnerabilities/other/metinfo-lfi.yaml    .....///.....///config
vulnerabilities/other/voyager-lfi.yaml    .....%2F%2F%2F....
vulnerabilities/other/huawei-hg659-lfi    ....//....//....//
vulnerabilities/gitea/gitea-rce.yaml      ....../../../etc/passwd
vulnerabilities/generic/generic-linux-lfi ....//....//etc/passwd
vulnerabilities/generic/generic-windows-lfi ....//....//windows/...
```

Two are in `http/cves` and were both **blocked** in run 32184771851 — but neither exercises
the gap:

| CVE | request | why it was blocked |
| --- | --- | --- |
| CVE-2015-4666 | `GET /opm/read_sessionlog.php?logFile=....//....//....//....//etc/passwd` | payload is in a **parameter**, so `930120` sees `etc/passwd` |
| CVE-2018-10201 | `GET /..../..../..../windows/win.ini` | target is **win.ini**, which is in `restricted-files.data`, so `930130` matches the path |

That is the whole reason the earlier read of this analysis said "zero corpus impact". The
two CVEs that use the form are caught by mechanisms that have nothing to do with the dot
run, and a corpus CVE combining *path placement* + *four dots* + *a Unix target* does not
exist yet.

## Why this was not filed

- **Nothing in the corpus exercises it.** The gap needs all three of path placement, a
  four-dot form, and a target that lives only in `lfi-os-files.data`. No CVE template
  combines them.
- **`....//` is not traversal on its own** (see above). It depends on a single-pass
  `../`-stripping sanitiser in the origin, which was assumed rather than demonstrated
  against a real application.
- **The cost of the obvious fix is unmeasured.** Adding a URI variable to `930120` means
  matching a ~1,000-entry list against every request path. Whether that is acceptable for
  performance, and how often those entries appear in legitimate paths, was not tested.
- Extending the dot bound from `\.{2,3}` to `\.{2,}` is a smaller change, but it only covers
  mechanism 1, and mechanism 2 is what actually lets `/x/etc/passwd` through with no
  traversal syntax at all.

## What would settle it

1. **The strongest argument is mechanism 2 on its own**, independent of dot forms:
   `GET /x/etc/passwd` returns 200 with score 0. If that is considered a gap, the dot-form
   analysis is a footnote rather than the finding.
2. Measure the cost of matching `lfi-os-files.data` against `REQUEST_FILENAME`: rule
   evaluation time, and how often its entries appear in the paths of a real access log.
3. Demonstrate a real framework collapsing `....//` — or drop the single-strip framing and
   argue mechanism 1 purely as pattern completeness.
4. Re-check on an origin that does not answer 400 for `../` in the request line. Apache
   pre-empts the plainest traversal before phase 2, so some of this is Apache-specific.

## Reproducing

Needs the compose stack in this repo, plus an override, because the default configuration
logs relevant transactions only and a clean 200 never appears:

```yaml
# audit-on.yml
services:
  crs:
    environment:
      MODSEC_AUDIT_ENGINE: "On"
      MODSEC_AUDIT_LOG_PARTS: "ABIJH"
```

```bash
go run . gen-mock
SEAWEED_PORT=18080 SEAWEED_PARANOIA=4 \
  docker compose -f docker-compose.yml -f audit-on.yml up -d --wait mock crs
python3 dotforms.py
docker compose -f docker-compose.yml -f audit-on.yml down
```

`dotforms.py` sends `Host: crs:8080` and an `Accept` header deliberately, so that `920350`
(numeric host) and `920300` (missing accept) contribute nothing and the benign control scores
0. Replaying to `127.0.0.1` inflates every score by 3, which is enough to turn a two-point
notice into a block; that invalidated a first run of this analysis and reported 245 blocks
that were not real.

```python
import socket, json, re, subprocess, time, posixpath

FORMS = ["../", ".../", "..../", "...../", "....//", ".....//", "......//",
         "........//", "..././", "..;/", "..%2f", "%2e%2e/"]
EXTRA = [("unix-path", "/x/....//....//etc/passwd"),
         ("win-path", "/x/....//....//windows/win.ini"),
         ("unix-arg", "/x?f=....//....//etc/passwd"),
         ("unix-path-plain", "/x/etc/passwd"),
         ("win-path-plain", "/x/windows/win.ini"),
         ("benign", "/index.html")]

def send(label, path, port=18080):
    raw = (f"GET {path} HTTP/1.1\r\nHost: crs:8080\r\n"
           "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\r\n"
           "Accept: text/html,application/xhtml+xml\r\n"
           f"X-Probe: {label}\r\nConnection: close\r\n\r\n")
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(raw.encode())
    buf = b""
    while True:
        c = s.recv(8192)
        if not c or len(buf) > 60000:
            break
        buf += c
    s.close()
    return (int(buf.split(b" ")[1]) if buf.startswith(b"HTTP/") else 0,
            b"seaweed-mock-ok" in buf)

cases = [(f"form:{f}", f"/x/{f}{f}etc/passwd") for f in FORMS] + EXTRA
results = {label: send(label, path) for label, path in cases}
time.sleep(2)
subprocess.run(["docker", "compose", "cp",
                "crs:/var/log/apache2/modsec_audit.json", "audit.json"], capture_output=True)

idp, scp = re.compile(r'\[id "(\d+)"\]'), re.compile(r"Inbound Scores: blocking=(\d+),")
audit = {}
for line in open("audit.json", errors="replace"):
    try:
        d = json.loads(line)
    except Exception:
        continue
    lab = d.get("request", {}).get("headers", {}).get("X-Probe")
    if not lab:
        continue
    blob = " ".join(d.get("audit_data", {}).get("messages", []))
    sc = scp.search(blob)
    audit[lab] = (int(sc.group(1)) if sc else 0,
                  sorted(set(idp.findall(blob)) - {"949110", "980170", "980130"}))

for label, path in cases:
    code, reached = results[label]
    score, ids = audit.get(label, (None, []))
    print(f"{label:22s} {code:>4} reached={reached!s:5s} score={score} {ids}")
```

The collapse column needs no stack:

```python
for f in FORMS:
    print(f, "->", f.replace("../", "", 1),
          "| normpath:", posixpath.normpath(f"/x/{f}{f}etc/passwd"))
```

Finding the corpus templates:

```bash
grep -rlE '\.\.\.\.(/|%2f|%2F|\\)' nuclei-templates/http/
```
