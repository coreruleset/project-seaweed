# 20. Pin the User-Agent

Date: 2026-08-20

## Status

Accepted. Supersedes the churn floor recorded in
[ADR 10](0010-compare-each-run-with-the-previous-one.md) and removes the confound named in
[ADR 11](0011-scan-every-paranoia-level.md).

## Context

Nuclei rotates the User-Agent per request: 902 distinct values in one run of 4145 templates.
CRS does not treat them equally. Sending the same benign body six times, changing nothing but
the User-Agent:

| User-Agent | result | rules |
| --- | --- | --- |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/120` | 200 | — |
| `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) … Safari/605` | 200 | — |
| `Mozilla/5.0 (SS; Linux i686) … Chrome/132` | **403** | 920274, 932237 |
| `… Windows NT 5.1; es-ES; rv:1.9.2.3 … Firefox/3.6.3` | **403** | 932237 |
| `… Windows NT 5.1; nl; rv:1.9.2 … Firefox/3.6` | **403** | 932237 |
| `Mozilla/5.0 (Linux; Android 13; SM-S901B) … Chrome/120` | 200 | — |

That is [coreruleset#4761](https://github.com/coreruleset/coreruleset/issues/4761), reported
from this project: `ss` inside `(SS; Linux i686)` and the `es)`/`nl)` locale tags match a
Unix shell command rule, and 932237 alone scores 5 — the threshold.

The consequence is worse than noise. `CVE-2025-59136` sends ten requests that differ only in
`order_id=1..10`; two came back 403 and eight passed. The ruleset detected nothing about the
payload. It reacted to the scanner's User-Agent, and the report counted two blocks.

## Decision

Pin it: `-H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"`.

`-H` does work on nuclei v3.11.1 — an earlier note in this project said it was ignored at
scale, which was wrong for this version. Measured: 902 distinct User-Agents became 2, the
second being templates that set their own, which correctly still win.

A browser string rather than an honest `seaweed/1.0`, because CRS's 913xxx rules block known
scanner agents on sight. Naming ourselves would replace a small accidental inflation with a
total one, and an attacker who wants through does not announce itself either.

Measured over three full local runs at PL4, same corpus and code:

| | random User-Agent | pinned |
| --- | --- | --- |
| CVEs blocked | 2811 | 2771 |
| CVEs not blocked | 899 | 952 |
| block rate | 71.2% | **70.2%** |
| CVEs changing bucket between two identical runs | 48 (ADR 10) | **2** |

## Consequences

- **The published rate falls about a point**, and that point was never real: it was CRS
  answering a locale tag, not an attack.
- **Run-to-run comparison becomes usable.** The 48-change floor was mostly this. What is left
  is templates randomising their own payloads, so `expectedChurn` drops from 48 to 6, which
  still leaves headroom over the 2 measured. A diff that now reports 40 changes means
  something happened.
- **The paranoia curve loses a confound.** ADR 11 recorded that 932237 is a PL3 rule firing on
  the scanner's own User-Agent, which inflated PL3 and PL4 against PL1. Those levels are now
  comparable on the payloads alone.
- **We stop discovering User-Agent false positives by accident.** 932237 was found precisely
  because the scanner sent 902 of them. That was luck, and it has already been reported; false
  positives are the benign pass's job, and it uses the CRS regression corpus, which would not
  have found this one. If UA coverage is wanted it should be a deliberate probe rather than a
  side effect of the CVE scan.
- One value is now load-bearing in a way it was not before: if this string ever trips a rule,
  every request in the run carries it. It is checked against a live PL4 instance and scores 0.

## Alternatives considered

- **Leave it and correct for it in the report**, attributing each block to a rule and
  discounting the ones only a User-Agent rule caused. This was the original plan for
  [#161](https://github.com/coreruleset/project-seaweed/issues/161), and it needs a join
  between trace requests and audit transactions that the data does not support: the audit log
  records the request line but not the body, and hundreds of WordPress CVEs share
  `POST /wp-admin/admin-ajax.php`. Removing the cause is both cheaper and honest.
- **Send no User-Agent at all.** Trips 920320 and 920300 on every request instead.
- **An honest scanner string.** See above: 913xxx blocks it, and the run would measure
  scanner detection rather than CVE coverage.
