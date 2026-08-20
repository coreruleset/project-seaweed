package analyze

import (
	"fmt"
	"sort"
	"strings"
)

// expectedChurn is roughly how many CVEs change bucket between two identical runs. What is
// left is templates that randomise their own payload; the User-Agent, which used to account
// for nearly all of it, is now pinned in docker-compose.yml. Two identical runs measured 2
// changes, so this leaves headroom rather than describing a hard limit. See
// https://github.com/coreruleset/project-seaweed/issues/163.
const expectedChurn = 6

// bucketNames are the per-CVE buckets, in the order a report reads best.
var bucketNames = []string{"blocked", "partially blocked", "not blocked", "no verdict", "not exercised"}

// Change is one CVE landing somewhere different than it did last time.
type Change struct {
	CVE  string
	From string
	To   string
}

// Comparison is what moved between two runs.
type Comparison struct {
	Counts  map[string][2]int
	Changes []Change
}

func (r GlobalReport) buckets() map[string]string {
	membership := map[string]string{}
	for name, cves := range map[string][]string{
		"blocked":           r.CVEsBlocked,
		"partially blocked": r.CVEsPartially,
		"not blocked":       r.CVEsNotBlocked,
		"no verdict":        r.CVEsNoVerdict,
		"not exercised":     r.CVEsNotExercised,
	} {
		for _, cve := range cves {
			membership[cve] = name
		}
	}

	return membership
}

// Compare reports how the current run differs from the previous one.
func Compare(previous, current GlobalReport) Comparison {
	before, after := previous.buckets(), current.buckets()

	comparison := Comparison{Counts: map[string][2]int{}}
	for _, name := range bucketNames {
		comparison.Counts[name] = [2]int{0, 0}
	}
	for _, bucket := range before {
		counts := comparison.Counts[bucket]
		counts[0]++
		comparison.Counts[bucket] = counts
	}
	for _, bucket := range after {
		counts := comparison.Counts[bucket]
		counts[1]++
		comparison.Counts[bucket] = counts
	}

	seen := map[string]struct{}{}
	for cve := range before {
		seen[cve] = struct{}{}
	}
	for cve := range after {
		seen[cve] = struct{}{}
	}
	for cve := range seen {
		from, to := before[cve], after[cve]
		if from == to {
			continue
		}
		comparison.Changes = append(comparison.Changes, Change{CVE: cve, From: or(from, "absent"), To: or(to, "absent")})
	}
	sort.Slice(comparison.Changes, func(i, j int) bool {
		return comparison.Changes[i].CVE < comparison.Changes[j].CVE
	})

	return comparison
}

// Regressions are the CVEs the WAF used to stop and no longer does. They are the reason
// this comparison exists, and the only changes worth reading first.
func (c Comparison) Regressions() []Change {
	var lost []Change
	for _, change := range c.Changes {
		if change.From == "blocked" && (change.To == "not blocked" || change.To == "partially blocked") {
			lost = append(lost, change)
		}
	}

	return lost
}

func (c Comparison) String() string {
	var out strings.Builder
	fmt.Fprintf(&out, "%-20s %9s %9s %8s\n", "", "previous", "current", "change")
	for _, name := range bucketNames {
		counts := c.Counts[name]
		fmt.Fprintf(&out, "%-20s %9d %9d %+8d\n", name, counts[0], counts[1], counts[1]-counts[0])
	}

	regressions := c.Regressions()
	fmt.Fprintf(&out, "\n%d CVEs changed bucket, %d of them no longer blocked.\n",
		len(c.Changes), len(regressions))
	fmt.Fprintf(&out, "About %d changes is ordinary churn between identical runs, so read the totals "+
		"before the names.\n", expectedChurn)

	if len(regressions) > 0 {
		out.WriteString("\nno longer blocked:\n")
		for _, change := range regressions {
			fmt.Fprintf(&out, "  %s  %s -> %s\n", change.CVE, change.From, change.To)
		}
	}

	return out.String()
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}
