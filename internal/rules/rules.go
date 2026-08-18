// Package rules reports which CRS rules did the blocking, and which fired without
// managing it, from the ModSecurity audit log alone.
package rules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ruleID pulls the rule out of a ModSecurity v2 audit message, where it lives in the
// message text rather than a field of its own.
var ruleID = regexp.MustCompile(`\[id "(\d+)"\]`)

const (
	// anomalyExceeded is the rule that blocks once the inbound score passes the
	// threshold. Its presence is what marks a transaction as blocked, so no join with the
	// trace files is needed to tell blocked from allowed.
	anomalyExceeded = 949110
	// outboundExceeded is its response-side counterpart.
	outboundExceeded = 959100
)

// bookkeeping rules record the decision rather than detect anything, so counting them
// among the causes would say only that blocked requests were blocked.
func bookkeeping(rule int) bool {
	return rule == anomalyExceeded || rule == outboundExceeded || (rule >= 980000 && rule < 981000)
}

// attack reports whether a rule belongs to a family that looks for an attack, rather than
// protocol hygiene. A 920 firing under the threshold is a missing Accept header; a 942
// firing under it is SQL injection CRS saw and let through.
func attack(rule int) bool {
	family := rule / 1000

	return family >= 930 && family <= 944
}

// Summary is what the audit log says about a run.
type Summary struct {
	Transactions int
	Blocked      int
	// Contributing counts, per rule, the blocked transactions it fired in. CRS blocks on
	// an accumulated score, so this is contribution rather than sole cause.
	Contributing map[int]int
	// NearMiss counts, per attack rule, the transactions where it fired and the request
	// was not blocked anyway.
	NearMiss map[int]int
}

// Read summarises a ModSecurity JSON audit log.
func Read(path string) (Summary, error) {
	file, err := os.Open(path)
	if err != nil {
		return Summary{}, fmt.Errorf("reading %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()

	summary := Summary{Contributing: map[int]int{}, NearMiss: map[int]int{}}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)

	for scanner.Scan() {
		var record struct {
			AuditData struct {
				Messages []string `json:"messages"`
			} `json:"audit_data"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil {
			continue
		}
		summary.Transactions++

		fired := map[int]bool{}
		for _, message := range record.AuditData.Messages {
			for _, match := range ruleID.FindAllStringSubmatch(message, -1) {
				if rule, err := strconv.Atoi(match[1]); err == nil {
					fired[rule] = true
				}
			}
		}
		blocked := fired[anomalyExceeded] || fired[outboundExceeded]
		if blocked {
			summary.Blocked++
		}
		for rule := range fired {
			switch {
			case bookkeeping(rule):
			case blocked:
				summary.Contributing[rule]++
			case attack(rule):
				summary.NearMiss[rule]++
			}
		}
	}

	return summary, scanner.Err()
}

func (s Summary) String() string {
	var out strings.Builder
	fmt.Fprintf(&out, "%d transactions, %d blocked\n\n", s.Transactions, s.Blocked)

	out.WriteString("rules contributing to blocks:\n")
	for _, entry := range rank(s.Contributing, 10) {
		fmt.Fprintf(&out, "  %d  %5d\n", entry.rule, entry.count)
	}

	out.WriteString("\nattack rules that fired without blocking:\n")
	ranked := rank(s.NearMiss, 10)
	if len(ranked) == 0 {
		out.WriteString("  none\n")
	}
	for _, entry := range ranked {
		fmt.Fprintf(&out, "  %d  %5d\n", entry.rule, entry.count)
	}

	return out.String()
}

type entry struct {
	rule  int
	count int
}

func rank(counts map[int]int, limit int) []entry {
	ranked := make([]entry, 0, len(counts))
	for rule, count := range counts {
		ranked = append(ranked, entry{rule: rule, count: count})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].count != ranked[j].count {
			return ranked[i].count > ranked[j].count
		}

		return ranked[i].rule < ranked[j].rule
	})
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}

	return ranked
}
