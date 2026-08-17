package benign

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

// ruleID pulls the rule out of a ModSecurity v2 audit message, where it is embedded in the
// message text rather than given a field of its own.
var ruleID = regexp.MustCompile(`\[id "(\d+)"\]`)

// FiredRules maps each replayed request, by its marker, to the rules that matched it.
func FiredRules(auditLog string) (map[int]map[int]bool, error) {
	file, err := os.Open(auditLog)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", auditLog, err)
	}
	defer func() { _ = file.Close() }()

	fired := map[int]map[int]bool{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8<<20)

	for scanner.Scan() {
		var record struct {
			Request struct {
				Headers map[string]string `json:"headers"`
			} `json:"request"`
			AuditData struct {
				Messages []string `json:"messages"`
			} `json:"audit_data"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) != nil {
			continue
		}
		marker, ok := record.Request.Headers[MarkerHeader]
		if !ok {
			continue
		}
		id, err := strconv.Atoi(marker)
		if err != nil {
			continue
		}
		if fired[id] == nil {
			fired[id] = map[int]bool{}
		}
		for _, message := range record.AuditData.Messages {
			for _, match := range ruleID.FindAllStringSubmatch(message, -1) {
				if rule, err := strconv.Atoi(match[1]); err == nil {
					fired[id][rule] = true
				}
			}
		}
	}

	return fired, scanner.Err()
}

// FalsePositive is a rule that matched a request asserting it would not.
type FalsePositive struct {
	Rule  int
	Title string
	URI   string
}

// Compare reports which assertions the WAF broke.
func Compare(results []Result, fired map[int]map[int]bool) []FalsePositive {
	var found []FalsePositive
	for _, result := range results {
		if result.Err != nil {
			continue
		}
		for _, forbidden := range result.Request.Forbid {
			if fired[result.Request.ID][forbidden] {
				found = append(found, FalsePositive{
					Rule:  forbidden,
					Title: result.Request.Title,
					URI:   result.Request.URI,
				})
			}
		}
	}

	return found
}
