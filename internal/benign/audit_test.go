package benign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeAuditLog(t *testing.T, records ...string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit.json")
	contents := ""
	for _, record := range records {
		contents += record + "\n"
	}
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

	return path
}

// auditRecord builds one JSON Lines record the way ModSecurity v2 writes it: rule ids
// live inside the message text, not in a field of their own.
func auditRecord(t *testing.T, marker string, messages ...string) string {
	t.Helper()

	headers := map[string]string{"User-Agent": "test"}
	if marker != "" {
		headers[MarkerHeader] = marker
	}
	encoded, err := json.Marshal(map[string]any{
		"request":    map[string]any{"headers": headers},
		"audit_data": map[string]any{"messages": messages},
	})
	require.NoError(t, err)

	return string(encoded)
}

// The marker header is the join key: nothing else in a ModSecurity v2 record ties it back
// to the request that produced it.
func TestFiredRulesJoinsOnTheMarker(t *testing.T) {
	path := writeAuditLog(
		t,
		auditRecord(t, "1",
			`Warning. Pattern match at ARGS. [file "x"] [id "941100"] [msg "XSS"]`,
			`Warning. [id "949110"] [msg "Inbound Anomaly Score Exceeded"]`),
		auditRecord(t, "2", `Warning. [id "920350"] [msg "Host header is a numeric IP address"]`),
		auditRecord(t, "", `Warning. [id "941100"]`),
	)

	fired, err := FiredRules(path)
	require.NoError(t, err)

	require.Len(t, fired, 2, "records without a marker are not ours")
	assert.True(t, fired[1][941100])
	assert.True(t, fired[1][949110])
	assert.True(t, fired[2][920350])
	assert.False(t, fired[2][941100], "rules must not leak between requests")
}

func TestCompareReportsOnlyForbiddenRulesThatFired(t *testing.T) {
	results := []Result{
		{Request: Request{ID: 1, Forbid: []int{941100}, Title: "kept quiet", URI: "/a"}},
		{Request: Request{ID: 2, Forbid: []int{942151}, Title: "fired anyway", URI: "/b"}},
		{
			Request: Request{ID: 3, Forbid: []int{933100}, Title: "never answered", URI: "/c"},
			Err:     assert.AnError,
		},
	}
	fired := map[int]map[int]bool{
		1: {949110: true}, // blocked, but not by the forbidden rule
		2: {942151: true}, // the assertion broke
		3: {933100: true}, // errored, so it says nothing
	}

	positives := Compare(results, fired)

	require.Len(t, positives, 1)
	assert.Equal(t, 942151, positives[0].Rule)
	assert.Equal(t, "fired anyway", positives[0].Title)
}

// Blocking is not the measurement: many of these stages carry real attack payloads and
// assert only that a neighbouring rule stays quiet.
func TestSummaryRateCountsBlockingSeparatelyFromFalsePositives(t *testing.T) {
	summary := Summarise([]Result{
		{Status: 403}, {Status: 200}, {Status: 200}, {Err: assert.AnError},
	}, 2)

	assert.Equal(t, 4, summary.Total)
	assert.Equal(t, 1, summary.Blocked)
	assert.Equal(t, 1, summary.Errored)
	assert.Equal(t, 2, summary.Skipped)

	rate, ok := summary.Rate()
	require.True(t, ok)
	assert.InDelta(t, 1.0/3.0, rate, 0.0001, "errored requests leave the denominator")
}
