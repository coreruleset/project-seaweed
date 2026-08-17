package analyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareFindsWhatMoved(t *testing.T) {
	previous := GlobalReport{
		CVEsBlocked:      []string{"CVE-1", "CVE-2", "CVE-3"},
		CVEsNotBlocked:   []string{"CVE-4"},
		CVEsNotExercised: []string{"CVE-5"},
	}
	current := GlobalReport{
		CVEsBlocked:    []string{"CVE-1", "CVE-4"},
		CVEsPartially:  []string{"CVE-2"},
		CVEsNotBlocked: []string{"CVE-3", "CVE-5"},
	}

	comparison := Compare(previous, current)

	assert.Equal(t, [2]int{3, 2}, comparison.Counts["blocked"])
	assert.Equal(t, [2]int{0, 1}, comparison.Counts["partially blocked"])
	assert.Equal(t, [2]int{1, 2}, comparison.Counts["not blocked"])
	assert.Equal(t, [2]int{1, 0}, comparison.Counts["not exercised"])

	assert.Equal(t, []Change{
		{CVE: "CVE-2", From: "blocked", To: "partially blocked"},
		{CVE: "CVE-3", From: "blocked", To: "not blocked"},
		{CVE: "CVE-4", From: "not blocked", To: "blocked"},
		{CVE: "CVE-5", From: "not exercised", To: "not blocked"},
	}, comparison.Changes)
}

// The only changes worth reading first: the WAF used to stop these and no longer does.
func TestRegressionsAreOnlyLostBlocks(t *testing.T) {
	comparison := Compare(
		GlobalReport{CVEsBlocked: []string{"CVE-1", "CVE-2"}, CVEsNotBlocked: []string{"CVE-3"}},
		GlobalReport{CVEsNotBlocked: []string{"CVE-1"}, CVEsPartially: []string{"CVE-2"}, CVEsBlocked: []string{"CVE-3"}},
	)

	assert.Equal(t, []Change{
		{CVE: "CVE-1", From: "blocked", To: "not blocked"},
		{CVE: "CVE-2", From: "blocked", To: "partially blocked"},
	}, comparison.Regressions(), "a CVE newly blocked is not a regression")
}

func TestCompareHandlesCVEsPresentInOnlyOneRun(t *testing.T) {
	comparison := Compare(
		GlobalReport{CVEsBlocked: []string{"CVE-gone"}},
		GlobalReport{CVEsBlocked: []string{"CVE-new"}},
	)

	assert.Equal(t, []Change{
		{CVE: "CVE-gone", From: "blocked", To: "absent"},
		{CVE: "CVE-new", From: "absent", To: "blocked"},
	}, comparison.Changes)
	assert.Empty(t, comparison.Regressions(), "a CVE that vanished from the corpus is not a lost block")
}

func TestCompareOfIdenticalRunsIsEmpty(t *testing.T) {
	report := GlobalReport{CVEsBlocked: []string{"CVE-1"}, CVEsNotBlocked: []string{"CVE-2"}}

	comparison := Compare(report, report)

	assert.Empty(t, comparison.Changes)
	require.Contains(t, comparison.String(), "0 CVEs changed bucket")
}
