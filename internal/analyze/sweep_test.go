package analyze

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func levels() []Level {
	return []Level{
		{Name: "pl1", Report: GlobalReport{
			TotalRequests:  100,
			CVEsBlocked:    []string{"CVE-1"},
			CVEsNotBlocked: []string{"CVE-2", "CVE-3"},
		}},
		{Name: "pl4", Report: GlobalReport{
			TotalRequests:    100,
			CVEsBlocked:      []string{"CVE-1", "CVE-2", "CVE-3"},
			CVEsPartially:    []string{"CVE-4"},
			CVEsNotExercised: []string{"CVE-5"},
		}},
	}
}

func TestSweepTableIsFixedWidth(t *testing.T) {
	table := SweepTable(levels())

	lines := strings.Split(strings.TrimRight(table, "\n"), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "PL1")
	assert.Contains(t, lines[0], "33%")
	assert.Contains(t, lines[1], "PL4")
	assert.Contains(t, lines[1], "75%")
	// Slack only aligns columns inside a code block, and only if the rows match.
	assert.Equal(t, len([]rune(lines[0])), len([]rune(lines[1])), "rows must be the same width")
}

func TestSweepTableSurvivesALevelWithNoVerdicts(t *testing.T) {
	table := SweepTable([]Level{{Name: "pl1", Report: GlobalReport{CVEsNoVerdict: []string{"CVE-1"}}}})

	assert.Contains(t, table, "no CVE reached a verdict")
}

func TestSweepPayloadLeadsWithTheHighestLevel(t *testing.T) {
	encoded, err := json.Marshal(SweepPayload(levels(), "https://example.test/run"))
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "\n\"", "must stay on one line for a job output")

	var payload struct {
		Text        string `json:"text"`
		Attachments []struct {
			Blocks []struct {
				Type string `json:"type"`
				Text struct {
					Text string `json:"text"`
				} `json:"text"`
			} `json:"blocks"`
		} `json:"attachments"`
	}
	require.NoError(t, json.Unmarshal(encoded, &payload))

	assert.Equal(t, "WAF test: 75% of CVEs blocked at PL4", payload.Text)
	require.Len(t, payload.Attachments, 1)
	blocks := payload.Attachments[0].Blocks
	require.Len(t, blocks, 4)
	assert.Equal(t, "header", blocks[0].Type)
	// The curve is the point: every level has to be in the message, not just the headline.
	assert.Contains(t, blocks[1].Text.Text, "PL1")
	assert.Contains(t, blocks[1].Text.Text, "PL4")
	assert.True(t, strings.HasPrefix(blocks[1].Text.Text, "```"), "the table needs a code block to align")
	assert.Contains(t, string(encoded), "view the run")
}

func TestSweepPayloadWithNoLevelsFallsBackToAnEmptyReport(t *testing.T) {
	encoded, err := json.Marshal(SweepPayload(nil, ""))
	require.NoError(t, err)
	assert.Contains(t, string(encoded), "no CVE reached a verdict")
}
