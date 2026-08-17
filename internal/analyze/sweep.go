package analyze

import (
	"fmt"
	"math"
	"strings"
)

// Level is one paranoia level's worth of results, labelled by the directory it came from.
type Level struct {
	Name   string
	Report GlobalReport
}

// SweepTable renders the levels as fixed-width rows: rate, a bar, and the counts behind
// them. Fixed width because Slack only aligns columns inside a code block, and the job
// summary reads the same way.
func SweepTable(levels []Level) string {
	var table strings.Builder
	for _, level := range levels {
		rate, ok := level.Report.BlockRate()
		if !ok {
			fmt.Fprintf(&table, "%-4s      no CVE reached a verdict\n", strings.ToUpper(level.Name))

			continue
		}
		fmt.Fprintf(&table, "%-4s %3d%%  %s  %5d blocked  %5d not blocked\n",
			strings.ToUpper(level.Name), int(math.Round(rate*100)), bar(rate),
			len(level.Report.CVEsBlocked), len(level.Report.CVEsNotBlocked))
	}

	return table.String()
}

// SweepPayload renders a sweep as Slack Block Kit. The last level is the headline, for
// continuity with the single number this project reported before it swept anything; the
// table is what the reader actually wants.
func SweepPayload(levels []Level, runURL string) map[string]any {
	if len(levels) == 0 {
		return SlackPayload(GlobalReport{}, runURL)
	}

	headline := levels[len(levels)-1]
	text := fmt.Sprintf("WAF test: no CVE reached a verdict at %s", strings.ToUpper(headline.Name))
	if rate, ok := headline.Report.BlockRate(); ok {
		text = fmt.Sprintf("WAF test: %d%% of CVEs blocked at %s",
			int(math.Round(rate*100)), strings.ToUpper(headline.Name))
	}

	context := fmt.Sprintf("%d CVEs seen  ·  %d requests at %s  ·  %d rejected by the server  ·  %d upstream errors",
		headline.Report.CVEsTested(), headline.Report.TotalRequests, strings.ToUpper(headline.Name),
		headline.Report.TotalRejected, headline.Report.TotalErrored)
	if runURL != "" {
		context += fmt.Sprintf("  ·  <%s|view the run>", runURL)
	}

	return map[string]any{
		"text": text,
		"attachments": []any{map[string]any{
			"color": completedColour,
			"blocks": []any{
				map[string]any{
					"type": "header",
					"text": map[string]any{"type": "plain_text", "text": text, "emoji": true},
				},
				map[string]any{
					"type": "section",
					"text": map[string]any{"type": "mrkdwn", "text": "```\n" + SweepTable(levels) + "```"},
				},
				map[string]any{
					"type": "section",
					"fields": []any{
						slackField("Partially blocked", len(headline.Report.CVEsPartially)),
						slackField("Not exercised", len(headline.Report.CVEsNotExercised)),
					},
				},
				map[string]any{
					"type":     "context",
					"elements": []any{map[string]any{"type": "mrkdwn", "text": context}},
				},
			},
		}},
	}
}
