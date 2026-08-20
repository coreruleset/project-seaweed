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

// sweepBars renders the levels as one emoji bar per line, for Slack. The counts that
// SweepTable puts beside each bar do not come along: emoji are not monospace, so a column
// after them cannot be aligned. They are summarised for the headline level instead, which
// is the level anyone reading a notification is asking about.
func sweepBars(levels []Level) string {
	var bars strings.Builder
	for _, level := range levels {
		rate, ok := level.Report.BlockRate()
		if !ok {
			fmt.Fprintf(&bars, "`%s`  no CVE reached a verdict\n", strings.ToUpper(level.Name))

			continue
		}
		fmt.Fprintf(&bars, "`%s`  %s  *%d%%*\n",
			strings.ToUpper(level.Name), emojiBar(rate), int(math.Round(rate*100)))
	}

	return strings.TrimRight(bars.String(), "\n")
}

// SweepPayload renders a sweep as Slack Block Kit. The last level is the headline, for
// continuity with the single number this project reported before it swept anything; the
// bars are what the reader actually wants.
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

	// Short enough not to wrap: the level is already in the title, and "rejected by the
	// server" said in full pushed this onto a second line in a normal-width channel.
	context := fmt.Sprintf("%d CVEs  ·  %d requests  ·  %d rejected  ·  %d upstream errors",
		headline.Report.CVEsTested(), headline.Report.TotalRequests,
		headline.Report.TotalRejected, headline.Report.TotalErrored)
	if runURL != "" {
		context += fmt.Sprintf("  ·  <%s|view the run>", runURL)
	}

	title := fmt.Sprintf("\U0001F6E1 %s", strings.TrimPrefix(text, "WAF test: "))
	counts := fmt.Sprintf("*%d* blocked  ·  *%d* not blocked\n*%d* partially blocked  ·  *%d* not exercised",
		len(headline.Report.CVEsBlocked), len(headline.Report.CVEsNotBlocked),
		len(headline.Report.CVEsPartially), len(headline.Report.CVEsNotExercised))
	// Whether a request is authorised is not visible in the request, so these are CVEs no
	// generic rule can decide. Reported beside the headline rather than removed from it.
	if rate, ok := headline.Report.BlockRateAddressable(); ok && headline.Report.AccessControlTested() > 0 {
		counts += fmt.Sprintf("\n*%d* access-control  ·  *%d%%* blocked excluding them",
			headline.Report.AccessControlTested(), int(math.Round(rate*100)))
	}

	return map[string]any{
		"text": text,
		"attachments": []any{map[string]any{
			"color": completedColour,
			"blocks": []any{
				map[string]any{
					"type": "header",
					// The notification text says the same thing in a sentence; this is the
					// title, so it leads with the number rather than with "WAF test".
					"text": map[string]any{"type": "plain_text", "text": title, "emoji": true},
				},
				map[string]any{
					"type": "section",
					"text": map[string]any{"type": "mrkdwn", "text": sweepBars(levels)},
				},
				map[string]any{
					"type": "section",
					"text": map[string]any{"type": "mrkdwn", "text": counts},
				},
				map[string]any{
					"type":     "context",
					"elements": []any{map[string]any{"type": "mrkdwn", "text": context}},
				},
			},
		}},
	}
}
