package analyze

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/coreruleset/project-seaweed/internal/reader"
)

// maxErrorRate is the share of upstream errors above which a run stops being a
// measurement of the WAF and becomes a measurement of its plumbing. The last run before
// this gate existed sat at 30%, and reported it as the WAF failing to block.
const maxErrorRate = 0.1

// GlobalReport represents the global report of the Nuclei output.
//
// The request counters cover every request sent. Each CVE appears in exactly one of the
// CVE lists: fully blocked, partially blocked, not blocked at all, or no verdict because
// every one of its requests hit an upstream error.
type GlobalReport struct {
	TotalRequests    uint
	TotalBlocked     uint
	TotalNotBlocked  uint
	TotalErrored     uint
	TotalRejected    uint
	CVEsBlocked      []string
	CVEsPartially    []string
	CVEsNotBlocked   []string
	CVEsNoVerdict    []string
	CVEsNotExercised []string
}

const (
	// barCells is the width of the block-rate bar in the terminal and the job summary.
	barCells = 20
	// emojiBarCells is the width of the Slack one, in emoji. Fifteen: ten cannot tell the
	// paranoia levels apart, because a real curve climbs about 6 points a level and each
	// cell is worth 10, so the run this was designed against rendered as 5, 5, 6, 6 — a
	// bar that shows none of the climb it is there to show. Twenty wraps on a narrow window.
	emojiBarCells = 15
	// completedColour is the stripe on a run that finished, whatever the WAF scored.
	completedColour = "#28a745"
)

// ReportNucleiBlocks reports how the WAF answered the payloads in the Nuclei output.
func ReportNucleiBlocks(path string, format string, runURL string, gated map[string]bool) error {
	results, err := reader.ParseNucleiOutputDirectory(path)
	if err != nil {
		return err
	}

	report := BuildReport(results, gated)
	if err := printReport(report, format, runURL); err != nil {
		return err
	}

	// Printed first: the numbers are worth seeing even when the run is not usable.
	return report.Validate()
}

// BuildReport aggregates per-CVE trace results into a single report.
//
// gated names the CVEs whose template holds its payload behind a flow gate; pass nil when
// the templates are not available. A template without a gate sends everything it has, so
// a trace holding only a bare `GET /` means that was the whole attack.
func BuildReport(results []reader.NucleiTraceOutput, gated map[string]bool) GlobalReport {
	var report GlobalReport

	for _, result := range results {
		report.TotalRequests += result.TotalRequests
		report.TotalBlocked += result.BlockedRequests
		report.TotalNotBlocked += result.NotBlockedRequests
		report.TotalErrored += result.ErroredRequests
		report.TotalRejected += result.RejectedRequests

		verdicts := result.BlockedRequests + result.NotBlockedRequests
		switch {
		case !exercised(result, gated):
			// The payload step never ran, so this CVE was not tested at all. Counting it
			// as "not blocked" blames the WAF for an attack nobody sent.
			report.CVEsNotExercised = append(report.CVEsNotExercised, result.CVENumber)
		case verdicts == 0:
			// Every request either errored upstream or was rejected before the backend,
			// so the WAF never answered for this CVE.
			report.CVEsNoVerdict = append(report.CVEsNoVerdict, result.CVENumber)
		case result.BlockedRequests == verdicts:
			report.CVEsBlocked = append(report.CVEsBlocked, result.CVENumber)
		case result.BlockedRequests == 0:
			report.CVEsNotBlocked = append(report.CVEsNotBlocked, result.CVENumber)
		default:
			report.CVEsPartially = append(report.CVEsPartially, result.CVENumber)
		}
	}

	return report
}

// exercised reports whether the template got to send what it meant to send.
func exercised(result reader.NucleiTraceOutput, gated map[string]bool) bool {
	if result.Exercised {
		return true
	}

	// A trace of nothing but metadata fetches asked the WAF about a plugin's readme, not
	// about the CVE. That holds whether or not the template declares a gate: an ungated one
	// sent everything it has, and everything it has is a file fetch. The exception is a WAF
	// that answered anyway -- refusing version enumeration is a real answer, and hiding it
	// here would lose it.
	if result.MetadataProbes > 0 {
		return result.BlockedRequests > 0
	}

	// Only a gated template can stop early. Without the templates to check against, keep
	// the pessimistic reading rather than quietly reclassifying.
	return gated != nil && !gated[result.CVENumber]
}

// Validate reports whether the run measured the WAF at all.
func (r GlobalReport) Validate() error {
	if r.TotalRequests == 0 {
		return errors.New("no requests found: does the output directory hold Nuclei trace files?")
	}

	rate := float64(r.TotalErrored) / float64(r.TotalRequests)
	if rate > maxErrorRate {
		return fmt.Errorf(
			"%d of %d requests (%.0f%%) got an upstream error: the WAF or its backend was unhealthy, so these results do not measure blocking",
			r.TotalErrored, r.TotalRequests, rate*100,
		)
	}

	return nil
}

// CVEsTested is the number of CVEs the run has any trace of.
func (r GlobalReport) CVEsTested() int {
	return len(r.CVEsBlocked) + len(r.CVEsPartially) + len(r.CVEsNotBlocked) +
		len(r.CVEsNoVerdict) + len(r.CVEsNotExercised)
}

// BlockRate is the share of CVEs the WAF blocked outright, out of those it reached any
// verdict on. CVEs whose requests all hit an upstream error are not a verdict either way,
// so counting them would move the number without measuring anything.
func (r GlobalReport) BlockRate() (float64, bool) {
	decided := len(r.CVEsBlocked) + len(r.CVEsPartially) + len(r.CVEsNotBlocked)
	if decided == 0 {
		return 0, false
	}

	return float64(len(r.CVEsBlocked)) / float64(decided), true
}

func bar(rate float64) string {
	filled := int(math.Round(rate * barCells))

	return strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", barCells-filled)
}

// emojiBar is the Slack bar. Slack renders emoji as emoji inside a code block too, which
// destroys the monospace alignment a code block exists for, so the two cannot be combined:
// this one is used in plain sections, and bar() stays for the terminal and the job summary.
//
// Ten cells rather than twenty because an emoji is about twice as wide as a character, and
// twenty wrap on a narrow window. The exact rate is printed beside it either way.
func emojiBar(rate float64) string {
	filled := int(math.Round(rate * emojiBarCells))

	return strings.Repeat("\U0001F7E9", filled) + strings.Repeat("\u2B1C", emojiBarCells-filled)
}

// SlackPayload renders the report as Slack Block Kit.
func SlackPayload(report GlobalReport, runURL string) map[string]any {
	headline := "WAF test: no CVE reached a verdict"
	summary := "Every request hit an upstream error, so nothing was measured."

	if rate, ok := report.BlockRate(); ok {
		percent := int(math.Round(rate * 100))
		headline = fmt.Sprintf("WAF test: %d%% of CVEs blocked", percent)
		summary = fmt.Sprintf("%s  *%d%%*", emojiBar(rate), percent)
	}

	context := fmt.Sprintf(
		"%d CVEs seen  ·  %d requests  ·  %d rejected by the server  ·  %d upstream errors  ·  %d with no verdict",
		report.CVEsTested(), report.TotalRequests, report.TotalRejected,
		report.TotalErrored, len(report.CVEsNoVerdict),
	)
	if runURL != "" {
		context += fmt.Sprintf("  ·  <%s|view the run>", runURL)
	}

	// Blocks inside an attachment: the blocks give the layout, the attachment gives the
	// colour stripe down the side, which is the part you read from across the room.
	return map[string]any{
		"text": headline,
		"attachments": []any{map[string]any{
			"color": completedColour,
			"blocks": []any{
				map[string]any{
					"type": "header",
					"text": map[string]any{"type": "plain_text", "text": headline, "emoji": true},
				},
				map[string]any{
					"type": "section",
					"text": map[string]any{"type": "mrkdwn", "text": summary},
				},
				map[string]any{
					"type": "section",
					"fields": []any{
						slackField("Blocked", len(report.CVEsBlocked)),
						slackField("Partially blocked", len(report.CVEsPartially)),
						slackField("Not blocked", len(report.CVEsNotBlocked)),
						slackField("Not exercised", len(report.CVEsNotExercised)),
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

func slackField(label string, count int) map[string]any {
	return map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%d", label, count)}
}

func printReport(report GlobalReport, format string, runURL string) error {
	if format == "slack" {
		// One line, so the workflow can carry it in a job output.
		payload, err := json.Marshal(SlackPayload(report, runURL))
		if err != nil {
			return err
		}
		fmt.Println(string(payload))

		return nil
	}

	if format == "json" {
		marshal, err := json.Marshal(report)
		if err != nil {
			return err
		}
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, marshal, "", "\t"); err != nil {
			return err
		}
		fmt.Println(prettyJSON.String())

		return nil
	}

	fmt.Printf("total_requests=%d\n", report.TotalRequests)
	fmt.Printf("total_blocked=%d\n", report.TotalBlocked)
	fmt.Printf("total_not_blocked=%d\n", report.TotalNotBlocked)
	fmt.Printf("total_errored=%d\n", report.TotalErrored)
	fmt.Printf("total_rejected=%d\n", report.TotalRejected)
	fmt.Printf("cves_tested=%d\n", report.CVEsTested())
	fmt.Printf("cves_blocked=%d\n", len(report.CVEsBlocked))
	fmt.Printf("cves_partially_blocked=%d\n", len(report.CVEsPartially))
	fmt.Printf("cves_not_blocked=%d\n", len(report.CVEsNotBlocked))
	fmt.Printf("cves_no_verdict=%d\n", len(report.CVEsNoVerdict))
	fmt.Printf("cves_not_exercised=%d\n", len(report.CVEsNotExercised))

	return nil
}
