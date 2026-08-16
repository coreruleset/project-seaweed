package analyze

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

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
	TotalRequests   uint
	TotalBlocked    uint
	TotalNotBlocked uint
	TotalErrored    uint
	CVEsBlocked     []string
	CVEsPartially   []string
	CVEsNotBlocked  []string
	CVEsErrored     []string
}

// ReportNucleiBlocks reports how the WAF answered the payloads in the Nuclei output.
func ReportNucleiBlocks(path string, format string) error {
	results, err := reader.ParseNucleiOutputDirectory(path)
	if err != nil {
		return err
	}

	report := BuildReport(results)
	if err := printReport(report, format); err != nil {
		return err
	}

	// Printed first: the numbers are worth seeing even when the run is not usable.
	return report.Validate()
}

// BuildReport aggregates per-CVE trace results into a single report.
func BuildReport(results []reader.NucleiTraceOutput) GlobalReport {
	var report GlobalReport

	for _, result := range results {
		report.TotalRequests += result.TotalRequests
		report.TotalBlocked += result.BlockedRequests
		report.TotalNotBlocked += result.NotBlockedRequests
		report.TotalErrored += result.ErroredRequests

		verdicts := result.BlockedRequests + result.NotBlockedRequests
		switch {
		case verdicts == 0:
			report.CVEsErrored = append(report.CVEsErrored, result.CVENumber)
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
	return len(r.CVEsBlocked) + len(r.CVEsPartially) + len(r.CVEsNotBlocked) + len(r.CVEsErrored)
}

func printReport(report GlobalReport, format string) error {
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
	fmt.Printf("cves_tested=%d\n", report.CVEsTested())
	fmt.Printf("cves_blocked=%d\n", len(report.CVEsBlocked))
	fmt.Printf("cves_partially_blocked=%d\n", len(report.CVEsPartially))
	fmt.Printf("cves_not_blocked=%d\n", len(report.CVEsNotBlocked))
	fmt.Printf("cves_errored=%d\n", len(report.CVEsErrored))

	return nil
}
