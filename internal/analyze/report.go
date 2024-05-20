package analyze

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/coreruleset/project-seaweed/internal/reader"
)

// GlobalReport represents the global report of the Nuclei output.
type GlobalReport struct {
	TotalRequests   uint
	TotalBlocked    uint
	TotalNotBlocked uint
	PartialBlocked  uint
	CVEsBlocked     []string
	CVEsPartially   []string
	CVEsNotBlocked  []string
}

// ReportNucleiBlocks reports the number of blocked requests in the Nuclei output.
func ReportNucleiBlocks(path string, format string) error {
	results, err := reader.ParseNucleiOutputDirectory(path)
	if err != nil {
		return err
	}
	var globalReport GlobalReport

	for _, result := range results {
		var partiallyBlocked uint
		// if there is more than one request and not all of them are blocked
		if result.TotalRequests > 1 && result.BlockedRequests != result.TotalRequests {
			partiallyBlocked = result.TotalRequests - result.BlockedRequests
			globalReport.PartialBlocked += partiallyBlocked
			globalReport.CVEsPartially = append(globalReport.CVEsPartially, result.CVENumber)
		}
		if result.BlockedRequests > 0 {
			globalReport.TotalBlocked += result.BlockedRequests
			globalReport.CVEsBlocked = append(globalReport.CVEsBlocked, result.CVENumber)
		}
		if result.BlockedRequests == 0 {
			globalReport.TotalNotBlocked += result.NotBlockedRequests - partiallyBlocked
			globalReport.CVEsNotBlocked = append(globalReport.CVEsNotBlocked, result.CVENumber)

		}
		globalReport.TotalRequests += result.TotalRequests
	}

	// output the results
	switch format {
	case "json":
		var prettyJSON bytes.Buffer
		marshal, err := json.Marshal(globalReport)
		if err != nil {
			return err
		}
		err = json.Indent(&prettyJSON, marshal, "", "\t")
		if err != nil {
			return err
		}
		fmt.Println(prettyJSON.String())
	default:
		fmt.Printf("total_requests=%d\n", globalReport.TotalRequests)
		fmt.Printf("total_blocked=%d\n", globalReport.TotalBlocked)
		fmt.Printf("total_not_blocked=%d\n", globalReport.TotalNotBlocked)
		fmt.Printf("partially_blocked=%d\n", globalReport.PartialBlocked)
		//fmt.Printf("CVEs blocked: %v\n", globalReport.CVEsBlocked)
		//fmt.Printf("CVEs Not blocked: %v\n", globalReport.CVEsNotBlocked)
	}
	return nil
}
