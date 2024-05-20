package analyze

import (
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
func ReportNucleiBlocks(path string) error {
	results, err := reader.ParseNucleiOutputDirectory(path)
	if err != nil {
		return err
	}
	var globalReport GlobalReport

	for _, result := range results {
		if result.TotalRequests > 0 {
			if result.BlockedRequests/result.TotalRequests != 1 {
				globalReport.PartialBlocked++
				globalReport.CVEsPartially = append(globalReport.CVEsPartially, result.CVENumber)
			}
		}
		if result.BlockedRequests > 0 {
			globalReport.TotalBlocked += result.BlockedRequests
			globalReport.CVEsBlocked = append(globalReport.CVEsBlocked, result.CVENumber)
		}
		if result.NotBlockedRequests > 0 {
			globalReport.TotalNotBlocked += result.NotBlockedRequests
			globalReport.CVEsNotBlocked = append(globalReport.CVEsNotBlocked, result.CVENumber)

		}
		globalReport.TotalRequests += result.TotalRequests
	}

	// Print the global report
	fmt.Printf("Total requests: %d\n", globalReport.TotalRequests)
	fmt.Printf("Total blocked: %d\n", globalReport.TotalBlocked)
	fmt.Printf("Total not blocked: %d\n", globalReport.TotalNotBlocked)
	fmt.Printf("Partially blocked: %d\n", globalReport.PartialBlocked)
	fmt.Printf("CVEs blocked: %v\n", globalReport.CVEsBlocked)
	fmt.Printf("CVEs Not blocked: %v\n", globalReport.CVEsNotBlocked)
	return nil
}
