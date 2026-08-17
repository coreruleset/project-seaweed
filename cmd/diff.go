package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/coreruleset/project-seaweed/internal/analyze"
	"github.com/spf13/cobra"
)

func newDiffCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <previous.json> <current.json>",
		Short: "Compare two JSON reports and show what moved",
		Long: "Reads two reports written by `seaweed -f json` and reports how each CVE bucket " +
			"changed, leading with the CVEs the WAF used to block and no longer does.",
		Args: cobra.ExactArgs(2),
		RunE: runDiff,
	}
}

func runDiff(cmd *cobra.Command, args []string) error {
	previous, err := readReport(args[0])
	if err != nil {
		return err
	}
	current, err := readReport(args[1])
	if err != nil {
		return err
	}

	cmd.Print(analyze.Compare(previous, current).String())

	return nil
}

func readReport(path string) (analyze.GlobalReport, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return analyze.GlobalReport{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var report analyze.GlobalReport
	if err := json.Unmarshal(contents, &report); err != nil {
		return analyze.GlobalReport{}, fmt.Errorf("parsing %s: is it `seaweed -f json` output? %w", path, err)
	}

	return report, nil
}
