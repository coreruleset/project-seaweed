package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/coreruleset/project-seaweed/internal/analyze"
	"github.com/coreruleset/project-seaweed/internal/reader"
	"github.com/coreruleset/project-seaweed/internal/templates"
	"github.com/spf13/cobra"
)

func newSweepCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sweep <directory>",
		Short: "Report every paranoia level under a directory",
		Long: "Reads each immediate subdirectory as one paranoia level, named after the " +
			"directory, and reports them together. Use this rather than pointing -o at the " +
			"parent, which would merge the levels into a number describing no configuration.",
		Args: cobra.ExactArgs(1),
		RunE: runSweep,
	}
	cmd.Flags().String("format", "text", "output format; 'text' (default) or 'slack'")
	cmd.Flags().String("run-url", "", "link to include in the slack message, usually the CI run")
	cmd.Flags().String("templates", "nuclei-templates/http/cves",
		"path to the Nuclei templates, used to tell a gated template from one that simply finished")

	return cmd
}

func runSweep(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	runURL, _ := cmd.Flags().GetString("run-url")
	templatesPath, _ := cmd.Flags().GetString("templates")

	gated, err := templates.Gated(templatesPath)
	if err != nil {
		gated = nil
	}
	cwes, err := templates.CWEs(templatesPath)
	if err != nil {
		cwes = nil
	}

	levels, err := readLevels(args[0], gated, cwes)
	if err != nil {
		return err
	}
	if len(levels) == 0 {
		return fmt.Errorf("no level subdirectories under %q: a sweep writes one per level", args[0])
	}

	if format == "slack" {
		payload, err := json.Marshal(analyze.SweepPayload(levels, runURL))
		if err != nil {
			return err
		}
		cmd.Println(string(payload))

		return nil
	}
	cmd.Print(analyze.SweepTable(levels))

	return nil
}

func readLevels(root string, gated map[string]bool, cwes map[string][]string) ([]analyze.Level, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}

	var levels []analyze.Level
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		results, err := reader.ParseNucleiOutputDirectory(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		if len(results) == 0 {
			continue
		}
		levels = append(levels, analyze.Level{Name: entry.Name(), Report: analyze.BuildReport(results, gated, cwes)})
	}
	sort.Slice(levels, func(i, j int) bool { return levels[i].Name < levels[j].Name })

	return levels, nil
}
