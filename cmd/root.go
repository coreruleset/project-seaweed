package cmd

import (
	"context"
	"log"

	"github.com/coreruleset/project-seaweed/internal/analyze"
	"github.com/coreruleset/project-seaweed/internal/templates"

	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

type FormatMode enumflag.Flag

const (
	GitHub FormatMode = iota
	JSON
	Slack
)

var FormatModeIds = map[FormatMode][]string{
	GitHub: {"github"},
	JSON:   {"json"},
	Slack:  {"slack"},
}

func Execute() error {
	rootCmd := NewRootCommand()
	return rootCmd.ExecuteContext(context.Background())
}

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "seaweed",
		Short: "Parses Nuclei test files output",
		RunE:  runE,
		// A run that fails on its results is not a usage mistake.
		SilenceUsage: true,
	}
	var formatMode FormatMode
	output := new(string)
	rootCmd.PersistentFlags().StringVarP(output, "output", "o", ".", "path to find output trace files")
	rootCmd.PersistentFlags().VarP(enumflag.New(&formatMode, "format", FormatModeIds, enumflag.EnumCaseInsensitive),
		"format", "f",
		"format to output the results; can be 'github' (default), 'json' or 'slack'")
	rootCmd.PersistentFlags().String("run-url", "",
		"link to include in the slack message, usually the CI run")
	rootCmd.PersistentFlags().String("templates", "nuclei-templates/http/cves",
		"path to the Nuclei templates, used to tell a gated template from one that simply finished")

	rootCmd.AddCommand(newGenMockCommand())

	return rootCmd
}

func runE(cmd *cobra.Command, _ []string) error {
	path, _ := cmd.Flags().GetString("output")
	runURL, _ := cmd.Flags().GetString("run-url")
	templatesPath, _ := cmd.Flags().GetString("templates")
	format := cmd.PersistentFlags().Lookup("format").Value.String()

	gated, err := templates.Gated(templatesPath)
	if err != nil {
		// Without the templates every CVE that sent only `GET /` stays "not exercised",
		// which is the safe reading, so say so and carry on.
		log.Printf("not cross-referencing templates: %v", err)
		gated = nil
	}

	return analyze.ReportNucleiBlocks(path, format, runURL, gated)
}
