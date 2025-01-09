package cmd

import (
	"context"

	"github.com/coreruleset/project-seaweed/internal/analyze"

	"github.com/spf13/cobra"
	"github.com/thediveo/enumflag/v2"
)

type FormatMode enumflag.Flag

const (
	GitHub FormatMode = iota
	JSON
)

var FormatModeIds = map[FormatMode][]string{
	GitHub: {"github"},
	JSON:   {"json"},
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
	}
	var formatMode FormatMode
	output := new(string)
	rootCmd.PersistentFlags().StringVarP(output, "output", "o", ".", "path to find output trace files")
	rootCmd.PersistentFlags().VarP(enumflag.New(&formatMode, "format", FormatModeIds, enumflag.EnumCaseInsensitive),
		"format", "f",
		"format to output the results; can be 'github' (default) or 'json'")

	return rootCmd
}

func runE(cmd *cobra.Command, _ []string) error {
	path, _ := cmd.Flags().GetString("output")
	format := cmd.PersistentFlags().Lookup("format").Value.String()

	return analyze.ReportNucleiBlocks(path, format)
}
