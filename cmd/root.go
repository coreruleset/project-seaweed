package cmd

import (
	"context"
	"github.com/coreruleset/project-seaweed/internal/analyze"

	"github.com/spf13/cobra"
)

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
	output := new(string)
	rootCmd.PersistentFlags().StringVarP(output, "output", "o", ".", "path to find output trace files")

	return rootCmd
}

func runE(cmd *cobra.Command, _ []string) error {
	path, _ := cmd.Flags().GetString("output")

	return analyze.ReportNucleiBlocks(path)
}
