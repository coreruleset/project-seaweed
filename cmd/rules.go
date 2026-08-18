package cmd

import (
	"github.com/coreruleset/project-seaweed/internal/rules"
	"github.com/spf13/cobra"
)

func newRulesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "rules <audit-log>",
		Short: "Report which CRS rules did the blocking, and which fired without managing it",
		Long: "Reads a ModSecurity JSON audit log. A transaction is blocked when 949110 fired, " +
			"so no join with the trace files is needed. Rules are reported as contributing to " +
			"blocks rather than causing them, because CRS blocks on an accumulated score.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			summary, err := rules.Read(args[0])
			if err != nil {
				return err
			}
			cmd.Print(summary.String())

			return nil
		},
	}
}
