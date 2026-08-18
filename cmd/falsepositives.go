package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/coreruleset/project-seaweed/internal/benign"
	"github.com/spf13/cobra"
)

func newFalsePositivesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "false-positives <target>",
		Short: "Replay the CRS regression suite and count the rules that fire when they should not",
		Long: "Reads the CRS regression suite, takes every stage asserting that particular rules " +
			"must not fire, and sends it at the target. With --audit-log it then checks which of " +
			"those rules matched anyway: a false positive by the ruleset's own definition. " +
			"Blocking is deliberately not the test, because many of these stages carry real " +
			"attack payloads and assert only that a neighbouring rule stays quiet. " +
			"Target is host:port.",
		Args: cobra.ExactArgs(1),
		RunE: runFalsePositives,
	}
	cmd.Flags().String("tests", "crs-tests", "path to the CRS regression suite")
	cmd.Flags().Duration("timeout", 5*time.Second, "per-request timeout")
	cmd.Flags().String("audit-log", "",
		"ModSecurity JSON audit log for this run, copied out of the container; without it only "+
			"blocking is reported, which does not measure false positives")
	cmd.Flags().Bool("list", false, "list each false positive rather than only counting them")
	cmd.Flags().Bool("no-send", false,
		"skip the replay and only read --audit-log, for when the requests were sent by an "+
			"earlier invocation and the log has since been copied out of the container")

	return cmd
}

func runFalsePositives(cmd *cobra.Command, args []string) error {
	tests, _ := cmd.Flags().GetString("tests")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	auditLog, _ := cmd.Flags().GetString("audit-log")
	list, _ := cmd.Flags().GetBool("list")
	noSend, _ := cmd.Flags().GetBool("no-send")

	if noSend && auditLog == "" {
		return errors.New("--no-send needs --audit-log: there is nothing else to read")
	}

	requests, skipped, err := benign.Load(tests)
	if err != nil {
		return err
	}
	if len(requests) == 0 {
		return fmt.Errorf("no benign stages under %q: is it the CRS regression suite?", tests)
	}

	results := benign.Replay(args[0], requests, timeout)
	if noSend {
		// The requests were sent already; build results that carry the requests without
		// claiming anything about their responses.
		results = make([]benign.Result, 0, len(requests))
		for _, request := range requests {
			results = append(results, benign.Result{Request: request})
		}
	}
	summary := benign.Summarise(results, skipped)

	if !noSend {
		rate, ok := summary.Rate()
		if !ok {
			return fmt.Errorf("no benign request got an answer from %s", args[0])
		}
		cmd.Printf("benign_requests=%d\n", summary.Total-summary.Errored)
		cmd.Printf("benign_blocked=%d\n", summary.Blocked)
		cmd.Printf("benign_blocked_rate=%.2f\n", rate*100)
	}
	if summary.Errored > 0 {
		cmd.Printf("benign_errored=%d\n", summary.Errored)
	}
	if summary.Skipped > 0 {
		cmd.Printf("benign_unreplayable=%d\n", summary.Skipped)
	}

	if auditLog == "" {
		cmd.Println("# false positives need --audit-log: blocking alone does not measure them")

		return nil
	}

	fired, err := benign.FiredRules(auditLog)
	if err != nil {
		return err
	}
	positives := benign.Compare(results, fired)
	cmd.Printf("false_positives=%d\n", len(positives))
	cmd.Printf("false_positive_rate=%.2f\n",
		100*float64(len(positives))/float64(max(summary.Total-summary.Errored, 1)))
	if list {
		for _, positive := range positives {
			cmd.Printf("# %d fired on %q  %s\n", positive.Rule, positive.Title, positive.URI)
		}
	}

	return nil
}
