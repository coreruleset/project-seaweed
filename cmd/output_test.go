package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cobra's Print helpers default to stderr. A caller redirecting stdout — the workflow
// writing a job summary, or a shell capturing a Slack payload — then gets nothing, and
// the text still shows up in logs, so it looks like it worked.
func TestSubcommandsWriteTheirReportToStdout(t *testing.T) {
	dir := t.TempDir()
	report := `{"CVEsBlocked":["CVE-1"],"CVEsNotBlocked":["CVE-2"]}`
	previous := filepath.Join(dir, "previous.json")
	current := filepath.Join(dir, "current.json")
	require.NoError(t, os.WriteFile(previous, []byte(report), 0o600))
	require.NoError(t, os.WriteFile(current, []byte(report), 0o600))

	var out bytes.Buffer
	command := NewRootCommand()
	command.SetOut(&out)
	command.SetArgs([]string{"diff", previous, current})

	require.NoError(t, command.Execute())
	assert.Contains(t, out.String(), "previous", "the table must go to the configured output")
	assert.Contains(t, out.String(), "0 CVEs changed bucket")
}

// The command must be born writing to stdout, not merely be configurable to.
func TestRootCommandWritesToStdoutByDefault(t *testing.T) {
	assert.Equal(t, os.Stdout, NewRootCommand().OutOrStdout())
}
