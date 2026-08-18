package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBodyLiterals(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		want       []string
	}{
		{
			name:       "plain contains on the body",
			expression: `contains(body,"/wp-content/plugins/tom-m8te/")`,
			want:       []string{"/wp-content/plugins/tom-m8te/"},
		},
		{
			name:       "lowercased body",
			expression: `contains(tolower(body), 'altenergy power control')`,
			want:       []string{"altenergy power control"},
		},
		{
			name:       "every literal of a contains_all",
			expression: `contains_all(body,"Navis","Tags:")`,
			want:       []string{"Navis", "Tags:"},
		},
		{
			name:       "a numbered body from a later step",
			expression: `contains(body_2,"jenkins")`,
			want:       []string{"jenkins"},
		},
		{
			// Serving a string the gate did not strictly need only risks sending the
			// payload, which is what we want; missing one loses the CVE entirely.
			name:       "mixed clause contributes its literals too",
			expression: `contains(body,"wp-content") && contains(header,"text/html")`,
			want:       []string{"wp-content", "text/html"},
		},
		{
			name:       "clauses that never mention the body are ignored",
			expression: `status_code == 200 && contains(header,"Server: nginx")`,
		},
		{
			name:       "a version comparison has nothing to serve",
			expression: `compare_versions(version, '< 2.0.0')`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bodyLiterals(tt.expression))
		})
	}
}

// The page is generated at scan time and not committed, so nothing downstream would
// notice a harvester that quietly stopped matching. This is the only thing that would.
func TestGenMockRefusesAShortPage(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cve.yaml"), []byte(`id: CVE-2024-0001
flow: http(1) && http(2)
http:
  - matchers:
      - type: word
        internal: true
        words:
          - "the only fingerprint here"
`), 0o600))
	out := filepath.Join(dir, "fingerprints.html")

	command := NewRootCommand()
	command.SetOut(&bytes.Buffer{})
	command.SetArgs([]string{"gen-mock", "--templates", dir, "--out", out})

	err := command.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "found only 1 gate words")
	assert.NoFileExists(t, out, "a page that failed the floor must not be left behind")
}
