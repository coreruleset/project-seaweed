package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
