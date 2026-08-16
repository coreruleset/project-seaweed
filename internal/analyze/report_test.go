package analyze

import (
	"testing"

	"github.com/coreruleset/project-seaweed/internal/reader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildReportPutsEachCVEInExactlyOneBucket(t *testing.T) {
	tests := []struct {
		name     string
		result   reader.NucleiTraceOutput
		blocked  []string
		partial  []string
		notBlckd []string
		errored  []string
	}{
		{
			name:    "every request blocked",
			result:  reader.NucleiTraceOutput{CVENumber: "CVE-1", TotalRequests: 2, BlockedRequests: 2},
			blocked: []string{"CVE-1"},
		},
		{
			name:     "no request blocked",
			result:   reader.NucleiTraceOutput{CVENumber: "CVE-2", TotalRequests: 2, NotBlockedRequests: 2},
			notBlckd: []string{"CVE-2"},
		},
		{
			name: "some stages blocked",
			result: reader.NucleiTraceOutput{
				CVENumber: "CVE-3", TotalRequests: 3, BlockedRequests: 1, NotBlockedRequests: 2,
			},
			partial: []string{"CVE-3"},
		},
		{
			name:    "no verdict at all",
			result:  reader.NucleiTraceOutput{CVENumber: "CVE-4", TotalRequests: 2, ErroredRequests: 2},
			errored: []string{"CVE-4"},
		},
		{
			// An upstream error alongside a real block is still a real block.
			name: "errors alongside verdicts do not hide the verdicts",
			result: reader.NucleiTraceOutput{
				CVENumber: "CVE-5", TotalRequests: 3, BlockedRequests: 2, ErroredRequests: 1,
			},
			blocked: []string{"CVE-5"},
		},
		{
			name:    "a trace with no responses is not a measurement",
			result:  reader.NucleiTraceOutput{CVENumber: "CVE-6"},
			errored: []string{"CVE-6"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := BuildReport([]reader.NucleiTraceOutput{tt.result})

			assert.Equal(t, tt.blocked, report.CVEsBlocked)
			assert.Equal(t, tt.partial, report.CVEsPartially)
			assert.Equal(t, tt.notBlckd, report.CVEsNotBlocked)
			assert.Equal(t, tt.errored, report.CVEsErrored)
			assert.Equal(t, 1, report.CVEsTested())
		})
	}
}

func TestBuildReportSumsRequestCounters(t *testing.T) {
	report := BuildReport([]reader.NucleiTraceOutput{
		{CVENumber: "CVE-1", TotalRequests: 2, BlockedRequests: 2},
		{CVENumber: "CVE-2", TotalRequests: 3, BlockedRequests: 1, NotBlockedRequests: 1, ErroredRequests: 1},
	})

	assert.Equal(t, uint(5), report.TotalRequests)
	assert.Equal(t, uint(3), report.TotalBlocked)
	assert.Equal(t, uint(1), report.TotalNotBlocked)
	assert.Equal(t, uint(1), report.TotalErrored)
	assert.Equal(t, 2, report.CVEsTested())
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		report  GlobalReport
		wantErr string
	}{
		{
			name:    "nothing parsed",
			report:  GlobalReport{},
			wantErr: "no requests found",
		},
		{
			name:   "a few upstream errors are tolerated",
			report: GlobalReport{TotalRequests: 100, TotalErrored: 10},
		},
		{
			// The archived run that motivated this gate sat at 30%.
			name:    "an unhealthy environment is not a measurement",
			report:  GlobalReport{TotalRequests: 100, TotalErrored: 30},
			wantErr: "30 of 100 requests (30%) got an upstream error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.report.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)

				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
