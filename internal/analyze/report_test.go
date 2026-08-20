package analyze

import (
	"encoding/json"
	"strings"
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
			result:  reader.NucleiTraceOutput{Exercised: true, CVENumber: "CVE-1", TotalRequests: 2, BlockedRequests: 2},
			blocked: []string{"CVE-1"},
		},
		{
			name:     "no request blocked",
			result:   reader.NucleiTraceOutput{Exercised: true, CVENumber: "CVE-2", TotalRequests: 2, NotBlockedRequests: 2},
			notBlckd: []string{"CVE-2"},
		},
		{
			name: "some stages blocked",
			result: reader.NucleiTraceOutput{
				Exercised: true, CVENumber: "CVE-3", TotalRequests: 3,
				BlockedRequests: 1, NotBlockedRequests: 2,
			},
			partial: []string{"CVE-3"},
		},
		{
			name:    "no verdict at all",
			result:  reader.NucleiTraceOutput{Exercised: true, CVENumber: "CVE-4", TotalRequests: 2, ErroredRequests: 2},
			errored: []string{"CVE-4"},
		},
		{
			// An upstream error alongside a real block is still a real block.
			name: "errors alongside verdicts do not hide the verdicts",
			result: reader.NucleiTraceOutput{
				Exercised: true, CVENumber: "CVE-5", TotalRequests: 3,
				BlockedRequests: 2, ErroredRequests: 1,
			},
			blocked: []string{"CVE-5"},
		},
		{
			name:    "a trace with no responses is not a measurement",
			result:  reader.NucleiTraceOutput{Exercised: true, CVENumber: "CVE-6"},
			errored: []string{"CVE-6"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := BuildReport([]reader.NucleiTraceOutput{tt.result}, nil, nil)

			assert.Equal(t, tt.blocked, report.CVEsBlocked)
			assert.Equal(t, tt.partial, report.CVEsPartially)
			assert.Equal(t, tt.notBlckd, report.CVEsNotBlocked)
			assert.Equal(t, tt.errored, report.CVEsNoVerdict)
			assert.Equal(t, 1, report.CVEsTested())
		})
	}
}

func TestBuildReportSumsRequestCounters(t *testing.T) {
	report := BuildReport([]reader.NucleiTraceOutput{
		{CVENumber: "CVE-1", TotalRequests: 2, BlockedRequests: 2},
		{CVENumber: "CVE-2", TotalRequests: 3, BlockedRequests: 1, NotBlockedRequests: 1, ErroredRequests: 1},
	}, nil, nil)

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

func TestBlockRate(t *testing.T) {
	tests := []struct {
		name   string
		report GlobalReport
		want   float64
		ok     bool
	}{
		{
			name:   "nothing reached a verdict",
			report: GlobalReport{CVEsNoVerdict: []string{"CVE-1"}},
		},
		{
			name:   "everything blocked",
			report: GlobalReport{CVEsBlocked: []string{"CVE-1", "CVE-2"}},
			want:   1, ok: true,
		},
		{
			name:   "nothing blocked",
			report: GlobalReport{CVEsNotBlocked: []string{"CVE-1"}},
			want:   0, ok: true,
		},
		{
			// CVEs with no verdict must not dilute the rate.
			name: "errored CVEs are excluded from the denominator",
			report: GlobalReport{
				CVEsBlocked: []string{"CVE-1"}, CVEsNotBlocked: []string{"CVE-2"},
				CVEsNoVerdict: []string{"CVE-3", "CVE-4"},
			},
			want: 0.5, ok: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.report.BlockRate()
			assert.Equal(t, tt.ok, ok)
			assert.InDelta(t, tt.want, got, 0.0001)
		})
	}
}

func TestBar(t *testing.T) {
	assert.Equal(t, strings.Repeat("░", barCells), bar(0))
	assert.Equal(t, strings.Repeat("█", barCells), bar(1))
	assert.Equal(t, strings.Repeat("█", 10)+strings.Repeat("░", 10), bar(0.5))
	// Every bar is the same width, whatever the rounding does.
	for percent := 0; percent <= 100; percent++ {
		assert.Equal(t, barCells, len([]rune(bar(float64(percent)/100))), "at %d%%", percent)
	}
}

func TestEmojiBar(t *testing.T) {
	assert.Equal(t, strings.Repeat("\u2B1C", emojiBarCells), emojiBar(0))
	assert.Equal(t, strings.Repeat("\U0001F7E9", emojiBarCells), emojiBar(1))
	for percent := 0; percent <= 100; percent++ {
		assert.Equal(t, emojiBarCells, len([]rune(emojiBar(float64(percent)/100))), "at %d%%", percent)
	}
}

func TestSlackPayloadIsValidBlockKit(t *testing.T) {
	report := GlobalReport{
		TotalRequests: 100, TotalErrored: 4,
		CVEsBlocked:    []string{"CVE-1", "CVE-2"},
		CVEsPartially:  []string{"CVE-3"},
		CVEsNotBlocked: []string{"CVE-4"},
		CVEsNoVerdict:  []string{"CVE-5"},
	}

	encoded, err := json.Marshal(SlackPayload(report, "https://example.test/run/1"))
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "\n", "must stay on one line for a job output")

	var payload struct {
		Text        string `json:"text"`
		Attachments []struct {
			Color  string `json:"color"`
			Blocks []struct {
				Type string `json:"type"`
			} `json:"blocks"`
		} `json:"attachments"`
	}
	require.NoError(t, json.Unmarshal(encoded, &payload))
	assert.Equal(t, "WAF test: 50% of CVEs blocked", payload.Text)
	require.Len(t, payload.Attachments, 1)
	assert.Equal(t, completedColour, payload.Attachments[0].Color)
	require.Len(t, payload.Attachments[0].Blocks, 4)
	assert.Equal(t, "header", payload.Attachments[0].Blocks[0].Type)
	assert.Contains(t, string(encoded), "view the run")
}

func TestSlackPayloadWithoutRunURL(t *testing.T) {
	encoded, err := json.Marshal(SlackPayload(GlobalReport{CVEsBlocked: []string{"CVE-1"}}, ""))
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "view the run")
}

func TestBuildReportSeparatesUnexercisedCVEs(t *testing.T) {
	report := BuildReport([]reader.NucleiTraceOutput{
		// Detection step answered 200 and the template stopped there.
		{CVENumber: "CVE-1", TotalRequests: 1, NotBlockedRequests: 1, Exercised: false},
		{CVENumber: "CVE-2", TotalRequests: 1, NotBlockedRequests: 1, Exercised: true},
	}, nil, nil)

	assert.Equal(t, []string{"CVE-1"}, report.CVEsNotExercised)
	assert.Equal(t, []string{"CVE-2"}, report.CVEsNotBlocked)

	// An untested CVE must not drag the block rate down.
	rate, ok := report.BlockRate()
	require.True(t, ok)
	assert.InDelta(t, 0.0, rate, 0.0001)

	blocked := BuildReport([]reader.NucleiTraceOutput{
		{CVENumber: "CVE-1", TotalRequests: 1, NotBlockedRequests: 1, Exercised: false},
		{CVENumber: "CVE-2", TotalRequests: 1, BlockedRequests: 1, Exercised: true},
	}, nil, nil)
	rate, ok = blocked.BlockRate()
	require.True(t, ok)
	assert.InDelta(t, 1.0, rate, 0.0001, "one tested CVE, blocked, is a 100% block rate")
}

func TestBuildReportCountsRejectedRequests(t *testing.T) {
	report := BuildReport([]reader.NucleiTraceOutput{
		{CVENumber: "CVE-1", TotalRequests: 2, BlockedRequests: 1, RejectedRequests: 1, Exercised: true},
	}, nil, nil)

	assert.Equal(t, uint(1), report.TotalRejected)
	// Rejected requests are not verdicts, so the CVE is fully blocked, not partial.
	assert.Equal(t, []string{"CVE-1"}, report.CVEsBlocked)
	assert.Empty(t, report.CVEsPartially)
}

// A template with no flow gate sends everything it has, so a trace holding only a bare
// `GET /` means that was the whole attack — not that the template stopped early.
func TestOnlyGatedTemplatesCanBeUnexercised(t *testing.T) {
	results := []reader.NucleiTraceOutput{
		{CVENumber: "CVE-gated", TotalRequests: 1, NotBlockedRequests: 1},
		{CVENumber: "CVE-plain", TotalRequests: 1, NotBlockedRequests: 1},
		{CVENumber: "CVE-plain-blocked", TotalRequests: 1, BlockedRequests: 1},
	}
	gated := map[string]bool{"CVE-gated": true}

	report := BuildReport(results, gated, nil)

	assert.Equal(t, []string{"CVE-gated"}, report.CVEsNotExercised)
	assert.Equal(t, []string{"CVE-plain"}, report.CVEsNotBlocked)
	// This one is the reason it matters: a WAF block that used to be filed as untested.
	assert.Equal(t, []string{"CVE-plain-blocked"}, report.CVEsBlocked)
}

// Without the templates, keep the pessimistic reading rather than quietly reclassifying.
func TestWithoutTemplatesEverythingUnsentStaysUnexercised(t *testing.T) {
	results := []reader.NucleiTraceOutput{
		{CVENumber: "CVE-1", TotalRequests: 1, NotBlockedRequests: 1},
	}

	report := BuildReport(results, nil, nil)

	assert.Equal(t, []string{"CVE-1"}, report.CVEsNotExercised)
	assert.Empty(t, report.CVEsNotBlocked)
}

// 60 CVEs in one run send nothing but a fetch of a plugin's readme, which is how the
// template decides whether to attack at all. Reporting those as "not blocked" says the WAF
// failed to stop an attack that was never sent.
func TestMetadataProbesAreNotAVerdict(t *testing.T) {
	probeOnly := reader.NucleiTraceOutput{
		CVENumber: "CVE-1", TotalRequests: 1, NotBlockedRequests: 1, MetadataProbes: 1,
	}
	report := BuildReport([]reader.NucleiTraceOutput{probeOnly}, map[string]bool{}, nil)
	assert.Equal(t, []string{"CVE-1"}, report.CVEsNotExercised, "a readme fetch tests nothing")
	assert.Empty(t, report.CVEsNotBlocked)

	// Even ungated, where ADR 9 otherwise reads a short trace as the whole attack.
	report = BuildReport([]reader.NucleiTraceOutput{probeOnly}, map[string]bool{"CVE-1": false}, nil)
	assert.Equal(t, []string{"CVE-1"}, report.CVEsNotExercised)

	// But a WAF that refuses the enumeration has answered, and that must survive -- including
	// for a gated template, where the gated branch below would otherwise swallow it.
	blocked := probeOnly
	blocked.NotBlockedRequests, blocked.BlockedRequests = 0, 1
	for _, gated := range []map[string]bool{{}, {"CVE-1": true}, nil} {
		report = BuildReport([]reader.NucleiTraceOutput{blocked}, gated, nil)
		assert.Equal(t, []string{"CVE-1"}, report.CVEsBlocked, "gated=%v", gated)
		assert.Empty(t, report.CVEsNotExercised, "gated=%v", gated)
	}
}

// Access-control CVEs are counted in the ordinary buckets and again on their own, so the
// headline rate stays honest and a reader can see how much of it CRS could ever act on.
func TestAccessControlIsCountedSeparatelyWithoutLeavingTheBuckets(t *testing.T) {
	results := []reader.NucleiTraceOutput{
		{CVENumber: "CVE-authz", TotalRequests: 1, NotBlockedRequests: 1, Exercised: true},
		{CVENumber: "CVE-sqli", TotalRequests: 1, NotBlockedRequests: 1, Exercised: true},
		{CVENumber: "CVE-blocked-authz", TotalRequests: 1, BlockedRequests: 1, Exercised: true},
	}
	cwes := map[string][]string{
		"CVE-authz":         {"CWE-862"},
		"CVE-sqli":          {"CWE-89"},
		"CVE-blocked-authz": {"CWE-287"},
	}

	report := BuildReport(results, map[string]bool{}, cwes)

	assert.ElementsMatch(t, []string{"CVE-authz", "CVE-sqli"}, report.CVEsNotBlocked,
		"an access-control CVE stays in the bucket it earned")
	assert.Equal(t, 2, report.AccessControlTested())
	assert.Equal(t, 1, report.AccessControlNotBlocked)
	assert.Equal(t, 1, report.AccessControlBlocked)

	overall, ok := report.BlockRate()
	require.True(t, ok)
	assert.InDelta(t, 1.0/3.0, overall, 0.001, "1 of 3 blocked")

	addressable, ok := report.BlockRateAddressable()
	require.True(t, ok)
	assert.InDelta(t, 0.0, addressable, 0.001, "the only addressable CVE was not blocked")
}

// A template naming several CWEs writes them as one comma-separated scalar, and one
// access-control entry among them is enough.
func TestAccessControlAcceptsAnyOfSeveralCWEs(t *testing.T) {
	assert.True(t, isAccessControl([]string{"CWE-121", "CWE-287"}))
	assert.False(t, isAccessControl([]string{"CWE-121", "CWE-787"}))
	assert.False(t, isAccessControl(nil), "no classification is not an access-control class")
	assert.False(t, isAccessControl([]string{"CWE-200"}), "exposure is a mixed class, not a blind one")
}
