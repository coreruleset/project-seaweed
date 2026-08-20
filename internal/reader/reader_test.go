package reader

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNucleiTraceOutput(t *testing.T) {
	tests := []struct {
		name string
		file string
		want NucleiTraceOutput
	}{
		{
			name: "a 200 means the payload got through",
			file: "allowed.txt",
			want: NucleiTraceOutput{CVENumber: "CVE-2014-4550", TotalRequests: 1, NotBlockedRequests: 1},
		},
		{
			name: "a 403 means the WAF blocked it",
			file: "blocked.txt",
			want: NucleiTraceOutput{
				CVENumber: "CVE-2009-1496", TotalRequests: 1, BlockedRequests: 1,
				BlockedAttacks: 1, Exercised: true,
			},
		},
		{
			name: "a multi-stage attack counts each stage",
			file: "partial.txt",
			want: NucleiTraceOutput{
				CVENumber: "CVE-2023-34362", TotalRequests: 3, BlockedRequests: 1,
				NotBlockedRequests: 1, RejectedRequests: 1,
				// the 404 was a POST, so a payload the WAF did not refuse
				UnblockedPayloads: 1, BlockedAttacks: 1, Exercised: true,
			},
		},
		{
			name: "an unreachable backend is an error, not a pass",
			file: "errored.txt",
			want: NucleiTraceOutput{
				CVENumber: "CVE-2021-32682", TotalRequests: 1, ErroredRequests: 1, Exercised: true,
			},
		},
		{
			name: "a clustered trace has no CVE to attribute requests to",
			file: "cluster.txt",
			want: NucleiTraceOutput{
				TotalRequests: 1, BlockedRequests: 1, BlockedAttacks: 1, Exercised: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNucleiTraceOutput(filepath.Join("testdata", tt.file))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Response bodies in real traces run to hundreds of kilobytes on one line. bufio.Scanner
// stops at 64 KB, which used to drop every response in the file without saying so.
func TestParseNucleiTraceOutputReadsLinesOverScannerLimit(t *testing.T) {
	trace := "[CVE-2019-2725] Dumped HTTP response http://crs:8080/\n" +
		"HTTP/1.1 403 Forbidden\n" +
		"\n" +
		strings.Repeat("A", 200*1024) + "\n" +
		"[CVE-2019-2725] Dumped HTTP response http://crs:8080/x\n" +
		"HTTP/1.1 200 OK\n"

	file := filepath.Join(t.TempDir(), "long.txt")
	require.NoError(t, os.WriteFile(file, []byte(trace), 0o600))

	got, err := parseNucleiTraceOutput(file)
	require.NoError(t, err)
	assert.Equal(t, NucleiTraceOutput{
		CVENumber: "CVE-2019-2725", TotalRequests: 2, BlockedRequests: 1, NotBlockedRequests: 1,
	}, got)
}

// A CVE id in a payload URL or a response body is not the template's own id.
func TestParseNucleiTraceOutputIgnoresCVEsOutsideTheHeader(t *testing.T) {
	trace := "[CVE-2009-1496] Dumped HTTP request for http://crs:8080/?poc=CVE-2020-1111\n" +
		"GET /?poc=CVE-2020-1111 HTTP/1.1\n" +
		"\n" +
		"[CVE-2009-1496] Dumped HTTP response http://crs:8080/?poc=CVE-2020-1111\n" +
		"HTTP/1.1 403 Forbidden\n" +
		"\n" +
		"see also CVE-2021-2222\n"

	file := filepath.Join(t.TempDir(), "payload.txt")
	require.NoError(t, os.WriteFile(file, []byte(trace), 0o600))

	got, err := parseNucleiTraceOutput(file)
	require.NoError(t, err)
	assert.Equal(t, "CVE-2009-1496", got.CVENumber)
}

func TestParseNucleiOutputDirectory(t *testing.T) {
	results, err := ParseNucleiOutputDirectory("testdata")
	require.NoError(t, err)

	// cluster.txt has no CVE id, so it is skipped rather than reported under "".
	cves := make([]string, 0, len(results))
	for _, result := range results {
		cves = append(cves, result.CVENumber)
	}
	assert.Equal(t, []string{"CVE-2009-1496", "CVE-2014-4550", "CVE-2021-32682", "CVE-2023-34362"}, cves)
}

// The old glob was path + "/**/*.txt", which Go reads as exactly one directory level.
func TestParseNucleiOutputDirectoryWalksNestedDirectories(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "http", "deeper")
	require.NoError(t, os.MkdirAll(nested, 0o750))

	trace := "[CVE-2009-1496] Dumped HTTP response http://crs:8080/\nHTTP/1.1 403 Forbidden\n"
	require.NoError(t, os.WriteFile(filepath.Join(nested, "trace.txt"), []byte(trace), 0o600))

	results, err := ParseNucleiOutputDirectory(root)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, uint(1), results[0].BlockedRequests)
}

// Two trace files for the same CVE are one CVE, not two.
func TestParseNucleiOutputDirectoryMergesRunsOfTheSameCVE(t *testing.T) {
	root := t.TempDir()
	blocked := "[CVE-2009-1496] Dumped HTTP response http://a:8080/\nHTTP/1.1 403 Forbidden\n"
	allowed := "[CVE-2009-1496] Dumped HTTP response http://b:8080/\nHTTP/1.1 200 OK\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte(blocked), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "b.txt"), []byte(allowed), 0o600))

	results, err := ParseNucleiOutputDirectory(root)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, NucleiTraceOutput{
		CVENumber: "CVE-2009-1496", TotalRequests: 2, BlockedRequests: 1, NotBlockedRequests: 1,
	}, results[0])
}

func TestParseNucleiOutputDirectoryFailsOnMissingPath(t *testing.T) {
	_, err := ParseNucleiOutputDirectory(filepath.Join(t.TempDir(), "nope"))
	require.Error(t, err)
}

// A template that only ever probes the root was never exercised: its detection step did
// not match, so the payload step never ran and the WAF was never asked about the CVE.
func TestExercisedTracksWhetherAPayloadWasSent(t *testing.T) {
	tests := []struct {
		name  string
		trace string
		want  bool
	}{
		{
			name:  "only a bare root probe",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nGET / HTTP/1.1\n",
		},
		{
			name:  "a payload path",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080/x\nGET /wp-admin/x.php HTTP/1.1\n",
			want:  true,
		},
		{
			name:  "a payload in the query string of the root",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080/\nGET /?s=<script> HTTP/1.1\n",
			want:  true,
		},
		{
			// The shape that was being missed: `flow: http(1) || http(2)` templates that
			// POST their payload to the root path. A probe by path, an attack by method.
			name:  "a payload posted to the root",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nPOST / HTTP/1.1\n",
			want:  true,
		},
		{
			name:  "a HEAD probe of the root is still a probe",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nHEAD / HTTP/1.1\n",
		},
		{
			// CVE-2017-7269 exploits IIS WebDAV through the method itself.
			name:  "an exotic method aimed at the root",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nPROPFIND / HTTP/1.1\n",
			want:  true,
		},
		{
			// The most common request in the whole miss set. The template reads
			// "Stable tag:" out of the readme and never sends anything else.
			name:  "a plugin readme fetch",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nGET /wp-content/plugins/x/readme.txt HTTP/1.1\n",
		},
		{
			name: "a readme fetch followed by a payload",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nGET /wp-content/plugins/x/readme.txt HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP request for http://crs:8080\nGET /wp-content/plugins/x/x.php?a=1 HTTP/1.1\n",
			want: true,
		},
		{
			// A metadata filename reached through traversal is not a metadata fetch.
			name:  "a readme reached by traversal",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nGET /x/../../readme.txt HTTP/1.1\n",
			want:  true,
		},
		{
			name:  "the theme stylesheet is not on the list",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nGET /wp-content/themes/x/style.css HTTP/1.1\n",
			want:  true,
		},
		{
			name: "root probe first, payload second",
			trace: "[CVE-1111-1] Dumped HTTP request for http://crs:8080\nGET / HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP request for http://crs:8080/x\nPOST /upload.php HTTP/1.1\n",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "trace.txt")
			require.NoError(t, os.WriteFile(file, []byte(tt.trace), 0o600))

			got, err := parseNucleiTraceOutput(file)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.Exercised)
		})
	}
}

// Apache answers these before the backend sees the payload, so they are neither a WAF
// block nor the WAF letting an attack through.
func TestRejectedStatusesAreNotVerdicts(t *testing.T) {
	for _, status := range []int{400, 404, 405} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			trace := "[CVE-1111-1] Dumped HTTP request for http://crs:8080/x\n" +
				"GET /x HTTP/1.1\n" +
				fmt.Sprintf("HTTP/1.1 %d Rejected\n", status)

			file := filepath.Join(t.TempDir(), "trace.txt")
			require.NoError(t, os.WriteFile(file, []byte(trace), 0o600))

			got, err := parseNucleiTraceOutput(file)
			require.NoError(t, err)
			assert.Equal(t, uint(1), got.RejectedRequests)
			assert.Zero(t, got.NotBlockedRequests)
			assert.Zero(t, got.BlockedRequests)
		})
	}
}

// The whole point of reading the body: two identical status codes, opposite meanings.
// Apache refusing an encoded slash and an application saying "no such page" are both
// 404, and only the backend marker separates them.
func TestTheSameStatusMeansDifferentThingsDependingOnDelivery(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantRejected uint
		wantAllowed  uint
	}{
		{
			name:        "404 from the application, which the payload reached",
			body:        "<html>not found - " + BackendMarker + "</html>\n",
			wantAllowed: 1,
		},
		{
			name:         "404 from Apache, which refused it first",
			body:         "<html><title>404 Not Found</title></html>\n",
			wantRejected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace := "[CVE-1111-1] Dumped HTTP request for http://crs:8080/x\n" +
				"GET /x HTTP/1.1\n" +
				"\n[CVE-1111-1] Dumped HTTP response http://crs:8080/x\n" +
				"HTTP/1.1 404 Not Found\n\n" + tt.body

			file := filepath.Join(t.TempDir(), "trace.txt")
			require.NoError(t, os.WriteFile(file, []byte(trace), 0o600))

			got, err := parseNucleiTraceOutput(file)
			require.NoError(t, err)
			assert.Equal(t, tt.wantRejected, got.RejectedRequests)
			assert.Equal(t, tt.wantAllowed, got.NotBlockedRequests)
		})
	}
}

// A marker in one response body must not leak onto the next request's verdict.
func TestDeliveryIsDecidedPerResponse(t *testing.T) {
	trace := "[CVE-1111-1] Dumped HTTP response http://crs:8080/a\n" +
		"HTTP/1.1 200 OK\n\nhello " + BackendMarker + "\n" +
		"[CVE-1111-1] Dumped HTTP request for http://crs:8080/b\n" +
		"GET /b HTTP/1.1\n" +
		"[CVE-1111-1] Dumped HTTP response http://crs:8080/b\n" +
		"HTTP/1.1 404 Not Found\n\n<title>404 Not Found</title>\n"

	file := filepath.Join(t.TempDir(), "trace.txt")
	require.NoError(t, os.WriteFile(file, []byte(trace), 0o600))

	got, err := parseNucleiTraceOutput(file)
	require.NoError(t, err)
	assert.Equal(t, uint(2), got.TotalRequests)
	assert.Equal(t, uint(1), got.NotBlockedRequests, "the 200 reached the backend")
	assert.Equal(t, uint(1), got.RejectedRequests, "the 404 did not")
}

// The counters behind the reclassification: what the template threw, and what came back.
func TestPayloadAccounting(t *testing.T) {
	tests := []struct {
		name              string
		trace             string
		unblockedPayloads uint
		blockedAttacks    uint
	}{
		{
			name: "recon passes, the attack is refused",
			trace: "[CVE-1111-1] Dumped HTTP request\nGET /wp-content/plugins/x/ HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 200 OK\n" +
				"[CVE-1111-1] Dumped HTTP request\nGET /shop/?id=1%27+OR+1=1 HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 403 Forbidden\n",
			blockedAttacks: 1,
		},
		{
			name: "the upload is refused, the check for its file passes",
			trace: "[CVE-1111-1] Dumped HTTP request\nPOST /wp-admin/admin.php?page=x HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 403 Forbidden\n" +
				"[CVE-1111-1] Dumped HTTP request\nGET /wp-content/uploads/x/shell.php HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 200 OK\n",
			blockedAttacks: 1,
		},
		{
			// No sensitive filename in it, so the traversal sequence is the only thing
			// that makes this a payload rather than a plain fetch.
			name: "a traversal path is a payload even with no query string",
			trace: "[CVE-1111-1] Dumped HTTP request\nGET /x/../../config/db.yml HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 200 OK\n",
			unblockedPayloads: 1,
		},
		{
			name: "a path naming a system file is a payload with no traversal at all",
			trace: "[CVE-1111-1] Dumped HTTP request\nGET /files/etc/passwd HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 200 OK\n",
			unblockedPayloads: 1,
		},
		{
			name: "a body makes a GET a payload",
			trace: "[CVE-1111-1] Dumped HTTP request\nGET /x HTTP/1.1\nHost: crs:8080\n\n{\"a\":1}\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 200 OK\n",
			unblockedPayloads: 1,
		},
		{
			name: "refusing a plain sign-in is not refusing an attack",
			trace: "[CVE-1111-1] Dumped HTTP request\nPOST /wp-login.php HTTP/1.1\nHost: crs:8080\n\nlog=a&pwd=b\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 403 Forbidden\n",
		},
		{
			name: "an attack aimed at the sign-in page is an attack",
			trace: "[CVE-1111-1] Dumped HTTP request\nGET /wp-login.php?e=<script> HTTP/1.1\n" +
				"[CVE-1111-1] Dumped HTTP response\nHTTP/1.1 403 Forbidden\n",
			blockedAttacks: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "trace.txt")
			require.NoError(t, os.WriteFile(file, []byte(tt.trace), 0o600))

			got, err := parseNucleiTraceOutput(file)
			require.NoError(t, err)
			assert.Equal(t, tt.unblockedPayloads, got.UnblockedPayloads, "unblocked payloads")
			assert.Equal(t, tt.blockedAttacks, got.BlockedAttacks, "blocked attacks")
		})
	}
}
