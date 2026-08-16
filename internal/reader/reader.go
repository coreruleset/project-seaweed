package reader

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

var (
	// Nuclei prefixes every dump in a trace file with the template it came from:
	// "[CVE-2015-2807] Dumped HTTP request for http://...". Anchoring here keeps CVE
	// ids that appear in a payload or a response body from being mistaken for the
	// template's own id.
	tracePattern = regexp.MustCompile(`^\[(CVE-\d{4}-\d+)\] Dumped HTTP `)

	responsePattern = regexp.MustCompile(`^HTTP/1\.1\s(\d{3})`)

	// The request line of a dumped request, e.g. "GET /wp-admin/x.php?a=1 HTTP/1.1".
	requestPattern = regexp.MustCompile(`^[A-Z]+ (\S+) HTTP/1\.1`)
)

// upstreamErrorStatuses are answers the reverse proxy gives about itself rather than
// verdicts on a payload. Counting them as "the WAF let it through" is how an unreachable
// backend reads as a WAF failure: 30% of the last run before this distinction existed.
var upstreamErrorStatuses = map[int]bool{
	http.StatusRequestTimeout:      true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
}

// rejectedStatuses are refusals by the server in front of the backend, before the
// payload could land. The bundled mock answers 200 on every path and every method, so
// under `docker compose up` anything here came from Apache, not from the application:
// 400 for a malformed request, and 404 for an encoded slash, which Apache rejects during
// URI translation before ModSecurity's phase 2 blocking rule can act. A run against some
// other backend, where 404 is an ordinary application answer, will over-count this.
var rejectedStatuses = map[int]bool{
	http.StatusBadRequest:       true,
	http.StatusNotFound:         true,
	http.StatusMethodNotAllowed: true,
}

// ParseNucleiOutputDirectory reads every trace file under path and returns one result
// per CVE, sorted by CVE number.
func ParseNucleiOutputDirectory(path string) ([]NucleiTraceOutput, error) {
	byCVE := map[string]*NucleiTraceOutput{}

	err := filepath.WalkDir(path, func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(file) != ".txt" {
			return nil
		}

		trace, err := parseNucleiTraceOutput(file)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", file, err)
		}
		if trace.CVENumber == "" {
			// Nuclei clusters templates that send identical requests into one trace file
			// headed by a cluster hash, so its requests cannot be attributed to a CVE.
			// Run nuclei with -dc to keep that from happening.
			log.Printf("skipping %s: no CVE id in trace header", file)
			return nil
		}

		if merged, seen := byCVE[trace.CVENumber]; seen {
			merged.TotalRequests += trace.TotalRequests
			merged.BlockedRequests += trace.BlockedRequests
			merged.NotBlockedRequests += trace.NotBlockedRequests
			merged.ErroredRequests += trace.ErroredRequests
			merged.RejectedRequests += trace.RejectedRequests
			merged.Exercised = merged.Exercised || trace.Exercised
		} else {
			byCVE[trace.CVENumber] = &trace
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	results := make([]NucleiTraceOutput, 0, len(byCVE))
	for _, trace := range byCVE {
		results = append(results, *trace)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].CVENumber < results[j].CVENumber })

	return results, nil
}

func parseNucleiTraceOutput(filename string) (NucleiTraceOutput, error) {
	var trace NucleiTraceOutput

	file, err := os.Open(filename)
	if err != nil {
		return trace, err
	}
	// Read-only: nothing to lose on a failed close.
	defer func() { _ = file.Close() }()

	reader := bufio.NewReader(file)
	for {
		// ReadString has no line length limit. Response bodies in these traces run to
		// hundreds of kilobytes on a single line, which bufio.Scanner truncates at 64 KB
		// and reports only through an Err() that is easy to miss.
		line, readErr := reader.ReadString('\n')
		if line != "" {
			countLine(&trace, line)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return trace, fmt.Errorf("reading %s: %w", filename, readErr)
		}
	}

	return trace, nil
}

func countLine(trace *NucleiTraceOutput, line string) {
	if found := tracePattern.FindStringSubmatch(line); found != nil {
		if trace.CVENumber == "" {
			trace.CVENumber = found[1]
		}
		return
	}

	// A template whose every request is a bare "GET /" never sent a payload: its
	// detection step did not match, so the WAF was never asked about this CVE.
	if request := requestPattern.FindStringSubmatch(line); request != nil {
		if request[1] != "/" {
			trace.Exercised = true
		}

		return
	}

	found := responsePattern.FindStringSubmatch(line)
	if found == nil {
		return
	}
	status, err := strconv.Atoi(found[1])
	if err != nil {
		return
	}

	trace.TotalRequests++
	switch {
	case status == http.StatusForbidden:
		trace.BlockedRequests++
	case upstreamErrorStatuses[status]:
		trace.ErroredRequests++
	case rejectedStatuses[status]:
		trace.RejectedRequests++
	default:
		trace.NotBlockedRequests++
	}
}
