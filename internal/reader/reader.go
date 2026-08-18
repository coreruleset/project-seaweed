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
	"strings"
)

var (
	// Nuclei prefixes every dump in a trace file with the template it came from:
	// "[CVE-2015-2807] Dumped HTTP request for http://...". Anchoring here keeps CVE
	// ids that appear in a payload or a response body from being mistaken for the
	// template's own id.
	tracePattern = regexp.MustCompile(`^\[(CVE-\d{4}-\d+)\] Dumped HTTP `)

	responsePattern = regexp.MustCompile(`^HTTP/1\.1\s(\d{3})`)

	// The request line of a dumped request, e.g. "GET /wp-admin/x.php?a=1 HTTP/1.1".
	// The method matters as much as the path: see line().
	requestPattern = regexp.MustCompile(`^([A-Z]+) (\S+) HTTP/1\.1`)
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

// probeMethods carry nothing a WAF could object to. Any other method aimed at the root
// path is a template sending something, which is the distinction the path alone misses.
var probeMethods = map[string]bool{
	http.MethodGet:  true,
	http.MethodHead: true,
}

// BackendMarker is served in the body of every response the mock backend produces, on
// every path and every method. Its presence is proof the request reached the application;
// its absence means something in front answered instead. That is a stronger test than
// reading status codes: an application's own 404 and Apache refusing an encoded slash
// look identical by status and are opposites by meaning.
const BackendMarker = "seaweed-mock-ok"

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
	file, err := os.Open(filename)
	if err != nil {
		return NucleiTraceOutput{}, err
	}
	// Read-only: nothing to lose on a failed close.
	defer func() { _ = file.Close() }()

	scanner := &traceScanner{}
	reader := bufio.NewReader(file)
	for {
		// ReadString has no line length limit. Response bodies in these traces run to
		// hundreds of kilobytes on a single line, which bufio.Scanner truncates at 64 KB
		// and reports only through an Err() that is easy to miss.
		line, readErr := reader.ReadString('\n')
		if line != "" {
			scanner.line(line)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return NucleiTraceOutput{}, fmt.Errorf("reading %s: %w", filename, readErr)
		}
	}
	scanner.settle()

	return scanner.trace, nil
}

// traceScanner walks a trace file, pairing each dumped response with the body that
// follows it so that delivery can be decided per request.
type traceScanner struct {
	trace     NucleiTraceOutput
	awaiting  bool
	status    int
	delivered bool
}

func (s *traceScanner) line(text string) {
	if found := tracePattern.FindStringSubmatch(text); found != nil {
		s.settle()
		if s.trace.CVENumber == "" {
			s.trace.CVENumber = found[1]
		}

		return
	}

	// A template whose every request is a bare "GET /" never sent a payload: its
	// detection step did not match, so the WAF was never asked about this CVE.
	//
	// The method is half of that test. Plenty of templates aim their payload at the root
	// path and carry it in the body — `flow: http(1) || http(2)` sending an RCE blob to
	// POST /, for one — which is a probe only by path. Five CVEs a run were reported as
	// never tested when the WAF had already answered for them, three of those answers
	// being blocks.
	if request := requestPattern.FindStringSubmatch(text); request != nil {
		s.settle()
		if !probeMethods[request[1]] || request[2] != "/" {
			s.trace.Exercised = true
		}

		return
	}

	if found := responsePattern.FindStringSubmatch(text); found != nil {
		s.settle()
		status, err := strconv.Atoi(found[1])
		if err != nil {
			return
		}
		s.awaiting, s.status, s.delivered = true, status, false

		return
	}

	if s.awaiting && strings.Contains(text, BackendMarker) {
		s.delivered = true
	}
}

// settle records the response the scanner has been reading the body of, if any.
func (s *traceScanner) settle() {
	if !s.awaiting {
		return
	}
	s.awaiting = false

	s.trace.TotalRequests++
	switch {
	case s.delivered || s.status < http.StatusBadRequest:
		// It reached the application, so the WAF let the payload through, whatever the
		// application then chose to answer. A success or a redirect is never a refusal,
		// marker or not, which is also what keeps this sane against a backend that does
		// not carry one.
		s.trace.NotBlockedRequests++
	case s.status == http.StatusForbidden:
		s.trace.BlockedRequests++
	case upstreamErrorStatuses[s.status]:
		s.trace.ErroredRequests++
	default:
		// Something in front of the application refused it: a malformed request, or an
		// encoded slash, which Apache rejects during URI translation before
		// ModSecurity's phase 2 blocking rule can act.
		s.trace.RejectedRequests++
	}
}
