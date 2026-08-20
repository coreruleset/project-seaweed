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

	headerPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*:\s`)
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

// metadataFiles hold facts about the application rather than any of its data: a version
// number, a changelog, a licence. Nuclei templates fetch them to decide whether a target is
// worth attacking -- 58 of the 60 that stop here extract a version and run it through
// compare_versions -- so a trace made only of these asked the WAF nothing.
//
// Deliberately short. Every entry has to be a file a browser never requests while rendering
// a page, which rules out the theme stylesheet a plugin's readme sits next to.
var metadataFiles = map[string]bool{
	"readme.txt":    true,
	"readme.md":     true,
	"changelog.txt": true,
	"changelog.md":  true,
	"license.txt":   true,
}

// isMetadataProbe reports whether a request only asks for one of those files. A query
// string, an encoded character or a traversal sequence means the path is carrying something
// besides the filename, so it is left alone.
func isMetadataProbe(method, path string) bool {
	if !probeMethods[method] || strings.ContainsAny(path, "?%") || strings.Contains(path, "..") {
		return false
	}

	return metadataFiles[strings.ToLower(path[strings.LastIndex(path, "/")+1:])]
}

// osFiles are the targets a path names outright when the path itself is the payload, so a
// bare GET for one is an attack rather than reconnaissance.
var osFiles = regexp.MustCompile(`(?i)etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|/proc/|/\.(git|env|aws|ssh)\b`)

// authPaths are where a template signs in before attacking. A WAF that blocks one of these
// has refused an ordinary login, which says nothing about whether it would stop the exploit
// that was going to follow.
var authPaths = regexp.MustCompile(`(?i)(wp-login\.php|/login|/signin|/session|/auth|/j_security_check)`)

// carriesPayload reports whether a request contains something a WAF could reasonably object
// to. A GET for a plain path is reconnaissance: a template reading a version, or checking
// afterwards for the file its blocked upload would have written. Anything else -- another
// method, a query string, a body, an encoded character, a traversal sequence, or a path
// naming a system file -- is the template attacking.
func carriesPayload(method, path string, body bool) bool {
	if !probeMethods[method] || body {
		return true
	}
	if strings.ContainsAny(path, "?%") || strings.Contains(path, "..") {
		return true
	}

	return osFiles.MatchString(path)
}

// isAuthStep reports whether a request is a plain sign-in. A query string means the path is
// carrying an attack of its own -- `/wp-login.php?login-error=<script>` is an XSS payload
// aimed at the login page, not a login.
func isAuthStep(path string) bool {
	return !strings.Contains(path, "?") && authPaths.MatchString(path)
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
			merged.MetadataProbes += trace.MetadataProbes
			merged.UnblockedPayloads += trace.UnblockedPayloads
			merged.BlockedAttacks += trace.BlockedAttacks
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

	// what the request that produced the response being read looked like
	inRequest  bool
	reqMethod  string
	reqPath    string
	reqHasBody bool
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
		s.inRequest, s.reqMethod, s.reqPath, s.reqHasBody = true, request[1], request[2], false
		switch {
		case isMetadataProbe(request[1], request[2]):
			s.trace.MetadataProbes++
		case !probeMethods[request[1]] || request[2] != "/":
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
		s.awaiting, s.status, s.delivered, s.inRequest = true, status, false, false

		return
	}

	// A non-header line inside the request is its body.
	if s.inRequest && strings.TrimSpace(text) != "" && !headerPattern.MatchString(text) {
		s.reqHasBody = true
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

	// Accounting for the reclassification in the report: was every payload this template
	// sent actually refused, and was anything refused besides an ordinary sign-in?
	//
	// Only where the request line was seen. A response dumped without one says nothing about
	// what was sent, and guessing "not a GET, so a payload" from an empty method would count
	// an attack that may not exist.
	if s.reqMethod != "" {
		if carriesPayload(s.reqMethod, s.reqPath, s.reqHasBody) && s.status != http.StatusForbidden {
			s.trace.UnblockedPayloads++
		}
		if s.status == http.StatusForbidden && !isAuthStep(s.reqPath) {
			s.trace.BlockedAttacks++
		}
	}

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
