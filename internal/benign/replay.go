package benign

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"
)

// statusLine matches the first line of the response, which is all this needs: whether the
// WAF let a benign request through.
var statusLine = regexp.MustCompile(`^HTTP/1\.\d (\d{3})`)

// Result is what happened to one benign request.
type Result struct {
	Request Request
	Status  int
	Err     error
}

// Blocked reports whether the WAF refused a request it should have allowed.
func (r Result) Blocked() bool {
	return r.Status == 403
}

// Replay sends every request to target and reports what came back. Requests go one at a
// time on their own connection, so a rule that depends on the request as sent is not
// disturbed by connection reuse or pipelining.
func Replay(target string, requests []Request, timeout time.Duration) []Result {
	results := make([]Result, 0, len(requests))
	for _, request := range requests {
		results = append(results, send(target, request, timeout))
	}

	return results
}

func send(target string, request Request, timeout time.Duration) Result {
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return Result{Request: request, Err: err}
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Result{Request: request, Err: err}
	}
	if _, err := conn.Write(request.Bytes(target)); err != nil {
		return Result{Request: request, Err: err}
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return Result{Request: request, Err: fmt.Errorf("reading response to %q: %w", request.Title, err)}
	}
	found := statusLine.FindStringSubmatch(line)
	if found == nil {
		return Result{Request: request, Err: fmt.Errorf("unparseable status line %q", line)}
	}
	status, err := strconv.Atoi(found[1])
	if err != nil {
		return Result{Request: request, Err: err}
	}

	return Result{Request: request, Status: status}
}

// Summary counts a replay.
type Summary struct {
	Total   int
	Blocked int
	Errored int
	Skipped int
}

// Rate is the share of benign requests the WAF blocked, over those that got an answer.
func (s Summary) Rate() (float64, bool) {
	answered := s.Total - s.Errored
	if answered <= 0 {
		return 0, false
	}

	return float64(s.Blocked) / float64(answered), true
}

// Summarise counts results, carrying through how many stages could not be replayed.
func Summarise(results []Result, skipped int) Summary {
	summary := Summary{Total: len(results), Skipped: skipped}
	for _, result := range results {
		switch {
		case result.Err != nil:
			summary.Errored++
		case result.Blocked():
			summary.Blocked++
		}
	}

	return summary
}
