// Package benign reads the requests CRS's own regression suite says must not be blocked,
// and replays them so the share that is blocked can be measured.
package benign

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// MarkerHeader carries a per-request id so a replayed request can be found again in the
// audit log. Nothing else in this project can join a request to its ModSecurity record;
// here the requests are ours to label.
const MarkerHeader = "X-Seaweed-Case"

// Request is one stage of a CRS regression test that asserts particular rules must not
// fire. If one of them does, that is a false positive by the ruleset's own definition.
//
// A blocked response is *not* the test: many of these stages carry genuine attack payloads
// and assert only that some neighbouring rule stays quiet, so CRS is right to block them.
type Request struct {
	ID      int
	Forbid  []int
	Title   string
	Method  string
	URI     string
	Version string
	Headers []Header
	Data    string
}

// Header keeps the order the test wrote, because some CRS rules care about it.
type Header struct {
	Name  string
	Value string
}

// suite mirrors the parts of a go-ftw test file this needs. A test is named by the rule
// it belongs to and its index, the same way go-ftw names it, so failures from the two can
// be compared directly.
type suite struct {
	RuleID int `yaml:"rule_id"`
	Tests  []struct {
		TestID int `yaml:"test_id"`
		Stages []struct {
			Input struct {
				Method  string    `yaml:"method"`
				URI     string    `yaml:"uri"`
				Version string    `yaml:"version"`
				Headers yaml.Node `yaml:"headers"`
				Data    string    `yaml:"data"`

				// Features this replayer does not reproduce. A stage using either is
				// skipped and counted rather than sent wrongly.
				AutocompleteHeaders *bool  `yaml:"autocomplete_headers"`
				EncodedRequest      string `yaml:"encoded_request"`
			} `yaml:"input"`
			Output struct {
				Log struct {
					NoExpectIDs []int `yaml:"no_expect_ids"`
				} `yaml:"log"`
			} `yaml:"output"`
		} `yaml:"stages"`
	} `yaml:"tests"`
}

// Load reads every regression test under root and returns the stages that must not be
// blocked, along with how many were skipped as unreproducible.
func Load(root string) (requests []Request, skipped int, err error) {
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", path, readErr)
		}

		var parsed suite
		if yaml.Unmarshal(contents, &parsed) != nil {
			// The suite is third party; one unreadable file must not stop the run.
			return nil
		}
		for _, test := range parsed.Tests {
			for _, stage := range test.Stages {
				if len(stage.Output.Log.NoExpectIDs) == 0 {
					continue
				}
				if stage.Input.EncodedRequest != "" || stage.Input.AutocompleteHeaders != nil {
					skipped++

					continue
				}
				requests = append(requests, Request{
					ID:      len(requests) + 1,
					Forbid:  stage.Output.Log.NoExpectIDs,
					Title:   fmt.Sprintf("%d-%d", parsed.RuleID, test.TestID),
					Method:  orDefault(stage.Input.Method, "GET"),
					URI:     orDefault(stage.Input.URI, "/"),
					Version: orDefault(stage.Input.Version, "HTTP/1.1"),
					Headers: headers(stage.Input.Headers),
					Data:    stage.Input.Data,
				})
			}
		}

		return nil
	})

	return requests, skipped, err
}

func headers(node yaml.Node) []Header {
	var pairs []Header
	for i := 0; i+1 < len(node.Content); i += 2 {
		pairs = append(pairs, Header{Name: node.Content[i].Value, Value: node.Content[i+1].Value})
	}

	return pairs
}

// Bytes renders the request exactly as it goes on the wire.
//
// Host, Content-Length and Content-Type are added only when the test left them out. The
// suite relies on its runner doing this: 385 of the benign stages carry a body and only
// 163 declare a Content-Type, so without it CRS answers 920340 ("Request Containing
// Content but Missing Content-Type") to requests the suite considers clean.
func (r Request) Bytes(host string) []byte {
	var out strings.Builder
	fmt.Fprintf(&out, "%s %s %s\r\n", r.Method, r.URI, r.Version)

	var hasHost, hasLength, hasType bool
	for _, header := range r.Headers {
		switch strings.ToLower(header.Name) {
		case "host":
			hasHost = true
		case "content-length":
			hasLength = true
		case "content-type":
			hasType = true
		}
		fmt.Fprintf(&out, "%s: %s\r\n", header.Name, header.Value)
	}
	if !hasHost {
		fmt.Fprintf(&out, "Host: %s\r\n", host)
	}
	if r.Data != "" && !hasLength {
		fmt.Fprintf(&out, "Content-Length: %d\r\n", len(r.Data))
	}
	if r.Data != "" && !hasType {
		// The form encoding, so ModSecurity parses the body into ARGS, which is what the
		// rules these stages guard against actually inspect.
		out.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	}
	fmt.Fprintf(&out, "%s: %d\r\n", MarkerHeader, r.ID)
	out.WriteString("\r\n")
	out.WriteString(r.Data)

	return []byte(out.String())
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}
