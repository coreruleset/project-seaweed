package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// mockMarker is served by the mock backend so the WAF healthcheck can prove that a
// request reached the backend and came back, rather than only that Apache is listening.
const mockMarker = "seaweed-mock-ok"

// nucleiTemplate is the subset of a Nuclei template needed to find flow gates.
//
// Templates that declare `flow` only send their payload steps when an earlier step's
// `internal: true` matcher hits, so those matcher words are the fingerprints the mock
// backend has to serve. See docs/adr/0001-generate-mock-backend-fingerprints.md.
type nucleiTemplate struct {
	Flow string `yaml:"flow"`
	HTTP []struct {
		Matchers []struct {
			Type     string   `yaml:"type"`
			Part     string   `yaml:"part"`
			Internal bool     `yaml:"internal"`
			Words    []string `yaml:"words"`
			DSL      []string `yaml:"dsl"`
		} `yaml:"matchers"`
	} `yaml:"http"`
}

var (
	// A dsl gate that talks about the body wants the same thing a word matcher does,
	// written differently: contains(body, "..."), contains(tolower(body), "..."),
	// contains_all(body, "...", "..."). Two thirds of the gates the mock cannot satisfy
	// are this shape.
	dslBodyClause = regexp.MustCompile(`(?i)\bbody(?:_?\d+)?\b`)
	dslLiteral    = regexp.MustCompile(`'([^']*)'|"([^"]*)"`)
)

// bodyLiterals returns the strings a dsl expression expects to find in the body. An
// expression that also tests something else contributes its literals too: serving a
// string the gate did not strictly need only risks letting a payload through to the WAF,
// which is the point of the exercise.
func bodyLiterals(expression string) []string {
	if !dslBodyClause.MatchString(expression) {
		return nil
	}

	var found []string
	for _, match := range dslLiteral.FindAllStringSubmatch(expression, -1) {
		literal := match[1]
		if literal == "" {
			literal = match[2]
		}
		if literal != "" {
			found = append(found, literal)
		}
	}

	return found
}

func newGenMockCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-mock",
		Short: "Generate the mock backend page from Nuclei flow-gated templates",
		Long: "Collects every internal word matcher from templates that declare a `flow` gate " +
			"and writes them into a single HTML page. Serving that page for every path lets " +
			"flow-gated templates reach their payload step, so the WAF actually sees the attack.",
		RunE: runGenMock,
	}
	cmd.Flags().StringP("templates", "t", "nuclei-templates/http/cves", "path to the Nuclei templates to scan")
	cmd.Flags().StringP("out", "O", "mock/fingerprints.html", "path of the HTML page to write")

	return cmd
}

func runGenMock(cmd *cobra.Command, _ []string) error {
	templates, err := cmd.Flags().GetString("templates")
	if err != nil {
		return err
	}
	out, err := cmd.Flags().GetString("out")
	if err != nil {
		return err
	}

	words, err := collectGateWords(templates)
	if err != nil {
		return err
	}
	if len(words) == 0 {
		return fmt.Errorf("no flow gate words found under %q: is it a Nuclei templates directory?", templates)
	}

	if err := os.WriteFile(out, []byte(renderFingerprintPage(words)), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", out, err)
	}
	cmd.Printf("wrote %s with %d fingerprints from %s\n", out, len(words), templates)

	return nil
}

// collectGateWords returns the sorted, deduplicated set of words that flow-gated
// templates expect to find in a response body before they send their payload.
func collectGateWords(root string) ([]string, error) {
	unique := map[string]struct{}{}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		var template nucleiTemplate
		if err := yaml.Unmarshal(contents, &template); err != nil {
			// Templates are third party; a single unparseable one must not fail the run.
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)
			return nil
		}
		if template.Flow == "" {
			return nil
		}
		for _, request := range template.HTTP {
			for _, matcher := range request.Matchers {
				if !matcher.Internal {
					continue
				}
				for _, word := range matcher.Words {
					unique[word] = struct{}{}
				}
				for _, expression := range matcher.DSL {
					for _, literal := range bodyLiterals(expression) {
						unique[literal] = struct{}{}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	words := make([]string, 0, len(unique))
	for word := range unique {
		words = append(words, word)
	}
	sort.Strings(words)

	return words, nil
}

func renderFingerprintPage(words []string) string {
	var page strings.Builder
	page.WriteString("<!DOCTYPE html>\n<html>\n<head><title>seaweed mock backend</title></head>\n<body>\n")
	page.WriteString("<!-- Generated by `seaweed gen-mock`; do not edit by hand. -->\n")
	page.WriteString("<h1>It works!</h1>\n")
	page.WriteString("<p>" + mockMarker + "</p>\n")
	page.WriteString("<pre>\n")
	for _, word := range words {
		page.WriteString(word + "\n")
	}
	page.WriteString("</pre>\n</body>\n</html>\n")

	return page.String()
}
