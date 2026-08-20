// Package templates reads the subset of Nuclei templates that the mock backend and the
// report need to know about.
package templates

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Template is the part of a Nuclei template this project cares about.
//
// Templates that declare `flow` only send their payload steps when an earlier step's
// `internal: true` matcher hits. Those matchers say what the mock has to serve, and their
// presence says whether a template that sent nothing was gated or simply done.
type Template struct {
	ID   string `yaml:"id"`
	Flow string `yaml:"flow"`
	Info struct {
		Classification struct {
			CWE stringList `yaml:"cwe-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
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

// stringList is a field the corpus writes either way: `cwe-id: CWE-89` on most templates
// and `cwe-id: [CWE-121, CWE-787]` where more than one applies.
type stringList []string

func (l *stringList) UnmarshalYAML(node *yaml.Node) error {
	var many []string
	if err := node.Decode(&many); err != nil {
		var one string
		if err := node.Decode(&one); err != nil {
			return fmt.Errorf("cwe-id is neither a string nor a list: %w", err)
		}
		many = []string{one}
	}

	// Where a template names more than one CWE it writes them as a single comma-separated
	// scalar -- `cwe-id: CWE-121,CWE-787` -- rather than as a YAML list.
	var split []string
	for _, entry := range many {
		for _, part := range strings.Split(entry, ",") {
			if part = strings.TrimSpace(part); part != "" {
				split = append(split, part)
			}
		}
	}
	*l = split

	return nil
}

// CWEs returns the CWE ids each template declares, keyed by CVE id. Templates without a
// classification are absent rather than empty, so a caller can tell "no CWE recorded" from
// "recorded as something else".
func CWEs(root string) (map[string][]string, error) {
	cwes := map[string][]string{}
	err := Each(root, func(template Template) {
		if template.ID == "" || len(template.Info.Classification.CWE) == 0 {
			return
		}
		cwes[template.ID] = template.Info.Classification.CWE
	})
	if err != nil {
		return nil, err
	}

	return cwes, nil
}

// Each parses every template under root and hands it to visit.
func Each(root string, visit func(Template)) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
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
		var template Template
		if err := yaml.Unmarshal(contents, &template); err != nil {
			// Templates are third party; a single unparseable one must not fail the run.
			fmt.Fprintf(os.Stderr, "skipping %s: %v\n", path, err)

			return nil
		}
		visit(template)

		return nil
	})
}

// Gated returns the ids of templates whose payload step is behind a flow gate. A template
// without one sends everything it has, so a trace holding only a bare `GET /` means that
// was the whole attack, not that the template stopped early.
func Gated(root string) (map[string]bool, error) {
	gated := map[string]bool{}
	err := Each(root, func(template Template) {
		if template.Flow != "" && template.ID != "" {
			gated[template.ID] = true
		}
	})
	if err != nil {
		return nil, err
	}

	return gated, nil
}
