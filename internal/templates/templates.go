// Package templates reads the subset of Nuclei templates that the mock backend and the
// report need to know about.
package templates

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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
