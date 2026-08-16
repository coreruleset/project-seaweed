package main

import (
	"os"

	"github.com/coreruleset/project-seaweed/cmd"
)

func main() {
	// Cobra has already printed the error; exit non-zero so CI notices.
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
