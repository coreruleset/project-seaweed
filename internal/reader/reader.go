package reader

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

var patterns = map[string]*regexp.Regexp{
	"response": regexp.MustCompile(`^HTTP/1\.1\s(\d{3})`),
	"cve":      regexp.MustCompile(`(CVE-\d{4}-\d{1,})`),
}

// ParseNucleiOutputDirectory will parse the output directory of nuclei
func ParseNucleiOutputDirectory(path string) ([]NucleiTraceOutput, error) {
	var results []NucleiTraceOutput
	var err error

	files, err := filepath.Glob(path + "/**/*.txt")

	if err != nil {
		return results, err
	}

	for _, fileName := range files {
		testOutput, err := parseNucleiTraceOutput(fileName)
		if err != nil {
			log.Println("Error parsing file:", fileName, err)
			continue
		}
		results = append(results, testOutput)
	}

	return results, nil
}

func parseNucleiTraceOutput(filename string) (NucleiTraceOutput, error) {
	// parse the content
	var pl NucleiTraceOutput
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return pl, err
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		line := fileScanner.Text()
		for name, pattern := range patterns {
			found := pattern.FindStringSubmatch(line)
			if len(found) > 0 {
				switch name {
				case "response":
					pl.TotalRequests++
					pl.StatusCode, _ = strconv.Atoi(found[1])
					if pl.StatusCode == 403 {
						pl.BlockedRequests++
					} else {
						pl.NotBlockedRequests++
					}
				case "cve":
					pl.CVENumber = found[1]
				}
			}
		}
	}
	return pl, nil
}
