// Package main provides a tool to detect affected Bazel targets.
//
// Usage:
//
//	affected [options] [base_ref] [head_ref]
//
// Options:
//
//	-type string   Filter targets by type (build, test, all). Default: all
//	-json          Output as JSON
//
// Examples:
//
//	affected main HEAD              # Compare HEAD with main
//	affected -type=test main HEAD   # Only show affected test targets
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Output struct {
	ChangedFiles    []string `json:"changed_files"`
	AffectedTargets []string `json:"affected_targets"`
	TestTargets     []string `json:"test_targets"`
	BuildTargets    []string `json:"build_targets"`
}

func main() {
	targetType := flag.String("type", "all", "Target type: build, test, all")
	jsonOutput := flag.Bool("json", false, "Output as JSON")
	flag.Parse()

	baseRef := "origin/main"
	headRef := "HEAD"

	args := flag.Args()
	if len(args) >= 1 {
		baseRef = args[0]
	}
	if len(args) >= 2 {
		headRef = args[1]
	}

	// Get changed files
	changedFiles, err := getChangedFiles(baseRef, headRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting changed files: %v\n", err)
		os.Exit(1)
	}

	if len(changedFiles) == 0 {
		fmt.Fprintln(os.Stderr, "No changed files detected")
		os.Exit(0)
	}

	// Convert to Bazel patterns
	patterns := filesToPatterns(changedFiles)
	if len(patterns) == 0 {
		fmt.Fprintln(os.Stderr, "No Bazel patterns found")
		os.Exit(0)
	}

	// Query affected targets
	allTargets := queryTargets(patterns)
	testTargets := filterTestTargets(allTargets)
	buildTargets := filterBuildTargets(allTargets)

	if *jsonOutput {
		output := Output{
			ChangedFiles:    changedFiles,
			AffectedTargets: allTargets,
			TestTargets:     testTargets,
			BuildTargets:    buildTargets,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(output)
		return
	}

	// Print based on type
	var targets []string
	switch *targetType {
	case "test":
		targets = testTargets
	case "build":
		targets = buildTargets
	default:
		targets = allTargets
	}

	for _, t := range targets {
		fmt.Println(t)
	}
}

func getChangedFiles(baseRef, headRef string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", baseRef, headRef)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var files []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		file := strings.TrimSpace(scanner.Text())
		if file != "" {
			files = append(files, file)
		}
	}
	return files, scanner.Err()
}

func filesToPatterns(files []string) []string {
	patternSet := make(map[string]bool)

	for _, file := range files {
		// Skip non-existent files (deleted)
		if _, err := os.Stat(file); os.IsNotExist(err) {
			continue
		}

		dir := filepath.Dir(file)
		if dir == "." {
			patternSet["//:all"] = true
		} else {
			// Find the nearest BUILD file
			pattern := findBuildPattern(dir)
			if pattern != "" {
				patternSet[pattern] = true
			}
		}
	}

	patterns := make([]string, 0, len(patternSet))
	for p := range patternSet {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	return patterns
}

func findBuildPattern(dir string) string {
	// Walk up the directory tree to find a BUILD file
	current := dir
	for current != "" && current != "." {
		if hasBuildFile(current) {
			return "//" + current + "/..."
		}
		current = filepath.Dir(current)
		if current == "." {
			break
		}
	}
	return "//" + dir + "/..."
}

func hasBuildFile(dir string) bool {
	for _, name := range []string{"BUILD", "BUILD.bazel"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

func queryTargets(patterns []string) []string {
	targetSet := make(map[string]bool)

	for _, pattern := range patterns {
		cmd := exec.Command("bazel", "query", pattern)
		cmd.Stderr = os.Stderr
		out, err := cmd.Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: bazel query %s failed: %v\n", pattern, err)
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			target := strings.TrimSpace(scanner.Text())
			if target != "" {
				targetSet[target] = true
			}
		}
	}

	targets := make([]string, 0, len(targetSet))
	for t := range targetSet {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	return targets
}

func filterTestTargets(targets []string) []string {
	var tests []string
	for _, t := range targets {
		if strings.HasSuffix(t, "_test") || strings.Contains(t, "_test:") {
			tests = append(tests, t)
		}
	}
	return tests
}

func filterBuildTargets(targets []string) []string {
	var builds []string
	for _, t := range targets {
		if !strings.HasSuffix(t, "_test") && !strings.Contains(t, "_test:") {
			builds = append(builds, t)
		}
	}
	return builds
}
