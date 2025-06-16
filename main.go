package main

import (
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
	"github.com/mostafa/zizzles/audit_rules"
	"github.com/mostafa/zizzles/schema"
	"github.com/mostafa/zizzles/types"
)

func main() {
	// Parse command line arguments
	// TODO: update the flags based on the features.
	summary := flag.Bool("summary", true, "Show summary of findings")
	quiet := flag.Bool("quiet", false, "Quiet mode")
	flag.Parse()

	// Get remaining arguments as files
	files := flag.Args()
	if len(files) == 0 {
		fmt.Println("Please provide one or more GitHub Action YAML files")
		os.Exit(1)
	}

	if !*quiet {
		fmt.Println(types.Logo)
	}

	// Get all rules
	rules := audit_rules.GetAllRules()

	// Process each file
	allFindings := make(map[types.Category]*types.Finding)
	for _, file := range files {
		// Get absolute path
		absPath, err := filepath.Abs(file)
		if err != nil {
			log.Printf("Failed to get absolute path for %s: %v", file, err)
			continue
		}

		// Read the file content
		content, err := os.ReadFile(absPath)
		if err != nil {
			log.Printf("Failed to read file %s: %v", absPath, err)
			continue
		}

		// Unmarshal the metadata
		var metadata schema.GithubActionJson
		if err := yaml.Unmarshal(content, &metadata); err != nil {
			log.Printf("Failed to unmarshal metadata: %v", err)
			os.Exit(1)
		}

		fmt.Printf("File is valid: %s\n", file)

		// Find patterns in the file
		findings := make(map[types.Category]*types.Finding)
		for _, rule := range rules {
			patternFindings, err := types.FindPattern(absPath, &rule)
			if err != nil {
				log.Printf("Error finding pattern %s in %s: %v", rule.Pattern, absPath, err)
				continue
			}

			// Add findings to the map
			maps.Copy(findings, patternFindings)
		}

		// Add findings to the global map
		maps.Copy(allFindings, findings)

		// Print findings for this file if any found
		if len(findings) > 0 {
			printer := types.NewPrinter(content, file, *quiet)
			printer.PrintFindings(findings)
		}
	}

	// Create a registry and print summary if requested
	if len(allFindings) > 0 {
		reg := types.NewRegistry()
		reg.AddAll(allFindings)
		if *summary {
			reg.PrintSummary()
		}
		os.Exit(1)
	}

	if !*quiet {
		fmt.Println("No security findings found.")
	}
}
