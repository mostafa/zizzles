package main

import (
	"flag"
	"fmt"
	"log"
	"maps"
	"os"
	"path/filepath"

	"github.com/mostafa/zizzles/audit_rules"
	"github.com/mostafa/zizzles/finding"
	"github.com/mostafa/zizzles/registry"
	"github.com/mostafa/zizzles/types"
)

func main() {
	// Parse command line arguments
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	summary := flag.Bool("summary", true, "Show summary of findings")
	flag.Parse()

	// Get remaining arguments as files
	files := flag.Args()
	if len(files) == 0 {
		fmt.Println("Please provide one or more GitHub Action YAML files")
		os.Exit(1)
	}

	// Get all rules
	rules := audit_rules.GetAllRules()

	// Process each file
	allFindings := make(map[string]*types.Finding)
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

		// Find patterns in the file
		findings := make(map[string]*types.Finding)
		for _, rule := range rules {
			patternFindings, err := finding.FindPattern(absPath, &rule)
			if err != nil {
				if *verbose {
					log.Printf("Error finding pattern %s in %s: %v", rule.Pattern, absPath, err)
				}
				continue
			}

			// Add findings to the map
			maps.Copy(findings, patternFindings)
		}

		// Add findings to the global map
		maps.Copy(allFindings, findings)

		// Print findings for this file if any found
		if len(findings) > 0 {
			printer := registry.NewPrinter(content, file)
			printer.PrintFindings(findings)
		}
	}

	// Create a registry and print summary if requested
	if len(allFindings) > 0 {
		reg := registry.New()
		reg.AddAll(allFindings)
		if *summary {
			reg.PrintSummary()
		}
		os.Exit(1)
	}

	fmt.Println("No security findings found.")
}
