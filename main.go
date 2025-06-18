package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/goccy/go-yaml"
	"github.com/mostafa/zizzles/audit_rules"
	"github.com/mostafa/zizzles/schema"
	"github.com/mostafa/zizzles/types"
)

func main() {
	// Parse command line arguments
	// TODO: update the flags based on the features.
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

	// Create rule executor with all registered rules
	executor := audit_rules.CreateRuleExecutor()

	// Process each file
	allFindings := make(map[types.Category][]*types.Finding)
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

		validStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
		fmt.Printf("File is valid: %s\n", validStyle.Render(file))

		// Execute all rules (AST and pattern-based) using the unified executor
		findings, err := executor.ExecuteAll(absPath, content)
		if err != nil {
			log.Printf("Failed to execute rules on %s: %v", absPath, err)
			continue
		}

		// Print findings for this file if any found
		if len(findings) > 0 {
			printer := types.NewPrinter(content, file, *quiet)
			printer.PrintFindings(findings)

			// Add findings to the global map
			for cat, fs := range findings {
				allFindings[cat] = append(allFindings[cat], fs...)
			}
		}
	}

	// Create a registry and print summary if requested
	if len(allFindings) > 0 {
		reg := types.NewRegistry()
		reg.AddAll(allFindings)

		reg.PrintSummary()
		os.Exit(1)
	}

	if !*quiet {
		fmt.Println("No security findings found.")
	}
}
