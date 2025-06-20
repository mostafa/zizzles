package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/goccy/go-yaml"
	"github.com/mostafa/zizzles/audit_rules"
	"github.com/mostafa/zizzles/schema"
	"github.com/mostafa/zizzles/types"
	"github.com/spf13/cobra"
)

var (
	quiet         bool
	fix           bool
	severityLevel string
)

var runCmd = &cobra.Command{
	Use:   "run [files...]",
	Short: "Run security audits on GitHub Actions files",
	Long: `Run security audits on one or more GitHub Actions YAML files.
The command will scan the provided files for security vulnerabilities
and provide detailed reports with recommendations.`,
	Args: cobra.MinimumNArgs(1),
	Run:  runAudit,
}

// severityOrder defines the order of severities from lowest to highest
var severityOrder = map[types.Severity]int{
	types.SeverityInfo:     0,
	types.SeverityLow:      1,
	types.SeverityMedium:   2,
	types.SeverityHigh:     3,
	types.SeverityCritical: 4,
}

// parseSeverityLevel converts string to severity type
func parseSeverityLevel(level string) (types.Severity, error) {
	switch strings.ToLower(level) {
	case "info", "informational":
		return types.SeverityInfo, nil
	case "low":
		return types.SeverityLow, nil
	case "medium", "med":
		return types.SeverityMedium, nil
	case "high":
		return types.SeverityHigh, nil
	case "critical", "crit":
		return types.SeverityCritical, nil
	default:
		return "", fmt.Errorf("invalid severity level: %s (valid options: info, low, medium, high, critical)", level)
	}
}

// shouldShowFinding determines if a finding should be displayed based on severity filter
func shouldShowFinding(finding *types.Finding, minSeverity types.Severity) bool {
	if minSeverity == "" {
		return true // No filter, show all
	}

	findingSeverityLevel, exists := severityOrder[finding.Rule.Severity]
	if !exists {
		return true // Unknown severity, show by default
	}

	minSeverityLevel, exists := severityOrder[minSeverity]
	if !exists {
		return true // Invalid min severity, show all
	}

	return findingSeverityLevel >= minSeverityLevel
}

// filterFindingsBySeverity filters findings for display while preserving originals for counting
func filterFindingsBySeverity(findings map[types.Category][]*types.Finding, minSeverity types.Severity) map[types.Category][]*types.Finding {
	if minSeverity == "" {
		return findings // No filter
	}

	filtered := make(map[types.Category][]*types.Finding)
	for category, categoryFindings := range findings {
		var filteredCategoryFindings []*types.Finding
		for _, finding := range categoryFindings {
			if shouldShowFinding(finding, minSeverity) {
				filteredCategoryFindings = append(filteredCategoryFindings, finding)
			}
		}
		if len(filteredCategoryFindings) > 0 {
			filtered[category] = filteredCategoryFindings
		}
	}
	return filtered
}

func runAudit(cmd *cobra.Command, args []string) {
	files := args

	// Parse severity level if provided
	var minSeverity types.Severity
	var err error
	if severityLevel != "" {
		minSeverity, err = parseSeverityLevel(severityLevel)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	}

	if !quiet {
		fmt.Println("🔥 Zizzles is scanning your GitHub Actions metadata for security vulnerabilities...")
	}

	executor := audit_rules.CreateRuleExecutor()
	allFindings := make(map[types.Category][]*types.Finding)
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			cmd.Printf("Failed to get absolute path for %s: %v", file, err)
			continue
		}

		content, err := os.ReadFile(absPath)
		if err != nil {
			cmd.Printf("Failed to read file %s: %v", absPath, err)
			continue
		}

		var metadata schema.GithubActionJson
		if err := yaml.Unmarshal(content, &metadata); err != nil {
			cmd.Printf("Failed to unmarshal metadata: %v", err)
			os.Exit(1)
		}

		validStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
		fmt.Printf("File is valid: %s\n", validStyle.Render(file))

		findings, err := executor.ExecuteAll(absPath, content)
		if err != nil {
			cmd.Printf("Failed to execute rules on %s: %v", absPath, err)
			continue
		}

		if len(findings) > 0 {
			// Filter findings for display based on severity
			displayFindings := filterFindingsBySeverity(findings, minSeverity)

			// Only print if there are findings to display after filtering
			if len(displayFindings) > 0 {
				printer := types.NewPrinter(content, file, quiet)
				printer.PrintFindings(displayFindings)
			}

			// Add ALL findings (not filtered) to the global map for accurate counting
			for cat, fs := range findings {
				allFindings[cat] = append(allFindings[cat], fs...)
			}
		}
	}

	if len(allFindings) > 0 {
		reg := types.NewRegistry()
		reg.AddAll(allFindings)

		filteredCount := 0
		filteredFindings := filterFindingsBySeverity(allFindings, minSeverity)
		for _, findings := range filteredFindings {
			filteredCount += len(findings)
		}

		totalCount := 0
		for _, findings := range allFindings {
			totalCount += len(findings)
		}

		fmt.Printf("📊 Showing %d findings with severity %s and above (out of %d total findings)\n",
			filteredCount, strings.ToUpper(string(minSeverity)), totalCount)

		reg.PrintSummary()

		if fix {
			fmt.Println("\n🔧 Fix functionality is not yet implemented.")
		}

		os.Exit(1)
	}

	if !quiet {
		fmt.Println("No security findings found.")
	}
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode - suppress banner and success messages")
	runCmd.Flags().BoolVar(&fix, "fix", false, "Automatically fix issues where possible (not yet implemented)")
	runCmd.Flags().StringVarP(&severityLevel, "severity", "s", "info", "Filter findings by minimum severity level (info, low, medium, high, critical)")
}
