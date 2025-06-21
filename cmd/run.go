package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
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
	exportPath    string
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

	findingSeverityLevel, exists := severityOrder[finding.Severity]
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

// countFindingsBySeverity counts findings by severity level
func countFindingsBySeverity(findings map[types.Category][]*types.Finding) map[types.Severity]int {
	counts := map[types.Severity]int{
		types.SeverityCritical: 0,
		types.SeverityHigh:     0,
		types.SeverityMedium:   0,
		types.SeverityLow:      0,
		types.SeverityInfo:     0,
	}

	for _, categoryFindings := range findings {
		for _, finding := range categoryFindings {
			counts[finding.Severity]++
		}
	}

	return counts
}

// printFileSummary prints a summary of findings for a single file
func printFileSummary(filename string, findings map[types.Category][]*types.Finding, displayFindings map[types.Category][]*types.Finding, minSeverity types.Severity) {
	if len(findings) == 0 {
		fmt.Printf("📝 %s: No security issues found\n", filename)
		return
	}

	totalCount := 0
	for _, fs := range findings {
		totalCount += len(fs)
	}

	filteredCount := 0
	for _, fs := range displayFindings {
		filteredCount += len(fs)
	}

	counts := countFindingsBySeverity(findings)

	// Color coding for severity counts
	colorNum := func(num int, color string) string {
		if num == 0 {
			return fmt.Sprintf("\033[90m%d\033[0m", num) // Gray for zero
		}
		return fmt.Sprintf("%s%d\033[0m", color, num)
	}

	fmt.Printf("📝 %s: %d finding%s (%s info, %s low, %s medium, %s high, %s critical)",
		filename,
		totalCount,
		func() string {
			if totalCount == 1 {
				return ""
			}
			return "s"
		}(),
		colorNum(counts[types.SeverityInfo], "\033[32m"),       // Green
		colorNum(counts[types.SeverityLow], "\033[32m"),        // Green
		colorNum(counts[types.SeverityMedium], "\033[33m"),     // Yellow
		colorNum(counts[types.SeverityHigh], "\033[31m"),       // Red
		colorNum(counts[types.SeverityCritical], "\033[1;31m"), // Bold red
	)

	if minSeverity != "" && filteredCount != totalCount {
		fmt.Printf(" - showing %d", filteredCount)
	}
	fmt.Println()
}

// printOverallSummary prints an enhanced overall summary
func printOverallSummary(allFindings map[types.Category][]*types.Finding, minSeverity types.Severity, fileCount int) {
	totalCount := 0
	for _, fs := range allFindings {
		totalCount += len(fs)
	}

	counts := countFindingsBySeverity(allFindings)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("📊 OVERALL SUMMARY\n")
	fmt.Printf("Files scanned: %d\n", fileCount)
	fmt.Printf("Total findings: %d\n", totalCount)

	if totalCount > 0 {
		fmt.Println("\nFindings by severity:")

		severities := []struct {
			severity types.Severity
			name     string
			emoji    string
			color    string
		}{
			{types.SeverityCritical, "Critical", "🚨", "\033[1;31m"},
			{types.SeverityHigh, "High", "🔴", "\033[31m"},
			{types.SeverityMedium, "Medium", "🟡", "\033[33m"},
			{types.SeverityLow, "Low", "🟢", "\033[32m"},
			{types.SeverityInfo, "Info", "ℹ️", "\033[32m"},
		}

		for _, sev := range severities {
			count := counts[sev.severity]
			if count > 0 {
				fmt.Printf("  %s %s%s: %d finding%s\033[0m\n",
					sev.emoji,
					sev.color,
					sev.name,
					count,
					func() string {
						if count == 1 {
							return ""
						}
						return "s"
					}(),
				)
			}
		}

		fmt.Println("\nFindings by category:")
		for category, categoryFindings := range allFindings {
			if len(categoryFindings) > 0 {
				fmt.Printf("  📋 %s: %d finding%s\n",
					category,
					len(categoryFindings),
					func() string {
						if len(categoryFindings) == 1 {
							return ""
						}
						return "s"
					}(),
				)
			}
		}
	}
	fmt.Println(strings.Repeat("=", 60))
}

func runAudit(cmd *cobra.Command, args []string) {
	files := args

	// Parse severity level if provided
	var minSeverity types.Severity
	var err error
	if severityLevel != "" {
		minSeverity, err = parseSeverityLevel(severityLevel)
		if err != nil {
			log.Fatalf("❌ Error: %v", err)
		}
	}

	if !quiet {
		fmt.Println("🔥 Zizzles is scanning your GitHub Actions metadata for security vulnerabilities...")
	}

	executor := audit_rules.CreateRuleExecutor()
	allFindings := make(map[types.Category][]*types.Finding)
	processedFiles := 0

	origLen := len(files)

	// Deduplicate files
	files = slices.Compact(files)

	if origLen != len(files) {
		fmt.Printf("🧹 Deduplicated %d file(s)\n", origLen-len(files))
	}

	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			cmd.Printf("⚠️  Failed to get absolute path for %s: %v\n", file, err)
			continue
		}

		content, err := os.ReadFile(absPath)
		if err != nil {
			cmd.Printf("📁 Failed to read file %s: %v\n", absPath, err)
			continue
		}

		var metadata schema.GithubActionJson
		if err := yaml.Unmarshal(content, &metadata); err != nil {
			cmd.Printf("💥 Failed to unmarshal metadata: %v\n", err)
			os.Exit(1)
		}

		validStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
		fmt.Printf("✅ File is valid: %s\n", validStyle.Render(file))

		findings, err := executor.ExecuteAll(absPath, content)
		if err != nil {
			cmd.Printf("🔍 Failed to execute rules on %s: %v\n", absPath, err)
			continue
		}

		processedFiles++

		// Filter findings for display based on severity
		displayFindings := filterFindingsBySeverity(findings, minSeverity)

		// Print findings if there are any to display
		if len(displayFindings) > 0 {
			printer := types.NewPrinter(content, file, quiet)
			printer.PrintFindings(displayFindings)
		}

		// Print per-file summary
		printFileSummary(file, findings, displayFindings, minSeverity)

		// Add ALL findings (not filtered) to the global map for accurate counting
		for cat, fs := range findings {
			allFindings[cat] = append(allFindings[cat], fs...)
		}

		// Add spacing between files if not the last file and there are findings
		if len(findings) > 0 && file != files[len(files)-1] {
			fmt.Println()
		}
	}

	// Print overall summary
	printOverallSummary(allFindings, minSeverity, processedFiles)

	if len(allFindings) > 0 {
		filteredCount := 0
		filteredFindings := filterFindingsBySeverity(allFindings, minSeverity)
		for _, findings := range filteredFindings {
			filteredCount += len(findings)
		}

		totalCount := 0
		for _, findings := range allFindings {
			totalCount += len(findings)
		}

		// Show filter info with appropriate emoji based on severity level
		var severityEmoji string
		switch minSeverity {
		case types.SeverityCritical:
			severityEmoji = "🚨"
		case types.SeverityHigh:
			severityEmoji = "🔴"
		case types.SeverityMedium:
			severityEmoji = "🟡"
		case types.SeverityLow:
			severityEmoji = "🟢"
		case types.SeverityInfo:
			severityEmoji = "ℹ️"
		default:
			severityEmoji = "📊"
		}

		if severityLevel != "" {
			fmt.Printf("\n%s Showing %d findings with severity %s and above (out of %d total findings)\n",
				severityEmoji, filteredCount, strings.ToUpper(string(minSeverity)), totalCount)
		} else {
			fmt.Printf("\n📊 Found %d total findings\n", totalCount)
		}

		reg := types.NewRegistry()
		reg.AddAll(allFindings)
		reg.PrintSummary()

		if fix {
			fmt.Println("\n🔧 Fix functionality is not yet implemented.")
		}

		// Export to SARIF if requested
		if exportPath != "" {
			fmt.Printf("\n📄 Exporting findings to SARIF format: %s\n", exportPath)
			if err := types.ExportFindings(allFindings, exportPath); err != nil {
				fmt.Printf("❌ Failed to export SARIF: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("✅ Successfully exported %d findings to SARIF file\n", totalCount)
		}

		os.Exit(1)
	}

	if !quiet {
		fmt.Println("🎉 No security findings found. Your GitHub Actions metadata is looking good!")
	}

	// Export empty SARIF report if requested
	if exportPath != "" {
		fmt.Printf("\n📄 Exporting empty findings to SARIF format: %s\n", exportPath)
		if err := types.ExportFindings(allFindings, exportPath); err != nil {
			fmt.Printf("❌ Failed to export SARIF: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Successfully exported empty SARIF file")
	}
}

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode - suppress banner and success messages")
	runCmd.Flags().BoolVar(&fix, "fix", false, "Automatically fix issues where possible (not yet implemented)")
	runCmd.Flags().StringVarP(&severityLevel, "severity", "s", "info", "Filter findings by minimum severity level (info, low, medium, high, critical)")
	runCmd.Flags().StringVarP(&exportPath, "export", "e", "", "Export findings to SARIF 2.2 format (specify output file path)")
}
