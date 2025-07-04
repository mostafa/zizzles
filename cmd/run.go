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
	"github.com/mostafa/zizzles/yaml_patch"
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
func printOverallSummary(allFindings map[types.Category][]*types.Finding, fileCount int) {
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

// applyFixes applies all available fixes to the files
func applyFixes(allFindings map[types.Category][]*types.Finding, files []string) {
	// Group fixes by file - we need to track which file each finding came from
	// We'll modify the approach to collect this during the scan phase
	fileFixMap := make(map[string][]*types.Finding)

	// Since we can't easily map findings back to files after the fact,
	// let's iterate through the files again and re-run the executor
	// to get file-specific findings that we can then apply fixes to
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			continue
		}

		content, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}

		// Re-run the executor for this specific file
		executor := audit_rules.CreateRuleExecutor()
		findings, err := executor.ExecuteAll(absPath, content)
		if err != nil {
			continue
		}

		// Collect findings with fixes for this file
		var fileFindings []*types.Finding
		for _, categoryFindings := range findings {
			for _, finding := range categoryFindings {
				if finding.HasFixes() {
					fileFindings = append(fileFindings, finding)
				}
			}
		}

		if len(fileFindings) > 0 {
			fileFixMap[file] = fileFindings
		}
	}

	if len(fileFixMap) == 0 {
		fmt.Println("📝 No fixable issues found.")
		return
	}

	totalApplied := 0
	totalFailed := 0
	fixedFiles := make([]string, 0)

	for file, findings := range fileFixMap {
		fmt.Printf("\n📄 Processing %s...\n", file)

		// Read the original file content
		originalContent, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("❌ Failed to read %s: %v\n", file, err)
			totalFailed += len(findings)
			continue
		}

		currentContent := string(originalContent)
		appliedCount := 0
		failedCount := 0

		// Deduplicate fixes to avoid applying the same fix multiple times
		// Group by step path and expression to prevent conflicts
		stepFixes := make(map[string]map[string]*types.Fix) // stepPath -> expression -> fix
		fixSources := make(map[string]string)               // Track which finding each fix came from

		for _, finding := range findings {
			if !finding.HasFixes() {
				continue
			}

			for _, fix := range finding.Fixes {
				// Extract step path and expression from patches
				var stepPath, expression string
				for _, patch := range fix.Patches {
					if strings.Contains(patch.Path, ".run") || strings.Contains(patch.Path, ".shell") ||
						strings.Contains(patch.Path, ".working-directory") || strings.Contains(patch.Path, ".if") ||
						strings.Contains(patch.Path, ".with.") {
						parts := strings.Split(patch.Path, ".")
						if len(parts) > 1 {
							stepPath = strings.Join(parts[:len(parts)-1], ".")
						}

						// For 'with' context, we need to remove the ".with" part to get the actual step path
						if strings.Contains(patch.Path, ".with.") {
							withIndex := strings.LastIndex(stepPath, ".with")
							if withIndex != -1 {
								stepPath = stepPath[:withIndex]
							}
						}

						// Extract expression from RewriteFragmentOp
						switch op := patch.Operation.(type) {
						case yaml_patch.RewriteFragmentOp:
							expression = op.From
						}
						break
					}
				}

				if stepPath == "" || expression == "" {
					continue
				}

				// Group fixes by step and expression
				if stepFixes[stepPath] == nil {
					stepFixes[stepPath] = make(map[string]*types.Fix)
				}

				// Only keep the first fix for each expression per step
				if _, exists := stepFixes[stepPath][expression]; !exists {
					stepFixes[stepPath][expression] = &fix
					fixKey := fmt.Sprintf("%s|%s", stepPath, expression)
					fixSources[fixKey] = string(finding.Rule.Category)
				}
			}
		}

		// Apply unique fixes
		for stepPath, expressionFixes := range stepFixes {
			for expression, fix := range expressionFixes {
				fixKey := fmt.Sprintf("%s|%s", stepPath, expression)
				newContent, err := fix.ApplyToContent(currentContent)
				if err != nil {
					fmt.Printf("  ❌ Failed to apply fix for %s: %v\n", fixSources[fixKey], err)
					failedCount++
					continue
				}

				if newContent != currentContent {
					fmt.Printf("  ✅ Applied: %s (confidence: %s)\n", fix.Title, fix.Confidence)
					currentContent = newContent
					appliedCount++
				} else {
					fmt.Printf("  ⚠️  No changes needed for: %s\n", fix.Title)
				}
			}
		}

		// Write the modified content back to the file if there were changes
		if appliedCount > 0 {
			err := os.WriteFile(file, []byte(currentContent), 0644)
			if err != nil {
				fmt.Printf("❌ Failed to write %s: %v\n", file, err)
				totalFailed += appliedCount
			} else {
				fmt.Printf("💾 Saved %s with %d fix(es) applied\n", file, appliedCount)
				fixedFiles = append(fixedFiles, file)
				totalApplied += appliedCount
			}
		}

		if failedCount > 0 {
			totalFailed += failedCount
		}
	}

	// Print summary
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("🔧 FIX SUMMARY\n")
	fmt.Printf("Files processed: %d\n", len(fileFixMap))
	fmt.Printf("Fixes applied: %d\n", totalApplied)

	if totalFailed > 0 {
		fmt.Printf("Fixes failed: %d\n", totalFailed)
	}

	if len(fixedFiles) > 0 {
		fmt.Println("\nFixed files:")
		for _, file := range fixedFiles {
			fmt.Printf("  ✅ %s\n", file)
		}
		fmt.Println("\n💡 Tip: Run the audit again to verify all issues have been resolved.")
	}

	if totalApplied == 0 && totalFailed == 0 {
		fmt.Println("📝 No fixes were applied. All issues may already be resolved or no automatic fixes are available.")
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
		fmt.Println("🔥 Zizzles is scanning your action metadata for security vulnerabilities...")
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
	printOverallSummary(allFindings, processedFiles)

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
			fmt.Println("\n🔧 Applying available fixes...")
			applyFixes(allFindings, files)
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
		fmt.Println("🎉 No security findings found. Your action metadata is looking good!")
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
	runCmd.Flags().BoolVar(&fix, "fix", false, "Automatically fix issues where possible")
	runCmd.Flags().StringVarP(&severityLevel, "severity", "s", "info", "Filter findings by minimum severity level (info, low, medium, high, critical)")
	runCmd.Flags().StringVarP(&exportPath, "export", "e", "", "Export findings to SARIF 2.2 format (specify output file path)")
}
