package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/goccy/go-yaml"
	"github.com/mostafa/zizzles/audit_rules"
	"github.com/mostafa/zizzles/schema"
	"github.com/mostafa/zizzles/types"
	"github.com/spf13/cobra"
)

var (
	quiet bool
	fix   bool
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

func runAudit(cmd *cobra.Command, args []string) {
	files := args

	if !quiet {
		fmt.Println(types.Logo)
	}

	executor := audit_rules.CreateRuleExecutor()
	allFindings := make(map[types.Category][]*types.Finding)
	for _, file := range files {
		absPath, err := filepath.Abs(file)
		if err != nil {
			log.Printf("Failed to get absolute path for %s: %v", file, err)
			continue
		}

		content, err := os.ReadFile(absPath)
		if err != nil {
			log.Printf("Failed to read file %s: %v", absPath, err)
			continue
		}

		var metadata schema.GithubActionJson
		if err := yaml.Unmarshal(content, &metadata); err != nil {
			log.Printf("Failed to unmarshal metadata: %v", err)
			os.Exit(1)
		}

		validStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true)
		fmt.Printf("File is valid: %s\n", validStyle.Render(file))

		findings, err := executor.ExecuteAll(absPath, content)
		if err != nil {
			log.Printf("Failed to execute rules on %s: %v", absPath, err)
			continue
		}

		if len(findings) > 0 {
			printer := types.NewPrinter(content, file, quiet)
			printer.PrintFindings(findings)

			// Add findings to the global map
			for cat, fs := range findings {
				allFindings[cat] = append(allFindings[cat], fs...)
			}
		}
	}

	if len(allFindings) > 0 {
		reg := types.NewRegistry()
		reg.AddAll(allFindings)

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
}
