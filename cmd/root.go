package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "zizzles",
	Short: "A security scanner for GitHub Actions",
	Long: `Zizzles is a comprehensive security scanner for GitHub Actions YAML files.
It detects various security vulnerabilities and provides detailed reports
with recommendations for fixing identified issues.`,
}

// Execute runs the root command and exits with an error code if there's an error
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Initialize root command configuration
}
