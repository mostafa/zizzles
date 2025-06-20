package cmd

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/spf13/cobra"
)

//go:embed docs/expression_injection.md
var expressionInjectionDocs string

// Available doc topics
var availableTopics = map[string]string{
	"expression-injection": expressionInjectionDocs,
}

// docCmd represents the doc command for detection rules
var docCmd = &cobra.Command{
	Use:   "doc [topic]",
	Short: "Display detailed documentation for specific detection rules",
	Long: `Display detailed documentation for specific detection rules.
Available topics:
  expression-injection    - Learn about expression injection vulnerabilities

Example:
  zizzles doc expression-injection`,
	Args: cobra.ExactArgs(1),
	Run:  showDoc,
}

func showDoc(cmd *cobra.Command, args []string) {
	topic := strings.ToLower(args[0])

	// Check if topic exists
	content, exists := availableTopics[topic]
	if !exists {
		fmt.Fprintf(os.Stderr, "Unknown documentation topic: %s\n\n", topic)
		fmt.Println("Available topics:")
		for topicName := range availableTopics {
			fmt.Printf("  %s\n", topicName)
		}
		os.Exit(1)
	}

	// Render markdown with glamour
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(120),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create markdown renderer: %v\n", err)
		// Fall back to plain text
		fmt.Println(content)
		return
	}

	rendered, err := renderer.Render(content)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to render markdown: %v\n", err)
		// Fall back to plain text
		fmt.Println(content)
		return
	}

	fmt.Print(rendered)
}

func init() {
	rootCmd.AddCommand(docCmd)
}
