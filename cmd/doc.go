package cmd

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

//go:embed docs/expression_injection.md
var expressionInjectionDocs string

// Available doc topics
var availableTopics = map[string]string{
	"expression-injection": expressionInjectionDocs,
}

var docCmd = &cobra.Command{
	Use:   "doc [topic]",
	Short: "Display detailed documentation for specific detection rules",
	Long: `Display detailed documentation for specific detection rules.
Available topics:
  expression-injection    - Learn about expression injection vulnerabilities

Example:
  zizzles doc expression-injection

Navigation:
  ↑/k       - scroll up
  ↓/j       - scroll down
  b/pgup    - page up
  f/pgdn    - page down
  g/home    - go to top
  G/end     - go to bottom
  q/esc     - quit`,
	Args: cobra.ExactArgs(1),
	Run:  showDoc,
}

// docModel represents the Bubble Tea model for the paginated doc viewer
type docModel struct {
	viewport    viewport.Model
	content     string
	ready       bool
	headerStyle lipgloss.Style
	footerStyle lipgloss.Style
}

type errMsg struct {
	err error
}

func (e errMsg) Error() string { return e.err.Error() }

func (m docModel) Init() tea.Cmd {
	return nil
}

func (m docModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := lipgloss.Height(m.footerView())
		verticalMarginHeight := headerHeight + footerHeight

		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-verticalMarginHeight)
			m.viewport.SetContent(m.content)
			m.viewport.MouseWheelEnabled = true
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - verticalMarginHeight
		}
	}

	// Always let the viewport handle the message for its built-in navigation
	m.viewport, cmd = m.viewport.Update(msg)

	return m, cmd
}

func (m docModel) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}
	return fmt.Sprintf("%s\n%s\n%s", m.headerView(), m.viewport.View(), m.footerView())
}

func (m docModel) headerView() string {
	title := "Zizzles Documentation"
	line := strings.Repeat("─", max(0, m.viewport.Width-lipgloss.Width(title)))
	return m.headerStyle.Render(fmt.Sprintf("%s %s", title, line))
}

func (m docModel) footerView() string {
	info := fmt.Sprintf("%3.f%%", m.viewport.ScrollPercent()*100)
	help := "↑/k up • ↓/j down • b/pgup page up • f/pgdn page down • g/home top • G/end bottom • q/esc quit"

	// Calculate available space for the line
	usedWidth := lipgloss.Width(info) + lipgloss.Width(help)
	lineWidth := max(0, m.viewport.Width-usedWidth-2) // -2 for spacing
	line := strings.Repeat("─", lineWidth)

	if lineWidth > 0 {
		return m.footerStyle.Render(fmt.Sprintf("%s %s %s", help, line, info))
	} else {
		// If not enough space, just show the percentage
		return m.footerStyle.Render(info)
	}
}

func showDoc(cmd *cobra.Command, args []string) {
	topic := strings.ToLower(args[0])

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
		fmt.Println(content)
		return
	}

	rendered, err := renderer.Render(content)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to render markdown: %v\n", err)
		fmt.Println(content)
		return
	}

	// Create the paginated doc viewer
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Bold(true)

	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	m := docModel{
		content:     rendered,
		headerStyle: headerStyle,
		footerStyle: footerStyle,
	}

	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running doc viewer: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(docCmd)
}
