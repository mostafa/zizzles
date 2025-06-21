package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/mostafa/zizzles/docs"
	"github.com/spf13/cobra"
)

// Available doc topics
var availableTopics = map[string]string{
	"expression-injection": docs.ExpressionInjectionDocs,
	"output-handling":      docs.OutputHandlingDocs,
	"runs-version":         docs.RunsVersionDocs,
}

// docItem represents a documentation topic in the list
type docItem struct {
	title       string
	description string
	key         string
}

func (i docItem) FilterValue() string { return i.title }
func (i docItem) Title() string       { return i.title }
func (i docItem) Description() string { return i.description }

// Navigation commands
type showMenuMsg struct{}
type showDocMsg struct{ topic string }

var docCmd = &cobra.Command{
	Use:   "doc [topic]",
	Short: "Display detailed documentation for specific detection rules",
	Long: `Display detailed documentation for specific detection rules.
Available topics:
  expression-injection    - Learn about expression injection vulnerabilities
  output-handling         - Learn about output handling vulnerabilities
  runs-version            - Learn about runs version vulnerabilities

Example:
  zizzles doc expression-injection
  zizzles doc              - Show interactive menu

Navigation:
  ↑/k       - scroll up
  ↓/j       - scroll down
  b/pgup    - page up
  f/pgdn    - page down
  g/home    - go to top
  G/end     - go to bottom
  backspace - go back to menu (when viewing docs)
  q/esc     - quit`,
	Args: cobra.MaximumNArgs(1),
	Run:  showDoc,
}

// appModel represents the main application model that can switch between menu and doc viewer
type appModel struct {
	state      string // "menu" or "doc"
	menuModel  menuModel
	docModel   docModel
	currentDoc string
	windowSize tea.WindowSizeMsg
}

func (m appModel) Init() tea.Cmd {
	return nil
}

func (m appModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.windowSize = msg
		if m.state == "menu" {
			var cmd tea.Cmd
			model, cmd := m.menuModel.Update(msg)
			m.menuModel = model.(menuModel)
			return m, cmd
		} else {
			var cmd tea.Cmd
			model, cmd := m.docModel.Update(msg)
			m.docModel = model.(docModel)
			return m, cmd
		}

	case showMenuMsg:
		m.state = "menu"
		// Re-initialize menu model
		m.menuModel = createMenuModel()
		if m.windowSize.Width > 0 {
			model, _ := m.menuModel.Update(m.windowSize)
			m.menuModel = model.(menuModel)
		}
		return m, nil

	case showDocMsg:
		m.state = "doc"
		m.currentDoc = msg.topic
		var err error
		m.docModel, err = createDocModel(msg.topic)
		if err != nil {
			return m, tea.Quit
		}
		if m.windowSize.Width > 0 {
			model, _ := m.docModel.Update(m.windowSize)
			m.docModel = model.(docModel)
		}
		return m, nil

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	if m.state == "menu" {
		var cmd tea.Cmd
		model, cmd := m.menuModel.Update(msg)
		m.menuModel = model.(menuModel)

		// Check if user selected a topic
		if m.menuModel.choice != "" {
			return m, func() tea.Msg { return showDocMsg{topic: m.menuModel.choice} }
		}

		// Check if user quit
		if m.menuModel.quit {
			return m, tea.Quit
		}

		return m, cmd
	} else {
		var cmd tea.Cmd
		model, cmd := m.docModel.Update(msg)
		m.docModel = model.(docModel)

		// Check if user wants to go back
		if m.docModel.goBack {
			return m, func() tea.Msg { return showMenuMsg{} }
		}

		// Check if user quit
		if m.docModel.quit {
			return m, tea.Quit
		}

		return m, cmd
	}
}

func (m appModel) View() string {
	if m.state == "menu" {
		return m.menuModel.View()
	} else {
		return m.docModel.View()
	}
}

// menuModel represents the Bubble Tea model for the topic selection menu
type menuModel struct {
	list   list.Model
	choice string
	quit   bool
}

func (m menuModel) Init() tea.Cmd {
	return nil
}

func (m menuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		m.list.SetHeight(msg.Height - 2) // Leave some space for margins
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "esc":
			m.quit = true
			return m, nil

		case "enter":
			i, ok := m.list.SelectedItem().(docItem)
			if ok {
				m.choice = i.key
			}
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m menuModel) View() string {
	if m.quit {
		return ""
	}
	return "\n" + m.list.View()
}

// docModel represents the Bubble Tea model for the paginated doc viewer
type docModel struct {
	viewport    viewport.Model
	content     string
	ready       bool
	headerStyle lipgloss.Style
	footerStyle lipgloss.Style
	goBack      bool
	quit        bool
}

func (m docModel) Init() tea.Cmd {
	return nil
}

func (m docModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			m.quit = true
			return m, nil
		case "backspace":
			m.goBack = true
			return m, nil
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
	help := "↑/k up • ↓/j down • b/pgup page up • f/pgdn page down • g/home top • G/end bottom • backspace back • q/esc quit"

	// Calculate available space for the line
	usedWidth := lipgloss.Width(info) + lipgloss.Width(help)
	lineWidth := max(0, m.viewport.Width-usedWidth-2) // -2 for spacing
	line := strings.Repeat("─", lineWidth)

	if lineWidth > 0 {
		return m.footerStyle.Render(fmt.Sprintf("%s %s %s", help, line, info))
	} else {
		// If not enough space, show condensed help
		shortHelp := "↑/↓ scroll • backspace back • q quit"
		usedWidth = lipgloss.Width(info) + lipgloss.Width(shortHelp)
		lineWidth = max(0, m.viewport.Width-usedWidth-2)
		if lineWidth > 0 {
			line = strings.Repeat("─", lineWidth)
			return m.footerStyle.Render(fmt.Sprintf("%s %s %s", shortHelp, line, info))
		} else {
			return m.footerStyle.Render(info)
		}
	}
}

func createMenuModel() menuModel {
	items := []list.Item{
		docItem{
			title:       "Expression Injection",
			description: "Learn about expression injection vulnerabilities in GitHub Actions",
			key:         "expression-injection",
		},
		docItem{
			title:       "Output Handling",
			description: "Learn about output handling vulnerabilities in GitHub Actions",
			key:         "output-handling",
		},
		docItem{
			title:       "Runs Version",
			description: "Learn about runs version vulnerabilities in GitHub Actions",
			key:         "runs-version",
		},
	}

	const defaultWidth = 20
	const defaultHeight = 24 // Increased default height

	l := list.New(items, list.NewDefaultDelegate(), defaultWidth, defaultHeight)
	l.Title = "Zizzles Documentation"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.Styles.Title = lipgloss.NewStyle().MarginLeft(2).Bold(true)
	l.Styles.PaginationStyle = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	l.Styles.HelpStyle = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)

	return menuModel{list: l}
}

func createDocModel(topic string) (docModel, error) {
	content, exists := availableTopics[topic]
	if !exists {
		return docModel{}, fmt.Errorf("unknown documentation topic: %s", topic)
	}

	// Render markdown with glamour
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(120),
	)
	if err != nil {
		return docModel{}, fmt.Errorf("failed to create markdown renderer: %v", err)
	}

	rendered, err := renderer.Render(content)
	if err != nil {
		return docModel{}, fmt.Errorf("failed to render markdown: %v", err)
	}

	// Create the paginated doc viewer
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Bold(true)

	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	return docModel{
		content:     rendered,
		headerStyle: headerStyle,
		footerStyle: footerStyle,
	}, nil
}

func showDoc(cmd *cobra.Command, args []string) {
	var initialState string
	var initialTopic string

	if len(args) == 0 {
		// Start with menu
		initialState = "menu"
	} else {
		// Start with specific doc
		initialState = "doc"
		initialTopic = strings.ToLower(args[0])

		// Validate topic exists
		if _, exists := availableTopics[initialTopic]; !exists {
			fmt.Fprintf(os.Stderr, "Error: unknown documentation topic: %s\n", initialTopic)
			fmt.Println("\nAvailable topics:")
			for topicName := range availableTopics {
				fmt.Printf("  %s\n", topicName)
			}
			os.Exit(1)
		}
	}

	// Create the main app model
	app := appModel{
		state: initialState,
	}

	if initialState == "menu" {
		app.menuModel = createMenuModel()
	} else {
		var err error
		app.docModel, err = createDocModel(initialTopic)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		app.currentDoc = initialTopic
	}

	p := tea.NewProgram(app, tea.WithAltScreen(), tea.WithMouseCellMotion())

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running doc viewer: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(docCmd)
}
