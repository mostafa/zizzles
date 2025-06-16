package types

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const (
	logo = `⠀⠀⠀⠀⠀⠀⢱⣆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⣿⣷⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢸⣿⣿⣷⣧⠀⠀⠀
⠀⠀⠀⠀⡀⢠⣿⡟⣿⣿⣿⡇⠀⠀
⠀⠀⠀⠀⣳⣼⣿⡏⢸⣿⣿⣿⢀⠀
⠀⠀⠀⣰⣿⣿⡿⠁⢸⣿⣿⡟⣼⡆
⢰⢀⣾⣿⣿⠟⠀⠀⣾⢿⣿⣿⣿⣿
⢸⣿⣿⣿⡏⠀⠀⠀⠃⠸⣿⣿⣿⡿
⢳⣿⣿⣿⠀⠀⠀⠀⠀⠀⢹⣿⡿⡁
⠀⠹⣿⣿⡄⠀⠀⠀⠀⠀⢠⣿⡞⠁
⠀⠀⠈⠛⢿⣄⠀⠀⠀⣠⠞⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀`
)

var (
	// Styles for different parts of the output
	severityStyles = map[Severity]lipgloss.Style{
		SeverityCritical: lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Bold(true),
		SeverityHigh:     lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")),
		SeverityMedium:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")),
		SeverityLow:      lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")),
		SeverityInfo:     lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")),
	}

	lineNumberStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#0087d7"))
	suggestionStyle = lipgloss.NewStyle().Bold(true)
	messageStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
)

// Printer handles printing findings
type Printer struct {
	content []byte
	file    string
}

// NewPrinter creates a new Printer
func NewPrinter(content []byte, file string) *Printer {
	return &Printer{
		content: content,
		file:    file,
	}
}

// PrintFindings prints all findings with context
func (p *Printer) PrintFindings(findings map[Category]*Finding) {
	if len(findings) == 0 {
		fmt.Printf("\n%sNo untrusted code fetching patterns detected.%s\n", ColorGreen, ColorReset)
		return
	}

	fmt.Println(logo)

	// Group findings by severity
	severityGroups := make(map[Severity][]*Finding)
	for _, finding := range findings {
		severityGroups[finding.Severity] = append(severityGroups[finding.Severity], finding)
	}

	// Print findings by severity (critical first, then high, medium, low, informational)
	severities := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
	for _, severity := range severities {
		if findings, ok := severityGroups[severity]; ok {
			for _, finding := range findings {
				p.printFindingWithContext(finding)
			}
		}
	}
}

// printFindingWithContext prints a finding with its context
func (p *Printer) printFindingWithContext(finding *Finding) {
	// Get the severity style
	severityStyle := severityStyles[finding.Severity]

	// Build the finding header
	var header strings.Builder
	header.WriteString(severityStyle.Render(string(finding.Severity)))
	header.WriteString(severityStyle.Render("[" + string(finding.Rule.Category) + "]"))
	header.WriteString(": ")
	header.WriteString(messageStyle.Render(finding.Rule.Message))
	fmt.Println(header.String())

	// Build the location line
	var location strings.Builder
	location.WriteString("  --> ")
	location.WriteString(p.file)
	location.WriteString(fmt.Sprintf(":%d:%d", finding.Line, finding.Column))
	fmt.Println(location.String())

	fileLines := strings.Split(string(p.content), "\n")
	start := finding.Line - 3
	start = max(0, start)
	end := finding.Line
	end = min(end, len(fileLines))

	// Build context lines
	var context strings.Builder
	for i, line := range fileLines[start:end] {
		ln := start + i + 1
		// Truncate long lines with ellipsis
		if len(line) > 120 {
			line = line[:117] + "..."
		}

		// If this is the line with the finding, highlight the matched text
		if ln == finding.Line {
			// Calculate the start and end positions of the matched text
			startPos := finding.Column - 1
			endPos := startPos
			if finding.Rule != nil {
				pattern := finding.Rule.Pattern
				pattern = strings.ReplaceAll(pattern, `\b`, "")
				endPos = startPos + len(pattern)
			}
			if endPos == startPos {
				endPos = startPos + 1
			}

			// Get the indentation
			indent := len(line) - len(strings.TrimLeft(line, " "))
			// Adjust positions to account for indentation
			startPos = indent + (finding.Column - 1)
			endPos = startPos + (endPos - (finding.Column - 1))

			// Split the line into parts
			before := line[:startPos]
			matched := line[startPos:endPos]
			after := line[endPos:]

			// Build the line with the matched text in severity color
			var lineBuilder strings.Builder
			lineBuilder.WriteString(before)
			lineBuilder.WriteString(severityStyle.Render(matched))
			lineBuilder.WriteString(after)
			line = lineBuilder.String()
		}

		// Build the output line
		context.WriteString(lineNumberStyle.Render(""))
		context.WriteString(fmt.Sprintf("%4d", ln))
		context.WriteString(lineNumberStyle.Render(" |"))
		context.WriteString(" ")
		context.WriteString(line)
		context.WriteString("\n")
	}
	fmt.Print(context.String())

	// Print suggestion at the bottom if available
	if finding.Rule != nil && finding.Rule.Suggestion != "" {
		var suggestion strings.Builder
		suggestion.WriteString("\n")
		suggestion.WriteString(lineNumberStyle.Render("Suggestion: "))
		suggestion.WriteString(finding.Rule.Suggestion)
		fmt.Println(suggestionStyle.Render(suggestion.String()))
	}
	fmt.Println()
}
