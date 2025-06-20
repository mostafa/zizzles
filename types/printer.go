package types

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/charmbracelet/lipgloss"
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
	quiet   bool
}

// NewPrinter creates a new Printer
func NewPrinter(content []byte, file string, quiet bool) *Printer {
	return &Printer{
		content: content,
		file:    file,
		quiet:   quiet,
	}
}

// PrintFindings prints all findings with context
func (p *Printer) PrintFindings(findings map[Category][]*Finding) {
	if p.quiet {
		return
	}

	// Group findings by severity
	severityGroups := make(map[Severity][]*Finding)
	for _, findingList := range findings {
		for _, finding := range findingList {
			severityGroups[finding.Severity] = append(severityGroups[finding.Severity], finding)
		}
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
	severityStyle := severityStyles[finding.Severity]
	var header strings.Builder
	header.WriteString(severityStyle.Render(string(finding.Severity)))
	header.WriteString(severityStyle.Render("[" + string(finding.Rule.Category) + "]"))
	header.WriteString(": ")
	header.WriteString(messageStyle.Render(finding.Rule.Message))
	fmt.Println(header.String())

	var location strings.Builder
	location.WriteString("  --> ")
	location.WriteString(p.file)
	location.WriteString(fmt.Sprintf(":%d:%d", finding.Line, finding.ActualColumn))
	fmt.Println(location.String())

	fileLines := strings.Split(string(p.content), "\n")
	start := finding.Line - 3
	start = max(0, start)
	end := finding.Line

	if end < len(fileLines) && (strings.Contains(fileLines[end-1], "run: |") || strings.Contains(fileLines[end-1], "run: >")) {
		end = min(end+5, len(fileLines))
	}
	end = min(end, len(fileLines))
	var context strings.Builder
	for i, line := range fileLines[start:end] {
		ln := start + i + 1

		if ln == finding.Line {
			if strings.Contains(line, "run: |") || strings.Contains(line, "run: >") {
				// Expression is on subsequent lines for multiline blocks
			} else {
				if strings.Contains(line, "${{") {
					exprRe := regexp.MustCompile(`\$\{\{[^}]+\}\}`)
					matches := exprRe.FindAllStringIndex(line, -1)
					for _, match := range matches {
						matchStart := match[0] + 1
						if matchStart <= finding.ActualColumn && finding.ActualColumn <= matchStart+len(line[match[0]:match[1]]) {
							before := line[:match[0]]
							after := line[match[1]:]
							matchedExpr := line[match[0]:match[1]]

							var lineBuilder strings.Builder
							lineBuilder.WriteString(before)
							lineBuilder.WriteString(severityStyle.Render(matchedExpr))
							lineBuilder.WriteString(after)
							line = lineBuilder.String()
							break
						}
					}
				}
			}
		} else if ln > finding.Line && finding.MatchedLength > 0 {
			if strings.Contains(line, "${{") {
				exprRe := regexp.MustCompile(`\$\{\{[^}]+\}\}`)
				matches := exprRe.FindAllStringIndex(line, -1)

				for _, match := range matches {
					matchStart := match[0] + 1
					if matchStart <= finding.ActualColumn && finding.ActualColumn <= matchStart+len(line[match[0]:match[1]]) {
						before := line[:match[0]]
						after := line[match[1]:]
						matchedExpr := line[match[0]:match[1]]

						var lineBuilder strings.Builder
						lineBuilder.WriteString(before)
						lineBuilder.WriteString(severityStyle.Render(matchedExpr))
						lineBuilder.WriteString(after)
						line = lineBuilder.String()
						break
					}
				}
			}
		}

		context.WriteString(lineNumberStyle.Render(""))
		context.WriteString(fmt.Sprintf("%4d", ln))
		context.WriteString(lineNumberStyle.Render(" |"))
		context.WriteString(" ")
		context.WriteString(line)
		context.WriteString("\n")
	}
	fmt.Print(context.String())
	fmt.Println()
}
