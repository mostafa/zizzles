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

	// Extract the specific expression from the finding message
	specificExpression := p.extractExpressionFromMessage(finding.Rule.Message)

	fileLines := strings.Split(string(p.content), "\n")
	start := finding.Line - 3
	start = max(0, start)
	end := finding.Line

	// Extend context for multiline blocks
	if end < len(fileLines) && (strings.Contains(fileLines[end-1], "run: |") || strings.Contains(fileLines[end-1], "run: >")) {
		end = min(end+5, len(fileLines))
	}
	end = min(end, len(fileLines))

	var context strings.Builder
	for i, line := range fileLines[start:end] {
		ln := start + i + 1

		// Highlight only the specific expression in this line
		if strings.Contains(line, "${{") && specificExpression != "" {
			line = p.highlightSpecificExpression(line, specificExpression, severityStyle)
		}

		context.WriteString(lineNumberStyle.Render(""))
		context.WriteString(fmt.Sprintf("%4d", ln))
		context.WriteString(lineNumberStyle.Render(" |"))
		context.WriteString(" ")
		context.WriteString(line)
		context.WriteString("\n")
	}
	fmt.Print(context.String())

	// Print available fixes if any
	if finding.HasFixes() {
		p.printAvailableFixes(finding.Fixes)
	}

	fmt.Println()
}

// extractExpressionFromMessage extracts the specific expression from the finding message
func (p *Printer) extractExpressionFromMessage(message string) string {
	// Pattern to match "field: expression (capability:"
	re := regexp.MustCompile(`field: ([^(]+) \(capability:`)
	matches := re.FindStringSubmatch(message)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// highlightSpecificExpression highlights only the specific expression in the line
func (p *Printer) highlightSpecificExpression(line, targetExpression string, style lipgloss.Style) string {
	// Create regex pattern for the specific expression
	// We need to escape the expression and allow for whitespace variations
	escapedExpr := regexp.QuoteMeta(targetExpression)
	exprPattern := fmt.Sprintf(`\$\{\{\s*%s\s*\}\}`, escapedExpr)
	specificRe := regexp.MustCompile(exprPattern)

	// Find the specific expression match
	if loc := specificRe.FindStringIndex(line); loc != nil {
		before := line[:loc[0]]
		after := line[loc[1]:]
		matchedExpr := line[loc[0]:loc[1]]
		return before + style.Render(matchedExpr) + after
	}

	return line
}

// printAvailableFixes prints information about available fixes
func (p *Printer) printAvailableFixes(fixes []Fix) {
	if p.quiet {
		return
	}

	fixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF")).Bold(true)
	confidenceStyles := map[string]lipgloss.Style{
		"high":   lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")),
		"medium": lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")),
		"low":    lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")),
	}

	fmt.Println("  " + fixStyle.Render("Available fixes:"))
	for i, fix := range fixes {
		confidenceStyle := confidenceStyles[strings.ToLower(fix.Confidence)]
		if confidenceStyle.GetForeground() == nil {
			confidenceStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
		}

		fmt.Printf("    %d. %s (confidence: %s)\n",
			i+1,
			fix.Title,
			confidenceStyle.Render(fix.Confidence))

		if fix.Description != "" {
			fmt.Printf("       %s\n", fix.Description)
		}
	}
}
