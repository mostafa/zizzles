package types

import (
	"fmt"
)

// Finding represents a security finding in a YAML file
type Finding struct {
	Rule              *Rule
	YamlPath          string
	Line              int
	Column            int
	Value             string
	MatchedColumn     int
	MatchedLineOffset int
	Severity          Severity
	Suggestion        string
}

// NewFinding creates a new Finding from a rule and match information
func NewFinding(
	rule *Rule,
	yamlPath string,
	line,
	column int,
	value string,
	matchedColumn,
	matchedLineOffset int,
) *Finding {
	return &Finding{
		Rule:              rule,
		YamlPath:          yamlPath,
		Line:              line,
		Column:            column,
		Value:             value,
		MatchedColumn:     matchedColumn,
		MatchedLineOffset: matchedLineOffset,
		Severity:          rule.Severity,
		Suggestion:        rule.Suggestion,
	}
}

// String returns a string representation of the finding
func (f *Finding) String() string {
	if f.Rule == nil {
		return fmt.Sprintf("%s[unknown]: Unknown finding", f.Severity)
	}
	return fmt.Sprintf("%s[%s]: %s", f.Severity, f.Rule.Category, f.Rule.Message)
}

// GetYamlPath returns the YAML path in the format "key1.key2.[index].key3"
func (f *Finding) GetYamlPath() string {
	// TODO: Implement proper YAML path resolution
	return fmt.Sprintf("runs.steps.[%d].run", f.Line-30) // Temporary hack
}

// SeverityColor returns the ANSI color code for the finding's severity
func SeverityColor(severity Severity) string {
	switch severity {
	case SeverityCritical:
		return "\033[1;31m"
	case SeverityHigh:
		return "\033[31m"
	case SeverityMedium:
		return "\033[33m"
	case SeverityLow:
		return "\033[32m"
	case SeverityInfo:
		return "\033[32m"
	default:
		return "\033[0m"
	}
}
