package finding

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
)

// NewFinding creates a new Finding from a rule and match information
func NewFinding(
	rule *types.Rule,
	yamlPath string,
	line,
	column int,
	value string,
	matchedColumn, matchedLineOffset int,
) *types.Finding {
	return &types.Finding{
		Rule:              rule,
		YamlPath:          yamlPath,
		Line:              line,
		Column:            column,
		Value:             value,
		MatchedColumn:     matchedColumn,
		MatchedLineOffset: matchedLineOffset,
		Severity:          rule.Severity,
	}
}

// FindPattern searches for a pattern in a YAML file and returns a map of findings
func FindPattern(yamlPath string, rule *types.Rule) (map[string]*types.Finding, error) {
	// Read the YAML file
	content, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse the YAML file
	file, err := parser.ParseBytes(content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Create a visitor to find the pattern
	visitor := &patternVisitor{
		rule: rule,
		path: yamlPath,
	}

	// Visit the AST
	for _, doc := range file.Docs {
		ast.Walk(visitor, doc)
	}

	return visitor.findings, nil
}

// patternVisitor implements ast.Visitor to find patterns in YAML
type patternVisitor struct {
	rule     *types.Rule
	path     string
	findings map[string]*types.Finding
}

// Visit implements ast.Visitor
func (v *patternVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	// Check if the node is a string node
	if str, ok := node.(*ast.StringNode); ok {
		// Compile the regex pattern
		re, err := regexp.Compile(v.rule.Pattern)
		if err != nil {
			return v
		}

		// Check if the string matches the pattern
		if re.MatchString(str.Value) {
			// Find the match location
			loc := re.FindStringIndex(str.Value)
			if loc != nil {
				// Get the actual line number and column
				line := str.GetToken().Position.Line
				column := str.GetToken().Position.Column

				// If this is a multi-line string, find the actual line containing the pattern
				if strings.Contains(str.Value, "\n") {
					lines := strings.Split(str.Value, "\n")
					for i, l := range lines {
						if re.MatchString(l) {
							line = str.GetToken().Position.Line + i
							loc = re.FindStringIndex(l)
							column = loc[0] + 1 // Add 1 because column is 1-based
							break
						}
					}
				}

				// Create a finding
				finding := types.NewFinding(
					v.rule,
					v.path,
					line,
					column,
					str.Value,
					loc[0],
					0,
				)

				// Add the finding to the map
				if v.findings == nil {
					v.findings = make(map[string]*types.Finding)
				}
				v.findings[finding.String()] = finding
			}
		}
	}

	return v
}

// SeverityColor returns the ANSI color code for the finding's severity
func SeverityColor(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical:
		return "\033[1;31m"
	case types.SeverityHigh:
		return "\033[31m"
	case types.SeverityMedium:
		return "\033[33m"
	case types.SeverityLow:
		return "\033[32m"
	case types.SeverityInfo:
		return "\033[32m"
	default:
		return "\033[0m"
	}
}
