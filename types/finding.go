package types

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/yaml_patch"
)

// Fix represents a single fix for a security finding
type Fix struct {
	Title       string             // Human-readable title for the fix
	Description string             // Detailed description of what the fix does
	Patches     []yaml_patch.Patch // The YAML patches to apply
}

// Finding represents a security finding in a YAML file
type Finding struct {
	Rule              *Rule
	YamlPath          string
	Line              int
	Column            int
	Value             string
	MatchedColumn     int
	MatchedLineOffset int
	MatchedLength     int
	Severity          Severity
	Indentation       int   // Number of spaces/tabs for indentation
	ActualColumn      int   // Column position including indentation
	Fixes             []Fix // Available fixes for this finding
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
	matchedLength int,
) *Finding {
	return &Finding{
		Rule:              rule,
		YamlPath:          yamlPath,
		Line:              line,
		Column:            column,
		Value:             value,
		MatchedColumn:     matchedColumn,
		MatchedLineOffset: matchedLineOffset,
		MatchedLength:     matchedLength,
		Severity:          rule.Severity,
		Indentation:       0,       // Will be calculated if needed
		ActualColumn:      column,  // Default to column, will be updated if needed
		Fixes:             []Fix{}, // Initialize empty fixes slice
	}
}

// NewFindingFromAST creates a new Finding from AST node information
func NewFindingFromAST(
	rule *Rule,
	yamlPath string,
	node ast.Node,
	path []string,
	matchedColumn,
	matchedLineOffset int,
	matchedLength int,
) *Finding {
	var value string
	var line, column int

	switch n := node.(type) {
	case *ast.StringNode:
		value = n.Value
		line = n.GetToken().Position.Line
		column = n.GetToken().Position.Column
	case *ast.LiteralNode:
		value = n.String()
		line = n.GetToken().Position.Line
		column = n.GetToken().Position.Column
	default:
		// Fallback for other node types
		value = node.String()
		line = 1
		column = 1
	}

	// Calculate the actual line and column for multiline strings
	actualLine := line
	indentation := 0

	if strings.Contains(value, "\n") {
		// For multiline strings, we need to calculate the actual column
		// by finding the indentation of the line containing the match
		contentBeforeMatch := value[:matchedColumn]

		if strings.Contains(contentBeforeMatch, "\n") {
			// Find which line contains the match
			lineParts := strings.Split(contentBeforeMatch, "\n")
			actualLine = line + len(lineParts) - 1

			// Calculate the column position within the current line
			column = len(lineParts[len(lineParts)-1]) + 1 // +1 for 1-based column
		} else {
			// Match is on the first line, column is relative to the start
			column = column + matchedColumn
		}
	} else {
		// Single line, add the matched column offset
		column = column + matchedColumn
	}

	// Calculate actual indentation by reading the file
	indentation = calculateIndentation(yamlPath, actualLine)

	return &Finding{
		Rule:              rule,
		YamlPath:          strings.Join(path, "."),
		Line:              actualLine,
		Column:            column,
		Value:             value,
		MatchedColumn:     matchedColumn,
		MatchedLineOffset: matchedLineOffset,
		MatchedLength:     matchedLength,
		Severity:          rule.Severity,
		Indentation:       indentation,
		ActualColumn:      indentation + column,
		Fixes:             []Fix{}, // Initialize empty fixes slice
	}
}

// calculateIndentation calculates the actual indentation
func calculateIndentation(filePath string, line int) int {
	// Read the file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return 0
	}

	// Split into lines
	lines := strings.Split(string(content), "\n")
	if line <= 0 || line > len(lines) {
		return 0
	}

	actualLine := lines[line-1]
	indentation := 0
	for _, char := range actualLine {
		if char == ' ' {
			indentation++
		} else if char == '\t' {
			indentation += 4
		} else {
			break
		}
	}

	return indentation
}

// AddFix adds a fix to the finding
func (f *Finding) AddFix(fix Fix) {
	f.Fixes = append(f.Fixes, fix)
}

// HasFixes returns true if the finding has available fixes
func (f *Finding) HasFixes() bool {
	return len(f.Fixes) > 0
}

// String returns a string representation of the finding
func (f *Finding) String() string {
	if f.Rule == nil {
		return fmt.Sprintf("%s[unknown]: Unknown finding", f.Severity)
	}
	return fmt.Sprintf("%s[%s]: %s", f.Severity, f.Rule.Category, f.Rule.Message)
}

// FindPattern searches for a pattern in a YAML file and returns a map of findings
func FindPattern(yamlPath string, rule *Rule) (map[Category]*Finding, error) {
	content, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	file, err := parser.ParseBytes(content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	visitor := &patternVisitor{
		rule: rule,
		path: yamlPath,
	}

	for _, doc := range file.Docs {
		ast.Walk(visitor, doc)
	}

	return visitor.findings, nil
}

// patternVisitor implements ast.Visitor to find patterns in YAML
type patternVisitor struct {
	rule     *Rule
	path     string
	findings map[Category]*Finding
}

// Visit implements ast.Visitor
func (v *patternVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	if str, ok := node.(*ast.StringNode); ok {
		re, err := regexp.Compile(v.rule.Pattern)
		if err != nil {
			return v
		}

		if re.MatchString(str.Value) {
			loc := re.FindStringIndex(str.Value)
			if loc != nil {
				line := str.GetToken().Position.Line
				column := str.GetToken().Position.Column
				if strings.Contains(str.Value, "\n") {
					lines := strings.Split(str.Value, "\n")
					for i, l := range lines {
						if re.MatchString(l) {
							line = str.GetToken().Position.Line + i
							loc = re.FindStringIndex(l)
							column = loc[0] + 1
							break
						}
					}
				}

				finding := NewFinding(
					v.rule,
					v.path,
					line,
					column,
					str.Value,
					loc[0],
					0,
					len(str.Value),
				)

				if v.findings == nil {
					v.findings = make(map[Category]*Finding)
				}
				v.findings[v.rule.Category] = finding
			}
		}
	}

	return v
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

// NodeVisitor defines an interface for visiting YAML AST nodes
// Each rule that wants to inspect nodes should implement this
// findings slice is shared and appended to by all visitors
type NodeVisitor interface {
	VisitNode(node ast.Node, path []string, filePath string, findings *[]*Finding)
}

// WalkAST traverses the YAML AST and applies all registered NodeVisitors
func WalkAST(node ast.Node, path []string, filePath string, visitors []NodeVisitor, findings *[]*Finding) {
	if node == nil {
		return
	}
	for _, visitor := range visitors {
		visitor.VisitNode(node, path, filePath, findings)
	}
	switch n := node.(type) {
	case *ast.DocumentNode:
		// Document nodes contain the root content
		if n.Body != nil {
			WalkAST(n.Body, path, filePath, visitors, findings)
		}
	case *ast.MappingNode:
		for i := 0; i < len(n.Values); i++ {
			key := n.Values[i].Key
			value := n.Values[i].Value
			if key == nil || value == nil {
				continue
			}
			currentPath := append(path, key.String())
			WalkAST(value, currentPath, filePath, visitors, findings)
		}
	case *ast.SequenceNode:
		for i, value := range n.Values {
			currentPath := append(path, fmt.Sprintf("[%d]", i))
			WalkAST(value, currentPath, filePath, visitors, findings)
		}
	}
}
