package types

import (
	"fmt"
)

// RuleType indicates how a rule should be executed
type RuleType string

const (
	RuleTypeAST     RuleType = "ast"     // AST-based detection
	RuleTypePattern RuleType = "pattern" // Pattern-based detection
)

// Rule represents a security audit rule
type Rule struct {
	Category Category
	Pattern  string
	Severity Severity
	Message  string
	Type     RuleType // How this rule should be executed
}

// Category represents a category of rules
type Category string

// RuleSet represents a collection of rules for a specific category
type RuleSet struct {
	Category Category
	Rules    []Rule
}

// ASTRule represents a rule that uses AST-based detection
type ASTRule struct {
	Category Category
	Severity Severity
	Message  string
	Visitor  NodeVisitor // AST visitor for this rule
}

// PatternRule represents a rule that uses pattern-based detection
type PatternRule struct {
	Category Category
	Pattern  string
	Severity Severity
	Message  string
}

// DeduplicatedRule provides common deduplication functionality for all rules
type DeduplicatedRule struct {
	seenFindings map[string]bool
}

// NewDeduplicatedRule creates a new instance with deduplication capability
func NewDeduplicatedRule() *DeduplicatedRule {
	return &DeduplicatedRule{
		seenFindings: make(map[string]bool),
	}
}

// GenerateFindingKey creates a unique key for a finding based on its location and content
func (d *DeduplicatedRule) GenerateFindingKey(category Category, filePath string, line, column int, value, yamlPath string) string {
	return fmt.Sprintf("%s:%s:%d:%d:%s:%s", string(category), filePath, line, column, value, yamlPath)
}

// AddFindingIfNotSeen adds a finding only if it hasn't been seen before
func (d *DeduplicatedRule) AddFindingIfNotSeen(category Category, finding *Finding, filePath string, value string, findings *[]*Finding) {
	// Generate a unique key for this finding
	key := d.GenerateFindingKey(category, filePath, finding.Line, finding.Column, value, finding.YamlPath)

	// Check if we've already seen this finding
	if d.seenFindings[key] {
		return // Skip duplicate
	}

	// Mark as seen and add to findings
	d.seenFindings[key] = true
	*findings = append(*findings, finding)
}

// ResetDeduplication resets the deduplication state (useful for testing)
func (d *DeduplicatedRule) ResetDeduplication() {
	d.seenFindings = make(map[string]bool)
}
