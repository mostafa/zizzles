package types

import (
	"fmt"
	"sync"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// RuleExecutor handles the execution of both AST and pattern-based rules
type RuleExecutor struct {
	astRules     []*ASTRule
	patternRules []*PatternRule
}

// NewRuleExecutor creates a new rule executor
func NewRuleExecutor() *RuleExecutor {
	return &RuleExecutor{
		astRules:     make([]*ASTRule, 0),
		patternRules: make([]*PatternRule, 0),
	}
}

// AddASTRule adds an AST-based rule
func (re *RuleExecutor) AddASTRule(rule *ASTRule) {
	re.astRules = append(re.astRules, rule)
}

// AddPatternRule adds a pattern-based rule
func (re *RuleExecutor) AddPatternRule(rule *PatternRule) {
	re.patternRules = append(re.patternRules, rule)
}

// ExecuteAll executes all rules against a file and returns findings
func (re *RuleExecutor) ExecuteAll(filePath string, content []byte) (map[Category][]*Finding, error) {
	allFindings := make(map[Category][]*Finding)

	// Execute AST rules first (more accurate)
	astFindings, err := re.executeASTRules(filePath, content)
	if err != nil {
		return nil, fmt.Errorf("failed to execute AST rules: %w", err)
	}

	// Merge AST findings
	for cat, findings := range astFindings {
		allFindings[cat] = append(allFindings[cat], findings...)
	}

	// Execute pattern rules in parallel
	patternFindings, err := re.executePatternRules(filePath, content)
	if err != nil {
		return nil, fmt.Errorf("failed to execute pattern rules: %w", err)
	}

	// Merge pattern findings
	for cat, findings := range patternFindings {
		allFindings[cat] = append(allFindings[cat], findings...)
	}

	return allFindings, nil
}

// executeASTRules executes all AST-based rules
func (re *RuleExecutor) executeASTRules(filePath string, content []byte) (map[Category][]*Finding, error) {
	if len(re.astRules) == 0 {
		return make(map[Category][]*Finding), nil
	}

	// Parse the YAML AST
	fileAst, err := parser.ParseBytes(content, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML AST: %w", err)
	}

	// Collect all AST visitors
	visitors := make([]NodeVisitor, 0, len(re.astRules))
	for _, rule := range re.astRules {
		visitors = append(visitors, rule.Visitor)
	}

	// Execute AST rules in parallel for each document
	var wg sync.WaitGroup
	allFindings := make(map[Category][]*Finding)
	var findingsMutex sync.Mutex

	for _, doc := range fileAst.Docs {
		wg.Add(1)
		go func(doc ast.Node) {
			defer wg.Done()

			astFindings := make([]*Finding, 0)
			WalkAST(doc, []string{}, filePath, visitors, &astFindings)

			// Group findings by category
			docFindings := make(map[Category][]*Finding)
			for _, finding := range astFindings {
				docFindings[finding.Rule.Category] = append(docFindings[finding.Rule.Category], finding)
			}

			// Merge findings thread-safely
			findingsMutex.Lock()
			for cat, fs := range docFindings {
				allFindings[cat] = append(allFindings[cat], fs...)
			}
			findingsMutex.Unlock()
		}(doc)
	}

	wg.Wait()
	return allFindings, nil
}

// executePatternRules executes all pattern-based rules in parallel
func (re *RuleExecutor) executePatternRules(filePath string, content []byte) (map[Category][]*Finding, error) {
	if len(re.patternRules) == 0 {
		return make(map[Category][]*Finding), nil
	}

	allFindings := make(map[Category][]*Finding)
	var wg sync.WaitGroup
	var findingsMutex sync.Mutex

	// Execute pattern rules in parallel
	for _, rule := range re.patternRules {
		wg.Add(1)
		go func(rule *PatternRule) {
			defer wg.Done()

			// Convert PatternRule to Rule for FindPattern compatibility
			ruleForPattern := &Rule{
				Category: rule.Category,
				Pattern:  rule.Pattern,
				Severity: rule.Severity,
				Message:  rule.Message,
				Type:     RuleTypePattern,
			}

			patternFindings, err := FindPattern(filePath, ruleForPattern)
			if err != nil {
				// Log error but continue with other rules
				return
			}

			// Merge findings thread-safely
			findingsMutex.Lock()
			for cat, finding := range patternFindings {
				allFindings[cat] = append(allFindings[cat], finding)
			}
			findingsMutex.Unlock()
		}(rule)
	}

	wg.Wait()
	return allFindings, nil
}

// GetASTRules returns all AST rules
func (re *RuleExecutor) GetASTRules() []*ASTRule {
	return re.astRules
}

// GetPatternRules returns all pattern rules
func (re *RuleExecutor) GetPatternRules() []*PatternRule {
	return re.patternRules
}
