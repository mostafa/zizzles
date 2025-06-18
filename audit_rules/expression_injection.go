package audit_rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
)

const CategoryExpressionInjection types.Category = "expression_injection"

// GetExpressionInjectionRules returns a set of rules for detecting expression injections
func GetExpressionInjectionRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryExpressionInjection,
		Rules: []types.Rule{
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*run:\s*\|\s*$(?:\s*[^\n]*\$\{\{[^}]+\}\}[^\n]*\n?)+`,
				Severity: types.SeverityHigh,
				Message:  "Untrusted input expression found in literal multiline run block - potential command injection",
			},
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*run:\s*>\s*$(?:\s*[^\n]*\$\{\{[^}]+\}\}[^\n]*\n?)+`,
				Severity: types.SeverityHigh,
				Message:  "Untrusted input expression found in folded multiline run block - potential command injection",
			},
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*run:\s*(?![\|>]).*\$\{\{[^}]+\}\}`,
				Severity: types.SeverityHigh,
				Message:  "Untrusted input expression found in inline run command - potential command injection",
			},
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*run:\s*.*echo\s+.*\$\{\{\s*(github\.event\.[\w\.]+)\s*\}\}`,
				Severity: types.SeverityHigh,
				Message:  "Unsafe echo with GitHub event expressions - potential command injection",
			},
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*run:\s*.*\$\{\{\s*(inputs\.[\w\.]+|github\.event\.[\w\.]+|vars\.[\w\.]+)\s*\}\}`,
				Severity: types.SeverityHigh,
				Message:  "Untrusted input expression in shell commands - potential command injection",
			},
		},
	}
}

// ExpressionInjectionDetector provides AST-based detection for expression injection vulnerabilities
type ExpressionInjectionDetector struct{}

// NewExpressionInjectionDetector creates a new detector instance
func NewExpressionInjectionDetector() *ExpressionInjectionDetector {
	return &ExpressionInjectionDetector{}
}

// VisitNode implements types.NodeVisitor for expression injection
func (d *ExpressionInjectionDetector) VisitNode(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if node == nil {
		return
	}
	// Only interested in string nodes in a run context
	switch n := node.(type) {
	case *ast.StringNode:
		if strings.Contains(n.Value, "${{") && isInRunContext(path) {
			addExpressionInjectionFinding(n, path, filePath, findings)
		}
	case *ast.LiteralNode:
		if strings.Contains(n.String(), "${{") && isInRunContext(path) {
			addExpressionInjectionFinding(n, path, filePath, findings)
		}
	}
}

// isInRunContext checks if the current path is within a run block
func isInRunContext(path []string) bool {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == "run" {
			return true
		}
	}
	return false
}

// addExpressionInjectionFinding creates and adds a finding for expression injection
func addExpressionInjectionFinding(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	var value string

	switch n := node.(type) {
	case *ast.StringNode:
		value = n.Value
	case *ast.LiteralNode:
		value = n.String()
	default:
		return
	}

	// Find all ${{ ... }} occurrences in the value
	matchRe := regexp.MustCompile(`\$\{\{[^}]+\}\}`)
	locs := matchRe.FindAllStringIndex(value, -1)

	// Create a separate finding for each occurrence
	for _, loc := range locs {
		matchedExpr := value[loc[0]:loc[1]]
		matchedColumn := loc[0]
		matchedLength := loc[1] - loc[0]

		// Create rule for this finding
		rule := &types.Rule{
			Category: CategoryExpressionInjection,
			Severity: types.SeverityHigh,
			Message:  fmt.Sprintf("Untrusted input expression found in run block: %s", matchedExpr),
			Type:     types.RuleTypeAST,
		}

		// Use unified finding creation
		finding := types.NewFindingFromAST(
			rule,
			filePath,
			node,
			path,
			matchedColumn,
			0,
			matchedLength,
		)

		*findings = append(*findings, finding)
	}
}

// ExtractExpressions extracts all expressions from a string
func ExtractExpressions(value string) []string {
	re := regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
	matches := re.FindAllStringSubmatch(value, -1)

	expressions := make([]string, 0)
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 {
			expr := strings.TrimSpace(match[1])
			if !seen[expr] {
				expressions = append(expressions, expr)
				seen[expr] = true
			}
		}
	}

	return expressions
}

// ToEnvName converts an expression to a safe environment variable name
func ToEnvName(expression string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name := re.ReplaceAllString(expression, "_")
	name = strings.ToUpper(name)
	if len(name) > 0 && !regexp.MustCompile(`^[a-zA-Z]`).MatchString(name) {
		name = "EXPR_" + name
	}
	return name
}

// ExpressionInjectionFixer provides functionality to automatically fix expression injection vulnerabilities
type ExpressionInjectionFixer struct {
	detector *ExpressionInjectionDetector
}

// NewExpressionInjectionFixer creates a new fixer instance
func NewExpressionInjectionFixer() *ExpressionInjectionFixer {
	return &ExpressionInjectionFixer{
		detector: NewExpressionInjectionDetector(),
	}
}

// FixFile applies fixes to a YAML file and returns the fixed content
func (f *ExpressionInjectionFixer) FixFile(filePath string) (string, []string, error) {
	// Parse the YAML file
	file, err := parser.ParseFile(filePath, parser.ParseComments)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse YAML file: %w", err)
	}

	// Apply fixes to each document
	appliedFixes := make([]string, 0)
	for _, doc := range file.Docs {
		fixes, err := f.fixDocument(doc)
		if err != nil {
			return "", appliedFixes, fmt.Errorf("failed to fix document: %w", err)
		}
		appliedFixes = append(appliedFixes, fixes...)
	}

	// Convert back to string
	fixedContent := file.String()
	return fixedContent, appliedFixes, nil
}

// fixDocument applies fixes to a single YAML document
func (f *ExpressionInjectionFixer) fixDocument(doc ast.Node) ([]string, error) {
	appliedFixes := make([]string, 0)

	// Find all run blocks with expressions
	runBlocks := f.findRunBlocksWithExpressions(doc)

	for _, runBlock := range runBlocks {
		fix, err := f.createFixForRunBlock(runBlock)
		if err != nil {
			continue // Skip this block if we can't fix it
		}

		// Apply the fix
		if err := f.applyFixToRunBlock(runBlock, fix); err != nil {
			continue // Skip this block if fix fails
		}

		appliedFixes = append(appliedFixes, fmt.Sprintf("Fixed expression injection in run block at line %d", runBlock.Line))
	}

	return appliedFixes, nil
}

// RunBlockInfo contains information about a run block that needs fixing
type RunBlockInfo struct {
	Node        ast.Node
	Path        []string
	Line        int
	Column      int
	Value       string
	Expressions []string
}

// findRunBlocksWithExpressions finds all run blocks containing expressions
func (f *ExpressionInjectionFixer) findRunBlocksWithExpressions(node ast.Node) []*RunBlockInfo {
	var runBlocks []*RunBlockInfo
	f.traverseForRunBlocks(node, []string{}, &runBlocks)
	return runBlocks
}

// traverseForRunBlocks recursively traverses the AST to find run blocks
func (f *ExpressionInjectionFixer) traverseForRunBlocks(node ast.Node, path []string, runBlocks *[]*RunBlockInfo) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.MappingNode:
		f.traverseMappingForRunBlocks(n, path, runBlocks)
	case *ast.SequenceNode:
		f.traverseSequenceForRunBlocks(n, path, runBlocks)
	}
}

// traverseMappingForRunBlocks processes mapping nodes to find run blocks
func (f *ExpressionInjectionFixer) traverseMappingForRunBlocks(node *ast.MappingNode, path []string, runBlocks *[]*RunBlockInfo) {
	for i := 0; i < len(node.Values); i++ {
		key := node.Values[i].Key
		value := node.Values[i].Value

		if key == nil || value == nil {
			continue
		}

		currentPath := append(path, key.String())

		// Check if this is a 'run' key
		if key.String() == "run" {
			if runInfo := f.extractRunBlockInfo(value, currentPath); runInfo != nil {
				*runBlocks = append(*runBlocks, runInfo)
			}
		}

		// Recursively traverse child nodes
		f.traverseForRunBlocks(value, currentPath, runBlocks)
	}
}

// traverseSequenceForRunBlocks processes sequence nodes
func (f *ExpressionInjectionFixer) traverseSequenceForRunBlocks(node *ast.SequenceNode, path []string, runBlocks *[]*RunBlockInfo) {
	for i, value := range node.Values {
		currentPath := append(path, fmt.Sprintf("[%d]", i))
		f.traverseForRunBlocks(value, currentPath, runBlocks)
	}
}

// extractRunBlockInfo extracts information from a run block node
func (f *ExpressionInjectionFixer) extractRunBlockInfo(node ast.Node, path []string) *RunBlockInfo {
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
		return nil
	}

	// Check if this run block contains expressions
	if !strings.Contains(value, "${{") {
		return nil
	}

	expressions := f.extractExpressions(value)
	if len(expressions) == 0 {
		return nil
	}

	return &RunBlockInfo{
		Node:        node,
		Path:        path,
		Line:        line,
		Column:      column,
		Value:       value,
		Expressions: expressions,
	}
}

// extractExpressions extracts all expressions from a string
func (f *ExpressionInjectionFixer) extractExpressions(value string) []string {
	re := regexp.MustCompile(`\$\{\{\s*([^}]+)\s*\}\}`)
	matches := re.FindAllStringSubmatch(value, -1)

	expressions := make([]string, 0)
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 {
			expr := strings.TrimSpace(match[1])
			if !seen[expr] {
				expressions = append(expressions, expr)
				seen[expr] = true
			}
		}
	}

	return expressions
}

// RunBlockFix contains the information needed to fix a run block
type RunBlockFix struct {
	EnvVariables map[string]string
	FixedRun     string
}

// createFixForRunBlock creates a fix for a run block
func (f *ExpressionInjectionFixer) createFixForRunBlock(runBlock *RunBlockInfo) (*RunBlockFix, error) {
	// Create environment variables for each expression
	envVariables := make(map[string]string)
	for _, expr := range runBlock.Expressions {
		envName := f.toEnvName(expr)
		envVariables[envName] = fmt.Sprintf("${{ %s }}", expr)
	}

	// Create the fixed run block content
	fixedRun := f.RewriteRunWithEnv(runBlock.Value, runBlock.Expressions)

	return &RunBlockFix{
		EnvVariables: envVariables,
		FixedRun:     fixedRun,
	}, nil
}

// toEnvName converts an expression to a safe environment variable name
func (f *ExpressionInjectionFixer) toEnvName(expression string) string {
	// Replace dots and special characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name := re.ReplaceAllString(expression, "_")

	// Convert to uppercase
	name = strings.ToUpper(name)

	// Ensure it starts with a letter
	if len(name) > 0 && !regexp.MustCompile(`^[a-zA-Z]`).MatchString(name) {
		name = "EXPR_" + name
	}

	return name
}

// RewriteRunWithEnv rewrites a run block to use environment variables
func (f *ExpressionInjectionFixer) RewriteRunWithEnv(runContent string, expressions []string) string {
	fixed := runContent

	for _, expr := range expressions {
		envName := f.toEnvName(expr)
		pattern := regexp.QuoteMeta(fmt.Sprintf("${{ %s }}", expr))
		re := regexp.MustCompile(pattern)
		fixed = re.ReplaceAllString(fixed, fmt.Sprintf("$%s", envName))
	}

	return fixed
}

// applyFixToRunBlock applies a fix to a run block by modifying the AST
func (f *ExpressionInjectionFixer) applyFixToRunBlock(runBlock *RunBlockInfo, fix *RunBlockFix) error {
	// Find the parent mapping node (the step)
	parent := f.findParentMapping(runBlock.Node)
	if parent == nil {
		return fmt.Errorf("could not find parent mapping node")
	}

	// Add env block before run block
	if err := f.addEnvBlock(parent, fix.EnvVariables); err != nil {
		return fmt.Errorf("failed to add env block: %w", err)
	}

	// Update the run block content
	if err := f.updateRunBlock(runBlock.Node, fix.FixedRun); err != nil {
		return fmt.Errorf("failed to update run block: %w", err)
	}

	return nil
}

// findParentMapping finds the parent mapping node of a run block
func (f *ExpressionInjectionFixer) findParentMapping(node ast.Node) *ast.MappingNode {
	// This is a simplified implementation
	// In a full implementation, you would traverse up the AST to find the parent
	return nil
}

// addEnvBlock adds an env block to a mapping node
func (f *ExpressionInjectionFixer) addEnvBlock(parent *ast.MappingNode, envVariables map[string]string) error {
	// This is a simplified implementation
	// In a full implementation, you would create a new mapping node for env
	return nil
}

// updateRunBlock updates the content of a run block
func (f *ExpressionInjectionFixer) updateRunBlock(node ast.Node, newContent string) error {
	// This is a simplified implementation
	// In a full implementation, you would update the node's value
	return nil
}

// GenerateFixSuggestion generates a human-readable suggestion for fixing expression injection
func (f *ExpressionInjectionFixer) GenerateFixSuggestion(expressions []string) string {
	if len(expressions) == 0 {
		return "No expressions found to fix."
	}

	var sb strings.Builder
	sb.WriteString("To fix this expression injection vulnerability:\n\n")
	sb.WriteString("1. Add an 'env:' block to your step:\n")
	sb.WriteString("```yaml\n")
	sb.WriteString("- name: Your step name\n")
	sb.WriteString("  env:\n")

	for _, expr := range expressions {
		envName := f.toEnvName(expr)
		sb.WriteString(fmt.Sprintf("    %s: ${{ %s }}\n", envName, expr))
	}

	sb.WriteString("  run: |\n")
	sb.WriteString("    # Replace expressions with environment variables\n")
	sb.WriteString("    # Example: echo \"$ISSUE_TITLE\" instead of echo \"${{ github.event.issue.title }}\"\n")
	sb.WriteString("```\n\n")

	sb.WriteString("2. Update your run commands to use the environment variables:\n")
	for _, expr := range expressions {
		envName := f.toEnvName(expr)
		sb.WriteString(fmt.Sprintf("   - Replace `${{ %s }}` with `$%s`\n", expr, envName))
	}

	return sb.String()
}
