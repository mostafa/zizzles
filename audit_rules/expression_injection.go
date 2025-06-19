package audit_rules

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
	"github.com/mostafa/zizzles/yaml_patch"
)

const CategoryExpressionInjection types.Category = "expression_injection"

// ExpressionInjectionRule consolidates all logic and state for expression injection detection and fixing
type ExpressionInjectionRule struct {
	types.Rule
	Expressions  []string
	EnvVariables map[string]string
	FixedRun     string
	RunBlock     *RunBlockInfo
	Fix          *RunBlockFix
	Findings     []*types.Finding
	Fixes        []string
	detector     *ExpressionInjectionDetector
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

// RunBlockFix contains the information needed to fix a run block
type RunBlockFix struct {
	EnvVariables map[string]string
	FixedRun     string
}

// ExpressionInjectionDetector provides AST-based detection for expression injection vulnerabilities
type ExpressionInjectionDetector struct {
	rule *ExpressionInjectionRule
}

// NewExpressionInjectionRule creates a new expression injection rule instance
func NewExpressionInjectionRule() *ExpressionInjectionRule {
	rule := &ExpressionInjectionRule{
		Rule: types.Rule{
			Category: CategoryExpressionInjection,
			Severity: types.SeverityHigh,
			Message:  "Untrusted input expression found in run block - potential command injection",
			Type:     types.RuleTypeAST,
		},
		Expressions:  make([]string, 0),
		EnvVariables: make(map[string]string),
		Findings:     make([]*types.Finding, 0),
		Fixes:        make([]string, 0),
	}

	rule.detector = &ExpressionInjectionDetector{rule: rule}
	return rule
}

// NewExpressionInjectionDetector creates a new detector instance
func NewExpressionInjectionDetector() *ExpressionInjectionDetector {
	return &ExpressionInjectionDetector{}
}

// extractExpressions extracts all expressions from a string
func (r *ExpressionInjectionRule) extractExpressions(value string) []string {
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

// toEnvName converts an expression to a safe environment variable name
func (r *ExpressionInjectionRule) toEnvName(expression string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name := re.ReplaceAllString(expression, "_")
	name = strings.ToUpper(name)
	if len(name) > 0 && !regexp.MustCompile(`^[a-zA-Z]`).MatchString(name) {
		name = "EXPR_" + name
	}
	return name
}

// isInRunContext checks if the current path is within a run block
func (r *ExpressionInjectionRule) isInRunContext(path []string) bool {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == "run" {
			return true
		}
	}
	return false
}

// VisitNode implements types.NodeVisitor for expression injection
func (d *ExpressionInjectionDetector) VisitNode(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if node == nil {
		return
	}

	// Use the rule's context if available
	rule := d.rule
	if rule == nil {
		// Fallback for standalone detector
		rule = NewExpressionInjectionRule()
	}

	// Only interested in string nodes in a run context
	switch n := node.(type) {
	case *ast.StringNode:
		if strings.Contains(n.Value, "${{") && rule.isInRunContext(path) {
			rule.addExpressionInjectionFinding(n, path, filePath, findings)
		}
	case *ast.LiteralNode:
		if strings.Contains(n.String(), "${{") && rule.isInRunContext(path) {
			rule.addExpressionInjectionFinding(n, path, filePath, findings)
		}
	}
}

// addExpressionInjectionFinding creates and adds a finding for expression injection
func (r *ExpressionInjectionRule) addExpressionInjectionFinding(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
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
		findingRule := &types.Rule{
			Category: CategoryExpressionInjection,
			Severity: types.SeverityHigh,
			Message:  fmt.Sprintf("Untrusted input expression found in run block: %s", matchedExpr),
			Type:     types.RuleTypeAST,
		}

		// Use unified finding creation
		finding := types.NewFindingFromAST(
			findingRule,
			filePath,
			node,
			path,
			matchedColumn,
			0,
			matchedLength,
		)

		*findings = append(*findings, finding)
		r.Findings = append(r.Findings, finding)
	}
}

// DetectExpressionsInFile detects expression injection vulnerabilities in a file
func (r *ExpressionInjectionRule) DetectExpressionsInFile(filePath string) error {
	// Parse the YAML file
	file, err := parser.ParseFile(filePath, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("failed to parse YAML file: %w", err)
	}

	// Clear previous findings
	r.Findings = make([]*types.Finding, 0)

	// Detect expressions in each document
	for _, doc := range file.Docs {
		r.detectExpressionsInDocument(doc, filePath)
	}

	return nil
}

// detectExpressionsInDocument detects expressions in a single document
func (r *ExpressionInjectionRule) detectExpressionsInDocument(doc ast.Node, filePath string) {
	// Find all run blocks with expressions
	runBlocks := r.findRunBlocksWithExpressions(doc)

	// Process each run block
	for _, runBlock := range runBlocks {
		r.RunBlock = runBlock
		r.Expressions = runBlock.Expressions

		// Create findings for this run block
		r.createFindingsForRunBlock(runBlock, filePath)
	}
}

// findRunBlocksWithExpressions finds all run blocks containing expressions
func (r *ExpressionInjectionRule) findRunBlocksWithExpressions(node ast.Node) []*RunBlockInfo {
	var runBlocks []*RunBlockInfo
	r.traverseForRunBlocks(node, []string{}, &runBlocks)
	return runBlocks
}

// traverseForRunBlocks recursively traverses the AST to find run blocks
func (r *ExpressionInjectionRule) traverseForRunBlocks(node ast.Node, path []string, runBlocks *[]*RunBlockInfo) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.MappingNode:
		r.traverseMappingForRunBlocks(n, path, runBlocks)
	case *ast.SequenceNode:
		r.traverseSequenceForRunBlocks(n, path, runBlocks)
	case *ast.DocumentNode:
		if n.Body != nil {
			r.traverseForRunBlocks(n.Body, path, runBlocks)
		}
	}
}

// traverseMappingForRunBlocks processes mapping nodes to find run blocks
func (r *ExpressionInjectionRule) traverseMappingForRunBlocks(node *ast.MappingNode, path []string, runBlocks *[]*RunBlockInfo) {
	for i := 0; i < len(node.Values); i++ {
		key := node.Values[i].Key
		value := node.Values[i].Value

		if key == nil || value == nil {
			continue
		}

		currentPath := append(path, key.String())

		// Check if this is a 'run' key
		if key.String() == "run" {
			if runInfo := r.extractRunBlockInfo(value, currentPath); runInfo != nil {
				*runBlocks = append(*runBlocks, runInfo)
			}
		}

		// Recursively traverse child nodes
		r.traverseForRunBlocks(value, currentPath, runBlocks)
	}
}

// traverseSequenceForRunBlocks processes sequence nodes
func (r *ExpressionInjectionRule) traverseSequenceForRunBlocks(node *ast.SequenceNode, path []string, runBlocks *[]*RunBlockInfo) {
	for i, value := range node.Values {
		currentPath := append(path, fmt.Sprintf("%d", i))
		r.traverseForRunBlocks(value, currentPath, runBlocks)
	}
}

// extractRunBlockInfo extracts information from a run block node
func (r *ExpressionInjectionRule) extractRunBlockInfo(node ast.Node, path []string) *RunBlockInfo {
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

	expressions := r.extractExpressions(value)
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

// createFindingsForRunBlock creates findings for a specific run block
func (r *ExpressionInjectionRule) createFindingsForRunBlock(runBlock *RunBlockInfo, filePath string) {
	// Create a finding for each expression
	for _, expr := range runBlock.Expressions {
		rule := &types.Rule{
			Category: CategoryExpressionInjection,
			Severity: types.SeverityHigh,
			Message:  fmt.Sprintf("Untrusted input expression found in run block: %s", expr),
			Type:     types.RuleTypeAST,
		}

		finding := types.NewFindingFromAST(
			rule,
			filePath,
			runBlock.Node,
			runBlock.Path,
			runBlock.Column,
			runBlock.Line,
			len(expr),
		)

		r.Findings = append(r.Findings, finding)
	}
}

// FixFile applies fixes to a YAML file and returns the fixed content using yaml_patch
func (r *ExpressionInjectionRule) FixFile(filePath string) (string, error) {
	// Read the file content
	content, err := readFileContent(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Parse the YAML file to detect issues
	file, err := parser.ParseFile(filePath, parser.ParseComments)
	if err != nil {
		return "", fmt.Errorf("failed to parse YAML file: %w", err)
	}

	// Clear previous fixes
	r.Fixes = make([]string, 0)

	// Find all run blocks with expressions
	runBlocks := r.findRunBlocksWithExpressions(file.Docs[0].Body)

	if len(runBlocks) == 0 {
		return content, nil // No fixes needed
	}

	// Create all patches from the original content
	allPatches := make([]yaml_patch.Patch, 0)
	for _, runBlock := range runBlocks {
		runPatches, err := r.createPatchesForRunBlock(runBlock, content)
		if err != nil {
			continue // Skip this block if we can't create patches
		}
		allPatches = append(allPatches, runPatches...)
	}

	if len(allPatches) == 0 {
		return content, nil // No patches to apply
	}

	// Apply all patches to the original content
	fixedContent, err := yaml_patch.ApplyYAMLPatches(content, allPatches)
	if err != nil {
		return "", fmt.Errorf("failed to apply YAML patches: %w", err)
	}

	// Record the fixes
	for _, runBlock := range runBlocks {
		r.Fixes = append(r.Fixes, fmt.Sprintf("Fixed expression injection in run block at line %d", runBlock.Line))
	}

	return fixedContent, nil
}

// envKeyExistsInStep checks if the 'env' key exists in the step mapping at stepPath
func envKeyExistsInStep(content string, stepPath string) bool {
	file, err := parser.ParseBytes([]byte(content), parser.ParseComments)
	if err != nil {
		return false
	}
	parts := strings.Split(stepPath, ".")
	if len(file.Docs) == 0 {
		return false
	}
	current := file.Docs[0].Body
	for _, part := range parts {
		if mapping, ok := current.(*ast.MappingNode); ok {
			found := false
			for _, pair := range mapping.Values {
				if key, ok := pair.Key.(*ast.StringNode); ok && key.Value == part {
					current = pair.Value
					found = true
					break
				}
			}
			if !found {
				return false
			}
		} else if seq, ok := current.(*ast.SequenceNode); ok {
			// Handle numeric indices for steps
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(seq.Values) {
				return false
			}
			current = seq.Values[idx]
		} else {
			return false
		}
	}
	// Now current should be the step mapping
	if mapping, ok := current.(*ast.MappingNode); ok {
		for _, pair := range mapping.Values {
			if key, ok := pair.Key.(*ast.StringNode); ok && key.Value == "env" {
				return true
			}
		}
	}
	return false
}

// createPatchesForRunBlock creates yaml_patch operations for a run block
func (r *ExpressionInjectionRule) createPatchesForRunBlock(runBlock *RunBlockInfo, content string) ([]yaml_patch.Patch, error) {
	patches := make([]yaml_patch.Patch, 0)

	// Create environment variables for each expression
	envVariables := make(map[string]string)
	for _, expr := range runBlock.Expressions {
		envName := r.toEnvName(expr)
		envVariables[envName] = fmt.Sprintf("${{ %s }}", expr)
	}

	// Build the path to the run block
	runPath := strings.Join(runBlock.Path, ".")
	// Build the path to the step (parent of run)
	stepPath := strings.Join(runBlock.Path[:len(runBlock.Path)-1], ".")

	// First, create patches for each expression replacement in the run block
	for _, expr := range runBlock.Expressions {
		envName := r.toEnvName(expr)
		expressionPattern := fmt.Sprintf("${{ %s }}", expr)
		patches = append(patches, yaml_patch.Patch{
			Path: runPath,
			Operation: yaml_patch.RewriteFragmentOp{
				From: expressionPattern,
				To:   fmt.Sprintf("$%s", envName),
			},
		})
	}

	// Then, add env block to the step (this ensures env comes before run)
	if len(envVariables) > 0 {
		patches = append(patches, yaml_patch.Patch{
			Path: stepPath,
			Operation: yaml_patch.AddOp{
				Key:   "env",
				Value: envVariables,
			},
		})
	}

	return patches, nil
}

// readFileContent reads the content of a file
func readFileContent(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}
	return string(content), nil
}

// RewriteRunWithEnv rewrites a run block to use environment variables
func (r *ExpressionInjectionRule) RewriteRunWithEnv(runContent string, expressions []string) string {
	fixed := runContent

	for _, expr := range expressions {
		envName := r.toEnvName(expr)
		patternStr := `\$\{\{\s*` + regexp.QuoteMeta(expr) + `\s*\}\}`
		pattern := regexp.MustCompile(patternStr)
		fixed = pattern.ReplaceAllString(fixed, "$$"+envName)
	}

	return fixed
}

// GenerateFixSuggestion generates a human-readable suggestion for fixing expression injection
func (r *ExpressionInjectionRule) GenerateFixSuggestion() string {
	if len(r.Expressions) == 0 {
		return "No expressions found to fix."
	}

	var sb strings.Builder
	sb.WriteString("To fix this expression injection vulnerability:\n\n")
	sb.WriteString("1. Add an 'env:' block to your step:\n")
	sb.WriteString("```yaml\n")
	sb.WriteString("- name: Your step name\n")
	sb.WriteString("  env:\n")

	for _, expr := range r.Expressions {
		envName := r.toEnvName(expr)
		sb.WriteString(fmt.Sprintf("    %s: ${{ %s }}\n", envName, expr))
	}

	sb.WriteString("  run: |\n")
	sb.WriteString("    # Replace expressions with environment variables\n")
	sb.WriteString("    # Example: echo \"$ISSUE_TITLE\" instead of echo \"${{ github.event.issue.title }}\"\n")
	sb.WriteString("```\n\n")

	sb.WriteString("2. Update your run commands to use the environment variables:\n")
	for _, expr := range r.Expressions {
		envName := r.toEnvName(expr)
		sb.WriteString(fmt.Sprintf("   - Replace `${{ %s }}` with `$%s`\n", expr, envName))
	}

	return sb.String()
}

// GetFindings returns all findings from the rule
func (r *ExpressionInjectionRule) GetFindings() []*types.Finding {
	return r.Findings
}

// GetFixes returns all applied fixes
func (r *ExpressionInjectionRule) GetFixes() []string {
	return r.Fixes
}

// GetExpressions returns all detected expressions
func (r *ExpressionInjectionRule) GetExpressions() []string {
	return r.Expressions
}

// GetEnvVariables returns the environment variables mapping
func (r *ExpressionInjectionRule) GetEnvVariables() map[string]string {
	return r.EnvVariables
}

// GetExpressionInjectionRules returns a set of rules for detecting expression injections
// Note: These are now primarily for pattern-based detection of edge cases not covered by AST
func GetExpressionInjectionRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryExpressionInjection,
		Rules: []types.Rule{
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*run:\s*.*echo\s+.*\$\{\{\s*(github\.event\.[\w\.]+)\s*\}\}`,
				Severity: types.SeverityHigh,
				Message:  "Unsafe echo with GitHub event expressions - potential command injection",
				Type:     types.RuleTypePattern,
			},
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*run:\s*.*\$\{\{\s*(inputs\.[\w\.]+|github\.event\.[\w\.]+|vars\.[\w\.]+)\s*\}\}`,
				Severity: types.SeverityHigh,
				Message:  "Untrusted input expression in shell commands - potential command injection",
				Type:     types.RuleTypePattern,
			},
		},
	}
}
