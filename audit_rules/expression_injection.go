package audit_rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
	"github.com/mostafa/zizzles/yaml_patch"
)

const CategoryExpressionInjection types.Category = "expression_injection"

// ContextCapability represents how a context can expand in terms of security risk
type ContextCapability int

const (
	// Fixed means no meaningful injectable structure (read-only/safe)
	Fixed ContextCapability = iota
	// Structured means some attacker-controllable structure, but not fully arbitrary
	Structured
	// Arbitrary means the context's expansion is fully attacker-controllable
	Arbitrary
)

// ExpressionInjectionRule consolidates all logic and state for expression injection detection and fixing
type ExpressionInjectionRule struct {
	types.Rule
	Expressions         []string
	EnvVariables        map[string]string
	FixedRun            string
	RunBlock            *RunBlockInfo
	Fix                 *RunBlockFix
	Findings            []*types.Finding
	Fixes               []string
	detector            *ExpressionInjectionDetector
	contextCapabilities map[string]ContextCapability
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

// ExpressionContext represents a parsed GitHub Actions expression context
type ExpressionContext struct {
	Raw        string
	Context    string
	Capability ContextCapability
	Severity   types.Severity
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
		Expressions:         make([]string, 0),
		EnvVariables:        make(map[string]string),
		Findings:            make([]*types.Finding, 0),
		Fixes:               make([]string, 0),
		contextCapabilities: initializeContextCapabilities(),
	}

	rule.detector = &ExpressionInjectionDetector{rule: rule}
	return rule
}

// initializeContextCapabilities initializes the context capability mappings
// Based on GitHub's documentation and zizmor's context-capabilities data
func initializeContextCapabilities() map[string]ContextCapability {
	capabilities := make(map[string]ContextCapability)

	// Fixed/Safe contexts (read-only, not injectable)
	fixedContexts := []string{
		// GitHub metadata contexts
		"github.action_path",
		"github.event_name",
		"github.job",
		"github.repository",
		"github.repository_id",
		"github.repository_owner",
		"github.repository_owner_id",
		"github.repositoryurl",
		"github.run_attempt",
		"github.run_id",
		"github.run_number",
		"github.server_url",
		"github.sha",
		"github.token",
		"github.workspace",
		// Runner contexts
		"runner.arch",
		"runner.debug",
		"runner.os",
		"runner.temp",
		"runner.tool_cache",
		// Event metadata
		"github.event.after",
		"github.event.before",
		"github.event.number",
		"github.event.*.id",
		"github.event.*.node_id",
		// Action-controlled values
		"github.action",
		"github.action_ref",
		"github.action_repository",
		// Workflow-controlled values
		"github.workflow",
		"github.workflow_ref",
		"github.workflow_sha",
		// Safe numeric values
		"github.event.*.reactions.total_count",
		"github.event.*.reactions.+1",
		"github.event.*.reactions.-1",
		"github.event.*.reactions.confused",
		"github.event.*.reactions.eyes",
		"github.event.*.reactions.heart",
		"github.event.*.reactions.hooray",
		"github.event.*.reactions.laugh",
		"github.event.*.reactions.rocket",
	}

	for _, ctx := range fixedContexts {
		capabilities[ctx] = Fixed
	}

	// Arbitrary contexts (fully attacker-controllable)
	arbitraryContexts := []string{
		// User-controlled content
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.comment.body",
		"github.event.discussion.title",
		"github.event.discussion.body",
		"github.event.commits.*.message",
		"github.event.head_commit.message",
		"github.event.commits.*.author.name",
		"github.event.commits.*.author.email",
		"github.event.head_commit.author.name",
		"github.event.head_commit.author.email",
		// User identifiers
		"github.actor",
		"github.event.*.user.login",
		"github.event.*.user.name",
		"github.event.*.user.email",
		"github.event.sender.login",
		"github.event.sender.name",
		"github.event.sender.email",
		// Branch/ref names (can be controlled by attacker)
		"github.head_ref",
		"github.base_ref",
		"github.ref_name",
		"github.event.ref",
		"github.event.pull_request.head.ref",
		"github.event.pull_request.base.ref",
		// Repository names (in fork scenarios)
		"github.event.pull_request.head.repo.full_name",
		"github.event.pull_request.head.repo.name",
		// Label names and descriptions
		"github.event.label.name",
		"github.event.label.description",
		"github.event.*.labels.*.name",
		"github.event.*.labels.*.description",
		// Milestone titles and descriptions
		"github.event.milestone.title",
		"github.event.milestone.description",
		// Review content
		"github.event.review.body",
		"github.event.review_comment.body",
	}

	for _, ctx := range arbitraryContexts {
		capabilities[ctx] = Arbitrary
	}

	// Structured contexts (partially controllable)
	structuredContexts := []string{
		// URLs (structured but can contain user data)
		"github.event.*.html_url",
		"github.event.*.url",
		"github.event.*.avatar_url",
		"github.event.*.organizations_url",
		"github.event.*.repos_url",
		"github.event.*.followers_url",
		"github.event.*.following_url",
		"github.event.*.starred_url",
		"github.event.*.subscriptions_url",
		"github.event.*.events_url",
		"github.event.*.received_events_url",
		"github.event.*.gists_url",
		// API URLs with user data
		"github.api_url",
		"github.graphql_url",
		// Some identifiers that may contain structured user data
		"github.event.*.gravatar_id",
		// File paths (in some contexts)
		"github.event.*.filename",
		"github.event.*.path",
	}

	for _, ctx := range structuredContexts {
		capabilities[ctx] = Structured
	}

	return capabilities
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

// analyzeExpressionContext analyzes a GitHub Actions expression to determine its security implications
func (r *ExpressionInjectionRule) analyzeExpressionContext(expression string) *ExpressionContext {
	ctx := &ExpressionContext{
		Raw:        fmt.Sprintf("${{ %s }}", expression),
		Context:    expression,
		Capability: Arbitrary, // Default to most restrictive
		Severity:   types.SeverityHigh,
	}

	// Check for exact matches first
	if capability, exists := r.contextCapabilities[expression]; exists {
		ctx.Capability = capability
	} else {
		// Check for pattern matches
		ctx.Capability = r.matchContextPattern(expression)
	}

	// Determine severity based on capability
	switch ctx.Capability {
	case Fixed:
		// Fixed contexts are generally safe - don't flag them unless pedantic
		return nil // Skip fixed contexts entirely
	case Structured:
		ctx.Severity = types.SeverityMedium
	case Arbitrary:
		ctx.Severity = types.SeverityHigh
	}

	// Special handling for certain context patterns
	ctx = r.applySpecialContextRules(ctx)

	return ctx
}

// matchContextPattern matches expression against known patterns
func (r *ExpressionInjectionRule) matchContextPattern(expression string) ContextCapability {
	// Check for secrets context (generally safe to interpolate, just sensitive)
	if strings.HasPrefix(expression, "secrets.") {
		return Fixed // Don't flag secrets context
	}

	// Check for environment variables
	if strings.HasPrefix(expression, "env.") {
		// Environment variables from default GitHub Actions are generally safe
		envVar := strings.TrimPrefix(expression, "env.")
		if r.isDefaultGitHubEnvVar(envVar) {
			return Fixed
		}
		// User-defined env vars could be dangerous if they contain user input
		return Structured
	}

	// Check for inputs context
	if strings.HasPrefix(expression, "inputs.") {
		return Arbitrary // Inputs are generally user-controllable
	}

	// Check for needs context
	if strings.HasPrefix(expression, "needs.") {
		return Structured // Job outputs can vary in risk
	}

	// Check for matrix context
	if strings.HasPrefix(expression, "matrix.") {
		return Structured // Matrix values can be user-controlled in some cases
	}

	// Check for strategy context
	if strings.HasPrefix(expression, "strategy.") {
		return Structured
	}

	// Check for vars context
	if strings.HasPrefix(expression, "vars.") {
		return Structured // Repository/organization variables
	}

	// Check for job context
	if strings.HasPrefix(expression, "job.") {
		return Fixed // Job context is generally safe
	}

	// Check for steps context
	if strings.HasPrefix(expression, "steps.") {
		return Structured // Step outputs can vary
	}

	// GitHub event context patterns
	if strings.HasPrefix(expression, "github.event.") {
		// Check for known dangerous patterns
		dangerousPatterns := []string{
			"github.event.issue.title",
			"github.event.issue.body",
			"github.event.pull_request.title",
			"github.event.pull_request.body",
			"github.event.comment.body",
			"github.event.commits.*.message",
			"github.event.head_commit.message",
		}

		for _, pattern := range dangerousPatterns {
			if matchesPattern(expression, pattern) {
				return Arbitrary
			}
		}

		// Check for user-related fields
		if strings.Contains(expression, ".user.login") ||
			strings.Contains(expression, ".user.name") ||
			strings.Contains(expression, ".user.email") ||
			strings.Contains(expression, ".author.name") ||
			strings.Contains(expression, ".author.email") {
			return Arbitrary
		}

		// Check for URLs (structured)
		if strings.Contains(expression, "_url") || strings.Contains(expression, ".url") {
			return Structured
		}

		// Default for github.event.*
		return Structured
	}

	// Other github.* contexts
	if strings.HasPrefix(expression, "github.") {
		// Most github.* contexts are fixed, but some can be dangerous
		dangerousGithubContexts := []string{
			"github.actor",
			"github.head_ref",
			"github.base_ref",
			"github.ref_name",
		}

		for _, dangerous := range dangerousGithubContexts {
			if expression == dangerous {
				return Arbitrary
			}
		}

		return Fixed // Most github.* contexts are safe
	}

	// Default to arbitrary for unknown contexts
	return Arbitrary
}

// applySpecialContextRules applies special rules for certain contexts
func (r *ExpressionInjectionRule) applySpecialContextRules(ctx *ExpressionContext) *ExpressionContext {
	// Special handling for actor context - commonly misused
	if ctx.Context == "github.actor" {
		ctx.Severity = types.SeverityHigh
		// Add special message about actor spoofing
		ctx.Context = fmt.Sprintf("%s (warning: github.actor can be spoofed)", ctx.Context)
	}

	// Special handling for head_ref/base_ref - can be controlled in PR scenarios
	if ctx.Context == "github.head_ref" || ctx.Context == "github.base_ref" {
		ctx.Severity = types.SeverityHigh
	}

	return ctx
}

// isDefaultGitHubEnvVar checks if an environment variable is a default GitHub Actions env var
func (r *ExpressionInjectionRule) isDefaultGitHubEnvVar(envVar string) bool {
	defaultEnvVars := []string{
		"GITHUB_ACTION",
		"GITHUB_ACTION_PATH",
		"GITHUB_ACTION_REPOSITORY",
		"GITHUB_ACTIONS",
		"GITHUB_ACTOR",
		"GITHUB_ACTOR_ID",
		"GITHUB_API_URL",
		"GITHUB_BASE_REF",
		"GITHUB_ENV",
		"GITHUB_EVENT_NAME",
		"GITHUB_EVENT_PATH",
		"GITHUB_GRAPHQL_URL",
		"GITHUB_HEAD_REF",
		"GITHUB_JOB",
		"GITHUB_OUTPUT",
		"GITHUB_PATH",
		"GITHUB_REF",
		"GITHUB_REF_NAME",
		"GITHUB_REF_PROTECTED",
		"GITHUB_REF_TYPE",
		"GITHUB_REPOSITORY",
		"GITHUB_REPOSITORY_ID",
		"GITHUB_REPOSITORY_OWNER",
		"GITHUB_REPOSITORY_OWNER_ID",
		"GITHUB_RUN_ATTEMPT",
		"GITHUB_RUN_ID",
		"GITHUB_RUN_NUMBER",
		"GITHUB_SERVER_URL",
		"GITHUB_SHA",
		"GITHUB_STEP_SUMMARY",
		"GITHUB_WORKSPACE",
		"RUNNER_ARCH",
		"RUNNER_DEBUG",
		"RUNNER_NAME",
		"RUNNER_OS",
		"RUNNER_TEMP",
		"RUNNER_TOOL_CACHE",
	}

	for _, defaultVar := range defaultEnvVars {
		if envVar == defaultVar {
			return true
		}
	}
	return false
}

// matchesPattern checks if a string matches a pattern with wildcards
func matchesPattern(str, pattern string) bool {
	// Simple pattern matching with * wildcards
	// Convert pattern to regex
	regexPattern := strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, `[^.]*`)
	regexPattern = "^" + regexPattern + "$"

	matched, err := regexp.MatchString(regexPattern, str)
	if err != nil {
		return false
	}
	return matched
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

// isInVulnerableContext checks if the current path is within a context that can be vulnerable to expression injection
func (r *ExpressionInjectionRule) isInVulnerableContext(path []string) bool {
	if len(path) == 0 {
		return false
	}

	// Get the last element in the path (the field name)
	fieldName := path[len(path)-1]

	// High-risk contexts (direct command execution or path manipulation)
	highRiskFields := []string{
		"run",               // Shell command execution
		"shell",             // Shell selection
		"entrypoint",        // Docker entrypoint
		"pre-entrypoint",    // Docker pre-entrypoint
		"post-entrypoint",   // Docker post-entrypoint
		"working-directory", // Working directory path
	}

	for _, field := range highRiskFields {
		if fieldName == field {
			return true
		}
	}

	// Medium-risk contexts (logic control and action inputs)
	mediumRiskFields := []string{
		"if", // Conditional logic
	}

	for _, field := range mediumRiskFields {
		if fieldName == field {
			return true
		}
	}

	// Check for 'with' context (action inputs) - needs parent context check
	if fieldName == "with" || r.isWithinWithContext(path) {
		return true
	}

	// Check for 'args' in Docker context
	if fieldName == "args" && r.isDockerContext(path) {
		return true
	}

	return false
}

// isWithinWithContext checks if we're within a 'with' block (action inputs)
func (r *ExpressionInjectionRule) isWithinWithContext(path []string) bool {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == "with" {
			return true
		}
	}
	return false
}

// isDockerContext checks if we're in a Docker action context
func (r *ExpressionInjectionRule) isDockerContext(path []string) bool {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == "runs" {
			// Look for Docker-specific fields in the path
			for j := i; j < len(path); j++ {
				if path[j] == "image" || path[j] == "entrypoint" {
					return true
				}
			}
		}
	}
	return false
}

// getContextRiskLevel determines the risk level based on the field context
func (r *ExpressionInjectionRule) getContextRiskLevel(path []string) string {
	if len(path) == 0 {
		return "unknown"
	}

	fieldName := path[len(path)-1]

	// High-risk contexts
	highRiskFields := []string{"run", "shell", "entrypoint", "pre-entrypoint", "post-entrypoint", "working-directory"}
	for _, field := range highRiskFields {
		if fieldName == field {
			return "command-execution"
		}
	}

	// Docker args context
	if fieldName == "args" && r.isDockerContext(path) {
		return "command-execution"
	}

	// Medium-risk contexts
	if fieldName == "if" {
		return "logic-control"
	}

	if fieldName == "with" || r.isWithinWithContext(path) {
		return "action-input"
	}

	return "unknown"
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

	// Check string nodes in vulnerable contexts (expanded beyond just run blocks)
	switch n := node.(type) {
	case *ast.StringNode:
		if strings.Contains(n.Value, "${{") && rule.isInVulnerableContext(path) {
			rule.addExpressionInjectionFinding(n, path, filePath, findings)
		}
	case *ast.LiteralNode:
		if strings.Contains(n.String(), "${{") && rule.isInVulnerableContext(path) {
			rule.addExpressionInjectionFinding(n, path, filePath, findings)
		}
	case *ast.SequenceNode:
		// Handle arrays (like Docker args)
		if rule.isInVulnerableContext(path) {
			for _, item := range n.Values {
				switch itemNode := item.(type) {
				case *ast.StringNode:
					if strings.Contains(itemNode.Value, "${{") {
						rule.addExpressionInjectionFinding(itemNode, path, filePath, findings)
					}
				case *ast.LiteralNode:
					if strings.Contains(itemNode.String(), "${{") {
						rule.addExpressionInjectionFinding(itemNode, path, filePath, findings)
					}
				}
			}
		}
	}
}

// addExpressionInjectionFinding creates and adds a finding for expression injection with context analysis
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

	// Extract and analyze all expressions in the value
	expressions := r.extractExpressions(value)

	// Get the context risk level for better messaging
	contextRisk := r.getContextRiskLevel(path)
	contextField := path[len(path)-1]

	for _, expr := range expressions {
		// Analyze the expression context
		exprCtx := r.analyzeExpressionContext(expr)
		if exprCtx == nil {
			// Skip fixed/safe contexts
			continue
		}

		// Create context-specific message
		var message string
		switch contextRisk {
		case "command-execution":
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s) - risk of command injection",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		case "logic-control":
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s) - risk of workflow logic manipulation",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		case "action-input":
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s) - risk depends on action implementation",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		default:
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s)",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		}

		// Create rule for this finding with context-specific severity
		findingRule := &types.Rule{
			Category: CategoryExpressionInjection,
			Severity: exprCtx.Severity,
			Message:  message,
			Type:     types.RuleTypeAST,
		}

		// Use unified finding creation
		finding := types.NewFindingFromAST(
			findingRule,
			filePath,
			node,
			path,
			0, // Column will be computed by NewFindingFromAST
			0, // Line will be computed by NewFindingFromAST
			len(exprCtx.Raw),
		)

		*findings = append(*findings, finding)
		r.Findings = append(r.Findings, finding)
	}
}

// capabilityString returns a string representation of ContextCapability
func (r *ExpressionInjectionRule) capabilityString(capability ContextCapability) string {
	switch capability {
	case Fixed:
		return "fixed"
	case Structured:
		return "structured"
	case Arbitrary:
		return "arbitrary"
	default:
		return "unknown"
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
	// Find all vulnerable blocks with expressions (run, shell, if, etc.)
	vulnerableBlocks := r.findVulnerableBlocksWithExpressions(doc)

	// Process each vulnerable block
	for _, block := range vulnerableBlocks {
		r.RunBlock = block
		r.Expressions = block.Expressions

		// Create findings for this block
		r.createFindingsForRunBlock(block, filePath)
	}
}

// findVulnerableBlocksWithExpressions finds all vulnerable blocks containing expressions
func (r *ExpressionInjectionRule) findVulnerableBlocksWithExpressions(node ast.Node) []*RunBlockInfo {
	var vulnerableBlocks []*RunBlockInfo
	r.traverseForVulnerableBlocks(node, []string{}, &vulnerableBlocks)
	return vulnerableBlocks
}

// findRunBlocksWithExpressions finds all run blocks containing expressions (kept for compatibility)
func (r *ExpressionInjectionRule) findRunBlocksWithExpressions(node ast.Node) []*RunBlockInfo {
	var runBlocks []*RunBlockInfo
	r.traverseForRunBlocks(node, []string{}, &runBlocks)
	return runBlocks
}

// traverseForVulnerableBlocks recursively traverses the AST to find vulnerable blocks
func (r *ExpressionInjectionRule) traverseForVulnerableBlocks(node ast.Node, path []string, blocks *[]*RunBlockInfo) {
	if node == nil {
		return
	}

	switch n := node.(type) {
	case *ast.MappingNode:
		r.traverseMappingForVulnerableBlocks(n, path, blocks)
	case *ast.SequenceNode:
		r.traverseSequenceForVulnerableBlocks(n, path, blocks)
	case *ast.DocumentNode:
		if n.Body != nil {
			r.traverseForVulnerableBlocks(n.Body, path, blocks)
		}
	}
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

// traverseMappingForVulnerableBlocks processes mapping nodes to find vulnerable blocks
func (r *ExpressionInjectionRule) traverseMappingForVulnerableBlocks(node *ast.MappingNode, path []string, blocks *[]*RunBlockInfo) {
	for i := 0; i < len(node.Values); i++ {
		key := node.Values[i].Key
		value := node.Values[i].Value

		if key == nil || value == nil {
			continue
		}

		currentPath := append(path, key.String())

		// Check if this is a vulnerable field
		if r.isInVulnerableContext(currentPath) {
			if blockInfo := r.extractVulnerableBlockInfo(value, currentPath); blockInfo != nil {
				*blocks = append(*blocks, blockInfo)
			}
		}

		// Recursively traverse child nodes
		r.traverseForVulnerableBlocks(value, currentPath, blocks)
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

// traverseSequenceForVulnerableBlocks processes sequence nodes for vulnerable blocks
func (r *ExpressionInjectionRule) traverseSequenceForVulnerableBlocks(node *ast.SequenceNode, path []string, blocks *[]*RunBlockInfo) {
	for i, value := range node.Values {
		currentPath := append(path, fmt.Sprintf("%d", i))
		r.traverseForVulnerableBlocks(value, currentPath, blocks)
	}
}

// traverseSequenceForRunBlocks processes sequence nodes
func (r *ExpressionInjectionRule) traverseSequenceForRunBlocks(node *ast.SequenceNode, path []string, runBlocks *[]*RunBlockInfo) {
	for i, value := range node.Values {
		currentPath := append(path, fmt.Sprintf("%d", i))
		r.traverseForRunBlocks(value, currentPath, runBlocks)
	}
}

// extractVulnerableBlockInfo extracts information from a vulnerable block node
func (r *ExpressionInjectionRule) extractVulnerableBlockInfo(node ast.Node, path []string) *RunBlockInfo {
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

	// Check if this block contains expressions
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

// createFindingsForRunBlock creates findings for a specific run block with context analysis
func (r *ExpressionInjectionRule) createFindingsForRunBlock(runBlock *RunBlockInfo, filePath string) {
	// Get the context risk level for better messaging
	contextRisk := r.getContextRiskLevel(runBlock.Path)
	contextField := runBlock.Path[len(runBlock.Path)-1]

	// Create a finding for each expression with context analysis
	for _, expr := range runBlock.Expressions {
		// Analyze the expression context
		exprCtx := r.analyzeExpressionContext(expr)
		if exprCtx == nil {
			// Skip fixed/safe contexts
			continue
		}

		// Create context-specific message
		var message string
		switch contextRisk {
		case "command-execution":
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s) - risk of command injection",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		case "logic-control":
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s) - risk of workflow logic manipulation",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		case "action-input":
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s) - risk depends on action implementation",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		default:
			message = fmt.Sprintf("Potentially unsafe expression in %s field: %s (capability: %s)",
				contextField, exprCtx.Context, r.capabilityString(exprCtx.Capability))
		}

		rule := &types.Rule{
			Category: CategoryExpressionInjection,
			Severity: exprCtx.Severity,
			Message:  message,
			Type:     types.RuleTypeAST,
		}

		finding := types.NewFindingFromAST(
			rule,
			filePath,
			runBlock.Node,
			runBlock.Path,
			runBlock.Column,
			runBlock.Line,
			len(exprCtx.Raw),
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

// createPatchesForRunBlock creates yaml_patch operations for a run block with context filtering
func (r *ExpressionInjectionRule) createPatchesForRunBlock(runBlock *RunBlockInfo, content string) ([]yaml_patch.Patch, error) {
	patches := make([]yaml_patch.Patch, 0)

	// Create environment variables only for expressions that are flagged as unsafe
	envVariables := make(map[string]string)
	unsafeExpressions := make([]string, 0)

	for _, expr := range runBlock.Expressions {
		// Analyze the expression context to determine if it's unsafe
		exprCtx := r.analyzeExpressionContext(expr)
		if exprCtx == nil {
			// Skip fixed/safe contexts
			continue
		}

		// Only create fixes for unsafe expressions
		envName := r.toEnvName(expr)
		envVariables[envName] = fmt.Sprintf("${{ %s }}", expr)
		unsafeExpressions = append(unsafeExpressions, expr)
	}

	// If no unsafe expressions, no patches needed
	if len(unsafeExpressions) == 0 {
		return patches, nil
	}

	// Build the path to the run block
	runPath := strings.Join(runBlock.Path, ".")
	// Build the path to the step (parent of run)
	stepPath := strings.Join(runBlock.Path[:len(runBlock.Path)-1], ".")

	// First, create patches for each unsafe expression replacement in the run block
	for _, expr := range unsafeExpressions {
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
				Pattern:  `(?m)^\s*(run|shell|entrypoint|working-directory):\s*.*\$\{\{\s*(inputs\.[\w\.]+|github\.event\.[\w\.]+|vars\.[\w\.]+)\s*\}\}`,
				Severity: types.SeverityHigh,
				Message:  "Untrusted input expression in command execution context - potential injection vulnerability",
				Type:     types.RuleTypePattern,
			},
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*if:\s*.*\$\{\{\s*(inputs\.[\w\.]+|github\.event\.[\w\.]+|github\.actor)\s*\}\}`,
				Severity: types.SeverityMedium,
				Message:  "Untrusted input expression in conditional logic - potential workflow manipulation",
				Type:     types.RuleTypePattern,
			},
			{
				Category: CategoryExpressionInjection,
				Pattern:  `(?m)^\s*with:\s*\n.*\$\{\{\s*(inputs\.[\w\.]+|github\.event\.[\w\.]+|github\.actor)\s*\}\}`,
				Severity: types.SeverityMedium,
				Message:  "Untrusted input expression in action inputs - security risk depends on action implementation",
				Type:     types.RuleTypePattern,
			},
		},
	}
}
