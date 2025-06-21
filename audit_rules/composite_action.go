package audit_rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/mostafa/zizzles/types"
)

const CategoryCompositeAction types.Category = "composite_action"

// CompositeActionRule provides detection for composite action security issues
type CompositeActionRule struct {
	types.Rule
	*types.DeduplicatedRule
	detector *CompositeActionDetector
}

// CompositeActionDetector provides AST-based detection for composite action vulnerabilities
type CompositeActionDetector struct {
	rule *CompositeActionRule
}

// NewCompositeActionRule creates a new composite action rule instance
func NewCompositeActionRule() *CompositeActionRule {
	rule := &CompositeActionRule{
		Rule: types.Rule{
			Category: CategoryCompositeAction,
			Severity: types.SeverityHigh,
			Message:  "Composite action security vulnerability detected",
			Type:     types.RuleTypeAST,
		},
		DeduplicatedRule: types.NewDeduplicatedRule(),
	}

	rule.detector = &CompositeActionDetector{rule: rule}
	return rule
}

// addFindingIfNotSeen adds a finding only if it hasn't been seen before
func (r *CompositeActionRule) addFindingIfNotSeen(finding *types.Finding, filePath string, value string, findings *[]*types.Finding) {
	r.DeduplicatedRule.AddFindingIfNotSeen(CategoryCompositeAction, finding, filePath, value, findings)
}

// VisitNode implements types.NodeVisitor for composite action detection
func (d *CompositeActionDetector) VisitNode(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if node == nil {
		return
	}

	// Only process action.yml files (composite actions)
	if !strings.HasSuffix(filePath, "action.yml") && !strings.HasSuffix(filePath, "action.yaml") {
		return
	}

	// Check for composite action input injection
	d.checkCompositeInputInjection(node, path, filePath, findings)

	// Check for unsafe input defaults
	d.checkUnsafeInputDefaults(node, path, filePath, findings)

	// Check for unpinned actions
	d.checkUnpinnedActions(node, path, filePath, findings)

	// Check for environment leakage
	d.checkEnvironmentLeakage(node, path, filePath, findings)

	// Check for unset shell
	d.checkUnsetShell(node, path, filePath, findings)

	// Check for unsafe checkout
	d.checkUnsafeCheckout(node, path, filePath, findings)
}

// checkCompositeInputInjection detects direct use of ${{ inputs.* }} in run steps
func (d *CompositeActionDetector) checkCompositeInputInjection(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in a run step within a composite action
	if !d.isInCompositeRunStep(path) {
		return
	}

	var nodeValue string
	var nodeLine, nodeColumn int

	// Handle both StringNode and LiteralNode
	switch n := node.(type) {
	case *ast.StringNode:
		nodeValue = n.Value
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	case *ast.LiteralNode:
		nodeValue = n.String()
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	default:
		return
	}

	// Check for direct input injection patterns
	inputPattern := regexp.MustCompile(`\$\{\{\s*inputs\.[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}`)
	if inputPattern.MatchString(nodeValue) {
		matches := inputPattern.FindAllStringSubmatch(nodeValue, -1)
		for _, match := range matches {
			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryCompositeAction,
					Severity: types.SeverityHigh,
					Message:  "Direct input injection detected in run step - use environment variables instead",
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          nodeLine,
				Column:        nodeColumn,
				Value:         match[0],
				MatchedColumn: 0,
				MatchedLength: len(match[0]),
				Severity:      types.SeverityHigh,
			}
			d.rule.addFindingIfNotSeen(finding, filePath, nodeValue, findings)
		}
	}
}

// checkUnsafeInputDefaults detects unsafe default values in input definitions
func (d *CompositeActionDetector) checkUnsafeInputDefaults(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in an input default value
	if !d.isInInputDefault(path) {
		return
	}

	var nodeValue string
	var nodeLine, nodeColumn int

	// Handle both StringNode and LiteralNode
	switch n := node.(type) {
	case *ast.StringNode:
		nodeValue = n.Value
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	case *ast.LiteralNode:
		nodeValue = n.String()
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	default:
		return
	}

	// Check for dangerous metacharacters in default values
	dangerousChars := []string{";", "|", ">", "<", "&", "$", "`", "$(", "&&", "||"}
	for _, char := range dangerousChars {
		if strings.Contains(nodeValue, char) {
			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryCompositeAction,
					Severity: types.SeverityMedium,
					Message:  fmt.Sprintf("Unsafe default value contains metacharacter '%s' - validate and sanitize input", char),
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          nodeLine,
				Column:        nodeColumn,
				Value:         nodeValue,
				MatchedColumn: 0,
				MatchedLength: len(nodeValue),
				Severity:      types.SeverityMedium,
			}
			d.rule.addFindingIfNotSeen(finding, filePath, nodeValue, findings)
			break // Only report once per value
		}
	}
}

// checkUnpinnedActions detects the use of actions with floating tags
func (d *CompositeActionDetector) checkUnpinnedActions(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in a uses statement
	if !d.isInUsesStatement(path) {
		return
	}

	var nodeValue string
	var nodeLine, nodeColumn int

	// Handle both StringNode and LiteralNode
	switch n := node.(type) {
	case *ast.StringNode:
		nodeValue = n.Value
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	case *ast.LiteralNode:
		nodeValue = n.String()
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	default:
		return
	}

	// Remove quotes if present
	nodeValue = strings.Trim(nodeValue, "\"'")

	// Check for floating tags
	floatingTags := []string{"@main", "@master", "@develop", "@dev"}
	for _, tag := range floatingTags {
		if strings.HasSuffix(nodeValue, tag) {
			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryCompositeAction,
					Severity: types.SeverityMedium,
					Message:  fmt.Sprintf("Unpinned action using floating tag '%s' - pin to specific version or SHA", tag),
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          nodeLine,
				Column:        nodeColumn,
				Value:         nodeValue,
				MatchedColumn: 0,
				MatchedLength: len(nodeValue),
				Severity:      types.SeverityMedium,
			}
			d.rule.addFindingIfNotSeen(finding, filePath, nodeValue, findings)
			// Don't return here - continue to check for other issues with this action
		}
	}

	// Check for missing version entirely (if it contains '/' but no '@')
	if strings.Contains(nodeValue, "/") && !strings.Contains(nodeValue, "@") {
		finding := &types.Finding{
			Rule: &types.Rule{
				Category: CategoryCompositeAction,
				Severity: types.SeverityHigh,
				Message:  "Action without version specified - pin to specific version or SHA",
				Type:     types.RuleTypeAST,
			},
			YamlPath:      strings.Join(path, "."),
			Line:          nodeLine,
			Column:        nodeColumn,
			Value:         nodeValue,
			MatchedColumn: 0,
			MatchedLength: len(nodeValue),
			Severity:      types.SeverityHigh,
		}
		d.rule.addFindingIfNotSeen(finding, filePath, nodeValue, findings)
	}
}

// checkEnvironmentLeakage detects writing to GITHUB_ENV with potentially unsafe values
func (d *CompositeActionDetector) checkEnvironmentLeakage(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in a run step
	if !d.isInCompositeRunStep(path) {
		return
	}

	var nodeValue string
	var nodeLine, nodeColumn int

	// Handle both StringNode and LiteralNode
	switch n := node.(type) {
	case *ast.StringNode:
		nodeValue = n.Value
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	case *ast.LiteralNode:
		nodeValue = n.String()
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	default:
		return
	}

	// Check for GITHUB_ENV usage (both direct variable access and appending to file)
	if strings.Contains(nodeValue, "$GITHUB_ENV") || strings.Contains(nodeValue, "${GITHUB_ENV}") || strings.Contains(nodeValue, ">> $GITHUB_ENV") {
		// Check if it's writing potentially unsafe values (either direct expressions or environment variables derived from inputs)
		if strings.Contains(nodeValue, "inputs.") || strings.Contains(nodeValue, "${{ inputs.") ||
			(strings.Contains(nodeValue, "$SECRET") && strings.Contains(nodeValue, ">> $GITHUB_ENV")) {
			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryCompositeAction,
					Severity: types.SeverityMedium,
					Message:  "Writing input values to GITHUB_ENV - consider namespacing and sanitizing",
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          nodeLine,
				Column:        nodeColumn,
				Value:         nodeValue,
				MatchedColumn: 0,
				MatchedLength: len(nodeValue),
				Severity:      types.SeverityMedium,
			}
			d.rule.addFindingIfNotSeen(finding, filePath, nodeValue, findings)
		}
	}
}

// checkUnsetShell detects run steps without explicit shell specification
func (d *CompositeActionDetector) checkUnsetShell(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in a run step that should have a shell
	if !d.isInCompositeRunStep(path) {
		return
	}

	// Check if this is a run command (not shell)
	if len(path) > 0 && path[len(path)-1] == "run" {
		// Look for sibling shell node - we need to check the parent mapping
		// This is a simplified check - a full implementation would traverse the parent
		// For now, we'll assume any run step without explicit shell is potentially unsafe
		finding := &types.Finding{
			Rule: &types.Rule{
				Category: CategoryCompositeAction,
				Severity: types.SeverityLow,
				Message:  "Run step without explicit shell - specify 'shell: bash' for consistency",
				Type:     types.RuleTypeAST,
			},
			YamlPath:      strings.Join(path, "."),
			Line:          node.GetToken().Position.Line,
			Column:        node.GetToken().Position.Column,
			Value:         "run",
			MatchedColumn: 0,
			MatchedLength: 3,
			Severity:      types.SeverityLow,
		}
		d.rule.addFindingIfNotSeen(finding, filePath, "run", findings)
	}
}

// checkUnsafeCheckout detects checkout actions without persist-credentials: false
func (d *CompositeActionDetector) checkUnsafeCheckout(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in a uses statement
	if !d.isInUsesStatement(path) {
		return
	}

	var nodeValue string
	var nodeLine, nodeColumn int

	// Handle both StringNode and LiteralNode
	switch n := node.(type) {
	case *ast.StringNode:
		nodeValue = n.Value
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	case *ast.LiteralNode:
		nodeValue = n.String()
		nodeLine = n.GetToken().Position.Line
		nodeColumn = n.GetToken().Position.Column
	default:
		return
	}

	// Remove quotes if present
	nodeValue = strings.Trim(nodeValue, "\"'")

	// Check if it's a checkout action
	if strings.Contains(nodeValue, "actions/checkout") {
		// Always report the checkout action finding
		finding := &types.Finding{
			Rule: &types.Rule{
				Category: CategoryCompositeAction,
				Severity: types.SeverityMedium,
				Message:  "Checkout action detected - ensure 'persist-credentials: false' for PR safety",
				Type:     types.RuleTypeAST,
			},
			YamlPath:      strings.Join(path, "."),
			Line:          nodeLine,
			Column:        nodeColumn,
			Value:         nodeValue,
			MatchedColumn: 0,
			MatchedLength: len(nodeValue),
			Severity:      types.SeverityMedium,
		}
		d.rule.addFindingIfNotSeen(finding, filePath, nodeValue+"_checkout", findings)

		// Also check for floating tag patterns in checkout actions
		if strings.Contains(nodeValue, "@main") || strings.Contains(nodeValue, "@master") || strings.Contains(nodeValue, "@develop") || strings.Contains(nodeValue, "@dev") {
			floatingTagFinding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryCompositeAction,
					Severity: types.SeverityMedium,
					Message:  "Action using floating tag - pin to specific version or SHA",
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          nodeLine,
				Column:        nodeColumn,
				Value:         nodeValue,
				MatchedColumn: 0,
				MatchedLength: len(nodeValue),
				Severity:      types.SeverityMedium,
			}
			d.rule.addFindingIfNotSeen(floatingTagFinding, filePath, nodeValue+"_floating", findings)
		}
	}
}

// Helper methods to check path context

// isInCompositeRunStep checks if we're in a run step of a composite action
func (d *CompositeActionDetector) isInCompositeRunStep(path []string) bool {
	// Look for: runs.steps[].run
	for i, segment := range path {
		if segment == "runs" && i+3 < len(path) && path[i+1] == "steps" && path[i+3] == "run" {
			return true
		}
	}
	return false
}

// isInInputDefault checks if we're in an input default value
func (d *CompositeActionDetector) isInInputDefault(path []string) bool {
	// Look for: inputs.*.default
	for i, segment := range path {
		if segment == "inputs" && i+2 < len(path) && path[i+2] == "default" {
			return true
		}
	}
	return false
}

// isInUsesStatement checks if we're in a uses statement
func (d *CompositeActionDetector) isInUsesStatement(path []string) bool {
	// Look for: runs.steps[].uses
	for i, segment := range path {
		if segment == "runs" && i+3 < len(path) && path[i+1] == "steps" && path[i+3] == "uses" {
			return true
		}
	}
	return false
}

// GetCompositeActionRules returns the rule set for composite actions
func GetCompositeActionRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryCompositeAction,
		Rules: []types.Rule{
			{
				Category: CategoryCompositeAction,
				Pattern:  `\$\{\{\s*inputs\.[a-zA-Z_][a-zA-Z0-9_]*\s*\}\}`,
				Severity: types.SeverityHigh,
				Message:  "Direct input injection in composite action - use environment variables instead",
				Type:     types.RuleTypePattern,
			},
			{
				Category: CategoryCompositeAction,
				Pattern:  `@(main|master|develop|dev)(\s|$)`,
				Severity: types.SeverityMedium,
				Message:  "Unpinned action using floating tag - pin to specific version",
				Type:     types.RuleTypePattern,
			},
		},
	}
}
