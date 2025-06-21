package audit_rules

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/mostafa/zizzles/types"
)

const CategoryRunsVersion types.Category = "runs_version"

// RunsVersionRule provides detection for deprecated or unsupported Node.js versions
type RunsVersionRule struct {
	types.Rule
	*types.DeduplicatedRule
	detector *RunsVersionDetector
}

// RunsVersionDetector provides AST-based detection for runs version vulnerabilities
type RunsVersionDetector struct {
	rule *RunsVersionRule
}

// Supported and deprecated Node.js versions
var (
	SupportedNodeVersions  = []string{"node16", "node20", "node21"}
	DeprecatedNodeVersions = []string{"node12", "node14"}
	UnknownNodeVersions    = []string{"node10", "node8", "node6", "node4"}
)

// NewRunsVersionRule creates a new runs version rule instance
func NewRunsVersionRule() *RunsVersionRule {
	rule := &RunsVersionRule{
		Rule: types.Rule{
			Category: CategoryRunsVersion,
			Severity: types.SeverityHigh,
			Message:  "Deprecated or unsupported Node.js version detected in runs configuration",
			Type:     types.RuleTypeAST,
		},
		DeduplicatedRule: types.NewDeduplicatedRule(),
	}

	rule.detector = &RunsVersionDetector{rule: rule}
	return rule
}

// addFindingIfNotSeen adds a finding only if it hasn't been seen before
func (r *RunsVersionRule) addFindingIfNotSeen(finding *types.Finding, filePath string, value string, findings *[]*types.Finding) {
	r.DeduplicatedRule.AddFindingIfNotSeen(CategoryRunsVersion, finding, filePath, value, findings)
}

// VisitNode implements types.NodeVisitor for runs version detection
func (d *RunsVersionDetector) VisitNode(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if node == nil {
		return
	}

	// Check for deprecated Node.js versions in runs.using
	d.checkDeprecatedNodeVersion(node, path, filePath, findings)

	// Check for unsupported Node.js versions in runs.using
	d.checkUnsupportedNodeVersion(node, path, filePath, findings)

	// Check for missing Node.js version specification
	d.checkMissingNodeVersion(node, path, filePath, findings)
}

// checkDeprecatedNodeVersion detects deprecated Node.js versions in runs.using
func (d *RunsVersionDetector) checkDeprecatedNodeVersion(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if !d.isInRunsUsingContext(path) {
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

	// Check if it's a deprecated Node.js version
	for _, deprecatedVersion := range DeprecatedNodeVersions {
		if nodeValue == deprecatedVersion {
			severity := types.SeverityHigh
			message := fmt.Sprintf("Deprecated Node.js version '%s' detected - use node16 or node20 instead", deprecatedVersion)

			if deprecatedVersion == "node12" {
				severity = types.SeverityCritical
				message = "Critical: Node.js 12 is end-of-life and no longer supported - use node16 or node20 instead"
			}

			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryRunsVersion,
					Severity: severity,
					Message:  message,
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          nodeLine,
				Column:        nodeColumn,
				Value:         nodeValue,
				MatchedColumn: 0,
				MatchedLength: len(nodeValue),
				Severity:      severity,
			}
			d.rule.addFindingIfNotSeen(finding, filePath, nodeValue, findings)
			return
		}
	}

	// Check if it's an unknown/very old Node.js version
	for _, unknownVersion := range UnknownNodeVersions {
		if nodeValue == unknownVersion {
			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryRunsVersion,
					Severity: types.SeverityCritical,
					Message:  fmt.Sprintf("Unsupported Node.js version '%s' detected - use node16 or node20 instead", unknownVersion),
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          nodeLine,
				Column:        nodeColumn,
				Value:         nodeValue,
				MatchedColumn: 0,
				MatchedLength: len(nodeValue),
				Severity:      types.SeverityCritical,
			}
			d.rule.addFindingIfNotSeen(finding, filePath, nodeValue, findings)
			return
		}
	}
}

// checkUnsupportedNodeVersion detects when a Node.js action doesn't use a supported version
func (d *RunsVersionDetector) checkUnsupportedNodeVersion(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if !d.isInRunsUsingContext(path) {
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

	// Skip if it's a known deprecated or unknown version (handled by other checks)
	for _, deprecatedVersion := range DeprecatedNodeVersions {
		if nodeValue == deprecatedVersion {
			return
		}
	}
	for _, unknownVersion := range UnknownNodeVersions {
		if nodeValue == unknownVersion {
			return
		}
	}

	// Check if it's a supported Node.js version
	isSupported := false
	for _, supportedVersion := range SupportedNodeVersions {
		if nodeValue == supportedVersion {
			isSupported = true
			break
		}
	}

	// If it looks like a Node.js version but isn't supported, flag it
	if strings.HasPrefix(nodeValue, "node") && !isSupported {
		finding := &types.Finding{
			Rule: &types.Rule{
				Category: CategoryRunsVersion,
				Severity: types.SeverityMedium,
				Message:  fmt.Sprintf("Unknown Node.js version '%s' detected - recommended versions are node16 or node20", nodeValue),
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

// checkMissingNodeVersion detects when runs configuration is missing a version specification
func (d *RunsVersionDetector) checkMissingNodeVersion(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in a runs context but missing the using field
	if d.isInRunsContext(path) && !d.hasUsingField(node) {
		if mappingNode, ok := node.(*ast.MappingNode); ok {
			// Look for main field to indicate this might be a JavaScript action
			hasMain := false
			for _, value := range mappingNode.Values {
				if keyNode, ok := value.Key.(*ast.StringNode); ok {
					if keyNode.Value == "main" {
						hasMain = true
						break
					}
				}
			}

			if hasMain {
				finding := &types.Finding{
					Rule: &types.Rule{
						Category: CategoryRunsVersion,
						Severity: types.SeverityMedium,
						Message:  "JavaScript action missing 'using' field - specify node16 or node20",
						Type:     types.RuleTypeAST,
					},
					YamlPath:      strings.Join(path, "."),
					Line:          mappingNode.GetToken().Position.Line,
					Column:        mappingNode.GetToken().Position.Column,
					Value:         "missing using field",
					MatchedColumn: 0,
					MatchedLength: 0,
					Severity:      types.SeverityMedium,
				}
				d.rule.addFindingIfNotSeen(finding, filePath, "missing using field", findings)
			}
		}
	}
}

// isInRunsUsingContext checks if the current path is within runs.using
func (d *RunsVersionDetector) isInRunsUsingContext(path []string) bool {
	if len(path) < 2 {
		return false
	}

	// Check if path ends with "runs" -> "using"
	return path[len(path)-2] == "runs" && path[len(path)-1] == "using"
}

// isInRunsContext checks if the current path is within runs configuration
func (d *RunsVersionDetector) isInRunsContext(path []string) bool {
	if len(path) == 0 {
		return false
	}

	// Check if path ends with "runs"
	return path[len(path)-1] == "runs"
}

// hasUsingField checks if a mapping node has a "using" field
func (d *RunsVersionDetector) hasUsingField(node ast.Node) bool {
	if mappingNode, ok := node.(*ast.MappingNode); ok {
		for _, value := range mappingNode.Values {
			if keyNode, ok := value.Key.(*ast.StringNode); ok {
				if keyNode.Value == "using" {
					return true
				}
			}
		}
	}
	return false
}

// GetRunsVersionRules returns the rule set for runs version checking
func GetRunsVersionRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryRunsVersion,
		Rules: []types.Rule{
			{
				Category: CategoryRunsVersion,
				Pattern:  `using:\s*(node12|node14|node10|node8|node6|node4)`,
				Severity: types.SeverityHigh,
				Message:  "Deprecated or unsupported Node.js version detected in runs configuration",
				Type:     types.RuleTypePattern,
			},
		},
	}
}
