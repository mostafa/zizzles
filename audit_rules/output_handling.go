package audit_rules

import (
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/mostafa/zizzles/types"
)

const CategoryOutputHandling types.Category = "output_handling"

// OutputHandlingRule provides detection for output handling and sensitive data issues
type OutputHandlingRule struct {
	types.Rule
	*types.DeduplicatedRule
	detector *OutputHandlingDetector
}

// OutputHandlingDetector provides AST-based detection for output handling vulnerabilities
type OutputHandlingDetector struct {
	rule *OutputHandlingRule
}

// NewOutputHandlingRule creates a new output handling rule instance
func NewOutputHandlingRule() *OutputHandlingRule {
	rule := &OutputHandlingRule{
		Rule: types.Rule{
			Category: CategoryOutputHandling,
			Severity: types.SeverityMedium,
			Message:  "Output handling security issue detected",
			Type:     types.RuleTypeAST,
		},
		DeduplicatedRule: types.NewDeduplicatedRule(),
	}

	rule.detector = &OutputHandlingDetector{rule: rule}
	return rule
}

// addFindingIfNotSeen adds a finding only if it hasn't been seen before
func (r *OutputHandlingRule) addFindingIfNotSeen(finding *types.Finding, filePath string, value string, findings *[]*types.Finding) {
	r.DeduplicatedRule.AddFindingIfNotSeen(CategoryOutputHandling, finding, filePath, value, findings)
}

// VisitNode implements types.NodeVisitor for output handling detection
func (d *OutputHandlingDetector) VisitNode(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if node == nil {
		return
	}

	// Check for deprecated set-output command
	d.checkDeprecatedSetOutput(node, path, filePath, findings)

	// Check for output sanitization issues
	d.checkOutputSanitization(node, path, filePath, findings)

	// Check for unescaped output leak
	d.checkUnescapedOutputLeak(node, path, filePath, findings)

	// Check for output schema missing description
	d.checkOutputSchemaDescription(node, path, filePath, findings)

	// Check for unsafe use of output in shell
	d.checkUnsafeOutputInShell(node, path, filePath, findings)

	// Check for output uses secret without transformation
	d.checkOutputUsesSecret(node, path, filePath, findings)

	// Check for output uses user input directly
	d.checkOutputUsesUserInput(node, path, filePath, findings)

	// Check for GitHub token exposure
	d.checkGitHubTokenExposure(node, path, filePath, findings)
}

// checkDeprecatedSetOutput detects deprecated ::set-output command usage
func (d *OutputHandlingDetector) checkDeprecatedSetOutput(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if strNode, ok := node.(*ast.StringNode); ok {
		// Check for echo "::set-output usage
		setOutputPattern := `echo\s+"::set-output`
		if matched, _ := regexp.MatchString(setOutputPattern, strNode.Value); matched {
			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryOutputHandling,
					Severity: types.SeverityHigh,
					Message:  "Deprecated ::set-output command detected - use $GITHUB_OUTPUT instead",
					Type:     types.RuleTypeAST,
				},
				YamlPath:      strings.Join(path, "."),
				Line:          strNode.GetToken().Position.Line,
				Column:        strNode.GetToken().Position.Column,
				Value:         strNode.Value,
				MatchedColumn: 0,
				MatchedLength: len(strNode.Value),
				Severity:      types.SeverityHigh,
			}
			d.rule.addFindingIfNotSeen(finding, filePath, strNode.Value, findings)
		}
	}
}

// checkOutputSanitization detects output sanitization issues
func (d *OutputHandlingDetector) checkOutputSanitization(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
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

	// Check if this is a variable assignment pattern (which is generally safe)
	// Pattern: VARIABLE="${{ ... }}" or VARIABLE='${{ ... }}'
	isVariableAssignment := regexp.MustCompile(`^\s*[A-Z_][A-Z0-9_]*=["']\$\{\{\s*[^}]*\s*\}\}["']`).MatchString(nodeValue)

	if isVariableAssignment {
		// This is a safe pattern - variable assignment, not direct usage
		return
	}

	// Look for patterns that suggest unsanitized output
	unsanitizedPatterns := []string{
		`echo\s+"[^"]*\$\{\{\s*[^}]*\}\}[^"]*"`,              // Direct echo with expressions
		`echo\s+"[^"]*\$\{\{\s*[^}]*\}\}[^"]*";`,             // Echo with expression followed by semicolon
		`\$\{\{\s*[^}]*\}\}[^"']*;\s*echo`,                   // Expression followed by semicolon and another echo
		`echo\s+\$\{\{\s*[^}]*\}\}[^"']*;`,                   // Unquoted expression in echo followed by semicolon
		`\$\{\{\s*[^}]*\}\}[^"']*;\s*[a-zA-Z_][a-zA-Z0-9_]*`, // Expression followed by semicolon and command
	}

	for _, pattern := range unsanitizedPatterns {
		if matched, _ := regexp.MatchString(pattern, nodeValue); matched {
			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryOutputHandling,
					Severity: types.SeverityMedium,
					Message:  "Potential output sanitization issue - ensure special characters are escaped",
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
			break
		}
	}
}

// checkUnescapedOutputLeak detects potential sensitive data leakage in outputs
func (d *OutputHandlingDetector) checkUnescapedOutputLeak(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if strNode, ok := node.(*ast.StringNode); ok {
		// Check if we're in an outputs context and look for sensitive patterns
		if d.isInOutputsContext(path) {
			sensitivePatterns := []string{
				`\$\{\{\s*secrets\.`,              // Direct secret usage
				`\$\{\{\s*github\.token\s*\}\}`,   // GitHub token
				`\$\{\{\s*[^}]*password[^}]*\}\}`, // Password-like variables
				`\$\{\{\s*[^}]*key[^}]*\}\}`,      // Key-like variables
			}

			for _, pattern := range sensitivePatterns {
				if matched, _ := regexp.MatchString(pattern, strNode.Value); matched {
					// Determine severity based on pattern
					severity := types.SeverityHigh
					if strings.Contains(pattern, "secrets\\.") {
						severity = types.SeverityCritical
					}

					finding := &types.Finding{
						Rule: &types.Rule{
							Category: CategoryOutputHandling,
							Severity: severity,
							Message:  "Potential sensitive data leak in output - avoid exposing secrets or tokens",
							Type:     types.RuleTypeAST,
						},
						YamlPath:      strings.Join(path, "."),
						Line:          strNode.GetToken().Position.Line,
						Column:        strNode.GetToken().Position.Column,
						Value:         strNode.Value,
						MatchedColumn: 0,
						MatchedLength: len(strNode.Value),
						Severity:      severity,
					}
					d.rule.addFindingIfNotSeen(finding, filePath, strNode.Value, findings)
					break
				}
			}
		}
	}
}

// checkOutputSchemaDescription checks for missing or inadequate output descriptions
func (d *OutputHandlingDetector) checkOutputSchemaDescription(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	// Check if we're in an output definition context
	if d.isInOutputDefinitionContext(path) {
		switch n := node.(type) {
		case *ast.MappingNode:
			// Full output definition with description field
			hasDescription := false
			var descriptionNode *ast.StringNode

			for _, pair := range n.Values {
				if keyNode, ok := pair.Key.(*ast.StringNode); ok && keyNode.Value == "description" {
					hasDescription = true
					if strNode, ok := pair.Value.(*ast.StringNode); ok {
						descriptionNode = strNode
					}
					break
				}
			}

			if !hasDescription {
				finding := &types.Finding{
					Rule: &types.Rule{
						Category: CategoryOutputHandling,
						Severity: types.SeverityLow,
						Message:  "Output definition missing description - add clear documentation",
						Type:     types.RuleTypeAST,
					},
					YamlPath:      strings.Join(path, "."),
					Line:          n.GetToken().Position.Line,
					Column:        n.GetToken().Position.Column,
					Value:         n.String(),
					MatchedColumn: 0,
					MatchedLength: len(n.String()),
					Severity:      types.SeverityLow,
				}
				d.rule.addFindingIfNotSeen(finding, filePath, n.String(), findings)
			} else if descriptionNode != nil {
				// Check for vague or inadequate descriptions
				vague := []string{"string", "value", "result", "output"}
				desc := strings.ToLower(descriptionNode.Value)
				for _, v := range vague {
					if desc == v || desc == "a "+v || desc == "the "+v {
						finding := &types.Finding{
							Rule: &types.Rule{
								Category: CategoryOutputHandling,
								Severity: types.SeverityInfo,
								Message:  "Output description is too vague - provide format and usage details",
								Type:     types.RuleTypeAST,
							},
							YamlPath:      strings.Join(path, "."),
							Line:          descriptionNode.GetToken().Position.Line,
							Column:        descriptionNode.GetToken().Position.Column,
							Value:         descriptionNode.Value,
							MatchedColumn: 0,
							MatchedLength: len(descriptionNode.Value),
							Severity:      types.SeverityInfo,
						}
						d.rule.addFindingIfNotSeen(finding, filePath, descriptionNode.Value, findings)
						break
					}
				}
			}
		case *ast.StringNode:
			// Shorthand syntax: output_name: ${{ ... }} - missing description
			if len(path) >= 2 && path[len(path)-2] == "outputs" {
				finding := &types.Finding{
					Rule: &types.Rule{
						Category: CategoryOutputHandling,
						Severity: types.SeverityLow,
						Message:  "Output definition missing description - add clear documentation",
						Type:     types.RuleTypeAST,
					},
					YamlPath:      strings.Join(path, "."),
					Line:          n.GetToken().Position.Line,
					Column:        n.GetToken().Position.Column,
					Value:         n.Value,
					MatchedColumn: 0,
					MatchedLength: len(n.Value),
					Severity:      types.SeverityLow,
				}
				d.rule.addFindingIfNotSeen(finding, filePath, n.Value, findings)
			}
		}
	}
}

// checkUnsafeOutputInShell detects unsafe usage of outputs in shell commands
func (d *OutputHandlingDetector) checkUnsafeOutputInShell(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if strNode, ok := node.(*ast.StringNode); ok {
		// Check if we're in a run context
		if d.isInRunContext(path) {
			// Look for unquoted output usage in shell commands
			unsafePatterns := []string{
				`\$\{\{\s*steps\.[^}]+\.outputs\.[^}]+\s*\}\}(?!["])`,             // Unquoted steps output usage
				`echo\s+\$\{\{\s*steps\.[^}]+\.outputs\.[^}]+\s*\}\}`,             // Direct echo without quotes
				`\$\{\{\s*needs\.[^}]+\.outputs\.[^}]+\s*\}\}(?!["])`,             // Unquoted needs output usage
				`echo\s+\$\{\{\s*needs\.[^}]+\.outputs\.[^}]+\s*\}\}`,             // Direct echo of needs output
				`echo\s+"[^"]+\$\{\{\s*needs\.[^}]+\.outputs\.[^}]+\s*\}\}[^"]*"`, // Quoted needs output with prefix
				`echo\s+"[^"]*\$\{\{\s*needs\.[^}]+\.outputs\.[^}]+\s*\}\}[^"]+"`, // Quoted needs output with suffix
				`echo\s+"[^"]+\$\{\{\s*steps\.[^}]+\.outputs\.[^}]+\s*\}\}[^"]*"`, // Quoted steps output with prefix
				`echo\s+"[^"]*\$\{\{\s*steps\.[^}]+\.outputs\.[^}]+\s*\}\}[^"]+"`, // Quoted steps output with suffix
			}

			for _, pattern := range unsafePatterns {
				if matched, _ := regexp.MatchString(pattern, strNode.Value); matched {
					finding := &types.Finding{
						Rule: &types.Rule{
							Category: CategoryOutputHandling,
							Severity: types.SeverityMedium,
							Message:  "Unsafe output usage in shell - wrap outputs in quotes to prevent injection",
							Type:     types.RuleTypeAST,
						},
						YamlPath:      strings.Join(path, "."),
						Line:          strNode.GetToken().Position.Line,
						Column:        strNode.GetToken().Position.Column,
						Value:         strNode.Value,
						MatchedColumn: 0,
						MatchedLength: len(strNode.Value),
						Severity:      types.SeverityMedium,
					}
					d.rule.addFindingIfNotSeen(finding, filePath, strNode.Value, findings)
					break
				}
			}
		}
	}
}

// checkOutputUsesSecret detects outputs that directly use secrets without transformation
func (d *OutputHandlingDetector) checkOutputUsesSecret(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if strNode, ok := node.(*ast.StringNode); ok {
		if d.isInOutputsContext(path) {
			// Check for direct secret usage in outputs
			directSecretPattern := `^\s*\$\{\{\s*secrets\.[^}]+\s*\}\}\s*$`
			if matched, _ := regexp.MatchString(directSecretPattern, strNode.Value); matched {
				finding := &types.Finding{
					Rule: &types.Rule{
						Category: CategoryOutputHandling,
						Severity: types.SeverityCritical,
						Message:  "Output directly exposes secret without transformation - this is a security risk",
						Type:     types.RuleTypeAST,
					},
					YamlPath:      strings.Join(path, "."),
					Line:          strNode.GetToken().Position.Line,
					Column:        strNode.GetToken().Position.Column,
					Value:         strNode.Value,
					MatchedColumn: 0,
					MatchedLength: len(strNode.Value),
					Severity:      types.SeverityCritical,
				}
				d.rule.addFindingIfNotSeen(finding, filePath, strNode.Value, findings)
			}
		}
	}
}

// checkOutputUsesUserInput detects outputs that directly use user-controlled input
func (d *OutputHandlingDetector) checkOutputUsesUserInput(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if strNode, ok := node.(*ast.StringNode); ok {
		if d.isInOutputsContext(path) {
			// Check for direct user input usage in outputs
			userInputPatterns := []string{
				`\$\{\{\s*github\.event\.issue\.title\s*\}\}`,
				`\$\{\{\s*github\.event\.issue\.body\s*\}\}`,
				`\$\{\{\s*github\.event\.pull_request\.title\s*\}\}`,
				`\$\{\{\s*github\.event\.pull_request\.body\s*\}\}`,
				`\$\{\{\s*github\.event\.comment\.body\s*\}\}`,
				`\$\{\{\s*github\.actor\s*\}\}`,
				`\$\{\{\s*github\.head_ref\s*\}\}`,
				`\$\{\{\s*inputs\.user_input\s*\}\}`, // Include direct input usage
			}

			for _, pattern := range userInputPatterns {
				if matched, _ := regexp.MatchString(pattern, strNode.Value); matched {
					finding := &types.Finding{
						Rule: &types.Rule{
							Category: CategoryOutputHandling,
							Severity: types.SeverityMedium,
							Message:  "Output uses user-controlled input directly - validate and sanitize before outputting",
							Type:     types.RuleTypeAST,
						},
						YamlPath:      strings.Join(path, "."),
						Line:          strNode.GetToken().Position.Line,
						Column:        strNode.GetToken().Position.Column,
						Value:         strNode.Value,
						MatchedColumn: 0,
						MatchedLength: len(strNode.Value),
						Severity:      types.SeverityMedium,
					}
					d.rule.addFindingIfNotSeen(finding, filePath, strNode.Value, findings)
					break
				}
			}
		}
	}
}

// checkGitHubTokenExposure detects outputs that expose GitHub tokens
func (d *OutputHandlingDetector) checkGitHubTokenExposure(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if strNode, ok := node.(*ast.StringNode); ok {
		if d.isInOutputsContext(path) {
			// Check for GitHub token usage in outputs
			tokenPattern := `\$\{\{\s*github\.token\s*\}\}`
			if matched, _ := regexp.MatchString(tokenPattern, strNode.Value); matched {
				finding := &types.Finding{
					Rule: &types.Rule{
						Category: CategoryOutputHandling,
						Severity: types.SeverityHigh,
						Message:  "Output exposes GitHub token - this is a security risk",
						Type:     types.RuleTypeAST,
					},
					YamlPath:      strings.Join(path, "."),
					Line:          strNode.GetToken().Position.Line,
					Column:        strNode.GetToken().Position.Column,
					Value:         strNode.Value,
					MatchedColumn: 0,
					MatchedLength: len(strNode.Value),
					Severity:      types.SeverityHigh,
				}
				d.rule.addFindingIfNotSeen(finding, filePath, strNode.Value, findings)
			}
		}
	}
}

// isInOutputsContext checks if the current path is within an outputs definition
func (d *OutputHandlingDetector) isInOutputsContext(path []string) bool {
	// Check for both top-level outputs and job-level outputs
	for i, part := range path {
		if part == "outputs" {
			return true
		}
		// Also check for jobs.job_name.outputs pattern
		if part == "jobs" && i+2 < len(path) && path[i+2] == "outputs" {
			return true
		}
	}
	return false
}

// isInOutputDefinitionContext checks if we're in a specific output definition
func (d *OutputHandlingDetector) isInOutputDefinitionContext(path []string) bool {
	if len(path) < 2 {
		return false
	}

	// Look for patterns like: outputs.output_name or jobs.job_name.outputs.output_name
	for i := 0; i < len(path)-1; i++ {
		if path[i] == "outputs" && i+1 < len(path) {
			// We're in an output definition if we have outputs.something
			return true
		}
	}
	return false
}

// isInRunContext checks if the current path is within a run block
func (d *OutputHandlingDetector) isInRunContext(path []string) bool {
	if len(path) == 0 {
		return false
	}
	return path[len(path)-1] == "run"
}

// GetOutputHandlingRules returns the rule set for output handling
func GetOutputHandlingRules() types.RuleSet {
	rules := []types.Rule{
		// Keep only pattern rules that don't have AST equivalents
		// The AST rules handle secret detection, output context, etc. more accurately
	}

	return types.RuleSet{
		Category: CategoryOutputHandling,
		Rules:    rules,
	}
}
