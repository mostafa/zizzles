package audit_rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/mostafa/zizzles/types"
)

const CategoryDockerSecurity types.Category = "docker_security"

// DockerSecurityRule provides detection for Docker action security vulnerabilities
type DockerSecurityRule struct {
	types.Rule
	*types.DeduplicatedRule
	detector *DockerSecurityDetector
}

// DockerSecurityDetector provides AST-based detection for Docker security vulnerabilities
type DockerSecurityDetector struct {
	rule *DockerSecurityRule
}

// Docker security patterns
var (
	// Pinned image pattern: image:tag@sha256:hash (includes docker:// prefix)
	PinnedImageRegex = regexp.MustCompile(`^docker://.+(?::[^@]+)?@sha256:[a-fA-F0-9]{64}$`)

	// Unpinned dangerous patterns
	UnpinnedPatterns = []string{"latest", "main", "master", "develop"}

	// Minimal base images (preferred)
	MinimalBaseImages = []string{"alpine", "scratch", "distroless"}

	// Full OS images (should be avoided)
	FullOSImages = []string{"ubuntu", "debian", "centos", "fedora", "rhel"}

	// Development tools that shouldn't be in production images
	DevelopmentTools = []string{"curl", "wget", "git", "build-essential", "gcc", "make", "cmake"}
)

// NewDockerSecurityRule creates a new Docker security rule instance
func NewDockerSecurityRule() *DockerSecurityRule {
	rule := &DockerSecurityRule{
		Rule: types.Rule{
			Category: CategoryDockerSecurity,
			Severity: types.SeverityHigh,
			Message:  "Docker action security vulnerability detected",
			Type:     types.RuleTypeAST,
		},
		DeduplicatedRule: types.NewDeduplicatedRule(),
	}

	rule.detector = &DockerSecurityDetector{rule: rule}
	return rule
}

// addFindingIfNotSeen adds a finding only if it hasn't been seen before
func (r *DockerSecurityRule) addFindingIfNotSeen(finding *types.Finding, filePath string, value string, findings *[]*types.Finding) {
	// Docker security has custom key generation that includes message for better deduplication
	key := fmt.Sprintf("%s:%s:%d:%d:%s:%s:%s", string(CategoryDockerSecurity), filePath, finding.Line, finding.Column, value, finding.YamlPath, finding.Rule.Message)

	if r.DeduplicatedRule.GenerateFindingKey(CategoryDockerSecurity, filePath, finding.Line, finding.Column, value, finding.YamlPath) != key {
		// Use custom key for docker security due to message-based deduplication
		r.DeduplicatedRule.AddFindingIfNotSeen(CategoryDockerSecurity, finding, filePath, value+":"+finding.Rule.Message, findings)
	} else {
		r.DeduplicatedRule.AddFindingIfNotSeen(CategoryDockerSecurity, finding, filePath, value, findings)
	}
}

// VisitNode implements types.NodeVisitor for Docker security detection
func (d *DockerSecurityDetector) VisitNode(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	if node == nil {
		return
	}

	// Check for Docker image context (runs.image)
	if d.isDockerImageContext(path) {
		// For image context: check unpinned first, then non-minimal base images
		var nodeValue string
		switch n := node.(type) {
		case *ast.StringNode:
			nodeValue = n.Value
		case *ast.LiteralNode:
			nodeValue = n.String()
		default:
			return
		}

		nodeValue = strings.Trim(nodeValue, "\"'")

		// Skip if not a Docker image reference
		if !strings.Contains(nodeValue, "docker://") {
			return
		}

		// Check unpinned images first (higher priority)
		if strings.Contains(nodeValue, ":") && !PinnedImageRegex.MatchString(nodeValue) {
			d.checkUnpinnedImages(node, path, filePath, findings)
		} else {
			// Only check non-minimal if it's not an unpinned issue
			d.checkNonMinimalBaseImage(node, path, filePath, findings)
		}
	}

	// Check for Dockerfile context (runs.dockerfile)
	if d.isDockerfileContext(path) {
		var nodeValue string
		switch n := node.(type) {
		case *ast.StringNode:
			nodeValue = n.Value
		case *ast.LiteralNode:
			nodeValue = n.String()
		default:
			return
		}

		nodeValue = strings.Trim(nodeValue, "\"'")

		// Run all applicable checks for dockerfile content
		if d.containsSecretPattern(nodeValue) {
			d.checkSecretsExposure(node, path, filePath, findings)
		}
		if d.containsDevToolsPattern(nodeValue) {
			d.checkDevelopmentTools(node, path, filePath, findings)
		}
		if strings.Contains(nodeValue, "FROM ") && !strings.Contains(nodeValue, "USER ") {
			d.checkRootUser(node, path, filePath, findings)
		}
	}
}

// checkUnpinnedImages detects unpinned Docker images
func (d *DockerSecurityDetector) checkUnpinnedImages(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	var nodeValue string
	var nodeLine, nodeColumn int

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

	nodeValue = strings.Trim(nodeValue, "\"'")

	// Skip if not a Docker image reference or just a Dockerfile reference
	if !strings.Contains(nodeValue, "docker://") && !strings.Contains(nodeValue, ":") {
		return
	}

	// Skip Dockerfile references
	if nodeValue == "Dockerfile" || strings.Contains(nodeValue, "Dockerfile") {
		return
	}

	// Check if image is pinned with SHA256
	if !PinnedImageRegex.MatchString(nodeValue) {
		severity := types.SeverityHigh
		message := "Docker image is not pinned with SHA256 digest"

		// Check for particularly dangerous patterns
		for _, pattern := range UnpinnedPatterns {
			if strings.Contains(nodeValue, ":"+pattern) {
				severity = types.SeverityCritical
				message = fmt.Sprintf("Docker image uses dangerous unpinned tag '%s' - use specific version with SHA256 digest", pattern)
				break
			}
		}

		finding := &types.Finding{
			Rule: &types.Rule{
				Category: CategoryDockerSecurity,
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
	}
}

// checkRootUser detects when Docker actions run as root
func (d *DockerSecurityDetector) checkRootUser(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	var nodeValue string
	var nodeLine, nodeColumn int

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

	nodeValue = strings.Trim(nodeValue, "\"'")

	// Look for Dockerfile content that doesn't include USER directive
	if strings.Contains(nodeValue, "FROM ") && !strings.Contains(nodeValue, "USER ") {
		finding := &types.Finding{
			Rule: &types.Rule{
				Category: CategoryDockerSecurity,
				Severity: types.SeverityHigh,
				Message:  "Docker action runs as root - add USER directive to run as non-root user",
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

// checkNonMinimalBaseImage detects usage of non-minimal base images
func (d *DockerSecurityDetector) checkNonMinimalBaseImage(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	var nodeValue string
	var nodeLine, nodeColumn int

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

	nodeValue = strings.Trim(nodeValue, "\"'")

	// Skip if not a Docker image reference
	if !strings.Contains(nodeValue, "docker://") {
		return
	}

	// Skip Dockerfile references
	if nodeValue == "Dockerfile" || strings.Contains(nodeValue, "Dockerfile") {
		return
	}

	// Check for full OS images in FROM statements or image references
	for _, fullOS := range FullOSImages {
		if strings.Contains(strings.ToLower(nodeValue), fullOS) &&
			!strings.Contains(strings.ToLower(nodeValue), fullOS+"-slim") &&
			!strings.Contains(strings.ToLower(nodeValue), fullOS+"-minimal") {

			finding := &types.Finding{
				Rule: &types.Rule{
					Category: CategoryDockerSecurity,
					Severity: types.SeverityMedium,
					Message:  fmt.Sprintf("Using full OS image '%s' - consider using minimal alternatives like alpine or distroless", fullOS),
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

// checkDevelopmentTools detects development tools in production images
func (d *DockerSecurityDetector) checkDevelopmentTools(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	var nodeValue string
	var nodeLine, nodeColumn int

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

	nodeValue = strings.Trim(nodeValue, "\"'")

	// Check for development tools in RUN or install commands
	if strings.Contains(nodeValue, "RUN ") || strings.Contains(nodeValue, "apt-get install") ||
		strings.Contains(nodeValue, "apk add") || strings.Contains(nodeValue, "yum install") {

		for _, tool := range DevelopmentTools {
			if strings.Contains(nodeValue, tool) {
				finding := &types.Finding{
					Rule: &types.Rule{
						Category: CategoryDockerSecurity,
						Severity: types.SeverityMedium,
						Message:  fmt.Sprintf("Development tool '%s' found in Docker image - use multi-stage builds to avoid including dev tools in production", tool),
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
}

// checkSecretsExposure detects potential secrets exposure in Docker actions
func (d *DockerSecurityDetector) checkSecretsExposure(node ast.Node, path []string, filePath string, findings *[]*types.Finding) {
	var nodeValue string
	var nodeLine, nodeColumn int

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

	nodeValue = strings.Trim(nodeValue, "\"'")

	// Check for secrets exposure patterns
	secretPatterns := []string{
		"$INPUT_",
		"${{ secrets.",
		"${INPUT_",
	}

	// Check if this is an echo, print, or console.log command that contains secrets
	if strings.Contains(nodeValue, "echo ") || strings.Contains(nodeValue, "print(") ||
		strings.Contains(nodeValue, "console.log(") || strings.Contains(nodeValue, "printf ") {
		for _, pattern := range secretPatterns {
			if strings.Contains(nodeValue, pattern) {
				finding := &types.Finding{
					Rule: &types.Rule{
						Category: CategoryDockerSecurity,
						Severity: types.SeverityHigh,
						Message:  "Potential secret exposure detected - avoid printing or logging sensitive inputs",
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
				break
			}
		}
	}
}

// Helper methods for context detection
func (d *DockerSecurityDetector) isDockerImageContext(path []string) bool {
	if len(path) < 2 {
		return false
	}

	// Check for runs.image context
	return (path[len(path)-2] == "runs" && path[len(path)-1] == "image") ||
		(path[len(path)-1] == "image" && len(path) >= 2)
}

func (d *DockerSecurityDetector) isDockerfileContext(path []string) bool {
	if len(path) < 2 {
		return false
	}

	// Check for runs.dockerfile context specifically
	return (path[len(path)-2] == "runs" && path[len(path)-1] == "dockerfile")
}

func (d *DockerSecurityDetector) isDockerRunsContext(path []string) bool {
	if len(path) < 1 {
		return false
	}

	// Check if we're in a runs context for Docker actions
	return strings.Contains(strings.Join(path, "."), "runs") &&
		(strings.Contains(strings.Join(path, "."), "image") ||
			strings.Contains(strings.Join(path, "."), "using"))
}

// Helper methods for pattern detection
func (d *DockerSecurityDetector) containsSecretPattern(nodeValue string) bool {
	secretPatterns := []string{
		"$INPUT_",
		"${{ secrets.",
		"${INPUT_",
	}

	// Check if this is an echo, print, or console.log command that contains secrets
	if strings.Contains(nodeValue, "echo ") || strings.Contains(nodeValue, "print(") ||
		strings.Contains(nodeValue, "console.log(") || strings.Contains(nodeValue, "printf ") {
		for _, pattern := range secretPatterns {
			if strings.Contains(nodeValue, pattern) {
				return true
			}
		}
	}
	return false
}

func (d *DockerSecurityDetector) containsDevToolsPattern(nodeValue string) bool {
	return strings.Contains(nodeValue, "RUN ") || strings.Contains(nodeValue, "apt-get install") ||
		strings.Contains(nodeValue, "apk add") || strings.Contains(nodeValue, "yum install")
}

// GetDockerSecurityRules returns the Docker security rule set
func GetDockerSecurityRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryDockerSecurity,
		Rules: []types.Rule{
			{
				Category: CategoryDockerSecurity,
				Pattern:  `docker://.*:latest`,
				Severity: types.SeverityCritical,
				Message:  "Docker image uses 'latest' tag - pin to specific version with SHA256 digest",
				Type:     types.RuleTypePattern,
			},
			{
				Category: CategoryDockerSecurity,
				Pattern:  `FROM\s+(?:ubuntu|debian|centos|fedora)(?!.*-slim)`,
				Severity: types.SeverityMedium,
				Message:  "Using full OS base image - consider minimal alternatives like alpine or distroless",
				Type:     types.RuleTypePattern,
			},
			{
				Category: CategoryDockerSecurity,
				Pattern:  `echo\s+\$(?:INPUT_|secrets\.)`,
				Severity: types.SeverityHigh,
				Message:  "Potential secret exposure - avoid printing sensitive inputs",
				Type:     types.RuleTypePattern,
			},
		},
	}
}
