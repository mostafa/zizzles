package audit_rules

import (
	"github.com/mostafa/zizzles/types"
)

// Rule represents a security audit rule
type Rule struct {
	Category string
	Pattern  string
	Severity types.Severity
	Message  string
}

// RuleSet represents a collection of rules for a specific category
type RuleSet struct {
	Category string
	Rules    []types.Rule
}

// GetRulesByCategory returns all rules for a specific category
func GetRulesByCategory(category string) []types.Rule {
	switch category {
	case "file_download":
		return GetFileDownloadRules().Rules
	case "command_execution":
		return GetCommandExecutionRules().Rules
	case "network":
		return GetNetworkRules().Rules
	default:
		return nil
	}
}

// GetAllRules returns all rules from all categories
func GetAllRules() []types.Rule {
	var allRules []types.Rule
	allRules = append(allRules, GetFileDownloadRules().Rules...)
	allRules = append(allRules, GetCommandExecutionRules().Rules...)
	allRules = append(allRules, GetNetworkRules().Rules...)
	return allRules
}

// CreateFinding creates a new Finding from this rule
func CreateFinding(rule *types.Rule, yamlPath string, line, column int, value string) *types.Finding {
	return types.NewFinding(rule, yamlPath, line, column, value, 0, 0)
}
