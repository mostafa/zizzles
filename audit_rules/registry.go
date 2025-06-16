package audit_rules

import "github.com/mostafa/zizzles/types"

var registry = make(map[types.Category]types.RuleSet)

func init() {
	registry[CategoryFileDownload] = GetFileDownloadRules()
	registry[CategoryCommandExecution] = GetCommandExecutionRules()
	registry[CategoryNetwork] = GetNetworkRules()
}

// GetRuleSet returns a rule set by category
func GetRuleSet(category types.Category) types.RuleSet {
	return registry[category]
}

// GetAllRuleSets returns all rule sets
func GetAllRuleSets() []types.RuleSet {
	ruleSets := []types.RuleSet{}
	for _, ruleSet := range registry {
		ruleSets = append(ruleSets, ruleSet)
	}
	return ruleSets
}

// GetAllRules returns all rules
func GetAllRules() []types.Rule {
	rules := []types.Rule{}
	for _, ruleSet := range registry {
		rules = append(rules, ruleSet.Rules...)
	}
	return rules
}

// GetRulesByCategory returns rules by category
func GetRulesByCategory(category types.Category) []types.Rule {
	rules := []types.Rule{}
	for _, ruleSet := range registry {
		if ruleSet.Category == category {
			rules = append(rules, ruleSet.Rules...)
		}
	}
	return rules
}
