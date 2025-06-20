package audit_rules

import "github.com/mostafa/zizzles/types"

var registry = make(map[types.Category]types.RuleSet)

func init() {
	registry[CategoryExpressionInjection] = GetExpressionInjectionRules()
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

// GetASTRules returns all AST-based rules
func GetASTRules() []*types.ASTRule {
	astRules := []*types.ASTRule{}

	expressionRule := NewExpressionInjectionRule()
	astRules = append(astRules, &types.ASTRule{
		Category: CategoryExpressionInjection,
		Severity: types.SeverityHigh,
		Message:  "Untrusted input expression found in run block - potential command injection",
		Visitor:  expressionRule.detector,
	})

	return astRules
}

// GetPatternRules returns all pattern-based rules
func GetPatternRules() []*types.PatternRule {
	patternRules := []*types.PatternRule{}

	expressionRules := GetExpressionInjectionRules()
	for _, rule := range expressionRules.Rules {
		patternRules = append(patternRules, &types.PatternRule{
			Category: rule.Category,
			Pattern:  rule.Pattern,
			Severity: rule.Severity,
			Message:  rule.Message,
		})
	}

	return patternRules
}

// CreateRuleExecutor creates a new rule executor with all registered rules
func CreateRuleExecutor() *types.RuleExecutor {
	executor := types.NewRuleExecutor()

	for _, rule := range GetASTRules() {
		executor.AddASTRule(rule)
	}

	for _, rule := range GetPatternRules() {
		executor.AddPatternRule(rule)
	}

	return executor
}

// GetExpressionInjectionRuleInstance returns a new instance of the expression injection rule
func GetExpressionInjectionRuleInstance() *ExpressionInjectionRule {
	return NewExpressionInjectionRule()
}
