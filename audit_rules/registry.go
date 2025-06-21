package audit_rules

import "github.com/mostafa/zizzles/types"

var registry = make(map[types.Category]types.RuleSet)

func init() {
	registry[CategoryExpressionInjection] = GetExpressionInjectionRules()
	registry[CategoryOutputHandling] = GetOutputHandlingRules()
	registry[CategoryRunsVersion] = GetRunsVersionRules()
	registry[CategoryDockerSecurity] = GetDockerSecurityRules()
	registry[CategoryCompositeAction] = GetCompositeActionRules()
}

// GetRuleSet returns a rule set by category
func GetRuleSet(category types.Category) types.RuleSet {
	return registry[category]
}

// GetAllRuleSets returns all rule sets (currently unused but kept for future extensibility)
func GetAllRuleSets() []types.RuleSet {
	ruleSets := []types.RuleSet{}
	for _, ruleSet := range registry {
		ruleSets = append(ruleSets, ruleSet)
	}
	return ruleSets
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

	outputHandlingRule := NewOutputHandlingRule()
	astRules = append(astRules, &types.ASTRule{
		Category: CategoryOutputHandling,
		Severity: types.SeverityMedium,
		Message:  "Output handling security issue detected",
		Visitor:  outputHandlingRule.detector,
	})

	runsVersionRule := NewRunsVersionRule()
	astRules = append(astRules, &types.ASTRule{
		Category: CategoryRunsVersion,
		Severity: types.SeverityHigh,
		Message:  "Deprecated or unsupported Node.js version detected in runs configuration",
		Visitor:  runsVersionRule.detector,
	})

	dockerSecurityRule := NewDockerSecurityRule()
	astRules = append(astRules, &types.ASTRule{
		Category: CategoryDockerSecurity,
		Severity: types.SeverityHigh,
		Message:  "Docker action security vulnerability detected",
		Visitor:  dockerSecurityRule.detector,
	})

	compositeActionRule := NewCompositeActionRule()
	astRules = append(astRules, &types.ASTRule{
		Category: CategoryCompositeAction,
		Severity: types.SeverityHigh,
		Message:  "Composite action security vulnerability detected",
		Visitor:  compositeActionRule.detector,
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

	outputHandlingRules := GetOutputHandlingRules()
	for _, rule := range outputHandlingRules.Rules {
		patternRules = append(patternRules, &types.PatternRule{
			Category: rule.Category,
			Pattern:  rule.Pattern,
			Severity: rule.Severity,
			Message:  rule.Message,
		})
	}

	runsVersionRules := GetRunsVersionRules()
	for _, rule := range runsVersionRules.Rules {
		patternRules = append(patternRules, &types.PatternRule{
			Category: rule.Category,
			Pattern:  rule.Pattern,
			Severity: rule.Severity,
			Message:  rule.Message,
		})
	}

	dockerSecurityRules := GetDockerSecurityRules()
	for _, rule := range dockerSecurityRules.Rules {
		patternRules = append(patternRules, &types.PatternRule{
			Category: rule.Category,
			Pattern:  rule.Pattern,
			Severity: rule.Severity,
			Message:  rule.Message,
		})
	}

	compositeActionRules := GetCompositeActionRules()
	for _, rule := range compositeActionRules.Rules {
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

// Rule instance getters - these are simple wrappers that could be called directly
// Kept for API consistency but could be removed in favor of direct constructor calls

// GetExpressionInjectionRuleInstance returns a new instance of the expression injection rule
func GetExpressionInjectionRuleInstance() *ExpressionInjectionRule {
	return NewExpressionInjectionRule()
}

// GetOutputHandlingRuleInstance returns a new instance of the output handling rule
func GetOutputHandlingRuleInstance() *OutputHandlingRule {
	return NewOutputHandlingRule()
}

// GetRunsVersionRuleInstance returns a new instance of the runs version rule
func GetRunsVersionRuleInstance() *RunsVersionRule {
	return NewRunsVersionRule()
}

// GetDockerSecurityRuleInstance returns a new instance of the docker security rule
func GetDockerSecurityRuleInstance() *DockerSecurityRule {
	return NewDockerSecurityRule()
}

// GetCompositeActionRuleInstance returns a new instance of the composite action rule
func GetCompositeActionRuleInstance() *CompositeActionRule {
	return NewCompositeActionRule()
}
