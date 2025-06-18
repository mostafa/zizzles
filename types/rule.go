package types

// RuleType indicates how a rule should be executed
type RuleType string

const (
	RuleTypeAST     RuleType = "ast"     // AST-based detection
	RuleTypePattern RuleType = "pattern" // Pattern-based detection
)

// Rule represents a security audit rule
type Rule struct {
	Category Category
	Pattern  string
	Severity Severity
	Message  string
	Type     RuleType // How this rule should be executed
}

// Category represents a category of rules
type Category string

// RuleSet represents a collection of rules for a specific category
type RuleSet struct {
	Category Category
	Rules    []Rule
}

// ASTRule represents a rule that uses AST-based detection
type ASTRule struct {
	Category Category
	Severity Severity
	Message  string
	Visitor  NodeVisitor // AST visitor for this rule
}

// PatternRule represents a rule that uses pattern-based detection
type PatternRule struct {
	Category Category
	Pattern  string
	Severity Severity
	Message  string
}
