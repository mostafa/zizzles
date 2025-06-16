package types

// Rule represents a security audit rule
type Rule struct {
	Category   Category
	Pattern    string
	Severity   Severity
	Message    string
	Suggestion string
}

// Category represents a category of rules
type Category string

// RuleSet represents a collection of rules for a specific category
type RuleSet struct {
	Category Category
	Rules    []Rule
}
