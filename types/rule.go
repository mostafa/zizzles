package types

// Rule represents a security audit rule
type Rule struct {
	Category   string
	Pattern    string
	Severity   Severity
	Message    string
	Suggestion string
}
