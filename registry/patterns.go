package registry

import (
	"github.com/mostafa/zizzles/audit_rules"
	"github.com/mostafa/zizzles/types"
)

// PatternInfo contains information about a pattern to check
type PatternInfo struct {
	Pattern  string
	Severity types.Severity
	Message  string
}

// GetUntrustedCodePatterns returns a map of patterns to check for untrusted code fetching
func GetUntrustedCodePatterns() map[string]PatternInfo {
	patterns := make(map[string]PatternInfo)
	rules := audit_rules.GetAllRules()

	for _, rule := range rules {
		patterns[rule.Category] = PatternInfo{
			Pattern:  rule.Pattern,
			Severity: rule.Severity,
			Message:  rule.Message,
		}
	}

	return patterns
}
