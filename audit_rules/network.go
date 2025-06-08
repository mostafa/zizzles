package audit_rules

import (
	"github.com/mostafa/zizzles/types"
)

// GetNetworkRules returns rules for network operation patterns
func GetNetworkRules() RuleSet {
	return RuleSet{
		Category: "network",
		Rules: []types.Rule{
			{
				Category: "network",
				Pattern:  "curl",
				Severity: types.SeverityCritical,
				Message:  "Curl download",
			},
		},
	}
}
