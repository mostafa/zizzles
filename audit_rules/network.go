package audit_rules

import (
	"github.com/mostafa/zizzles/types"
)

const CategoryNetwork types.Category = "network"

// GetNetworkRules returns rules for network operation patterns
func GetNetworkRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryNetwork,
		Rules: []types.Rule{
			{
				Category: CategoryNetwork,
				Pattern:  "curl",
				Severity: types.SeverityCritical,
				Message:  "Curl download",
			},
		},
	}
}
