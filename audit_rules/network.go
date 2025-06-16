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
				Suggestion: `1. Consider using GitHub's built-in actions or verified third-party actions instead of direct command execution.
2. If those cannot be used, consider verifying the contents and integrity of the downloaded file using a checksum or signature.`,
			},
		},
	}
}
