package audit_rules

import (
	"github.com/mostafa/zizzles/types"
)

const CategoryCommandExecution types.Category = "command_execution"

// GetCommandExecutionRules returns rules for command execution patterns
func GetCommandExecutionRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryCommandExecution,
		Rules: []types.Rule{
			{
				Category: CategoryCommandExecution,
				Pattern:  "bash -c",
				Severity: types.SeverityCritical,
				Message:  "Direct bash command execution",
			},
			{
				Category: CategoryCommandExecution,
				Pattern:  "sh -c",
				Severity: types.SeverityCritical,
				Message:  "Direct shell command execution",
			},
			{
				Category: CategoryCommandExecution,
				Pattern:  "eval",
				Severity: types.SeverityCritical,
				Message:  "Command evaluation detected",
			},
			{
				Category: CategoryCommandExecution,
				Pattern:  "exec",
				Severity: types.SeverityHigh,
				Message:  "Command execution detected",
			},
			{
				Category: CategoryCommandExecution,
				Pattern:  "system",
				Severity: types.SeverityHigh,
				Message:  "System command execution",
			},
			{
				Category: CategoryCommandExecution,
				Pattern:  `\bcurl -sSfL\b`,
				Severity: types.SeverityCritical,
				Message:  "Direct command execution using curl -sSfL",
				Suggestion: `Consider using GitHub's built-in actions or verified third-party actions instead of direct command execution.
If those cannot be used, consider verifying the contents and integrity of the downloaded file using a checksum or signature.`,
			},
		},
	}
}
