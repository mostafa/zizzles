package audit_rules

import (
	"github.com/mostafa/zizzles/types"
)

// GetCommandExecutionRules returns rules for command execution patterns
func GetCommandExecutionRules() RuleSet {
	return RuleSet{
		Category: "command_execution",
		Rules: []types.Rule{
			{
				Category: "command_execution",
				Pattern:  "bash -c",
				Severity: types.SeverityCritical,
				Message:  "Direct bash command execution",
			},
			{
				Category: "command_execution",
				Pattern:  "sh -c",
				Severity: types.SeverityCritical,
				Message:  "Direct shell command execution",
			},
			{
				Category: "command_execution",
				Pattern:  "eval",
				Severity: types.SeverityCritical,
				Message:  "Command evaluation detected",
			},
			{
				Category: "command_execution",
				Pattern:  "exec",
				Severity: types.SeverityHigh,
				Message:  "Command execution detected",
			},
			{
				Category: "command_execution",
				Pattern:  "system",
				Severity: types.SeverityHigh,
				Message:  "System command execution",
			},
			{
				Pattern:  `\bcurl -sSfL\b`,
				Severity: types.SeverityCritical,
				Message:  "Direct command execution using curl -sSfL",
				Suggestion: `Consider using GitHub's built-in actions or verified third-party actions instead of direct command execution.
If those cannot be used, consider verifying the contents and integrity of the downloaded file using a checksum or signature.`,
			},
		},
	}
}
