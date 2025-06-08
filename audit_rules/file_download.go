package audit_rules

import (
	"github.com/mostafa/zizzles/types"
)

// GetFileDownloadRules returns a set of rules for detecting file downloads
func GetFileDownloadRules() RuleSet {
	return RuleSet{
		Category: "file_download",
		Rules: []types.Rule{
			{
				Category: "file_download",
				Pattern:  `\bwget\b`,
				Severity: types.SeverityHigh,
				Message:  "File download using wget",
				Suggestion: `Consider using GitHub's built-in actions/checkout or actions/download-artifact instead of direct file downloads.
If those cannot be used, consider verifying the contents and integrity of the downloaded file using a checksum or signature.`,
			},
			{
				Category: "file_download",
				Pattern:  `\bcurl\b(?!.*fetch-depth)(?!.*download-artifacts)`,
				Severity: types.SeverityHigh,
				Message:  "File download using curl",
				Suggestion: `Consider using GitHub's built-in actions/checkout or actions/download-artifact instead of direct file downloads.
If those cannot be used, consider verifying the contents and integrity of the downloaded file using a checksum or signature.`,
			},
			{
				Category: "file_download",
				Pattern:  "\\bdownload\\b(?!-artifacts|\\s*:)", // Exclude download-artifacts and download: syntax
				Severity: types.SeverityMedium,
				Message:  "File download operation detected",
			},
			{
				Category: "file_download",
				Pattern:  "\\bfetch\\b(?!-depth|\\s*:)", // Exclude fetch-depth and fetch: syntax
				Severity: types.SeverityMedium,
				Message:  "File fetch operation detected",
			},
		},
	}
}
