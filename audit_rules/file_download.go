package audit_rules

import (
	"github.com/mostafa/zizzles/types"
)

const CategoryFileDownload types.Category = "file_download"

// GetFileDownloadRules returns a set of rules for detecting file downloads
func GetFileDownloadRules() types.RuleSet {
	return types.RuleSet{
		Category: CategoryFileDownload,
		Rules: []types.Rule{
			{
				Category: CategoryFileDownload,
				Pattern:  `\bwget\b`,
				Severity: types.SeverityHigh,
				Message:  "File download using wget",
				Suggestion: `1. Consider using GitHub's built-in actions/checkout or actions/download-artifact instead of direct file downloads.
2. If those cannot be used, consider verifying the contents and integrity of the downloaded file using a checksum or signature.`,
			},
			{
				Category: CategoryFileDownload,
				Pattern:  `\bcurl\b(?!.*fetch-depth)(?!.*download-artifacts)`,
				Severity: types.SeverityHigh,
				Message:  "File download using curl",
				Suggestion: `1. Consider using GitHub's built-in actions/checkout or actions/download-artifact instead of direct file downloads.
2. If those cannot be used, consider verifying the contents and integrity of the downloaded file using a checksum or signature.`,
			},
			{
				Category: CategoryFileDownload,
				Pattern:  "\\bdownload\\b(?!-artifacts|\\s*:)", // Exclude download-artifacts and download: syntax
				Severity: types.SeverityMedium,
				Message:  "File download operation detected",
			},
			{
				Category: CategoryFileDownload,
				Pattern:  "\\bfetch\\b(?!-depth|\\s*:)", // Exclude fetch-depth and fetch: syntax
				Severity: types.SeverityMedium,
				Message:  "File fetch operation detected",
			},
		},
	}
}
