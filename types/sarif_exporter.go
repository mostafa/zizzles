package types

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v22/sarif"
)

const (
	ToolName        = "zizzles"
	ToolVersion     = "1.0.0"
	ToolURI         = "https://github.com/mostafa/zizzles"
	ToolDescription = "Security auditing tool for GitHub Actions metadata files"
)

// SARIFExporter handles the export of findings to SARIF format
type SARIFExporter struct {
	toolName    string
	toolVersion string
	toolURI     string
}

// NewSARIFExporter creates a new SARIF exporter
func NewSARIFExporter() *SARIFExporter {
	return &SARIFExporter{
		toolName:    ToolName,
		toolVersion: ToolVersion,
		toolURI:     ToolURI,
	}
}

// ExportToSARIF exports findings to a SARIF JSON file
func (se *SARIFExporter) ExportToSARIF(findings map[Category][]*Finding, outputPath string) error {
	// Create the basic SARIF report
	sarifReport := report.NewV22Report()

	// Create a run for our tool
	run := sarif.NewRunWithInformationURI(se.toolName, se.toolURI)
	run.Tool.Driver.Version = &se.toolVersion
	description := ToolDescription
	run.Tool.Driver.FullDescription = &sarif.MultiformatMessageString{
		Text: &description,
	}

	// Collect all unique rules and files
	rules := make(map[Category]*Rule)
	artifacts := make(map[string]bool)

	// First pass: collect rules and artifacts
	for category, categoryFindings := range findings {
		for _, finding := range categoryFindings {
			if finding.Rule != nil {
				rules[category] = finding.Rule
			}
			// Use relative path for artifacts
			relPath, err := filepath.Rel(".", finding.YamlPath)
			if err != nil {
				relPath = finding.YamlPath
			}
			artifacts[relPath] = true
		}
	}

	// Add rules to the run
	for category, rule := range rules {
		sarifRule := run.AddRule(string(category))
		sarifRule.WithDescription(rule.Message)

		// Map severity to SARIF level
		var level string
		switch rule.Severity {
		case SeverityCritical:
			level = "error"
		case SeverityHigh:
			level = "error"
		case SeverityMedium:
			level = "warning"
		case SeverityLow:
			level = "note"
		case SeverityInfo:
			level = "note"
		default:
			level = "note"
		}

		config := sarif.NewReportingConfiguration().WithLevel(level).WithEnabled(true)
		sarifRule.WithDefaultConfiguration(config)

		// Add help text if available
		if rule.Pattern != "" {
			sarifRule.WithHelpURI(se.toolURI + "/docs/rules/" + strings.ToLower(string(category)))
			sarifRule.WithMarkdownHelp(fmt.Sprintf("Pattern: `%s`\n\nSeverity: %s", rule.Pattern, rule.Severity))
		}
	}

	// Add artifacts to the run
	for artifactPath := range artifacts {
		run.AddDistinctArtifact("file://" + artifactPath)
	}

	// Add results (findings) to the run
	for category, categoryFindings := range findings {
		for _, finding := range categoryFindings {
			if finding.Rule == nil {
				continue
			}

			// Create result for this finding
			result := run.CreateResultForRule(string(category))

			// Set the level based on severity
			var level string
			switch finding.Rule.Severity {
			case SeverityCritical:
				level = "error"
			case SeverityHigh:
				level = "error"
			case SeverityMedium:
				level = "warning"
			case SeverityLow:
				level = "note"
			case SeverityInfo:
				level = "note"
			default:
				level = "note"
			}
			result.WithLevel(level)

			// Set the message
			message := finding.Rule.Message
			if finding.Value != "" {
				message = fmt.Sprintf("%s (found: %s)", message, strings.TrimSpace(finding.Value))
			}
			result.WithMessage(sarif.NewTextMessage(message))

			// Add location information
			relPath, err := filepath.Rel(".", finding.YamlPath)
			if err != nil {
				relPath = finding.YamlPath
			}

			location := sarif.NewLocationWithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(
						sarif.NewSimpleArtifactLocation("file://" + relPath),
					).WithRegion(
					sarif.NewRegion().
						WithStartLine(finding.Line).
						WithStartColumn(finding.Column).
						WithEndColumn(finding.Column + finding.MatchedLength),
				),
			)

			result.AddLocation(location)

			// Add additional properties
			properties := sarif.NewPropertyBag().
				Add("category", string(finding.Rule.Category)).
				Add("severity", string(finding.Rule.Severity)).
				Add("matchedColumn", finding.MatchedColumn).
				Add("matchedLength", finding.MatchedLength).
				Add("matchedLineOffset", finding.MatchedLineOffset)
			result.WithProperties(properties)
		}
	}

	// Add the run to the report
	sarifReport.AddRun(run)

	// Validate the report
	if err := sarifReport.Validate(); err != nil {
		return fmt.Errorf("SARIF report validation failed: %w", err)
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF report to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write SARIF file: %w", err)
	}

	return nil
}

// ExportFindings is a convenience function to export findings to SARIF
func ExportFindings(findings map[Category][]*Finding, outputPath string) error {
	exporter := NewSARIFExporter()
	return exporter.ExportToSARIF(findings, outputPath)
}
