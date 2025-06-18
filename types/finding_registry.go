package types

import (
	"fmt"
)

// Registry manages a collection of findings
type Registry struct {
	findings map[Category][]*Finding
}

// NewRegistry creates a new Registry
func NewRegistry() *Registry {
	return &Registry{
		findings: make(map[Category][]*Finding),
	}
}

// Add adds a finding to the registry
func (r *Registry) Add(finding *Finding) {
	r.findings[finding.Rule.Category] = append(r.findings[finding.Rule.Category], finding)
}

// AddAll adds multiple findings to the registry
func (r *Registry) AddAll(findings map[Category][]*Finding) {
	for cat, fs := range findings {
		r.findings[cat] = append(r.findings[cat], fs...)
	}
}

// Get returns a finding by category
func (r *Registry) Get(category Category) []*Finding {
	return r.findings[category]
}

// GetAll returns all findings
func (r *Registry) GetAll() map[Category][]*Finding {
	return r.findings
}

// CountBySeverity returns the count of findings by severity
func (r *Registry) CountBySeverity() map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}

	for _, fs := range r.findings {
		for _, finding := range fs {
			counts[finding.Severity]++
		}
	}

	return counts
}

// GroupBySeverity returns findings grouped by severity
func (r *Registry) GroupBySeverity() map[Severity][]*Finding {
	groups := make(map[Severity][]*Finding)
	for _, fs := range r.findings {
		for _, finding := range fs {
			groups[finding.Severity] = append(groups[finding.Severity], finding)
		}
	}
	return groups
}

// PrintSummary prints a summary of findings with colored numbers
func (r *Registry) PrintSummary() {
	counts := r.CountBySeverity()
	total := 0
	for _, fs := range r.findings {
		total += len(fs)
	}
	plural := ""
	if total > 1 {
		plural = "s"
	}

	colorNum := func(num int, color string) string {
		return fmt.Sprintf("%s%d%s", color, num, ColorReset)
	}

	fmt.Printf(
		"%d finding%s (0 unknown, %s informational, "+
			"%s low, %s medium, %s high, %s critical)\n",
		total,
		plural,
		colorNum(counts[SeverityInfo], ColorGreen),
		colorNum(counts[SeverityLow], ColorGreen),
		colorNum(counts[SeverityMedium], ColorYellow),
		colorNum(counts[SeverityHigh], ColorRed),
		colorNum(counts[SeverityCritical], "\033[1;31m"),
	)
}

// ANSI color codes
const (
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
	ColorReset  = "\033[0m"
	ColorBlue   = "\033[94m"
)
