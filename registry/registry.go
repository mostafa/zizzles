package registry

import (
	"fmt"

	"github.com/mostafa/zizzles/types"
)

// Registry manages a collection of findings
type Registry struct {
	findings map[string]*types.Finding
}

// New creates a new Registry
func New() *Registry {
	return &Registry{
		findings: make(map[string]*types.Finding),
	}
}

// Add adds a finding to the registry
func (r *Registry) Add(finding *types.Finding) {
	r.findings[finding.Rule.Category] = finding
}

// AddAll adds multiple findings to the registry
func (r *Registry) AddAll(findings map[string]*types.Finding) {
	for k, v := range findings {
		r.findings[k] = v
	}
}

// Get returns a finding by category
func (r *Registry) Get(category string) *types.Finding {
	return r.findings[category]
}

// GetAll returns all findings
func (r *Registry) GetAll() map[string]*types.Finding {
	return r.findings
}

// CountBySeverity returns the count of findings by severity
func (r *Registry) CountBySeverity() map[types.Severity]int {
	counts := map[types.Severity]int{
		types.SeverityCritical: 0,
		types.SeverityHigh:     0,
		types.SeverityMedium:   0,
		types.SeverityLow:      0,
		types.SeverityInfo:     0,
	}

	for _, finding := range r.findings {
		counts[finding.Severity]++
	}

	return counts
}

// GroupBySeverity returns findings grouped by severity
func (r *Registry) GroupBySeverity() map[types.Severity][]*types.Finding {
	groups := make(map[types.Severity][]*types.Finding)
	for _, finding := range r.findings {
		groups[finding.Severity] = append(groups[finding.Severity], finding)
	}
	return groups
}

// PrintSummary prints a summary of findings with colored numbers
func (r *Registry) PrintSummary() {
	counts := r.CountBySeverity()
	total := len(r.findings)
	plural := ""
	if total > 1 {
		plural = "s"
	}

	colorNum := func(num int, color string) string {
		return fmt.Sprintf("%s%d%s", color, num, ColorReset)
	}

	fmt.Printf("%d finding%s (0 unknown, %s informational, %s low, %s medium, %s high, %s critical)\n",
		total,
		plural,
		colorNum(counts[types.SeverityInfo], ColorGreen),
		colorNum(counts[types.SeverityLow], ColorGreen),
		colorNum(counts[types.SeverityMedium], ColorYellow),
		colorNum(counts[types.SeverityHigh], ColorRed),
		colorNum(counts[types.SeverityCritical], "\033[1;31m"),
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
