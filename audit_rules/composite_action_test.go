package audit_rules

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
)

func TestCompositeInputInjection(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test case with direct input injection in run step
	yamlContent := `
name: 'Test Action'
description: 'Test composite action'
inputs:
  message:
    description: 'Message to display'
    required: true
runs:
  using: 'composite'
  steps:
    - name: Display message
      run: echo "${{ inputs.message }}"
      shell: bash
    - name: Safe usage
      env:
        MESSAGE: ${{ inputs.message }}
      run: echo "$MESSAGE"
      shell: bash
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should find one finding for the direct input injection
	if len(findings) == 0 {
		t.Error("Expected to find input injection vulnerability, but found none")
	}

	// Check if the finding is for input injection
	found := false
	for _, finding := range findings {
		if strings.Contains(finding.Rule.Message, "Direct input injection") {
			found = true
			if finding.Rule.Severity != types.SeverityHigh {
				t.Errorf("Expected severity HIGH, got %s", finding.Rule.Severity)
			}
			break
		}
	}

	if !found {
		t.Error("Expected to find direct input injection finding")
	}
}

func TestUnsafeInputDefaults(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test case with unsafe default values
	yamlContent := `
name: 'Test Action'
description: 'Test composite action'
inputs:
  command:
    description: 'Command to run'
    required: false
    default: 'echo "safe"'
  unsafe_command:
    description: 'Unsafe command'
    required: false
    default: 'echo "test"; rm -rf /'
runs:
  using: 'composite'
  steps:
    - name: Run command
      run: ${{ inputs.command }}
      shell: bash
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should find findings for both the unsafe default and direct input usage
	if len(findings) == 0 {
		t.Error("Expected to find unsafe default value, but found none")
	}

	// Check if we found the unsafe default finding
	foundUnsafeDefault := false
	foundInputInjection := false
	for _, finding := range findings {
		if strings.Contains(finding.Rule.Message, "Unsafe default value") {
			foundUnsafeDefault = true
			if finding.Rule.Severity != types.SeverityMedium {
				t.Errorf("Expected severity MEDIUM for unsafe default, got %s", finding.Rule.Severity)
			}
		}
		if strings.Contains(finding.Rule.Message, "Direct input injection") {
			foundInputInjection = true
		}
	}

	if !foundUnsafeDefault {
		t.Error("Expected to find unsafe default value finding")
	}
	if !foundInputInjection {
		t.Error("Expected to find input injection finding")
	}
}

func TestUnpinnedActions(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test case with unpinned actions
	yamlContent := `
name: 'Test Action'
description: 'Test composite action'
runs:
  using: 'composite'
  steps:
    - name: Checkout with floating tag
      uses: actions/checkout@main
    - name: Checkout without version
      uses: actions/setup-node
    - name: Checkout properly pinned
      uses: actions/checkout@v4
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should find two findings: one for floating tag, one for missing version
	if len(findings) < 2 {
		t.Errorf("Expected at least 2 findings for unpinned actions, got %d", len(findings))
	}

	foundFloatingTag := false
	foundMissingVersion := false
	for _, finding := range findings {
		if strings.Contains(finding.Rule.Message, "floating tag") {
			foundFloatingTag = true
			if finding.Rule.Severity != types.SeverityMedium {
				t.Errorf("Expected severity MEDIUM for floating tag, got %s", finding.Rule.Severity)
			}
		}
		if strings.Contains(finding.Rule.Message, "without version") {
			foundMissingVersion = true
			if finding.Rule.Severity != types.SeverityHigh {
				t.Errorf("Expected severity HIGH for missing version, got %s", finding.Rule.Severity)
			}
		}
	}

	if !foundFloatingTag {
		t.Error("Expected to find floating tag finding")
	}
	if !foundMissingVersion {
		t.Error("Expected to find missing version finding")
	}
}

func TestEnvironmentLeakage(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test case with environment leakage
	yamlContent := `
name: 'Test Action'
description: 'Test composite action'
inputs:
  secret:
    description: 'Secret value'
    required: true
runs:
  using: 'composite'
  steps:
    - name: Write to environment
      run: echo "SECRET=${{ inputs.secret }}" >> $GITHUB_ENV
      shell: bash
    - name: Safe environment usage
      env:
        SECRET: ${{ inputs.secret }}
      run: echo "SECRET=$SECRET" >> $GITHUB_ENV
      shell: bash
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should find findings for both environment leakage and input injection
	foundEnvLeakage := false
	foundInputInjection := false
	for _, finding := range findings {
		if strings.Contains(finding.Rule.Message, "Writing input values to GITHUB_ENV") {
			foundEnvLeakage = true
			if finding.Rule.Severity != types.SeverityMedium {
				t.Errorf("Expected severity MEDIUM for environment leakage, got %s", finding.Rule.Severity)
			}
		}
		if strings.Contains(finding.Rule.Message, "Direct input injection") {
			foundInputInjection = true
		}
	}

	if !foundEnvLeakage {
		t.Error("Expected to find environment leakage finding")
	}
	if !foundInputInjection {
		t.Error("Expected to find input injection finding")
	}
}

func TestUnsafeCheckout(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test case with checkout action
	yamlContent := `
name: 'Test Action'
description: 'Test composite action'
runs:
  using: 'composite'
  steps:
    - name: Checkout code
      uses: actions/checkout@v4
    - name: Another checkout
      uses: actions/checkout@main
      with:
        persist-credentials: false
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should find findings for both checkout actions and the floating tag
	foundCheckout := 0
	foundFloatingTag := false
	for _, finding := range findings {
		if strings.Contains(finding.Rule.Message, "Checkout action detected") {
			foundCheckout++
			if finding.Rule.Severity != types.SeverityMedium {
				t.Errorf("Expected severity MEDIUM for checkout detection, got %s", finding.Rule.Severity)
			}
		}
		if strings.Contains(finding.Rule.Message, "floating tag") {
			foundFloatingTag = true
		}
	}

	if foundCheckout != 2 {
		t.Errorf("Expected to find 2 checkout findings, got %d", foundCheckout)
	}
	if !foundFloatingTag {
		t.Error("Expected to find floating tag finding")
	}
}

func TestUnsetShell(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test case with unset shell - this is a simplified test
	yamlContent := `
name: 'Test Action'
description: 'Test composite action'
runs:
  using: 'composite'
  steps:
    - name: Run without shell
      run: echo "hello"
    - name: Run with shell
      run: echo "hello"
      shell: bash
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should find findings for run step without explicit shell
	foundUnsetShell := false
	for _, finding := range findings {
		if strings.Contains(finding.Rule.Message, "without explicit shell") {
			foundUnsetShell = true
			if finding.Rule.Severity != types.SeverityLow {
				t.Errorf("Expected severity LOW for unset shell, got %s", finding.Rule.Severity)
			}
		}
	}

	if !foundUnsetShell {
		t.Error("Expected to find unset shell finding")
	}
}

func TestNonActionFile(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test with a workflow file (should not trigger composite action rules)
	yamlContent := `
name: 'Test Workflow'
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Direct input usage
        run: echo "${{ inputs.message }}"
      - uses: actions/checkout@main
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	types.WalkAST(doc.Docs[0], []string{}, "workflow.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should not find any findings since this is not an action.yml file
	if len(findings) > 0 {
		t.Errorf("Expected no findings for non-action file, got %d", len(findings))
	}
}

func TestGetCompositeActionRules(t *testing.T) {
	ruleSet := GetCompositeActionRules()

	if ruleSet.Category != CategoryCompositeAction {
		t.Errorf("Expected category %s, got %s", CategoryCompositeAction, ruleSet.Category)
	}

	if len(ruleSet.Rules) == 0 {
		t.Error("Expected some rules in the rule set")
	}

	// Check that all rules have the correct category
	for _, rule := range ruleSet.Rules {
		if rule.Category != CategoryCompositeAction {
			t.Errorf("Expected rule category %s, got %s", CategoryCompositeAction, rule.Category)
		}
	}
}

func TestRuleDeduplication(t *testing.T) {
	rule := NewCompositeActionRule()

	// Test case with duplicate issues
	yamlContent := `
name: 'Test Action'
description: 'Test composite action'
inputs:
  message:
    description: 'Message to display'
    required: true
runs:
  using: 'composite'
  steps:
    - name: Display message twice
      run: echo "${{ inputs.message }}" && echo "${{ inputs.message }}"
      shell: bash
`

	doc, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	var findings []*types.Finding
	// Run detection twice to test deduplication
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)
	types.WalkAST(doc.Docs[0], []string{}, "action.yml", []types.NodeVisitor{rule.detector}, &findings)

	// Should not have duplicates
	uniqueFindings := make(map[string]bool)
	duplicates := 0
	for _, finding := range findings {
		key := rule.GenerateFindingKey(CategoryCompositeAction, "action.yml", finding.Line, finding.Column, finding.Value, finding.YamlPath)
		if uniqueFindings[key] {
			duplicates++
		}
		uniqueFindings[key] = true
	}

	if duplicates > 0 {
		t.Errorf("Found %d duplicate findings, expected 0", duplicates)
	}
}
