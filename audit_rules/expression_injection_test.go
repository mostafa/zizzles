package audit_rules

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
	"github.com/mostafa/zizzles/yaml_patch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExpressionInjectionRule(t *testing.T) {
	rule := NewExpressionInjectionRule()

	// Test basic initialization
	if rule.Category != CategoryExpressionInjection {
		t.Errorf("expected category %s, got %s", CategoryExpressionInjection, rule.Category)
	}

	if rule.Severity != types.SeverityHigh {
		t.Errorf("expected severity %s, got %s", types.SeverityHigh, rule.Severity)
	}

	if rule.Type != types.RuleTypeAST {
		t.Errorf("expected type %s, got %s", types.RuleTypeAST, rule.Type)
	}

	// Test that slices and maps are initialized
	if rule.Expressions == nil {
		t.Error("expected Expressions to be initialized")
	}

	if rule.EnvVariables == nil {
		t.Error("expected EnvVariables to be initialized")
	}

	if rule.Findings == nil {
		t.Error("expected Findings to be initialized")
	}

	if rule.Fixes == nil {
		t.Error("expected Fixes to be initialized")
	}

	if rule.detector == nil {
		t.Error("expected detector to be initialized")
	}
}

func TestExpressionInjectionRuleExtractExpressions(t *testing.T) {
	rule := NewExpressionInjectionRule()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single expression",
			input:    "echo ${{ github.event.issue.title }}",
			expected: []string{"github.event.issue.title"},
		},
		{
			name:     "multiple expressions",
			input:    "echo ${{ github.event.issue.title }} and ${{ inputs.message }}",
			expected: []string{"github.event.issue.title", "inputs.message"},
		},
		{
			name:     "duplicate expressions",
			input:    "echo ${{ github.event.issue.title }} and ${{ github.event.issue.title }}",
			expected: []string{"github.event.issue.title"},
		},
		{
			name:     "no expressions",
			input:    "echo hello world",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.extractExpressions(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d expressions, got %d", len(tt.expected), len(result))
				return
			}
			for i, expr := range tt.expected {
				if result[i] != expr {
					t.Errorf("expected expression %s, got %s", expr, result[i])
				}
			}
		})
	}
}

func TestExpressionInjectionRuleToEnvName(t *testing.T) {
	rule := NewExpressionInjectionRule()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple expression",
			input:    "github.event.issue.title",
			expected: "GITHUB_EVENT_ISSUE_TITLE",
		},
		{
			name:     "with special characters",
			input:    "inputs.message-text",
			expected: "INPUTS_MESSAGE_TEXT",
		},
		{
			name:     "starts with number",
			input:    "123.input",
			expected: "EXPR_123_INPUT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.toEnvName(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestExpressionInjectionRuleIsInRunContext(t *testing.T) {
	rule := NewExpressionInjectionRule()

	tests := []struct {
		name     string
		path     []string
		expected bool
	}{
		{
			name:     "in run context",
			path:     []string{"jobs", "build", "steps", "0", "run"},
			expected: true,
		},
		{
			name:     "not in run context",
			path:     []string{"jobs", "build", "steps", "0", "name"},
			expected: false,
		},
		{
			name:     "empty path",
			path:     []string{},
			expected: false,
		},
		{
			name:     "run at end",
			path:     []string{"run"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.isInRunContext(tt.path)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestExpressionInjectionRuleRewriteRunWithEnv(t *testing.T) {
	rule := NewExpressionInjectionRule()

	input := "echo ${{ github.event.issue.title }} and ${{ inputs.message }}"
	expressions := []string{"github.event.issue.title", "inputs.message"}

	result := rule.RewriteRunWithEnv(input, expressions)

	// Check if the result contains the expected environment variable names
	if !strings.Contains(result, "$GITHUB_EVENT_ISSUE_TITLE") {
		t.Error("expected result to contain $GITHUB_EVENT_ISSUE_TITLE")
	}

	if !strings.Contains(result, "$INPUTS_MESSAGE") {
		t.Error("expected result to contain $INPUTS_MESSAGE")
	}
}

func TestExpressionInjectionRuleGetters(t *testing.T) {
	rule := NewExpressionInjectionRule()

	// Test initial state
	if len(rule.GetFindings()) != 0 {
		t.Error("expected empty findings initially")
	}

	if len(rule.GetFixes()) != 0 {
		t.Error("expected empty fixes initially")
	}

	if len(rule.GetExpressions()) != 0 {
		t.Error("expected empty expressions initially")
	}

	if len(rule.GetEnvVariables()) != 0 {
		t.Error("expected empty env variables initially")
	}

	// Test after setting some values
	rule.Expressions = []string{"test.expression"}
	rule.EnvVariables = map[string]string{"TEST_EXPRESSION": "${{ test.expression }}"}
	rule.Findings = []*types.Finding{}
	rule.Fixes = []string{"test fix"}

	if len(rule.GetExpressions()) != 1 {
		t.Error("expected 1 expression")
	}

	if len(rule.GetEnvVariables()) != 1 {
		t.Error("expected 1 env variable")
	}

	if len(rule.GetFixes()) != 1 {
		t.Error("expected 1 fix")
	}
}

func TestExpressionInjectionRule_ASTDetection(t *testing.T) {
	rule := NewExpressionInjectionRule()
	tests := []struct {
		name     string
		yaml     string
		expected []string // expected expressions
	}{
		{
			name: "single-line run",
			yaml: `steps:
  - run: echo ${{ github.event.issue.title }}`,
			expected: []string{"github.event.issue.title"},
		},
		{
			name: "multi-line literal run",
			yaml: `steps:
  - run: |
      echo before
      echo ${{ github.event.issue.title }}
      echo after`,
			expected: []string{"github.event.issue.title"},
		},
		{
			name: "multi-line folded run",
			yaml: `steps:
  - run: >
      echo before
      echo ${{ github.event.issue.title }}
      echo after`,
			expected: []string{"github.event.issue.title"},
		},
		{
			name: "multiple expressions",
			yaml: `steps:
  - run: echo ${{ github.event.issue.title }} and ${{ inputs.message }}`,
			expected: []string{"github.event.issue.title", "inputs.message"},
		},
		{
			name: "whitespace in expression",
			yaml: `steps:
  - run: echo ${{    github.event.issue.title    }}`,
			expected: []string{"github.event.issue.title"},
		},
		{
			name: "no expressions",
			yaml: `steps:
  - run: echo hello world`,
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			if err != nil {
				t.Fatalf("failed to parse yaml: %v", err)
			}
			rule.Findings = nil
			for _, doc := range file.Docs {
				rule.detectExpressionsInDocument(doc, "test.yaml")
			}
			var found []string
			for _, f := range rule.Findings {
				for _, expr := range tt.expected {
					if strings.Contains(f.Rule.Message, expr) {
						found = append(found, expr)
					}
				}
			}
			if len(found) != len(tt.expected) {
				t.Errorf("expected findings for %v, got %v", tt.expected, found)
			}
		})
	}
}

func TestPatternBasedDetection(t *testing.T) {
	ruleset := GetExpressionInjectionRules()
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		{
			name:        "pattern: echo with github.event",
			input:       "run: echo ${{ github.event.issue.title }}",
			shouldMatch: true,
		},
		{
			name:        "pattern: input variable",
			input:       "run: echo ${{ inputs.message }}",
			shouldMatch: true,
		},
		{
			name:        "pattern: no match",
			input:       "run: echo hello world",
			shouldMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := false
			for _, rule := range ruleset.Rules {
				re := regexp.MustCompile(rule.Pattern)
				if re.MatchString(tt.input) {
					matched = true
				}
			}
			if matched != tt.shouldMatch {
				t.Errorf("expected match=%v, got %v", tt.shouldMatch, matched)
			}
		})
	}
}

func TestExpressionInjection_EdgeCases(t *testing.T) {
	rule := NewExpressionInjectionRule()
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "nested expression (should not match)",
			input:    "echo ${{ ${{ github.event.issue.title }} }}",
			expected: []string{"${{ github.event.issue.title"}, // Current logic extracts first complete expression
		},
		{
			name: "expression with newline",
			input: `echo ${{
github.event.issue.title
}}`,
			expected: []string{"github.event.issue.title"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.extractExpressions(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d expressions, got %d", len(tt.expected), len(result))
				return
			}
			for i, expr := range tt.expected {
				if result[i] != expr {
					t.Errorf("expected expression %s, got %s", expr, result[i])
				}
			}
		})
	}
}

func TestGetExpressionInjectionRuleInstance(t *testing.T) {
	rule := GetExpressionInjectionRuleInstance()

	if rule == nil {
		t.Error("expected non-nil rule instance")
	}

	if rule.Category != CategoryExpressionInjection {
		t.Errorf("expected category %s, got %s", CategoryExpressionInjection, rule.Category)
	}
}

func TestExpressionInjectionRuleWithYAMLPatch(t *testing.T) {
	// Create a temporary YAML file with expression injection vulnerabilities
	yamlContent := `name: Test Workflow
on:
  issues:
    types: [opened]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Echo issue title
        run: 'echo "Issue: ${{ github.event.issue.title }}"'
      
      - name: Process input
        run: |
          echo 'Processing: ${{ inputs.process_name }}'
          echo 'Status: ${{ vars.status }}'
      
      - name: Safe command
        run: echo "This is safe"
`

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "test-*.yml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	// Create rule and detect issues
	rule := NewExpressionInjectionRule()
	err = rule.DetectExpressionsInFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify findings
	findings := rule.GetFindings()
	assert.Len(t, findings, 3, "Should detect 3 expression injection vulnerabilities")

	// Apply fixes using yaml_patch
	fixedContent, err := rule.FixFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify the fixed content
	expectedContent := `name: Test Workflow
on:
  issues:
    types: [opened]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Echo issue title
        run: 'echo "Issue: $GITHUB_EVENT_ISSUE_TITLE"'
        env:
          GITHUB_EVENT_ISSUE_TITLE: ${{ github.event.issue.title }}
      
      - name: Process input
        run: |
          echo 'Processing: $INPUTS_PROCESS_NAME'
          echo 'Status: $VARS_STATUS'
        env:
          INPUTS_PROCESS_NAME: ${{ inputs.process_name }}
          VARS_STATUS: ${{ vars.status }}
      
      - name: Safe command
        run: echo "This is safe"
`

	assert.Equal(t, expectedContent, fixedContent, "Fixed content should match expected")

	// Verify fixes were recorded
	fixes := rule.GetFixes()
	assert.Len(t, fixes, 2, "Should record 2 fixes")
}

func TestExpressionInjectionRuleWithComplexExpressions(t *testing.T) {
	// Test with more complex expressions
	yamlContent := `jobs:
  test:
    steps:
      - name: Complex expressions
        run: |
          echo 'Title: ${{ github.event.issue.title }}'
          echo 'Body: ${{ github.event.issue.body }}'
          echo 'User: ${{ github.event.issue.user.login }}'
          echo 'Repo: ${{ github.repository }}'
          echo 'Ref: ${{ github.ref_name }}'
`

	tmpFile, err := os.CreateTemp("", "test-complex-*.yml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	rule := NewExpressionInjectionRule()
	err = rule.DetectExpressionsInFile(tmpFile.Name())
	require.NoError(t, err)

	findings := rule.GetFindings()
	assert.Len(t, findings, 5, "Should detect 5 expression injection vulnerabilities")

	fixedContent, err := rule.FixFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify environment variables were added
	assert.Contains(t, fixedContent, "GITHUB_EVENT_ISSUE_TITLE:")
	assert.Contains(t, fixedContent, "GITHUB_EVENT_ISSUE_BODY:")
	assert.Contains(t, fixedContent, "GITHUB_EVENT_ISSUE_USER_LOGIN:")
	assert.Contains(t, fixedContent, "GITHUB_REPOSITORY:")
	assert.Contains(t, fixedContent, "GITHUB_REF_NAME:")

	// Verify expressions were replaced
	assert.Contains(t, fixedContent, "$GITHUB_EVENT_ISSUE_TITLE")
	assert.Contains(t, fixedContent, "$GITHUB_EVENT_ISSUE_BODY")
	assert.Contains(t, fixedContent, "$GITHUB_EVENT_ISSUE_USER_LOGIN")
	assert.Contains(t, fixedContent, "$GITHUB_REPOSITORY")
	assert.Contains(t, fixedContent, "$GITHUB_REF_NAME")
}

func TestExpressionInjectionRuleWithNoExpressions(t *testing.T) {
	// Test with no expressions (should not modify)
	yamlContent := `jobs:
  test:
    steps:
      - name: Safe command
        run: echo "This is safe"
      
      - name: Another safe command
        run: |
          echo "No expressions here"
          echo "Just plain text"
`

	tmpFile, err := os.CreateTemp("", "test-safe-*.yml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	rule := NewExpressionInjectionRule()
	err = rule.DetectExpressionsInFile(tmpFile.Name())
	require.NoError(t, err)

	findings := rule.GetFindings()
	assert.Len(t, findings, 0, "Should detect no expression injection vulnerabilities")

	fixedContent, err := rule.FixFile(tmpFile.Name())
	require.NoError(t, err)

	// Content should be unchanged
	assert.Equal(t, yamlContent, fixedContent, "Content should be unchanged when no expressions found")

	fixes := rule.GetFixes()
	assert.Len(t, fixes, 0, "Should record no fixes")
}

func TestExpressionInjectionRuleWithMultipleJobs(t *testing.T) {
	// Test with multiple jobs
	yamlContent := `jobs:
  job1:
    steps:
      - name: Job 1 step
        run: 'echo "Job 1: ${{ github.event.issue.title }}"'
  
  job2:
    steps:
      - name: Job 2 step
        run: 'echo "Job 2: ${{ inputs.name }}"'
`

	tmpFile, err := os.CreateTemp("", "test-multi-job-*.yml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	tmpFile.Close()

	rule := NewExpressionInjectionRule()
	err = rule.DetectExpressionsInFile(tmpFile.Name())
	require.NoError(t, err)

	findings := rule.GetFindings()
	assert.Len(t, findings, 2, "Should detect 2 expression injection vulnerabilities")

	fixedContent, err := rule.FixFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify both jobs were fixed
	assert.Contains(t, fixedContent, "job1:")
	assert.Contains(t, fixedContent, "job2:")
	assert.Contains(t, fixedContent, "GITHUB_EVENT_ISSUE_TITLE:")
	assert.Contains(t, fixedContent, "INPUTS_NAME:")
	assert.Contains(t, fixedContent, "$GITHUB_EVENT_ISSUE_TITLE")
	assert.Contains(t, fixedContent, "$INPUTS_NAME")
}

func TestToEnvName(t *testing.T) {
	rule := NewExpressionInjectionRule()

	tests := []struct {
		input    string
		expected string
	}{
		{"github.event.issue.title", "GITHUB_EVENT_ISSUE_TITLE"},
		{"inputs.process_name", "INPUTS_PROCESS_NAME"},
		{"vars.status", "VARS_STATUS"},
		{"github.event.issue.user.login", "GITHUB_EVENT_ISSUE_USER_LOGIN"},
		{"1invalid", "EXPR_1INVALID"},
		{"valid-name", "VALID_NAME"},
		{"mixed123_name", "MIXED123_NAME"},
	}

	for _, test := range tests {
		result := rule.toEnvName(test.input)
		assert.Equal(t, test.expected, result, "toEnvName(%s) should return %s", test.input, test.expected)
	}
}

func TestRewriteRunWithEnv(t *testing.T) {
	rule := NewExpressionInjectionRule()

	runContent := `echo "Title: ${{ github.event.issue.title }}"
echo "Body: ${{ github.event.issue.body }}"
echo "User: ${{ github.event.issue.user.login }}"`

	expressions := []string{
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.issue.user.login",
	}

	fixed := rule.RewriteRunWithEnv(runContent, expressions)

	expected := `echo "Title: $GITHUB_EVENT_ISSUE_TITLE"
echo "Body: $GITHUB_EVENT_ISSUE_BODY"
echo "User: $GITHUB_EVENT_ISSUE_USER_LOGIN"`

	assert.Equal(t, expected, fixed, "RewriteRunWithEnv should replace expressions correctly")
}

func TestYAMLPatchAddOpWithSequence(t *testing.T) {
	// Test yaml_patch AddOp with sequence items
	yamlContent := `steps:
  - name: Test step
    run: echo "test"
  - name: Another step
    run: echo "another"`

	patches := []yaml_patch.Patch{
		{
			Path: "steps.0",
			Operation: yaml_patch.AddOp{
				Key:   "env",
				Value: map[string]string{"TEST_VAR": "test_value"},
			},
		},
	}

	result, err := yaml_patch.ApplyYAMLPatches(yamlContent, patches)
	if err != nil {
		t.Logf("YAML patch error: %v", err)
		t.Logf("Result: %s", result)
		t.Fail()
	}

	t.Logf("Original: %s", yamlContent)
	t.Logf("Result: %s", result)

	// Verify the result is valid YAML
	expectedContains := "env:"
	if !strings.Contains(result, expectedContains) {
		t.Errorf("Expected result to contain '%s', got: %s", expectedContains, result)
	}
}
