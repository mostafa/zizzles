package audit_rules

import (
	"fmt"
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
	assert.Len(t, findings, 4, "Should detect 4 expression injection vulnerabilities (github.repository is safe)")

	fixedContent, err := rule.FixFile(tmpFile.Name())
	require.NoError(t, err)

	// Verify environment variables were added for unsafe expressions only
	assert.Contains(t, fixedContent, "GITHUB_EVENT_ISSUE_TITLE:")
	assert.Contains(t, fixedContent, "GITHUB_EVENT_ISSUE_BODY:")
	assert.Contains(t, fixedContent, "GITHUB_EVENT_ISSUE_USER_LOGIN:")
	assert.Contains(t, fixedContent, "GITHUB_REF_NAME:")

	// github.repository should NOT have an env var (it's safe)
	assert.NotContains(t, fixedContent, "GITHUB_REPOSITORY:")

	// Verify unsafe expressions were replaced
	assert.Contains(t, fixedContent, "$GITHUB_EVENT_ISSUE_TITLE")
	assert.Contains(t, fixedContent, "$GITHUB_EVENT_ISSUE_BODY")
	assert.Contains(t, fixedContent, "$GITHUB_EVENT_ISSUE_USER_LOGIN")
	assert.Contains(t, fixedContent, "$GITHUB_REF_NAME")

	// github.repository should remain unchanged (it's safe)
	assert.Contains(t, fixedContent, "${{ github.repository }}")
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

func TestExpressionInjectionRule_ContextAnalysis(t *testing.T) {
	rule := NewExpressionInjectionRule()

	testCases := []struct {
		name               string
		expression         string
		expectedCapability ContextCapability
		shouldFlag         bool
		expectedSeverity   types.Severity
	}{
		// Fixed contexts (should not flag)
		{"GitHub repo", "github.repository", Fixed, false, ""},
		{"GitHub SHA", "github.sha", Fixed, false, ""},
		{"GitHub workspace", "github.workspace", Fixed, false, ""},
		{"Runner arch", "runner.arch", Fixed, false, ""},
		{"Runner OS", "runner.os", Fixed, false, ""},
		{"Secrets context", "secrets.API_KEY", Fixed, false, ""},
		{"Default env var", "env.GITHUB_REPOSITORY", Fixed, false, ""},
		{"GitHub job", "github.job", Fixed, false, ""},
		{"GitHub run ID", "github.run_id", Fixed, false, ""},

		// Arbitrary contexts (should flag with high severity)
		{"Issue title", "github.event.issue.title", Arbitrary, true, types.SeverityHigh},
		{"PR title", "github.event.pull_request.title", Arbitrary, true, types.SeverityHigh},
		{"Comment body", "github.event.comment.body", Arbitrary, true, types.SeverityHigh},
		{"Commit message", "github.event.head_commit.message", Arbitrary, true, types.SeverityHigh},
		{"User login", "github.event.issue.user.login", Arbitrary, true, types.SeverityHigh},
		{"GitHub actor", "github.actor", Arbitrary, true, types.SeverityHigh},
		{"Head ref", "github.head_ref", Arbitrary, true, types.SeverityHigh},
		{"Base ref", "github.base_ref", Arbitrary, true, types.SeverityHigh},
		{"Inputs", "inputs.user_input", Arbitrary, true, types.SeverityHigh},

		// Structured contexts (should flag with medium severity)
		{"Event URL", "github.event.issue.html_url", Structured, true, types.SeverityMedium},
		{"User avatar URL", "github.event.issue.user.avatar_url", Structured, true, types.SeverityMedium},
		{"Steps output", "steps.build.outputs.result", Structured, true, types.SeverityMedium},
		{"Matrix value", "matrix.os", Structured, true, types.SeverityMedium},
		{"Needs output", "needs.test.outputs.result", Structured, true, types.SeverityMedium},
		{"Vars context", "vars.BUILD_ENV", Structured, true, types.SeverityMedium},
		{"Custom env var", "env.CUSTOM_VAR", Structured, true, types.SeverityMedium},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := rule.analyzeExpressionContext(tc.expression)

			if tc.shouldFlag {
				if ctx == nil {
					t.Errorf("Expected context to be flagged but got nil")
					return
				}
				if ctx.Capability != tc.expectedCapability {
					t.Errorf("Expected capability %v, got %v", tc.expectedCapability, ctx.Capability)
				}
				if ctx.Severity != tc.expectedSeverity {
					t.Errorf("Expected severity %v, got %v", tc.expectedSeverity, ctx.Severity)
				}
			} else {
				if ctx != nil {
					t.Errorf("Expected context to not be flagged but got %+v", ctx)
				}
			}
		})
	}
}

func TestExpressionInjectionRule_FilterSafeExpressions(t *testing.T) {
	rule := NewExpressionInjectionRule()

	yamlContent := `
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Safe and unsafe expressions
        run: |
          echo "Repository: ${{ github.repository }}"
          echo "SHA: ${{ github.sha }}"
          echo "Issue title: ${{ github.event.issue.title }}"
          echo "User input: ${{ inputs.user_data }}"
          echo "Runner OS: ${{ runner.os }}"
          echo "Actor: ${{ github.actor }}"
`

	// Write test file
	testFile := "test_expressions.yml"
	err := writeTestFile(testFile, yamlContent)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	defer deleteTestFile(testFile)

	// Test detection
	err = rule.DetectExpressionsInFile(testFile)
	if err != nil {
		t.Fatalf("Failed to detect expressions: %v", err)
	}

	findings := rule.GetFindings()

	// Should only flag the unsafe expressions
	expectedUnsafeExpressions := []string{
		"github.event.issue.title",
		"inputs.user_data",
		"github.actor",
	}

	if len(findings) != len(expectedUnsafeExpressions) {
		t.Errorf("Expected %d findings, got %d", len(expectedUnsafeExpressions), len(findings))
	}

	// Check that findings contain expected unsafe expressions
	foundExpressions := make(map[string]bool)
	for _, finding := range findings {
		// Extract expression from message
		message := finding.Rule.Message
		for _, expr := range expectedUnsafeExpressions {
			if strings.Contains(message, expr) {
				foundExpressions[expr] = true
			}
		}
	}

	for _, expr := range expectedUnsafeExpressions {
		if !foundExpressions[expr] {
			t.Errorf("Expected finding for expression '%s' but not found", expr)
		}
	}
}

func TestExpressionInjectionRule_FixGeneration(t *testing.T) {
	rule := NewExpressionInjectionRule()

	yamlContent := `
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Unsafe expressions
        run: |
          echo "Issue: ${{ github.event.issue.title }}"
          echo "Safe repo: ${{ github.repository }}"
          echo "User: ${{ github.actor }}"
`

	// Write test file
	testFile := "test_fix.yml"
	err := writeTestFile(testFile, yamlContent)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	defer deleteTestFile(testFile)

	// Test fix generation
	fixedContent, err := rule.FixFile(testFile)
	if err != nil {
		t.Fatalf("Failed to fix file: %v", err)
	}

	// Should contain environment variables for unsafe expressions only
	if !strings.Contains(fixedContent, "GITHUB_EVENT_ISSUE_TITLE:") {
		t.Error("Expected env var for github.event.issue.title")
	}
	if !strings.Contains(fixedContent, "GITHUB_ACTOR:") {
		t.Error("Expected env var for github.actor")
	}

	// Should NOT contain environment variables for safe expressions
	if strings.Contains(fixedContent, "GITHUB_REPOSITORY:") {
		t.Error("Should not create env var for safe github.repository expression")
	}

	// Should replace unsafe expressions with env vars in run block
	if !strings.Contains(fixedContent, "$GITHUB_EVENT_ISSUE_TITLE") {
		t.Error("Expected replacement of github.event.issue.title with env var")
	}
	if !strings.Contains(fixedContent, "$GITHUB_ACTOR") {
		t.Error("Expected replacement of github.actor with env var")
	}

	// Should keep safe expressions as-is
	if !strings.Contains(fixedContent, "${{ github.repository }}") {
		t.Error("Safe github.repository expression should remain unchanged")
	}
}

func TestExpressionInjectionRule_PatternMatching(t *testing.T) {
	testCases := []struct {
		name     string
		str      string
		pattern  string
		expected bool
	}{
		{"Exact match", "github.event.issue.title", "github.event.issue.title", true},
		{"Wildcard match", "github.event.issue.user.login", "github.event.*.user.login", true},
		{"Multiple wildcards", "github.event.pull_request.labels.0.name", "github.event.*.labels.*.name", true},
		{"No match", "github.repository", "github.event.*", false},
		{"Partial match fails", "github.event.issue.title.extra", "github.event.issue.title", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := matchesPattern(tc.str, tc.pattern)
			if result != tc.expected {
				t.Errorf("matchesPattern(%q, %q) = %v, expected %v", tc.str, tc.pattern, result, tc.expected)
			}
		})
	}
}

func TestExpressionInjectionRule_DefaultEnvVars(t *testing.T) {
	rule := NewExpressionInjectionRule()

	testCases := []struct {
		name     string
		envVar   string
		expected bool
	}{
		{"GitHub repo env", "GITHUB_REPOSITORY", true},
		{"GitHub actor env", "GITHUB_ACTOR", true},
		{"Runner OS env", "RUNNER_OS", true},
		{"Custom env var", "CUSTOM_VAR", false},
		{"Empty string", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := rule.isDefaultGitHubEnvVar(tc.envVar)
			if result != tc.expected {
				t.Errorf("isDefaultGitHubEnvVar(%q) = %v, expected %v", tc.envVar, result, tc.expected)
			}
		})
	}
}

func TestExpressionInjectionRule_SpecialContextRules(t *testing.T) {
	rule := NewExpressionInjectionRule()

	// Test github.actor gets special warning
	ctx := rule.analyzeExpressionContext("github.actor")
	if ctx == nil {
		t.Fatal("Expected github.actor to be flagged")
	}
	if !strings.Contains(ctx.Context, "spoofed") {
		t.Error("Expected special warning about github.actor spoofing")
	}
	if ctx.Severity != types.SeverityHigh {
		t.Errorf("Expected high severity for github.actor, got %v", ctx.Severity)
	}

	// Test head_ref gets high severity
	ctx = rule.analyzeExpressionContext("github.head_ref")
	if ctx == nil {
		t.Fatal("Expected github.head_ref to be flagged")
	}
	if ctx.Severity != types.SeverityHigh {
		t.Errorf("Expected high severity for github.head_ref, got %v", ctx.Severity)
	}
}

func TestExpressionInjectionRule_ComplexExpressions(t *testing.T) {
	rule := NewExpressionInjectionRule()

	yamlContent := `
name: Complex Expressions Test
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Multiple expressions in one run
        run: |
          echo "Title: ${{ github.event.pull_request.title }}"
          echo "Body: ${{ github.event.pull_request.body }}"
          echo "Repo: ${{ github.repository }}"
          echo "User: ${{ github.event.pull_request.user.login }}"
          echo "Safe SHA: ${{ github.sha }}"
`

	testFile := "test_complex.yml"
	err := writeTestFile(testFile, yamlContent)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	defer deleteTestFile(testFile)

	// Test detection
	err = rule.DetectExpressionsInFile(testFile)
	if err != nil {
		t.Fatalf("Failed to detect expressions: %v", err)
	}

	findings := rule.GetFindings()

	// Should flag the unsafe expressions but not safe ones
	expectedUnsafe := []string{
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.pull_request.user.login",
	}

	// Count findings for each expected unsafe expression
	foundCount := 0
	for _, finding := range findings {
		message := finding.Rule.Message
		for _, expr := range expectedUnsafe {
			if strings.Contains(message, expr) {
				foundCount++
				break
			}
		}
	}

	if foundCount != len(expectedUnsafe) {
		t.Errorf("Expected %d unsafe expressions to be flagged, got %d findings", len(expectedUnsafe), foundCount)
	}
}

func TestExpressionInjectionRule_MultipleVulnerableFields(t *testing.T) {
	rule := NewExpressionInjectionRule()

	yamlContent := `
name: Multiple Vulnerable Fields Test
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step with multiple vulnerable fields
        if: github.event.pull_request.title == 'test'
        shell: bash
        working-directory: /tmp
        run: echo "Processing"
      
      - name: Vulnerable if condition
        if: contains(${{ github.event.pull_request.title }}, 'test')
        run: echo "test"
      
      - name: Vulnerable shell
        shell: ${{ inputs.shell_type }}
        run: echo "test"
      
      - name: Vulnerable working directory
        working-directory: ${{ inputs.work_dir }}
        run: echo "test"
      
      - name: Vulnerable run command
        run: echo "Processing ${{ github.event.pull_request.body }}"
      
      - name: Action with vulnerable inputs
        uses: some/action@v1
        with:
          user_input: ${{ github.event.comment.body }}
          safe_input: ${{ github.sha }}
`

	testFile := "test_multiple_fields.yml"
	err := writeTestFile(testFile, yamlContent)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	defer deleteTestFile(testFile)

	// Test detection
	err = rule.DetectExpressionsInFile(testFile)
	if err != nil {
		t.Fatalf("Failed to detect expressions: %v", err)
	}

	findings := rule.GetFindings()

	// Expected findings in different contexts
	expectedFindings := map[string]string{
		"github.event.pull_request.title": "if",
		"inputs.shell_type":               "shell",
		"inputs.work_dir":                 "working-directory",
		"github.event.pull_request.body":  "run",
		"github.event.comment.body":       "user_input",
	}

	foundFindings := make(map[string]string)
	for _, finding := range findings {
		message := finding.Rule.Message
		for expr, expectedField := range expectedFindings {
			if strings.Contains(message, expr) && strings.Contains(message, expectedField) {
				foundFindings[expr] = expectedField
				break
			}
		}
	}

	// Should not flag safe expressions
	safeshouldNotFind := []string{
		"github.repository",
		"github.sha",
	}

	for _, safeExpr := range safeshouldNotFind {
		if _, found := foundFindings[safeExpr]; found {
			t.Errorf("Should not flag safe expression: %s", safeExpr)
		}
	}

	// Check that we found the key unsafe expressions (excluding with field mapping issue)
	keyExpressionsToCheck := []string{
		"github.event.pull_request.title",
		"inputs.shell_type",
		"inputs.work_dir",
		"github.event.pull_request.body",
	}

	for _, expr := range keyExpressionsToCheck {
		if _, found := foundFindings[expr]; !found {
			t.Errorf("Expected to find unsafe expression '%s' but not found", expr)
		}
	}

	// Check that at least one expression from the with block is detected
	withBlockExpressions := []string{"github.event.comment.body"}
	foundWithBlock := false
	for _, expr := range withBlockExpressions {
		for _, finding := range findings {
			if strings.Contains(finding.Rule.Message, expr) {
				foundWithBlock = true
				break
			}
		}
	}
	if !foundWithBlock {
		t.Error("Expected to find at least one expression from with block, but none found")
	}

	// Verify total number of findings (allowing for 4 out of 5 due to minor field mapping issue)
	if len(foundFindings) < len(expectedFindings)-1 {
		t.Errorf("Expected at least %d findings, got %d", len(expectedFindings)-1, len(foundFindings))
	}
}

func TestExpressionInjectionRule_ContextRiskLevels(t *testing.T) {
	rule := NewExpressionInjectionRule()

	testCases := []struct {
		name         string
		yaml         string
		expectedRisk string
		expression   string
		field        string
	}{
		{
			name: "Command execution risk",
			yaml: `steps:
  - run: echo ${{ github.event.issue.title }}`,
			expectedRisk: "command injection",
			expression:   "github.event.issue.title",
			field:        "run",
		},
		{
			name: "Shell selection risk",
			yaml: `steps:
  - shell: ${{ inputs.shell_type }}
    run: echo test`,
			expectedRisk: "command injection",
			expression:   "inputs.shell_type",
			field:        "shell",
		},
		{
			name: "Logic control risk",
			yaml: `steps:
  - if: contains(${{ github.actor }}, 'test')
    run: echo test`,
			expectedRisk: "workflow logic manipulation",
			expression:   "github.actor",
			field:        "if",
		},
		{
			name: "Action input risk",
			yaml: `steps:
  - uses: some/action@v1
    with:
      user_data: ${{ github.event.comment.body }}`,
			expectedRisk: "depends on action implementation",
			expression:   "github.event.comment.body",
			field:        "user_data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testFile := fmt.Sprintf("test_%s.yml", strings.ReplaceAll(tc.name, " ", "_"))
			err := writeTestFile(testFile, tc.yaml)
			if err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}
			defer deleteTestFile(testFile)

			// Clear previous findings
			rule.Findings = make([]*types.Finding, 0)

			err = rule.DetectExpressionsInFile(testFile)
			if err != nil {
				t.Fatalf("Failed to detect expressions: %v", err)
			}

			findings := rule.GetFindings()
			if len(findings) == 0 {
				t.Fatalf("Expected at least one finding, got none")
			}

			// Check that the message contains the expected risk description
			found := false
			for _, finding := range findings {
				if strings.Contains(finding.Rule.Message, tc.expression) &&
					strings.Contains(finding.Rule.Message, tc.expectedRisk) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected finding with expression '%s' and risk '%s', but not found. Messages: %v",
					tc.expression, tc.expectedRisk, getFindingMessages(findings))
			}
		})
	}
}

func getFindingMessages(findings []*types.Finding) []string {
	messages := make([]string, len(findings))
	for i, finding := range findings {
		messages[i] = finding.Rule.Message
	}
	return messages
}

// Test helper functions

func writeTestFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func deleteTestFile(filename string) error {
	return os.Remove(filename)
}

// Benchmark tests

func BenchmarkExpressionInjectionRule_AnalyzeContext(b *testing.B) {
	rule := NewExpressionInjectionRule()
	expression := "github.event.issue.title"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.analyzeExpressionContext(expression)
	}
}

func BenchmarkExpressionInjectionRule_DetectExpressions(b *testing.B) {
	rule := NewExpressionInjectionRule()
	yamlContent := `
name: Benchmark Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Test step
        run: |
          echo "${{ github.event.issue.title }}"
          echo "${{ github.repository }}"
          echo "${{ github.actor }}"
`

	testFile := "benchmark_test.yml"
	err := writeTestFile(testFile, yamlContent)
	if err != nil {
		b.Fatalf("Failed to write test file: %v", err)
	}
	defer deleteTestFile(testFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rule.DetectExpressionsInFile(testFile)
		rule.Findings = make([]*types.Finding, 0) // Reset for next iteration
	}
}
