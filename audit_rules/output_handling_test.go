package audit_rules

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOutputHandlingRule(t *testing.T) {
	rule := NewOutputHandlingRule()

	assert.Equal(t, CategoryOutputHandling, rule.Category)
	assert.Equal(t, types.SeverityMedium, rule.Severity)
	assert.Equal(t, types.RuleTypeAST, rule.Type)
	assert.NotNil(t, rule.detector)
}

func TestDeprecatedSetOutputDetection(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		expectIssue bool
		description string
	}{
		{
			name: "deprecated set-output command",
			yamlContent: `
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Set output
        run: echo "::set-output name=result::value"
`,
			expectIssue: true,
			description: "Should detect deprecated ::set-output command",
		},
		{
			name: "modern GITHUB_OUTPUT usage",
			yamlContent: `
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Set output
        run: echo "result=value" >> $GITHUB_OUTPUT
`,
			expectIssue: false,
			description: "Should not flag modern $GITHUB_OUTPUT usage",
		},
		{
			name: "mixed deprecated and modern",
			yamlContent: `
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Old way
        run: echo "::set-output name=old::value"
      - name: New way
        run: echo "new=value" >> $GITHUB_OUTPUT
`,
			expectIssue: true,
			description: "Should detect deprecated command even when modern usage is present",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)
			hasDeprecatedSetOutput := hasIssueWithMessage(findings, "Deprecated ::set-output command detected")
			assert.Equal(t, tt.expectIssue, hasDeprecatedSetOutput, tt.description)
		})
	}
}

func TestSensitiveDataLeakDetection(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		expectIssue bool
		description string
	}{
		{
			name: "direct secret in output",
			yamlContent: `
outputs:
  token:
    description: "API token"
    value: ${{ secrets.API_TOKEN }}
`,
			expectIssue: true,
			description: "Should detect direct secret exposure in outputs",
		},
		{
			name: "github token in output",
			yamlContent: `
outputs:
  github_token:
    description: "GitHub token"
    value: ${{ github.token }}
`,
			expectIssue: true,
			description: "Should detect GitHub token exposure",
		},
		{
			name: "password in output",
			yamlContent: `
outputs:
  db_password:
    description: "Database password"
    value: ${{ secrets.DB_PASSWORD }}
`,
			expectIssue: true,
			description: "Should detect password-like secrets",
		},
		{
			name: "safe output value",
			yamlContent: `
outputs:
  result:
    description: "Computation result"
    value: ${{ steps.compute.outputs.result }}
`,
			expectIssue: false,
			description: "Should not flag safe output values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)
			hasSensitiveDataLeak := hasIssueWithMessage(findings, "Potential sensitive data leak in output")
			assert.Equal(t, tt.expectIssue, hasSensitiveDataLeak, tt.description)
		})
	}
}

func TestOutputDescriptionChecks(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		expectIssue bool
		issueType   string
		description string
	}{
		{
			name: "missing description",
			yamlContent: `
outputs:
  result:
    value: ${{ steps.compute.outputs.result }}
`,
			expectIssue: true,
			issueType:   "missing",
			description: "Should detect missing output description",
		},
		{
			name: "vague description - string",
			yamlContent: `
outputs:
  result:
    description: "string"
    value: ${{ steps.compute.outputs.result }}
`,
			expectIssue: true,
			issueType:   "vague",
			description: "Should detect vague 'string' description",
		},
		{
			name: "vague description - a value",
			yamlContent: `
outputs:
  result:
    description: "a value"
    value: ${{ steps.compute.outputs.result }}
`,
			expectIssue: true,
			issueType:   "vague",
			description: "Should detect vague 'a value' description",
		},
		{
			name: "good description",
			yamlContent: `
outputs:
  result:
    description: "Base64-encoded computation result as JSON object with keys 'status' and 'data'"
    value: ${{ steps.compute.outputs.result }}
`,
			expectIssue: false,
			issueType:   "",
			description: "Should not flag detailed, clear description",
		},
		{
			name: "job output missing description",
			yamlContent: `
jobs:
  build:
    outputs:
      artifact:
        value: ${{ steps.build.outputs.artifact }}
`,
			expectIssue: true,
			issueType:   "missing",
			description: "Should detect missing description in job outputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)

			switch tt.issueType {
			case "missing":
				hasMissingDesc := hasIssueWithMessage(findings, "Output definition missing description")
				assert.Equal(t, tt.expectIssue, hasMissingDesc, tt.description)
			case "vague":
				hasVagueDesc := hasIssueWithMessage(findings, "Output description is too vague")
				assert.Equal(t, tt.expectIssue, hasVagueDesc, tt.description)
			default:
				// Should not have any description-related issues
				hasMissingDesc := hasIssueWithMessage(findings, "Output definition missing description")
				hasVagueDesc := hasIssueWithMessage(findings, "Output description is too vague")
				assert.False(t, hasMissingDesc || hasVagueDesc, tt.description)
			}
		})
	}
}

func TestUnsafeOutputInShellDetection(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		expectIssue bool
		description string
	}{
		{
			name: "unquoted output in shell",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Use output
        run: echo ${{ steps.previous.outputs.result }}
`,
			expectIssue: true,
			description: "Should detect unquoted output usage in shell",
		},
		{
			name: "direct echo without quotes",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Echo output
        run: echo ${{ steps.build.outputs.artifact_name }}
`,
			expectIssue: true,
			description: "Should detect direct echo without quotes",
		},
		{
			name: "properly quoted output",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Use output safely
        run: echo "${{ steps.previous.outputs.result }}"
`,
			expectIssue: false,
			description: "Should not flag properly quoted output usage",
		},
		{
			name: "output in environment variable",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Use output in env
        env:
          RESULT: ${{ steps.previous.outputs.result }}
        run: echo "$RESULT"
`,
			expectIssue: false,
			description: "Should not flag output usage in environment variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)
			hasUnsafeUsage := hasIssueWithMessage(findings, "Unsafe output usage in shell")
			assert.Equal(t, tt.expectIssue, hasUnsafeUsage, tt.description)
		})
	}
}

func TestUserInputDirectlyInOutputDetection(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		expectIssue bool
		description string
	}{
		{
			name: "issue title in output",
			yamlContent: `
outputs:
  issue_title:
    description: "Issue title"
    value: ${{ github.event.issue.title }}
`,
			expectIssue: true,
			description: "Should detect user-controlled issue title in output",
		},
		{
			name: "pull request body in output",
			yamlContent: `
outputs:
  pr_body:
    description: "PR body"
    value: ${{ github.event.pull_request.body }}
`,
			expectIssue: true,
			description: "Should detect user-controlled PR body in output",
		},
		{
			name: "github actor in output",
			yamlContent: `
outputs:
  actor:
    description: "GitHub actor"
    value: ${{ github.actor }}
`,
			expectIssue: true,
			description: "Should detect user-controlled actor in output",
		},
		{
			name: "safe computed value",
			yamlContent: `
outputs:
  computed:
    description: "Computed hash"
    value: ${{ steps.hash.outputs.sha256 }}
`,
			expectIssue: false,
			description: "Should not flag computed/derived values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)
			hasUserInput := hasIssueWithMessage(findings, "Output uses user-controlled input directly")
			assert.Equal(t, tt.expectIssue, hasUserInput, tt.description)
		})
	}
}

func TestOutputSanitizationDetection(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		expectIssue bool
		description string
	}{
		{
			name: "expression with dangerous characters",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Unsafe echo
        run: |
          echo "Result: ${{ steps.build.outputs.result }}"; echo "Done"
`,
			expectIssue: true,
			description: "Should detect expressions with dangerous characters",
		},
		{
			name: "direct echo with expression",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Direct echo
        run: echo "Value is ${{ inputs.value }}"
`,
			expectIssue: true,
			description: "Should detect direct echo with expressions",
		},
		{
			name: "properly escaped output",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Safe usage
        run: |
          VALUE="${{ steps.build.outputs.result }}"
          echo "Escaped value: $VALUE"
`,
			expectIssue: false,
			description: "Should not flag properly handled output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)

			hasSanitizationIssue := hasIssueWithMessage(findings, "Potential output sanitization issue")
			assert.Equal(t, tt.expectIssue, hasSanitizationIssue, tt.description)
		})
	}
}

func TestGetOutputHandlingRules(t *testing.T) {
	ruleSet := GetOutputHandlingRules()

	assert.Equal(t, CategoryOutputHandling, ruleSet.Category)

	// Output handling now uses AST-only detection for better accuracy and context awareness
	// Pattern rules were removed to avoid conflicts and redundancy with AST detection
	assert.Empty(t, ruleSet.Rules, "Output handling uses AST-only detection, no pattern rules needed")
}

func TestContextDetectionHelpers(t *testing.T) {
	rule := NewOutputHandlingRule()
	detector := rule.detector

	tests := []struct {
		name     string
		path     []string
		method   string
		expected bool
	}{
		{
			name:     "outputs context - root level",
			path:     []string{"outputs", "result"},
			method:   "isInOutputsContext",
			expected: true,
		},
		{
			name:     "outputs context - job level",
			path:     []string{"jobs", "build", "outputs", "artifact"},
			method:   "isInOutputsContext",
			expected: true,
		},
		{
			name:     "not in outputs context",
			path:     []string{"jobs", "build", "steps", "0"},
			method:   "isInOutputsContext",
			expected: false,
		},
		{
			name:     "output definition context",
			path:     []string{"outputs", "result"},
			method:   "isInOutputDefinitionContext",
			expected: true,
		},
		{
			name:     "job output definition context",
			path:     []string{"jobs", "build", "outputs", "artifact"},
			method:   "isInOutputDefinitionContext",
			expected: true,
		},
		{
			name:     "run context",
			path:     []string{"jobs", "test", "steps", "0", "run"},
			method:   "isInRunContext",
			expected: true,
		},
		{
			name:     "not run context",
			path:     []string{"jobs", "test", "steps", "0", "name"},
			method:   "isInRunContext",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result bool
			switch tt.method {
			case "isInOutputsContext":
				result = detector.isInOutputsContext(tt.path)
			case "isInOutputDefinitionContext":
				result = detector.isInOutputDefinitionContext(tt.path)
			case "isInRunContext":
				result = detector.isInRunContext(tt.path)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test complex real-world scenarios
func TestComplexOutputHandlingScenarios(t *testing.T) {
	tests := []struct {
		name           string
		yamlContent    string
		expectedIssues []string
		description    string
	}{
		{
			name: "action with multiple output issues",
			yamlContent: `
name: "Test Action"
description: "Action with output issues"
outputs:
  result:
    value: ${{ inputs.user_input }}
  secret_leak:
    description: "string"
    value: ${{ secrets.API_KEY }}
  missing_desc:
    value: "some value"
runs:
  using: "composite"
  steps:
    - name: "Set deprecated output"
      shell: bash
      run: echo "::set-output name=old::value"
    - name: "Unsafe shell usage"
      shell: bash
      run: echo ${{ steps.previous.outputs.result }}
`,
			expectedIssues: []string{
				"Output uses user-controlled input directly",
				"Output description is too vague",
				"Potential sensitive data leak in output",
				"Output definition missing description",
				"Deprecated ::set-output command detected",
				"Unsafe output usage in shell",
			},
			description: "Should detect multiple different output handling issues",
		},
		{
			name: "workflow with job outputs",
			yamlContent: `
name: "Test Workflow"
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      artifact: ${{ steps.build.outputs.file }}
      user_data: ${{ github.event.issue.title }}
    steps:
      - name: Build
        id: build
        run: echo "file=artifact.zip" >> $GITHUB_OUTPUT
      - name: Process user data  
        run: echo "${{ github.event.issue.title }}"
  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: echo "Deploying ${{ needs.build.outputs.artifact }}"
`,
			expectedIssues: []string{
				"Output definition missing description",
			},
			description: "Should detect issues in workflow job outputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)

			for _, expectedIssue := range tt.expectedIssues {
				found := hasIssueWithMessage(findings, expectedIssue)
				assert.True(t, found, "Expected to find issue: %s", expectedIssue)
			}
		})
	}
}

// Helper functions

// runOutputHandlingDetection runs the output handling detection on YAML content
func runOutputHandlingDetection(t *testing.T, yamlContent string) []*types.Finding {
	t.Helper()

	// Parse the YAML
	file, err := parser.ParseBytes([]byte(yamlContent), parser.ParseComments)
	require.NoError(t, err, "Failed to parse YAML")

	// Create detector
	rule := NewOutputHandlingRule()
	detector := rule.detector

	// Collect findings
	var findings []*types.Finding

	for _, doc := range file.Docs {
		types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{detector}, &findings)
	}

	return findings
}

// hasIssueWithMessage checks if any finding contains the expected message
func hasIssueWithMessage(findings []*types.Finding, expectedMessage string) bool {
	for _, finding := range findings {
		if finding.Rule != nil && strings.Contains(finding.Rule.Message, expectedMessage) {
			return true
		}
	}
	return false
}

func TestAdversarialOutputTesting(t *testing.T) {
	tests := []struct {
		name         string
		yamlContent  string
		expectIssues bool
		description  string
	}{
		{
			name: "newline injection in output",
			yamlContent: `
outputs:
  result:
    description: "Test output"
    value: ${{ github.event.issue.title }}
`,
			expectIssues: true,
			description:  "Should detect potential for newline injection via user input",
		},
		{
			name: "command injection potential",
			yamlContent: `
jobs:
  test:
    steps:
      - name: Dangerous usage
        run: echo ${{ github.event.pull_request.title }}; rm -rf /
`,
			expectIssues: true,
			description:  "Should detect potential command injection patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runOutputHandlingDetection(t, tt.yamlContent)
			hasIssues := len(findings) > 0
			assert.Equal(t, tt.expectIssues, hasIssues, tt.description)
		})
	}
}

func TestDebugStringParsing(t *testing.T) {
	yamlContent := `
jobs:
  test:
    steps:
      - name: Unsafe echo
        run: |
          echo "Result: ${{ steps.build.outputs.result }}"; echo "Done"
`
	findings := runOutputHandlingDetection(t, yamlContent)

	assert.Len(t, findings, 1)
}
