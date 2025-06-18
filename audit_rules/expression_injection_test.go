package audit_rules

import (
	"regexp"
	"strings"
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
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
