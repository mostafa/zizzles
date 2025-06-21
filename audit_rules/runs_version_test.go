package audit_rules

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRunsVersionRule(t *testing.T) {
	rule := NewRunsVersionRule()

	// Test basic initialization
	assert.Equal(t, CategoryRunsVersion, rule.Category)
	assert.Equal(t, types.SeverityHigh, rule.Severity)
	assert.Equal(t, types.RuleTypeAST, rule.Type)
	assert.NotNil(t, rule.detector)
	assert.NotNil(t, rule.seenFindings)
}

func TestRunsVersionRule_DetectDeprecatedNodeVersions(t *testing.T) {
	tests := []struct {
		name             string
		yaml             string
		expectedCount    int
		expectedSeverity types.Severity
		expectedMessage  string
	}{
		{
			name: "node12 deprecated",
			yaml: `
name: Test Action
runs:
  using: node12
  main: index.js
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityCritical,
			expectedMessage:  "Critical: Node.js 12 is end-of-life and no longer supported - use node16 or node20 instead",
		},
		{
			name: "node14 deprecated",
			yaml: `
name: Test Action
runs:
  using: node14
  main: index.js
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityHigh,
			expectedMessage:  "Deprecated Node.js version 'node14' detected - use node16 or node20 instead",
		},
		{
			name: "node16 supported",
			yaml: `
name: Test Action
runs:
  using: node16
  main: index.js
`,
			expectedCount: 0,
		},
		{
			name: "node20 supported",
			yaml: `
name: Test Action
runs:
  using: node20
  main: index.js
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRunsVersionRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))

			if tt.expectedCount > 0 {
				assert.Equal(t, tt.expectedSeverity, findings[0].Severity)
				assert.Contains(t, findings[0].Rule.Message, tt.expectedMessage)
			}
		})
	}
}

func TestRunsVersionRule_DetectUnsupportedNodeVersions(t *testing.T) {
	tests := []struct {
		name             string
		yaml             string
		expectedCount    int
		expectedSeverity types.Severity
	}{
		{
			name: "node10 unsupported",
			yaml: `
name: Test Action
runs:
  using: node10
  main: index.js
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityCritical,
		},
		{
			name: "node8 unsupported",
			yaml: `
name: Test Action
runs:
  using: node8
  main: index.js
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityCritical,
		},
		{
			name: "unknown node version",
			yaml: `
name: Test Action
runs:
  using: node99
  main: index.js
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRunsVersionRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))

			if tt.expectedCount > 0 {
				assert.Equal(t, tt.expectedSeverity, findings[0].Severity)
			}
		})
	}
}

func TestRunsVersionRule_DetectMissingNodeVersion(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
	}{
		{
			name: "missing using field with main",
			yaml: `
name: Test Action
runs:
  main: index.js
`,
			expectedCount: 1,
		},
		{
			name: "docker action without main",
			yaml: `
name: Test Action
runs:
  image: docker://alpine
`,
			expectedCount: 0,
		},
		{
			name: "composite action",
			yaml: `
name: Test Action
runs:
  using: composite
  steps:
    - run: echo hello
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRunsVersionRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))

			if tt.expectedCount > 0 {
				assert.Contains(t, findings[0].Rule.Message, "JavaScript action missing 'using' field")
				assert.Equal(t, types.SeverityMedium, findings[0].Severity)
			}
		})
	}
}

func TestRunsVersionRule_ContextDetection(t *testing.T) {
	rule := NewRunsVersionRule()

	tests := []struct {
		name     string
		path     []string
		expected bool
	}{
		{
			name:     "runs using context",
			path:     []string{"runs", "using"},
			expected: true,
		},
		{
			name:     "nested runs using context",
			path:     []string{"some", "nested", "runs", "using"},
			expected: true,
		},
		{
			name:     "not runs using context",
			path:     []string{"runs", "main"},
			expected: false,
		},
		{
			name:     "empty path",
			path:     []string{},
			expected: false,
		},
		{
			name:     "single element path",
			path:     []string{"using"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.detector.isInRunsUsingContext(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRunsVersionRule_RunsContextDetection(t *testing.T) {
	rule := NewRunsVersionRule()

	tests := []struct {
		name     string
		path     []string
		expected bool
	}{
		{
			name:     "runs context",
			path:     []string{"runs"},
			expected: true,
		},
		{
			name:     "nested runs context",
			path:     []string{"some", "nested", "runs"},
			expected: true,
		},
		{
			name:     "not runs context",
			path:     []string{"jobs", "build"},
			expected: false,
		},
		{
			name:     "empty path",
			path:     []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.detector.isInRunsContext(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRunsVersionRule_DeduplicationWorks(t *testing.T) {
	rule := NewRunsVersionRule()
	findings := []*types.Finding{}

	yaml := `
name: Test Action
runs:
  using: node12
  main: index.js
`

	file, err := parser.ParseBytes([]byte(yaml), parser.ParseComments)
	require.NoError(t, err)

	// Visit the same node multiple times
	for _, doc := range file.Docs {
		types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
		types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
		types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
	}

	// Should only have one finding due to deduplication
	assert.Equal(t, 1, len(findings))
}

func TestRunsVersionRule_PatternBasedDetection(t *testing.T) {
	ruleSet := GetRunsVersionRules()

	assert.Equal(t, CategoryRunsVersion, ruleSet.Category)
	assert.Equal(t, 1, len(ruleSet.Rules))

	rule := ruleSet.Rules[0]
	assert.Equal(t, types.RuleTypePattern, rule.Type)
	assert.Equal(t, types.SeverityHigh, rule.Severity)
	assert.Contains(t, rule.Pattern, "node12|node14|node10|node8|node6|node4")
}

func TestRunsVersionRule_ComplexYAMLStructures(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
	}{
		{
			name: "multiple actions with different versions",
			yaml: `
name: Test Action
runs:
  using: node12
  main: index.js
  pre: pre.js
  post: post.js
`,
			expectedCount: 1, // Only one finding for the using field
		},
		{
			name: "quoted version",
			yaml: `
name: Test Action
runs:
  using: "node12"
  main: index.js
`,
			expectedCount: 1,
		},
		{
			name: "single quoted version",
			yaml: `
name: Test Action
runs:
  using: 'node14'
  main: index.js
`,
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRunsVersionRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))
		})
	}
}

func TestRunsVersionRule_SupportedVersions(t *testing.T) {
	supportedVersions := []string{"node16", "node20", "node21"}

	for _, version := range supportedVersions {
		t.Run("supported_"+version, func(t *testing.T) {
			rule := NewRunsVersionRule()
			findings := []*types.Finding{}

			yaml := strings.ReplaceAll(`
name: Test Action
runs:
  using: VERSION
  main: index.js
`, "VERSION", version)

			file, err := parser.ParseBytes([]byte(yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			// Should have no findings for supported versions
			assert.Equal(t, 0, len(findings))
		})
	}
}

func TestRunsVersionRule_NonNodeActions(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
	}{
		{
			name: "docker action",
			yaml: `
name: Test Action
runs:
  using: docker
  image: Dockerfile
`,
			expectedCount: 0,
		},
		{
			name: "composite action",
			yaml: `
name: Test Action
runs:
  using: composite
  steps:
    - run: echo hello
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewRunsVersionRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))
		})
	}
}

func BenchmarkRunsVersionRule_Detection(b *testing.B) {
	rule := NewRunsVersionRule()
	yaml := `
name: Test Action
runs:
  using: node12
  main: index.js
`

	file, err := parser.ParseBytes([]byte(yaml), parser.ParseComments)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		findings := []*types.Finding{}
		for _, doc := range file.Docs {
			types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
		}
	}
}
