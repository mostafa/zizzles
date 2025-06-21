package audit_rules

import (
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/mostafa/zizzles/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDockerSecurityRule(t *testing.T) {
	rule := NewDockerSecurityRule()

	// Test basic initialization
	assert.Equal(t, CategoryDockerSecurity, rule.Category)
	assert.Equal(t, types.SeverityHigh, rule.Severity)
	assert.Equal(t, types.RuleTypeAST, rule.Type)
	assert.NotNil(t, rule.detector)
	assert.NotNil(t, rule.seenFindings)
}

func TestDockerSecurityRule_DetectUnpinnedImages(t *testing.T) {
	tests := []struct {
		name             string
		yaml             string
		expectedCount    int
		expectedSeverity types.Severity
		expectedMessage  string
	}{
		{
			name: "latest tag - critical",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://ubuntu:latest
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityCritical,
			expectedMessage:  "Docker image uses dangerous unpinned tag 'latest'",
		},
		{
			name: "main tag - critical",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://myorg/myimage:main
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityCritical,
			expectedMessage:  "Docker image uses dangerous unpinned tag 'main'",
		},
		{
			name: "unpinned version - high",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://node:18.16.0-alpine
`,
			expectedCount:    1,
			expectedSeverity: types.SeverityHigh,
			expectedMessage:  "Docker image is not pinned with SHA256 digest",
		},
		{
			name: "properly pinned image - safe",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://node:18.16.0-alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
`,
			expectedCount: 0,
		},
		{
			name: "dockerfile reference - unpinned",
			yaml: `
name: Test Action
runs:
  using: docker
  image: Dockerfile
`,
			expectedCount: 0, // Dockerfile references are not flagged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDockerSecurityRule()
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

func TestDockerSecurityRule_DetectRootUser(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
	}{
		{
			name: "dockerfile without USER directive",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM node:18-alpine
    COPY . /app
    WORKDIR /app
    RUN npm install
`,
			expectedCount: 1,
		},
		{
			name: "dockerfile with USER directive",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM node:18-alpine
    COPY . /app
    WORKDIR /app
    RUN npm install
    USER node
`,
			expectedCount: 0,
		},
		{
			name: "image reference without dockerfile",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://node:18-alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDockerSecurityRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))

			if tt.expectedCount > 0 {
				assert.Contains(t, findings[0].Rule.Message, "runs as root")
				assert.Equal(t, types.SeverityHigh, findings[0].Severity)
			}
		})
	}
}

func TestDockerSecurityRule_DetectNonMinimalBaseImage(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
		expectedOS    string
	}{
		{
			name: "ubuntu base image",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://ubuntu:20.04@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
`,
			expectedCount: 1,
			expectedOS:    "ubuntu",
		},
		{
			name: "debian base image",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://debian:bullseye@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
`,
			expectedCount: 1,
			expectedOS:    "debian",
		},
		{
			name: "ubuntu-slim is okay",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://ubuntu-slim:20.04@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
`,
			expectedCount: 0,
		},
		{
			name: "alpine is okay",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://alpine:3.18@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
`,
			expectedCount: 0,
		},
		{
			name: "scratch is okay",
			yaml: `
name: Test Action
runs:
  using: docker
  image: docker://scratch@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDockerSecurityRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))

			if tt.expectedCount > 0 {
				assert.Contains(t, findings[0].Rule.Message, "full OS image")
				assert.Contains(t, findings[0].Rule.Message, tt.expectedOS)
				assert.Equal(t, types.SeverityMedium, findings[0].Severity)
			}
		})
	}
}

func TestDockerSecurityRule_DetectDevelopmentTools(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
		expectedTool  string
	}{
		{
			name: "dockerfile with curl",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN apk add --no-cache curl nodejs npm
    USER node
    COPY . /app
`,
			expectedCount: 1,
			expectedTool:  "curl",
		},
		{
			name: "dockerfile with build tools",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM ubuntu:20.04
    RUN apt-get update && apt-get install -y build-essential
    USER appuser
    COPY . /app
`,
			expectedCount: 1,
			expectedTool:  "build-essential",
		},
		{
			name: "dockerfile without dev tools",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN apk add --no-cache nodejs npm
    USER node
    COPY . /app
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDockerSecurityRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))

			if tt.expectedCount > 0 {
				assert.Contains(t, findings[0].Rule.Message, "Development tool")
				assert.Contains(t, findings[0].Rule.Message, tt.expectedTool)
				assert.Equal(t, types.SeverityMedium, findings[0].Severity)
			}
		})
	}
}

func TestDockerSecurityRule_DetectSecretsExposure(t *testing.T) {
	tests := []struct {
		name          string
		yaml          string
		expectedCount int
	}{
		{
			name: "echo secret input",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN echo "Debug: $INPUT_TOKEN"
    USER appuser
`,
			expectedCount: 1,
		},
		{
			name: "echo GitHub secret",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN echo "Token: ${{ secrets.TOKEN }}"
    USER appuser
`,
			expectedCount: 1,
		},
		{
			name: "console.log exposure",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM node:18-alpine
    RUN echo "console.log($INPUT_PASSWORD)" > debug.js
    USER node
`,
			expectedCount: 1,
		},
		{
			name: "safe usage",
			yaml: `
name: Test Action
runs:
  using: docker
  dockerfile: |
    FROM alpine:3.18
    RUN echo "Starting application"
    USER appuser
`,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDockerSecurityRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			assert.Equal(t, tt.expectedCount, len(findings))

			if tt.expectedCount > 0 {
				assert.Contains(t, findings[0].Rule.Message, "secret exposure")
				assert.Equal(t, types.SeverityHigh, findings[0].Severity)
			}
		})
	}
}

func TestDockerSecurityRule_ContextDetection(t *testing.T) {
	rule := NewDockerSecurityRule()
	detector := rule.detector

	tests := []struct {
		name     string
		path     []string
		expected bool
		method   string
	}{
		{
			name:     "docker image context",
			path:     []string{"runs", "image"},
			expected: true,
			method:   "isDockerImageContext",
		},
		{
			name:     "dockerfile context",
			path:     []string{"runs", "dockerfile"},
			expected: true,
			method:   "isDockerfileContext",
		},
		{
			name:     "docker runs context",
			path:     []string{"runs", "using"},
			expected: true,
			method:   "isDockerRunsContext",
		},
		{
			name:     "non-docker context",
			path:     []string{"inputs", "token"},
			expected: false,
			method:   "isDockerImageContext",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result bool
			switch tt.method {
			case "isDockerImageContext":
				result = detector.isDockerImageContext(tt.path)
			case "isDockerfileContext":
				result = detector.isDockerfileContext(tt.path)
			case "isDockerRunsContext":
				result = detector.isDockerRunsContext(tt.path)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDockerSecurityRule_Deduplication(t *testing.T) {
	yaml := `
name: Test Action
runs:
  using: docker
  image: docker://ubuntu:latest
`

	rule := NewDockerSecurityRule()
	findings := []*types.Finding{}

	file, err := parser.ParseBytes([]byte(yaml), parser.ParseComments)
	require.NoError(t, err)

	// Run the detector multiple times to test deduplication
	for i := 0; i < 3; i++ {
		for _, doc := range file.Docs {
			types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
		}
	}

	// Should only have one finding despite multiple runs
	assert.Equal(t, 1, len(findings))
}

func TestDockerSecurityRule_PatternBasedDetection(t *testing.T) {
	ruleSet := GetDockerSecurityRules()

	assert.Equal(t, CategoryDockerSecurity, ruleSet.Category)
	assert.Equal(t, 3, len(ruleSet.Rules))

	// Test pattern rules
	patterns := make(map[string]types.Rule)
	for _, rule := range ruleSet.Rules {
		patterns[rule.Pattern] = rule
	}

	// Test latest tag pattern
	latestRule, exists := patterns[`docker://.*:latest`]
	assert.True(t, exists)
	assert.Equal(t, types.SeverityCritical, latestRule.Severity)
	assert.Contains(t, latestRule.Message, "latest")

	// Test FROM pattern
	fromRule, exists := patterns[`FROM\s+(?:ubuntu|debian|centos|fedora)(?!.*-slim)`]
	assert.True(t, exists)
	assert.Equal(t, types.SeverityMedium, fromRule.Severity)
	assert.Contains(t, fromRule.Message, "full OS")

	// Test echo pattern
	echoRule, exists := patterns[`echo\s+\$(?:INPUT_|secrets\.)`]
	assert.True(t, exists)
	assert.Equal(t, types.SeverityHigh, echoRule.Severity)
	assert.Contains(t, echoRule.Message, "secret exposure")
}

func TestDockerSecurityRule_ComplexYAMLStructures(t *testing.T) {
	yaml := `
name: Complex Docker Action
description: Tests multiple security issues
runs:
  using: docker
  image: docker://ubuntu:latest
  dockerfile: |
    FROM ubuntu:20.04
    RUN apt-get update && apt-get install -y curl build-essential
    COPY . /app
    WORKDIR /app
    RUN echo "Debug token: $INPUT_SECRET_TOKEN"
    CMD ["./app"]
`

	rule := NewDockerSecurityRule()
	findings := []*types.Finding{}

	file, err := parser.ParseBytes([]byte(yaml), parser.ParseComments)
	require.NoError(t, err)

	for _, doc := range file.Docs {
		types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
	}

	// Should detect multiple issues:
	// 1. Unpinned image (latest tag)
	// 2. Non-minimal base image (ubuntu)
	// 3. Development tools (curl, build-essential)
	// 4. Root user (no USER directive)
	// 5. Secret exposure (echo $INPUT_SECRET_TOKEN)

	assert.GreaterOrEqual(t, len(findings), 3) // At least 3 issues should be detected

	// Check that we have findings of different severities
	severities := make(map[types.Severity]int)
	for _, finding := range findings {
		severities[finding.Severity]++
	}

	assert.Greater(t, len(severities), 1) // Should have multiple severity levels
}

func TestDockerSecurityRule_NonDockerActions(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "node action",
			yaml: `
name: Node Action
runs:
  using: node16
  main: index.js
`,
		},
		{
			name: "composite action",
			yaml: `
name: Composite Action
runs:
  using: composite
  steps:
    - run: echo "Hello"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewDockerSecurityRule()
			findings := []*types.Finding{}

			file, err := parser.ParseBytes([]byte(tt.yaml), parser.ParseComments)
			require.NoError(t, err)

			for _, doc := range file.Docs {
				types.WalkAST(doc, []string{}, "test.yml", []types.NodeVisitor{rule.detector}, &findings)
			}

			// Should not detect any Docker security issues in non-Docker actions
			assert.Equal(t, 0, len(findings))
		})
	}
}

func BenchmarkDockerSecurityRule_Detection(b *testing.B) {
	yaml := `
name: Test Action
runs:
  using: docker
  image: docker://ubuntu:latest
  dockerfile: |
    FROM ubuntu:20.04
    RUN apt-get update && apt-get install -y curl
    COPY . /app
    WORKDIR /app
    CMD ["./app"]
`

	rule := NewDockerSecurityRule()

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
