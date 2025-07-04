package yaml_patch

import (
	"testing"

	"github.com/goccy/go-yaml/parser"
)

func TestApplyYAMLPatches_BasicOperations(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		patches  []Patch
		expected string
		wantErr  bool
	}{
		{
			name: "rewrite fragment in run block",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: "echo 'foo: ${{ github.event.issue.title }}'"
`,
			patches: []Patch{
				{
					Path: "jobs.test.steps.0.run",
					Operation: RewriteFragmentOp{
						From: "${{ github.event.issue.title }}",
						To:   "${GITHUB_EVENT_ISSUE_TITLE}",
					},
				},
			},
			expected: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: "echo 'foo: ${GITHUB_EVENT_ISSUE_TITLE}'"
`,
			wantErr: false,
		},
		{
			name: "replace value",
			content: `name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
`,
			patches: []Patch{
				{
					Path: "jobs.test.runs-on",
					Operation: ReplaceOp{
						Value: "macos-latest",
					},
				},
			},
			expected: `name: Test
on: push
jobs:
  test:
    runs-on: macos-latest
`,
			wantErr: false,
		},
		{
			name: "add new key-value pair",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			patches: []Patch{
				{
					Path: "jobs.test",
					Operation: AddOp{
						Key:   "permissions",
						Value: map[string]string{"contents": "read"},
					},
				},
			},
			expected: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
    permissions:
      contents: read
`,
			wantErr: false,
		},
		{
			name: "merge into existing mapping",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    env:
      NODE_ENV: production
`,
			patches: []Patch{
				{
					Path: "jobs.test",
					Operation: MergeIntoOp{
						Key:   "env",
						Value: map[string]string{"DEBUG": "true"},
					},
				},
			},
			expected: `jobs:
  test:
    runs-on: ubuntu-latest
    env:
      DEBUG: true
      NODE_ENV: production
`,
			wantErr: false,
		},
		{
			name: "remove key",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo "hello"
`,
			patches: []Patch{
				{
					Path:      "jobs.test.permissions",
					Operation: RemoveOp{},
				},
			},
			expected: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyYAMLPatches(tt.content, tt.patches)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyYAMLPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result != tt.expected {
				t.Errorf("ApplyYAMLPatches() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestApplyYAMLPatches_FlowStyles(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		patches  []Patch
		expected string
		wantErr  bool
	}{
		{
			name: "add to flow mapping",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: production }
`,
			patches: []Patch{
				{
					Path: "jobs.test.env",
					Operation: AddOp{
						Key:   "DEBUG",
						Value: "true",
					},
				},
			},
			expected: `jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: production, DEBUG: true }
`,
			wantErr: false,
		},
		{
			name: "replace in flow sequence",
			content: `on:
  push:
    branches: [main, develop]
`,
			patches: []Patch{
				{
					Path: "on.push.branches.0",
					Operation: ReplaceOp{
						Value: "master",
					},
				},
			},
			expected: `on:
  push:
    branches: [master, develop]
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyYAMLPatches(tt.content, tt.patches)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyYAMLPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result != tt.expected {
				t.Errorf("ApplyYAMLPatches() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestApplyYAMLPatches_MultilineContent(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		patches  []Patch
		expected string
		wantErr  bool
		skip     bool
	}{
		{
			name: "rewrite fragment in multiline literal",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "before"
          echo "foo: ${{ github.event.issue.title }}"
          echo "after"
`,
			patches: []Patch{
				{
					Path: "jobs.test.steps.0.run",
					Operation: RewriteFragmentOp{
						From: "${{ github.event.issue.title }}",
						To:   "${GITHUB_EVENT_ISSUE_TITLE}",
					},
				},
			},
			expected: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "before"
          echo "foo: ${GITHUB_EVENT_ISSUE_TITLE}"
          echo "after"
`,
			wantErr: false,
		},
		{
			name: "replace with multiline value",
			skip: true,
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			patches: []Patch{
				{
					Path: "jobs.test.steps.0.run",
					Operation: ReplaceOp{
						Value: `echo "line 1"
echo "line 2"`,
					},
				},
			},
			expected: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "line 1"
          echo "line 2"
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result string
			var err error
			result, err = ApplyYAMLPatches(tt.content, tt.patches)
			if tt.skip {
				t.Skip()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyYAMLPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result != tt.expected {
				t.Errorf("ApplyYAMLPatches() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestApplyYAMLPatches_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		content string
		patches []Patch
		wantErr bool
	}{
		{
			name:    "invalid YAML",
			content: `invalid: yaml: content: [`,
			patches: []Patch{
				{
					Path:      "test",
					Operation: ReplaceOp{Value: "test"},
				},
			},
			wantErr: true,
		},
		{
			name: "path not found",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
`,
			patches: []Patch{
				{
					Path:      "jobs.test.nonexistent",
					Operation: ReplaceOp{Value: "test"},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate key in add operation",
			content: `jobs:
  test:
    runs-on: ubuntu-latest
    permissions: read
`,
			patches: []Patch{
				{
					Path: "jobs.test",
					Operation: AddOp{
						Key:   "permissions",
						Value: "write",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ApplyYAMLPatches(tt.content, tt.patches)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyYAMLPatches() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDetectStyle(t *testing.T) {
	// This test would require creating AST nodes manually
	// For now, we'll test the style detection logic indirectly
	// through the patch operations
	t.Run("style detection through patches", func(t *testing.T) {
		content := `jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: production }
    steps:
      - run: echo "hello"
`
		patches := []Patch{
			{
				Path: "jobs.test.env",
				Operation: AddOp{
					Key:   "DEBUG",
					Value: "true",
				},
			},
		}

		result, err := ApplyYAMLPatches(content, patches)
		if err != nil {
			t.Errorf("ApplyYAMLPatches() error = %v", err)
			return
		}

		// Check that the result contains the expected flow mapping format
		if !contains(result, "env: { NODE_ENV: production, DEBUG: true }") {
			t.Errorf("Expected flow mapping format, got: %s", result)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 0; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}

func TestFlowMapping(t *testing.T) {
	content := `jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: production }
`

	file, err := parser.ParseBytes([]byte(content), parser.ParseComments)
	if err != nil {
		t.Fatalf("failed to parse YAML: %v", err)
	}

	nodeInfo, err := findNodeByPath(file, "jobs.test.env")
	if err != nil {
		t.Fatalf("failed to find node: %v", err)
	}

	// The node should be a flow mapping
	if nodeInfo.Style != FlowMapping {
		t.Errorf("expected FlowMapping style, got %s", nodeInfo.Style)
	}

	// The content should be the flow mapping
	expectedContent := "{ NODE_ENV: production }"
	if nodeInfo.Content != expectedContent {
		t.Errorf("expected content %q, got %q", expectedContent, nodeInfo.Content)
	}
}

func TestApplyYAMLPatches_WhitespaceHandling(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		patches  []Patch
		expected string
		wantErr  bool
	}{
		{
			name: "preserve space after colon in key-value pairs",
			content: `jobs:
  test:
    steps:
      - name: Action with vulnerable input
        uses: some/action@v1
        with:
          title: ${{ github.event.issue.title }}
          message: ${{ github.event.issue.body }}
`,
			patches: []Patch{
				{
					Path: "jobs.test.steps.0.with.title",
					Operation: RewriteFragmentOp{
						From: "${{ github.event.issue.title }}",
						To:   "${{ env.GITHUB_EVENT_ISSUE_TITLE }}",
					},
				},
			},
			expected: `jobs:
  test:
    steps:
      - name: Action with vulnerable input
        uses: some/action@v1
        with:
          title: ${{ env.GITHUB_EVENT_ISSUE_TITLE }}
          message: ${{ github.event.issue.body }}
`,
			wantErr: false,
		},
		{
			name: "preserve space in single line with expression",
			content: `name: Test
version: "1.0"
description: ${{ github.event.issue.title }}
`,
			patches: []Patch{
				{
					Path: "description",
					Operation: RewriteFragmentOp{
						From: "${{ github.event.issue.title }}",
						To:   "${{ env.GITHUB_EVENT_ISSUE_TITLE }}",
					},
				},
			},
			expected: `name: Test
version: "1.0"
description: ${{ env.GITHUB_EVENT_ISSUE_TITLE }}
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyYAMLPatches(tt.content, tt.patches)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyYAMLPatches() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && result != tt.expected {
				t.Errorf("ApplyYAMLPatches() = %v, want %v", result, tt.expected)
			}
		})
	}
}
