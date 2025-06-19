package yaml_patch

import (
	"fmt"
	"log"
)

// Example demonstrates how to use the YAML patch module
func Example() {
	// Example 1: Fix expression injection vulnerability
	exampleFixExpressionInjection()

	// Example 2: Add security permissions
	exampleAddSecurityPermissions()

	// Example 3: Update workflow configuration
	exampleUpdateWorkflowConfig()

	// Example 4: Merge environment variables
	exampleMergeEnvironmentVariables()

	// Example 5: Remove sensitive information
	exampleRemoveSensitiveInfo()
}

// exampleFixExpressionInjection demonstrates fixing expression injection vulnerabilities
func exampleFixExpressionInjection() {
	fmt.Println("=== Example 1: Fix Expression Injection ===")

	content := `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Process issue
        run: |
          echo "Processing issue: ${{ github.event.issue.title }}"
          echo "User: ${{ github.event.issue.user.login }}"
          echo "Labels: ${{ github.event.issue.labels.*.name }}"
`

	patches := []Patch{
		{
			Path: "jobs.test.steps.0.run",
			Operation: RewriteFragmentOp{
				From: "${{ github.event.issue.title }}",
				To:   "${GITHUB_EVENT_ISSUE_TITLE}",
			},
		},
		{
			Path: "jobs.test.steps.0.run",
			Operation: RewriteFragmentOp{
				From: "${{ github.event.issue.user.login }}",
				To:   "${GITHUB_EVENT_ISSUE_USER_LOGIN}",
			},
		},
		{
			Path: "jobs.test.steps.0.run",
			Operation: RewriteFragmentOp{
				From: "${{ github.event.issue.labels.*.name }}",
				To:   "${GITHUB_EVENT_ISSUE_LABELS_NAMES}",
			},
		},
		{
			Path: "jobs.test.steps.0",
			Operation: AddOp{
				Key: "env",
				Value: map[string]string{
					"GITHUB_EVENT_ISSUE_TITLE":        "${{ github.event.issue.title }}",
					"GITHUB_EVENT_ISSUE_USER_LOGIN":   "${{ github.event.issue.user.login }}",
					"GITHUB_EVENT_ISSUE_LABELS_NAMES": "${{ github.event.issue.labels.*.name }}",
				},
			},
		},
	}

	result, err := ApplyYAMLPatches(content, patches)
	if err != nil {
		log.Printf("Error applying patches: %v", err)
		return
	}

	fmt.Println("Original:")
	fmt.Println(content)
	fmt.Println("Fixed:")
	fmt.Println(result)
	fmt.Println()
}

// exampleAddSecurityPermissions demonstrates adding security permissions
func exampleAddSecurityPermissions() {
	fmt.Println("=== Example 2: Add Security Permissions ===")

	content := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
`

	patches := []Patch{
		{
			Path: "jobs.test",
			Operation: AddOp{
				Key: "permissions",
				Value: map[string]string{
					"contents": "read",
					"actions":  "read",
					"issues":   "write",
				},
			},
		},
	}

	result, err := ApplyYAMLPatches(content, patches)
	if err != nil {
		log.Printf("Error applying patches: %v", err)
		return
	}

	fmt.Println("Original:")
	fmt.Println(content)
	fmt.Println("With permissions:")
	fmt.Println(result)
	fmt.Println()
}

// exampleUpdateWorkflowConfig demonstrates updating workflow configuration
func exampleUpdateWorkflowConfig() {
	fmt.Println("=== Example 3: Update Workflow Configuration ===")

	content := `name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [16, 18, 20]
    steps:
      - run: echo "test"
`

	patches := []Patch{
		{
			Path: "on.push.branches.0",
			Operation: ReplaceOp{
				Value: "master",
			},
		},
		{
			Path: "on.pull_request.branches.0",
			Operation: ReplaceOp{
				Value: "master",
			},
		},
		{
			Path: "jobs.test.strategy.matrix.node-version.2",
			Operation: ReplaceOp{
				Value: 22,
			},
		},
	}

	result, err := ApplyYAMLPatches(content, patches)
	if err != nil {
		log.Printf("Error applying patches: %v", err)
		return
	}

	fmt.Println("Original:")
	fmt.Println(content)
	fmt.Println("Updated:")
	fmt.Println(result)
	fmt.Println()
}

// exampleMergeEnvironmentVariables demonstrates merging environment variables
func exampleMergeEnvironmentVariables() {
	fmt.Println("=== Example 4: Merge Environment Variables ===")

	content := `jobs:
  test:
    runs-on: ubuntu-latest
    env:
      NODE_ENV: production
      DEBUG: false
    steps:
      - run: echo "test"
`

	patches := []Patch{
		{
			Path: "jobs.test",
			Operation: MergeIntoOp{
				Key: "env",
				Value: map[string]string{
					"LOG_LEVEL": "info",
					"API_URL":   "https://api.example.com",
				},
			},
		},
	}

	result, err := ApplyYAMLPatches(content, patches)
	if err != nil {
		log.Printf("Error applying patches: %v", err)
		return
	}

	fmt.Println("Original:")
	fmt.Println(content)
	fmt.Println("Merged:")
	fmt.Println(result)
	fmt.Println()
}

// exampleRemoveSensitiveInfo demonstrates removing sensitive information
func exampleRemoveSensitiveInfo() {
	fmt.Println("=== Example 5: Remove Sensitive Information ===")

	content := `jobs:
  test:
    runs-on: ubuntu-latest
    env:
      API_KEY: ${{ secrets.API_KEY }}
      DATABASE_URL: ${{ secrets.DATABASE_URL }}
      NODE_ENV: production
    steps:
      - run: echo "test"
`

	patches := []Patch{
		{
			Path:      "jobs.test.env.API_KEY",
			Operation: RemoveOp{},
		},
		{
			Path:      "jobs.test.env.DATABASE_URL",
			Operation: RemoveOp{},
		},
	}

	result, err := ApplyYAMLPatches(content, patches)
	if err != nil {
		log.Printf("Error applying patches: %v", err)
		return
	}

	fmt.Println("Original:")
	fmt.Println(content)
	fmt.Println("Cleaned:")
	fmt.Println(result)
	fmt.Println()
}

// ExampleFlowStyles demonstrates working with flow-style YAML
func ExampleFlowStyles() {
	fmt.Println("=== Example: Flow Style YAML ===")

	content := `jobs:
  test:
    runs-on: ubuntu-latest
    env: { NODE_ENV: production, DEBUG: false }
    steps:
      - run: echo "test"
`

	patches := []Patch{
		{
			Path: "jobs.test.env",
			Operation: AddOp{
				Key:   "LOG_LEVEL",
				Value: "info",
			},
		},
	}

	result, err := ApplyYAMLPatches(content, patches)
	if err != nil {
		log.Printf("Error applying patches: %v", err)
		return
	}

	fmt.Println("Original:")
	fmt.Println(content)
	fmt.Println("Updated:")
	fmt.Println(result)
	fmt.Println()
}

// ExampleMultilineContent demonstrates working with multiline content
func ExampleMultilineContent() {
	fmt.Println("=== Example: Multiline Content ===")

	content := `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Build and test
        run: |
          npm install
          npm run build
          npm test
`

	patches := []Patch{
		{
			Path: "jobs.test.steps.0.run",
			Operation: RewriteFragmentOp{
				From: "npm install",
				To:   "npm ci",
			},
		},
		{
			Path: "jobs.test.steps.0",
			Operation: AddOp{
				Key: "env",
				Value: map[string]string{
					"NODE_ENV": "test",
					"CI":       "true",
				},
			},
		},
	}

	result, err := ApplyYAMLPatches(content, patches)
	if err != nil {
		log.Printf("Error applying patches: %v", err)
		return
	}

	fmt.Println("Original:")
	fmt.Println(content)
	fmt.Println("Updated:")
	fmt.Println(result)
	fmt.Println()
}
