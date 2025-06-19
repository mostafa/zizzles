# YAML Patch Module

A sophisticated Go package for comment and format-preserving YAML patch operations. This module allows you to modify YAML files while preserving comments, formatting, and structure. It supports both block and flow YAML styles and provides various patch operations.

## Features

- **Comment Preservation**: Maintains all comments and formatting during modifications
- **Style Detection**: Automatically detects and preserves YAML styles (block vs flow)
- **Multiple Operations**: Support for rewrite, replace, add, merge, and remove operations
- **Path-based Navigation**: String-based YAML paths for easy node targeting
- **Error Handling**: Comprehensive error reporting with context
- **Type Safety**: Strongly typed operations and values

## Installation

```bash
go get github.com/goccy/go-yaml
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "your-project/yaml_patch"
)

func main() {
    content := `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello ${{ github.event.issue.title }}"
`

    patches := []yaml_patch.Patch{
        {
            Path: "jobs.test.steps.0.run",
            Operation: yaml_patch.RewriteFragmentOp{
                From: "${{ github.event.issue.title }}",
                To:   "${GITHUB_EVENT_ISSUE_TITLE}",
            },
        },
        {
            Path: "jobs.test.steps.0",
            Operation: yaml_patch.AddOp{
                Key: "env",
                Value: map[string]string{
                    "GITHUB_EVENT_ISSUE_TITLE": "${{ github.event.issue.title }}",
                },
            },
        },
    }

    result, err := yaml_patch.ApplyYAMLPatches(content, patches)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(result)
}
```

## Operations

### RewriteFragment

Replaces specific text fragments within a node's content.

```go
yaml_patch.RewriteFragmentOp{
    From: "old text",
    To:   "new text",
    After: &bias, // Optional: start search after this many characters
}
```

### Replace

Replaces the entire value of a node.

```go
yaml_patch.ReplaceOp{
    Value: "new value", // Can be string, int, bool, map, slice, etc.
}
```

### Add

Adds a new key-value pair to a mapping.

```go
yaml_patch.AddOp{
    Key:   "new_key",
    Value: "new_value",
}
```

### MergeInto

Merges a value into an existing mapping or replaces it if not a mapping.

```go
yaml_patch.MergeIntoOp{
    Key:   "existing_key",
    Value: map[string]string{"key1": "value1", "key2": "value2"},
}
```

### Remove

Removes a key-value pair from a mapping.

```go
yaml_patch.RemoveOp{}
```

## YAML Paths

The module uses string-based paths to navigate YAML structures:

- `jobs.test.runs-on` - Navigate to a specific key
- `jobs.test.steps.0.run` - Access array elements by index
- `jobs.test.steps.[0].run` - Alternative array syntax
- `.` - Root document

## Style Detection

The module automatically detects and preserves YAML styles:

- **BlockMapping**: Traditional indented style
- **FlowMapping**: Inline `{ key: value }` style
- **BlockSequence**: Traditional list style
- **FlowSequence**: Inline `[ item1, item2 ]` style
- **MultilineLiteralScalar**: `|` literal style
- **MultilineFoldedScalar**: `>` folded style

## Examples

### Fix Expression Injection

```go
content := `jobs:
  test:
    steps:
      - run: echo "Issue: ${{ github.event.issue.title }}"
`

patches := []yaml_patch.Patch{
    {
        Path: "jobs.test.steps.0.run",
        Operation: yaml_patch.RewriteFragmentOp{
            From: "${{ github.event.issue.title }}",
            To:   "${GITHUB_EVENT_ISSUE_TITLE}",
        },
    },
    {
        Path: "jobs.test.steps.0",
        Operation: yaml_patch.AddOp{
            Key: "env",
            Value: map[string]string{
                "GITHUB_EVENT_ISSUE_TITLE": "${{ github.event.issue.title }}",
            },
        },
    },
}
```

### Add Security Permissions

```go
patches := []yaml_patch.Patch{
    {
        Path: "jobs.test",
        Operation: yaml_patch.AddOp{
            Key: "permissions",
            Value: map[string]string{
                "contents": "read",
                "actions":  "read",
                "issues":   "write",
            },
        },
    },
}
```

### Update Workflow Configuration

```go
patches := []yaml_patch.Patch{
    {
        Path: "on.push.branches.0",
        Operation: yaml_patch.ReplaceOp{
            Value: "master",
        },
    },
    {
        Path: "jobs.test.strategy.matrix.node-version.2",
        Operation: yaml_patch.ReplaceOp{
            Value: 22,
        },
    },
}
```

### Merge Environment Variables

```go
patches := []yaml_patch.Patch{
    {
        Path: "jobs.test",
        Operation: yaml_patch.MergeIntoOp{
            Key: "env",
            Value: map[string]string{
                "LOG_LEVEL": "info",
                "API_URL":   "https://api.example.com",
            },
        },
    },
}
```

### Remove Sensitive Information

```go
patches := []yaml_patch.Patch{
    {
        Path:      "jobs.test.env.API_KEY",
        Operation: yaml_patch.RemoveOp{},
    },
    {
        Path:      "jobs.test.env.DATABASE_URL",
        Operation: yaml_patch.RemoveOp{},
    },
}
```

## Error Handling

The module provides detailed error information:

```go
result, err := yaml_patch.ApplyYAMLPatches(content, patches)
if err != nil {
    if patchErr, ok := err.(*yaml_patch.Error); ok {
        fmt.Printf("Error type: %s\n", patchErr.Type)
        fmt.Printf("Message: %s\n", patchErr.Message)
        fmt.Printf("Path: %s\n", patchErr.Path)
    }
    return err
}
```

## API Reference

### Types

```go
type Patch struct {
    Path      string
    Operation Operation
}

type Operation interface {
    // Marker interface for operations
}

type RewriteFragmentOp struct {
    From  string
    To    string
    After *int
}

type ReplaceOp struct {
    Value interface{}
}

type AddOp struct {
    Key   string
    Value interface{}
}

type MergeIntoOp struct {
    Key   string
    Value interface{}
}

type RemoveOp struct {
    // No fields needed
}
```

### Functions

```go
func ApplyYAMLPatches(content string, patches []Patch) (string, error)
```

Applies a list of patch operations to YAML content while preserving comments and formatting.

## Best Practices

1. **Order Operations**: Operations are applied from the end backwards to avoid position invalidation
2. **Error Handling**: Always check for errors and handle them appropriately
3. **Path Validation**: Ensure paths exist before applying operations
4. **Style Consistency**: The module preserves the original style, so be consistent
5. **Testing**: Test your patches with various YAML styles and edge cases

## Contributing

When contributing to this module:

1. Follow Go best practices and conventions
2. Add comprehensive tests for new features
3. Update documentation for API changes
4. Ensure all tests pass before submitting

## License

This module is part of the Zizzles project and follows the same license terms. 