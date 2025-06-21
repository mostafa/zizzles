package yaml_patch

import (
	"fmt"

	"github.com/goccy/go-yaml/ast"
)

// Style represents different YAML styles for a feature.
type Style int

const (
	BlockMapping Style = iota
	BlockSequence
	// MultilineFlowMapping: { key: value, key2: value2 }
	MultilineFlowMapping
	// FlowMapping: { key: value, key2: value2 }
	FlowMapping
	// MultilineFlowSequence: [ item1, item2, ]
	MultilineFlowSequence
	// FlowSequence: [ item1, item2, item3 ]
	FlowSequence
	// MultilineLiteralScalar: |
	MultilineLiteralScalar
	// MultilineFoldedScalar: >
	MultilineFoldedScalar
	// DoubleQuoted: "value"
	DoubleQuoted
	// SingleQuoted: 'value'
	SingleQuoted
	PlainScalar
)

// String returns the string representation of the style
func (s Style) String() string {
	switch s {
	case BlockMapping:
		return "BlockMapping"
	case BlockSequence:
		return "BlockSequence"
	case MultilineFlowMapping:
		return "MultilineFlowMapping"
	case FlowMapping:
		return "FlowMapping"
	case MultilineFlowSequence:
		return "MultilineFlowSequence"
	case FlowSequence:
		return "FlowSequence"
	case MultilineLiteralScalar:
		return "MultilineLiteralScalar"
	case MultilineFoldedScalar:
		return "MultilineFoldedScalar"
	case DoubleQuoted:
		return "DoubleQuoted"
	case SingleQuoted:
		return "SingleQuoted"
	case PlainScalar:
		return "PlainScalar"
	default:
		return "Unknown"
	}
}

// Patch represents a single YAML patch operation.
// A patch operation consists of a path to the feature to patch
// and the operation to perform on that feature.
type Patch struct {
	// Path is the YAML path to the feature to patch (e.g., "jobs.test.steps.0.run")
	Path string
	// Operation is the operation to perform on the feature
	Operation Operation
}

// Operation represents a YAML patch operation.
type Operation interface {
	// Type returns the type of operation
	Type() string
}

// RewriteFragmentOp rewrites a fragment of a feature at the given path.
// This can be used to perform graceful rewrites of string values,
// regardless of their nested position or single/multi-line nature.
type RewriteFragmentOp struct {
	From  string // The text to replace
	To    string // The replacement text
	After *int   // Optional byte index after which to start searching
}

func (op RewriteFragmentOp) Type() string { return "RewriteFragment" }

// ReplaceOp replaces the value at the given path
type ReplaceOp struct {
	Value any // The new value to set
}

func (op ReplaceOp) Type() string { return "Replace" }

// AddOp adds a new key-value pair at the given path.
// The path should point to a mapping.
type AddOp struct {
	Key   string // The key to add
	Value any    // The value to add
}

func (op AddOp) Type() string { return "Add" }

// MergeIntoOp merges a key-value pair into an existing mapping at the given path,
// or creates the key if it doesn't exist.
// If both the existing value and new value are mappings, they are merged together.
// Otherwise, the new value replaces the existing one.
type MergeIntoOp struct {
	Key   string // The key to merge
	Value any    // The value to merge
}

func (op MergeIntoOp) Type() string { return "MergeInto" }

// RemoveOp removes the key at the given path
type RemoveOp struct{}

func (op RemoveOp) Type() string { return "Remove" }

// NodeInfo contains information about a YAML node including its location and style
type NodeInfo struct {
	Node        ast.Node
	Path        []string
	Style       Style
	StartPos    int
	EndPos      int
	Indentation int
	Content     string
}

// Error types for YAML patch operations
type Error struct {
	Type    string
	Message string
	Path    string
}

func (e Error) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("YAML patch error at %s: %s", e.Path, e.Message)
	}
	return fmt.Sprintf("YAML patch error: %s", e.Message)
}

// NewError creates a new YAML patch error
func NewError(errType, message, path string) Error {
	return Error{
		Type:    errType,
		Message: message,
		Path:    path,
	}
}
