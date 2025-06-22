package yaml_patch

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// ApplyYAMLPatches applies YAML patch operations while preserving comments and formatting
//
// This function takes a YAML string and a list of patch operations, applying them
// while preserving all comments, formatting, and structure that isn't directly modified.
//
// # Operation Order
//
// Operations are internally sorted by their byte positions and applied from the end
// of the document backwards to avoid invalidating byte positions during modification.
// This means the logical order of operations in the input slice is preserved, but
// the actual application order is optimized for correctness.
//
// # Error Handling
//
// Returns an error if any operation fails. The error includes details about which
// operation failed and why.
func ApplyYAMLPatches(content string, patches []Patch) (string, error) {
	// Quick sanity-check that the incoming YAML parses.
	if _, err := parser.ParseBytes([]byte(content), parser.ParseComments); err != nil {
		return "", fmt.Errorf("YAML patch error: input is not valid YAML: %w", err)
	}

	// First pass – locate each patch target in the *original* document so we can
	// gather the starting byte-span.  We purposely ignore any failures here; a
	// missing node will be surfaced later when we actually try to apply the
	// patch against the current document.
	type positionedPatch struct {
		start int
		patch Patch
	}

	var ordered []positionedPatch

	rootFile, _ := parser.ParseBytes([]byte(content), parser.ParseComments)

	for _, p := range patches {
		if nodeInfo, err := findNodeByPath(rootFile, p.Path); err == nil {
			ordered = append(ordered, positionedPatch{start: nodeInfo.StartPos, patch: p})
		} else {
			// If we cannot locate it yet (e.g. key to be added later), treat the
			// start as 0 so it will be applied last (i.e. safely after other
			// changes).
			ordered = append(ordered, positionedPatch{start: 0, patch: p})
		}
	}

	// Sort descending by starting byte position so later-in-file edits are
	// performed first, keeping earlier spans stable.
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].start > ordered[j].start
	})

	// Now apply patches in that order.
	result := content

	for _, pp := range ordered {
		// Parse *current* document to locate the feature fresh; this ensures the
		// path is still valid after prior modifications.
		file, err := parser.ParseBytes([]byte(result), parser.ParseComments)
		if err != nil {
			return "", fmt.Errorf("YAML patch error: intermediate result became invalid YAML: %w", err)
		}

		nodeInfo, err := findNodeByPath(file, pp.patch.Path)
		if err != nil {
			return "", fmt.Errorf("YAML patch error at %s: %w", pp.patch.Path, err)
		}

		switch op := pp.patch.Operation.(type) {
		case RewriteFragmentOp:
			result, err = applyRewriteFragment(result, nodeInfo, op)
		case ReplaceOp:
			result, err = applyReplace(result, nodeInfo, op)
		case AddOp:
			result, err = applyAdd(result, nodeInfo, op)
		case MergeIntoOp:
			result, err = applyMergeInto(result, nodeInfo, op)
		case RemoveOp:
			result, err = applyRemove(result, nodeInfo, op)
		default:
			err = fmt.Errorf("unknown operation type")
		}

		if err != nil {
			return "", fmt.Errorf("YAML patch error at %s: %w", pp.patch.Path, err)
		}
	}

	// Ensure the final document ends with a newline for consistency.
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}

	return result, nil
}

// findNodeByPath finds a node by its dot-separated path
func findNodeByPath(file *ast.File, path string) (*NodeInfo, error) {
	if path == "" || path == "." {
		// Root document
		if len(file.Docs) == 0 {
			return nil, NewError("path", "no documents found", path)
		}
		doc := file.Docs[0]
		return &NodeInfo{
			Node:        doc,
			Path:        []string{},
			Style:       detectStyle(doc),
			StartPos:    0,
			EndPos:      0,  // Will be set by caller
			Content:     "", // Will be set by caller
			Indentation: 0,  // Root has no indentation
		}, nil
	}

	parts := strings.Split(path, ".")
	currentNode := file.Docs[0].Body
	currentPath := []string{}
	indentation := 0

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Handle array indexing (e.g., [0])
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
			indexStr := part[1 : len(part)-1]
			if index, err := strconv.Atoi(indexStr); err == nil {
				if sequence, ok := currentNode.(*ast.SequenceNode); ok {
					if index >= 0 && index < len(sequence.Values) {
						currentNode = sequence.Values[index]
						currentPath = append(currentPath, part)
						indentation += 2
					} else {
						return nil, NewError("path", fmt.Sprintf("array index %d out of bounds", index), path)
					}
				} else {
					return nil, NewError("path", fmt.Sprintf("expected sequence at path %s", strings.Join(currentPath, ".")), path)
				}
			} else {
				currentPath = append(currentPath, part)
			}
			continue
		}

		// If the part is a number, treat as sequence index
		if idx, err := strconv.Atoi(part); err == nil {
			if sequence, ok := currentNode.(*ast.SequenceNode); ok {
				if idx >= 0 && idx < len(sequence.Values) {
					currentNode = sequence.Values[idx]
					currentPath = append(currentPath, part)
					indentation += 2
					continue
				} else {
					return nil, NewError("path", fmt.Sprintf("array index %d out of bounds", idx), path)
				}
			}
		}

		// Navigate to mapping node
		if mapping, ok := currentNode.(*ast.MappingNode); ok {
			found := false
			for _, pair := range mapping.Values {
				if key, ok := pair.Key.(*ast.StringNode); ok && key.Value == part {
					currentNode = pair.Value
					currentPath = append(currentPath, part)
					found = true
					indentation += 2
					break
				}
			}
			if !found {
				return nil, NewError("path", fmt.Sprintf("key '%s' not found at path %s", part, strings.Join(currentPath, ".")), path)
			}
		} else {
			return nil, NewError("path", fmt.Sprintf("expected mapping at path %s", strings.Join(currentPath, ".")), path)
		}
	}

	// Extract node information
	startPos, endPos := getNodePosition(currentNode)
	style := detectStyle(currentNode)
	nodeContent := extractNodeContent(currentNode)

	return &NodeInfo{
		Node:        currentNode,
		Path:        currentPath,
		Style:       style,
		StartPos:    startPos,
		EndPos:      endPos,
		Content:     nodeContent,
		Indentation: indentation,
	}, nil
}

// getNodePosition gets the start and end positions of a node in the source
func getNodePosition(node ast.Node) (int, int) {
	if node == nil {
		return 0, 0
	}

	switch n := node.(type) {
	case *ast.StringNode:
		tok := n.GetToken()
		if tok != nil {
			start := tok.Position.Offset
			end := start + len(tok.Value)
			// Adjust for off-by-one token offset issue
			if start > 0 {
				start = start - 1
			}
			return start, end
		}
	case *ast.LiteralNode:
		tok := n.GetToken()
		if tok != nil {
			start := tok.Position.Offset
			// For literal nodes, we need to get the full content including the multiline content
			// The token value only contains the | character, but we need the full string
			fullContent := n.String()
			end := start + len(fullContent)
			return start, end
		}
	case *ast.IntegerNode:
		tok := n.GetToken()
		if tok != nil {
			start := tok.Position.Offset
			end := start + len(tok.Value)
			return start, end
		}
	case *ast.FloatNode:
		tok := n.GetToken()
		if tok != nil {
			start := tok.Position.Offset
			end := start + len(tok.Value)
			return start, end
		}
	case *ast.BoolNode:
		tok := n.GetToken()
		if tok != nil {
			start := tok.Position.Offset
			end := start + len(tok.Value)
			return start, end
		}
	case *ast.MappingValueNode:
		// For mapping value nodes, we need to find the value's position
		// The value token offset should be correct for the start
		if n.Value != nil {
			valTok := n.Value.GetToken()
			if valTok != nil {
				start := valTok.Position.Offset
				end := start + len(valTok.Value)
				return start, end
			}
		}
	case *ast.MappingNode:
		if len(n.Values) > 0 {
			first := n.Values[0]
			last := n.Values[len(n.Values)-1]
			start, _ := getNodePosition(first.Key)
			_, end := getNodePosition(last.Value)
			return start, end
		}
	case *ast.SequenceNode:
		if len(n.Values) > 0 {
			start, _ := getNodePosition(n.Values[0])
			_, end := getNodePosition(n.Values[len(n.Values)-1])
			return start, end
		}
	}
	// Fallback: return 0,0
	return 0, 0
}

// extractNodeContent extracts the content of a node as a string
func extractNodeContent(node ast.Node) string {
	if node == nil {
		return ""
	}

	switch n := node.(type) {
	case *ast.StringNode:
		return n.Value
	case *ast.IntegerNode:
		return fmt.Sprintf("%v", n.Value)
	case *ast.FloatNode:
		return fmt.Sprintf("%v", n.Value)
	case *ast.BoolNode:
		return fmt.Sprintf("%t", n.Value)
	case *ast.LiteralNode:
		return n.String()
	case *ast.MappingNode:
		// For mapping nodes, try to preserve original formatting
		// Check if this is a flow mapping by examining the original source
		if len(n.Values) > 0 {
			// Get the first and last tokens to determine if it's a flow mapping
			firstToken := n.Values[0].Key.GetToken()
			lastToken := n.Values[len(n.Values)-1].Value.GetToken()

			if firstToken != nil && lastToken != nil {
				// If all key-value pairs are on the same line, it's likely a flow mapping
				if firstToken.Position.Line == lastToken.Position.Line {
					// For flow mappings, we need to reconstruct the original format
					// Check if the original had spaces around braces
					content := n.String()
					trimmed := strings.TrimSpace(content)

					if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
						// Reconstruct with spaces around braces to match common YAML formatting
						inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
						return "{ " + inner + " }"
					}
				}
			}
		}

		// Otherwise, serialize as block mapping
		return serializeMappingNode(n)
	case *ast.SequenceNode:
		// For sequence nodes, try to preserve original formatting
		content := n.String()
		trimmed := strings.TrimSpace(content)

		// If it looks like a flow sequence, reconstruct it with proper comma formatting
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// Extract the inner content without brackets
			inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])

			// Check if the original already has commas
			if strings.Contains(inner, ",") {
				// Original has commas, preserve them
				return trimmed
			}

			// Split by whitespace to get individual elements
			elements := strings.Fields(inner)

			// Reconstruct with commas
			if len(elements) > 0 {
				result := "[" + strings.Join(elements, ", ") + "]"
				return result
			}
			return "[]"
		}

		// Otherwise, serialize as block sequence
		return serializeSequenceNode(n)
	case *ast.DocumentNode:
		if n.Body != nil {
			return extractNodeContent(n.Body)
		}
		return ""
	default:
		// Fallback for other node types
		return n.String()
	}
}

// serializeMappingNode serializes a mapping node to YAML string
func serializeMappingNode(node *ast.MappingNode) string {
	if node == nil || len(node.Values) == 0 {
		return "{}"
	}

	var parts []string
	for _, pair := range node.Values {
		if pair.Key != nil && pair.Value != nil {
			keyStr := extractNodeContent(pair.Key)
			valueStr := extractNodeContent(pair.Value)

			// Check if the value is a complex structure that needs proper formatting
			switch pair.Value.(type) {
			case *ast.MappingNode, *ast.SequenceNode:
				// For complex values, format with proper indentation
				parts = append(parts, fmt.Sprintf("%s:\n  %s", keyStr, strings.ReplaceAll(valueStr, "\n", "\n  ")))
			default:
				// For simple values, use inline format
				parts = append(parts, fmt.Sprintf("%s: %s", keyStr, valueStr))
			}
		}
	}

	return strings.Join(parts, "\n")
}

// serializeSequenceNode serializes a sequence node to YAML string
func serializeSequenceNode(node *ast.SequenceNode) string {
	if node == nil || len(node.Values) == 0 {
		return "[]"
	}

	var parts []string
	for _, value := range node.Values {
		if value != nil {
			valueStr := extractNodeContent(value)
			parts = append(parts, fmt.Sprintf("- %s", valueStr))
		}
	}

	return strings.Join(parts, "\n")
}

// detectStyle detects the YAML style of a node
func detectStyle(node ast.Node) Style {
	if node == nil {
		return BlockMapping
	}

	// Helper to inspect the raw YAML representation of the node.
	getContent := func() string {
		return strings.TrimSpace(extractNodeContent(node))
	}

	switch n := node.(type) {
	case *ast.MappingNode:
		trimmed := getContent()

		// Flow mappings are surrounded by braces { }.
		if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
			if strings.Contains(trimmed, "\n") {
				return MultilineFlowMapping
			}
			return FlowMapping
		}

		return BlockMapping

	case *ast.SequenceNode:
		trimmed := getContent()

		// Flow sequences are surrounded by brackets [ ].
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if strings.Contains(trimmed, "\n") {
				return MultilineFlowSequence
			}
			return FlowSequence
		}

		return BlockSequence

	case *ast.StringNode:
		content := n.Value

		if strings.Contains(content, "\n") {
			// Literal (|) or folded (>) scalar.
			if strings.HasPrefix(content, "|") {
				return MultilineLiteralScalar
			}
			if strings.HasPrefix(content, ">") {
				return MultilineFoldedScalar
			}
		}

		// Quoted scalars.
		if strings.HasPrefix(content, `"`) && strings.HasSuffix(content, `"`) {
			return DoubleQuoted
		}
		if strings.HasPrefix(content, `'`) && strings.HasSuffix(content, `'`) {
			return SingleQuoted
		}

		return PlainScalar

	case *ast.LiteralNode:
		// Literal nodes already hold scalar text (often | block literals).
		if strings.Contains(n.String(), "\n") {
			return MultilineLiteralScalar
		}
		return PlainScalar

	default:
		return BlockMapping
	}
}

// convertToJSONPath converts dot notation (jobs.test.steps.0.run) to JSONPath ($.jobs.test.steps[0].run)
//
//nolint:unused
func convertToJSONPath(dotPath string) string {
	if dotPath == "" || dotPath == "." {
		return "$"
	}
	parts := strings.Split(dotPath, ".")
	var b strings.Builder
	b.WriteString("$")
	for _, part := range parts {
		if idx, err := strconv.Atoi(part); err == nil {
			b.WriteString("[")
			b.WriteString(strconv.Itoa(idx))
			b.WriteString("]")
		} else {
			b.WriteString(".")
			b.WriteString(part)
		}
	}
	return b.String()
}
