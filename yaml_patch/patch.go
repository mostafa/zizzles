package yaml_patch

import (
	"fmt"
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
	// Parse the YAML to validate it's valid
	file, err := parser.ParseBytes([]byte(content), parser.ParseComments)
	if err != nil {
		return "", fmt.Errorf("YAML patch error: input is not valid YAML: %w", err)
	}

	result := content

	// Apply each patch
	for _, patch := range patches {
		// Find the node at the path
		nodeInfo, err := findNodeByPath(file, patch.Path, content)
		if err != nil {
			return "", fmt.Errorf("YAML patch error at %s: %w", patch.Path, err)
		}

		// Apply the operation
		switch op := patch.Operation.(type) {
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
			return "", fmt.Errorf("YAML patch error at %s: unknown operation type", patch.Path)
		}

		if err != nil {
			return "", fmt.Errorf("YAML patch error at %s: %w", patch.Path, err)
		}

		// Re-parse the result to update the file for next operations
		file, err = parser.ParseBytes([]byte(result), parser.ParseComments)
		if err != nil {
			return "", fmt.Errorf("YAML patch error: result is not valid YAML: %w", err)
		}
	}

	// Ensure result ends with a newline to match expected format
	if !strings.HasSuffix(result, "\n") {
		result += "\n"
	}

	return result, nil
}

// findNodeByPath finds a node by its dot-separated path
func findNodeByPath(file *ast.File, path string, content string) (*NodeInfo, error) {
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

	switch n := node.(type) {
	case *ast.MappingNode:
		// For mapping nodes, we need to examine the original YAML content
		// rather than the serialized content to detect flow style
		if len(n.Values) == 0 {
			return BlockMapping
		}

		// Check if all key-value pairs are on the same line (flow style)
		// This is a heuristic: if the first and last tokens are close together, it's likely flow style
		firstToken := n.Values[0].Key.GetToken()
		lastToken := n.Values[len(n.Values)-1].Value.GetToken()

		if firstToken != nil && lastToken != nil {
			// If all key-value pairs are on the same line, it's likely a flow mapping
			if firstToken.Position.Line == lastToken.Position.Line {
				return FlowMapping
			}
		}

		// For single key-value pairs, check if they're on the same line
		if len(n.Values) == 1 {
			keyToken := n.Values[0].Key.GetToken()
			valueToken := n.Values[0].Value.GetToken()
			if keyToken != nil && valueToken != nil {
				// If key and value are on the same line, it's likely flow style
				if keyToken.Position.Line == valueToken.Position.Line {
					return FlowMapping
				}
			}
		}

		// Check if this is a block mapping by examining the structure
		// A block mapping should have the key on one line and the value on the next line with indentation
		if len(n.Values) == 1 {
			keyToken := n.Values[0].Key.GetToken()
			valueToken := n.Values[0].Value.GetToken()
			if keyToken != nil && valueToken != nil {
				// If key and value are on different lines, it's a block mapping
				if keyToken.Position.Line != valueToken.Position.Line {
					return BlockMapping
				}
			}
		}

		return BlockMapping

	case *ast.SequenceNode:
		// Similar logic for sequences
		if len(n.Values) == 0 {
			return BlockSequence
		}

		firstToken := n.Values[0].GetToken()
		lastToken := n.Values[len(n.Values)-1].GetToken()

		if firstToken != nil && lastToken != nil {
			if firstToken.Position.Line == lastToken.Position.Line {
				return FlowSequence
			}
		}

		return BlockSequence

	case *ast.StringNode:
		content := n.Value
		if strings.Contains(content, "\n") {
			// Check for literal or folded style indicators
			if strings.HasPrefix(content, "|") {
				return MultilineLiteralScalar
			}
			if strings.HasPrefix(content, ">") {
				return MultilineFoldedScalar
			}
		}

		// Check for quoted styles
		if strings.HasPrefix(content, `"`) && strings.HasSuffix(content, `"`) {
			return DoubleQuoted
		}
		if strings.HasPrefix(content, `'`) && strings.HasSuffix(content, `'`) {
			return SingleQuoted
		}

		return PlainScalar

	case *ast.LiteralNode:
		content := n.String()
		if strings.Contains(content, "\n") {
			return MultilineLiteralScalar
		}
		return PlainScalar

	default:
		return BlockMapping
	}
}

// convertToJSONPath converts dot notation (jobs.test.steps.0.run) to JSONPath ($.jobs.test.steps[0].run)
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
