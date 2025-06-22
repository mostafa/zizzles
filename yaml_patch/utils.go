package yaml_patch

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	yamlv3 "gopkg.in/yaml.v3"
)

// valueToYAMLString converts a value to a YAML string with proper formatting
func valueToYAMLString(value any) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case int:
		return strconv.Itoa(v), nil
	case bool:
		return strconv.FormatBool(v), nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case map[string]string:
		return serializeMap(v)
	case map[string]any:
		return serializeMap(v)
	case []string:
		return serializeSlice(v)
	case []any:
		return serializeSlice(v)
	default:
		// Use go-yaml for complex types
		bytes, err := yaml.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("failed to marshal value: %w", err)
		}
		return strings.TrimSpace(string(bytes)), nil
	}
}

// serializeMap serializes a map to YAML string
func serializeMap(m any) (string, error) {
	bytes, err := yaml.Marshal(m)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes)), nil
}

// serializeSlice serializes a slice to YAML string
func serializeSlice(s any) (string, error) {
	bytes, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes)), nil
}

// PathComponent represents a single component of a YAML path
type PathComponent struct {
	Type  PathComponentType
	Value any
}

// PathComponentType represents the type of a path component
type PathComponentType int

const (
	Key PathComponentType = iota
	ArrayIndex
)

// String returns the string representation of the path component
func (pc PathComponent) String() string {
	switch pc.Type {
	case Key:
		return pc.Value.(string)
	case ArrayIndex:
		return fmt.Sprintf("[%d]", pc.Value.(int))
	default:
		return ""
	}
}

// formatBlockMappingReplacement formats a replacement for block mapping style
func formatBlockMappingReplacement(value string, indentation int) string {
	indent := strings.Repeat("  ", indentation)
	if strings.Contains(value, "\n") {
		// Multiline value
		lines := strings.Split(value, "\n")
		result := lines[0]
		for i := 1; i < len(lines); i++ {
			result += "\n" + indent + "  " + lines[i]
		}
		return result
	}
	return value
}

// formatBlockMappingAddition formats an addition for block mapping style
func formatBlockMappingAddition(key, value string, indentation int) string {
	indent := strings.Repeat("  ", indentation/2)

	// Try to parse as YAML mapping
	var parsed map[string]any
	err := yamlv3.Unmarshal([]byte(value), &parsed)
	if err == nil && len(parsed) > 0 {
		// It's a mapping, format as nested YAML
		result := "\n" + indent + key + ":"
		for k, v := range parsed {
			// Serialize each key-value pair
			line := "\n" + indent + "  " + k + ": "
			if vs, ok := v.(string); ok {
				line += vs
			} else {
				// Fallback to YAML marshal for non-string values
				bytes, _ := yamlv3.Marshal(v)
				line += strings.TrimSpace(string(bytes))
			}
			result += line
		}
		return result
	}

	// Multiline string: use block scalar (|) and proper indentation
	if strings.Contains(value, "\n") {
		lines := strings.Split(value, "\n")
		result := "\n" + indent + key + ": |\n"
		contentIndent := indent + "  "
		for _, line := range lines {
			result += contentIndent + line + "\n"
		}
		return strings.TrimSuffix(result, "\n")
	}

	// Fallback: single-line value
	return "\n" + indent + key + ": " + value
}

// formatFlowMappingAddition formats an addition for flow mapping style
func formatFlowMappingAddition(key, value string, existingContent string) string {
	trimmed := strings.TrimSpace(existingContent)

	// Handle flow mappings with or without spaces around braces
	if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
		// Extract the inner content without braces
		inner := strings.TrimSuffix(strings.TrimPrefix(trimmed, "{"), "}")
		inner = strings.TrimSpace(inner)

		if inner == "" {
			// Empty flow mapping
			return "{ " + key + ": " + value + " }"
		}

		// Parse existing key-value pairs while preserving order
		var existingPairs []string
		if inner != "" {
			// Split by comma and parse each pair
			pairs := strings.Split(inner, ",")
			for _, pair := range pairs {
				pair = strings.TrimSpace(pair)
				if pair != "" {
					existingPairs = append(existingPairs, pair)
				}
			}
		}

		// Add the new key-value pair to the end
		newPair := key + ": " + value
		existingPairs = append(existingPairs, newPair)

		// Reconstruct the flow mapping
		result := "{ " + strings.Join(existingPairs, ", ") + " }"
		return result
	}

	// If it doesn't look like a flow mapping, append to the content
	return existingContent + ", " + key + ": " + value
}

// keyExists checks if a key already exists in the mapping
func keyExists(content string, nodeInfo *NodeInfo, key string) bool {
	// Parse the content to check if the key exists
	if nodeInfo == nil || nodeInfo.Content == "" {
		return false
	}

	// For a more robust implementation, we would parse the YAML and check the mapping
	// For now, we'll use a simple string-based check
	lines := strings.Split(nodeInfo.Content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, key+":") {
			return true
		}
	}
	return false
}

// findContentEnd finds the end of actual content, excluding trailing comments
func findContentEnd(nodeInfo *NodeInfo) int {
	if nodeInfo == nil {
		return 0
	}

	// For block mappings within sequences, we need to be more careful about finding the end
	// The issue is that nodeInfo.EndPos might include content from the next sequence item
	if nodeInfo.Style == BlockMapping && len(nodeInfo.Path) > 0 {
		// Check if this is a sequence item (path ends with a number)
		lastPathElement := nodeInfo.Path[len(nodeInfo.Path)-1]
		if _, err := strconv.Atoi(lastPathElement); err == nil {
			// This is a sequence item, we need to find the proper end of this mapping
			// by looking at the original content and finding where this item ends
			return findSequenceItemEnd(nodeInfo)
		}
	}

	// For block mappings, we want to insert at the end of the mapping
	// Use the end position of the node as the insertion point
	return nodeInfo.EndPos
}

// findSequenceItemEnd finds the end position of a mapping within a sequence
// by analyzing the source content structure
func findSequenceItemEnd(nodeInfo *NodeInfo) int {
	// We need to work with the original source content to find proper boundaries
	// This function should be called with access to the original content
	// For now, return the original end position as fallback
	return nodeInfo.EndPos
}

// isMappingValue checks if a value is a mapping
func isMappingValue(value any) bool {
	switch v := value.(type) {
	case map[string]string, map[string]any:
		return true
	case string:
		// Try to parse the string as YAML to see if it's a mapping
		var parsed any
		if err := yamlv3.Unmarshal([]byte(v), &parsed); err == nil {
			switch parsed.(type) {
			case map[string]any:
				return true
			}
		}
		// Also check if it looks like a simple key-value pair
		if strings.Contains(v, ":") && !strings.Contains(v, "\n") {
			parts := strings.SplitN(v, ":", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// mergeMappings merges two mapping values
func mergeMappings(existing, new any) (any, error) {
	// Parse existing value if it's a string
	var existingMap map[string]any
	switch existingVal := existing.(type) {
	case map[string]string:
		existingMap = make(map[string]any)
		for k, v := range existingVal {
			existingMap[k] = v
		}
	case map[string]any:
		existingMap = existingVal
	case string:
		// Try to parse the string as YAML
		if err := yamlv3.Unmarshal([]byte(existingVal), &existingMap); err != nil {
			// If parsing fails, try to parse as a simple key-value pair
			if strings.Contains(existingVal, ":") && !strings.Contains(existingVal, "\n") {
				parts := strings.SplitN(existingVal, ":", 2)
				if len(parts) == 2 {
					existingMap = map[string]any{
						strings.TrimSpace(parts[0]): strings.TrimSpace(parts[1]),
					}
				}
			}
		}
	}

	// Parse new value if it's a string
	var newMap map[string]any
	switch newVal := new.(type) {
	case map[string]string:
		newMap = make(map[string]any)
		for k, v := range newVal {
			newMap[k] = v
		}
	case map[string]any:
		newMap = newVal
	case string:
		if err := yamlv3.Unmarshal([]byte(newVal), &newMap); err != nil {
			return new, nil // Return new value as-is if parsing fails
		}
	}

	// Merge the maps
	if existingMap != nil && newMap != nil {
		result := make(map[string]any)
		for k, v := range existingMap {
			result[k] = v
		}
		for k, v := range newMap {
			result[k] = v
		}
		return result, nil
	}

	return new, nil
}

// findLineStart finds the start of the line containing the given position
func findLineStart(content string, pos int) int {
	for i := pos; i >= 0; i-- {
		if i == 0 || content[i-1] == '\n' {
			return i
		}
	}
	return pos
}

// findLineEnd finds the end of the line containing the given position
func findLineEnd(content string, pos int) int {
	for i := pos; i < len(content); i++ {
		if content[i] == '\n' {
			return i + 1
		}
	}
	return len(content)
}

// extractIndentation extracts the indentation level from a line
func extractIndentation(line string) int {
	indentation := 0
	for _, char := range line {
		if char == ' ' {
			indentation++
		} else if char == '\t' {
			indentation += 4 // Assume tab is 4 spaces
		} else {
			break
		}
	}
	return indentation
}

// formatBlockMappingValue formats a mapping value as a proper block mapping
func formatBlockMappingValue(value string, indentation int) string {
	indent := strings.Repeat("  ", indentation)

	// Try to parse the value as YAML to see if it's a mapping
	var parsed map[string]any
	if err := yamlv3.Unmarshal([]byte(value), &parsed); err == nil && len(parsed) > 0 {
		// It's a mapping, format as block mapping
		result := ""

		// For deterministic output, sort keys alphabetically
		keys := make([]string, 0, len(parsed))
		for k := range parsed {
			keys = append(keys, k)
		}

		// Always sort alphabetically for consistent output
		sort.Strings(keys)

		for _, k := range keys {
			v := parsed[k]
			line := "\n" + indent + k + ": "
			if vs, ok := v.(string); ok {
				line += vs
			} else {
				// Fallback to YAML marshal for non-string values
				bytes, _ := yamlv3.Marshal(v)
				line += strings.TrimSpace(string(bytes))
			}
			result += line
		}
		// Remove the leading newline since we're replacing content, not adding new lines
		result = strings.TrimPrefix(result, "\n")
		return result
	}

	// If parsing fails, treat as simple string
	return value
}

// extractLeadingWhitespace returns the leading whitespace (spaces/tabs) of the
// line that contains the given byte position. It relies on the original
// YAML source string so that we can preserve the user's indentation exactly.
func extractLeadingWhitespace(content string, pos int) string {
	if pos < 0 || pos >= len(content) {
		return ""
	}

	lineStart := findLineStart(content, pos)
	lineEnd := findLineEnd(content, pos)
	if lineStart >= lineEnd {
		return ""
	}

	line := content[lineStart:lineEnd]

	// Extract run of leading spaces (and tabs) before first non-space.
	i := 0
	for i < len(line) {
		if line[i] != ' ' && line[i] != '\t' {
			break
		}
		i++
	}
	return line[:i]
}

// extractLeadingIndentationForBlockItem mirrors the Rust helper: given a YAML
// list item that contains a mapping (e.g. a step inside `steps:`), determine
// the indentation the nested mapping keys should begin at.
//
// It walks the line that holds the list dash (`-`) and returns the index
// *after* that dash + space (or after the continuous sequence of dashes in
// unusual cases).
func extractLeadingIndentationForBlockItem(content string, nodeInfo *NodeInfo) int {
	// Obtain the complete line containing the mapping start.
	lineStart := findLineStart(content, nodeInfo.StartPos)
	lineEnd := findLineEnd(content, nodeInfo.StartPos)
	line := strings.TrimRight(content[lineStart:lineEnd], "\n")

	acceptDash := true
	for idx, r := range line {
		switch r {
		case ' ':
			acceptDash = true
		case '-':
			if acceptDash {
				acceptDash = false // first dash allowed
			} else {
				// second dash in a row that isn't separated by space treat the
				// previous char as start of scalar, so indentation is idx-1.
				return idx - 1
			}
		default:
			// On first non-space / non-dash char we decide.
			if !acceptDash {
				return idx - 1
			}
			return idx
		}
	}

	// Reached EOL with nothing but spaces/dashes. This happens for pattern:
	//   -
	//     key: val
	// We indent one space past the line length so nested mapping aligns.
	return len(line) + 1
}

// findContentEndInContent returns the absolute byte index (within the original
// YAML string) of the end of the last non-empty, non-comment line that belongs
// to the node represented by nodeInfo. This is much more accurate than relying
// on the parser's EndPos, which often includes trailing comments or the next
// list item when working inside sequences.
func findContentEndInContent(content string, nodeInfo *NodeInfo) int {
	if nodeInfo == nil {
		return 0
	}

	segmentStart := nodeInfo.StartPos
	segmentEnd := nodeInfo.EndPos
	if segmentStart < 0 {
		segmentStart = 0
	}
	if segmentEnd > len(content) {
		segmentEnd = len(content)
	}

	segment := content[segmentStart:segmentEnd]
	// Walk the lines backwards.
	lines := strings.Split(segment, "\n")

	// cumulativeOffset tracks length processed so we can compute absolute pos.
	cumulativeOffset := 0
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			// position is startPos + bytes up to this line + len(line)
			// Calculate bytes before this line.
			bytesBefore := 0
			for j := 0; j < i; j++ {
				bytesBefore += len(lines[j]) + 1 // +1 for newline
			}
			return segmentStart + bytesBefore + len(line)
		}
		cumulativeOffset += len(line) + 1 // not currently used but kept for clarity
	}

	// Fallback original EndPos.
	return nodeInfo.EndPos
}
