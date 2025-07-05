package yaml_patch

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"
)

// applyRewriteFragment applies a RewriteFragment operation
func applyRewriteFragment(content string, nodeInfo *NodeInfo, op RewriteFragmentOp) (string, error) {
	// Get accurate boundaries for the value content
	actualStart, actualEnd := getAccurateValueBounds(content, nodeInfo)

	// Additional safety check to prevent slice bounds errors
	if actualStart < 0 || actualEnd < 0 || actualStart > len(content) || actualEnd > len(content) || actualStart > actualEnd {
		return "", NewError("rewrite", fmt.Sprintf("invalid node boundaries: start=%d, end=%d, content_len=%d", actualStart, actualEnd, len(content)), strings.Join(nodeInfo.Path, "."))
	}

	// For multiline literal and folded scalars, extract just the body content for replacement
	var valueContent string
	var contentStart, contentEnd int

	if nodeInfo.Style == MultilineLiteralScalar || nodeInfo.Style == MultilineFoldedScalar {
		// Find the indicator line end
		indicatorEnd := actualStart
		for indicatorEnd < len(content) && content[indicatorEnd] != '\n' {
			indicatorEnd++
		}
		if indicatorEnd >= len(content) {
			return "", NewError("rewrite", "could not find end of multiline indicator line", strings.Join(nodeInfo.Path, "."))
		}

		// Content starts after the indicator line
		contentStart = indicatorEnd + 1
		contentEnd = actualEnd

		if contentStart > contentEnd || contentStart > len(content) {
			return "", NewError("rewrite", "invalid multiline content boundaries", strings.Join(nodeInfo.Path, "."))
		}

		valueContent = content[contentStart:contentEnd]
	} else {
		// For regular nodes, use the entire value
		valueContent = content[actualStart:actualEnd]
		contentStart = actualStart
		contentEnd = actualEnd
	}

	// Apply bias if specified
	bias := 0
	if op.After != nil {
		bias = *op.After
	}

	if bias > len(valueContent) {
		return "", NewError("rewrite", fmt.Sprintf("replacement scan index %d is out of bounds for feature", bias), strings.Join(nodeInfo.Path, "."))
	}

	// Search for the pattern within the value content
	searchContent := valueContent[bias:]
	fromStart := findFlexibleMatch(searchContent, op.From)
	if fromStart == -1 {
		return "", NewError("rewrite", fmt.Sprintf("no match for '%s' in feature", op.From), strings.Join(nodeInfo.Path, "."))
	}

	// Calculate absolute positions for replacement
	absoluteFromStart := contentStart + bias + fromStart
	absoluteFromEnd := absoluteFromStart + len(op.From)

	// Ensure we don't go beyond the content boundaries
	if absoluteFromEnd > contentEnd {
		return "", NewError("rewrite", "replacement would exceed value boundaries", strings.Join(nodeInfo.Path, "."))
	}

	// Perform the replacement - bounds checking for final reconstruction
	if absoluteFromStart < 0 || absoluteFromStart > len(content) || absoluteFromEnd < 0 || absoluteFromEnd > len(content) || absoluteFromStart > absoluteFromEnd {
		return "", NewError("rewrite", fmt.Sprintf("invalid replacement boundaries: absoluteFromStart=%d, absoluteFromEnd=%d, content_len=%d", absoluteFromStart, absoluteFromEnd, len(content)), strings.Join(nodeInfo.Path, "."))
	}

	result := content[:absoluteFromStart] + op.To + content[absoluteFromEnd:]

	return result, nil
}

// applyReplace applies a Replace operation
func applyReplace(content string, nodeInfo *NodeInfo, op ReplaceOp) (string, error) {
	// Convert the value to YAML string
	replacement, err := valueToYAMLString(op.Value)
	if err != nil {
		return "", NewError("serialization", fmt.Sprintf("failed to serialize value: %v", err), strings.Join(nodeInfo.Path, "."))
	}

	// Handle missing-value case (key exists but value is empty). This shows up
	// when StartPos == EndPos or content is empty.
	if nodeInfo.StartPos == nodeInfo.EndPos || strings.TrimSpace(nodeInfo.Content) == "" {
		// We are pointing at the *position* right after the key. Find colon on
		// the key line and insert.
		keyLineStart := findLineStart(content, nodeInfo.StartPos)
		keyLineEnd := findLineEnd(content, nodeInfo.StartPos)
		keyLine := content[keyLineStart:keyLineEnd]

		// Determine indentation for block scalar or value.
		indentWS := extractLeadingWhitespace(content, keyLineStart)

		if strVal, ok := op.Value.(string); ok && strings.Contains(strVal, "\n") {
			// multiline -> literal |
			lines := strings.Split(strVal, "\n")
			block := "|\n"
			for _, l := range lines {
				block += indentWS + "  " + l + "\n"
			}
			block = strings.TrimSuffix(block, "\n")

			// insert block after colon (and any spaces).
			colonIdx := strings.Index(keyLine, ":")
			insertPos := keyLineStart + colonIdx + 1
			for insertPos < len(content) && (content[insertPos] == ' ' || content[insertPos] == '\t') {
				insertPos++
			}
			result := content[:insertPos] + block + content[insertPos:]
			return result, nil
		}

		// single line value
		colonIdx := strings.Index(keyLine, ":")
		if colonIdx == -1 { // malformed line
			colonIdx = len(keyLine)
		}
		insertPos := keyLineStart + colonIdx + 1
		result := content[:insertPos] + " " + replacement + content[insertPos:]
		return result, nil
	}

	// Check if the replacement value is a multiline string that should be formatted as a literal block
	if strValue, ok := op.Value.(string); ok && strings.Contains(strValue, "\n") {
		lines := strings.Split(strValue, "\n")

		// Find the start and end of the line containing the key (e.g., 'run:')
		keyLineStart := findLineStart(content, nodeInfo.StartPos)
		keyLineEnd := findLineEnd(content, nodeInfo.StartPos)
		keyLine := content[keyLineStart:keyLineEnd]

		// Find the position of ':' in the key line
		colonIdx := strings.Index(keyLine, ":")
		if colonIdx == -1 {
			colonIdx = len(keyLine)
		}

		// Calculate the indentation up to the key (e.g., up to 'r' in 'run:')
		keyIndent := ""
		for i := 0; i < len(keyLine); i++ {
			if keyLine[i] == ' ' || keyLine[i] == '\t' {
				keyIndent += string(keyLine[i])
			} else if keyLine[i] == '-' {
				// Skip the dash and the following space
				i++
				if i < len(keyLine) && keyLine[i] == ' ' {
					i++
				}
				// Now add spaces up to the key
				for ; i < len(keyLine); i++ {
					if keyLine[i] == ' ' || keyLine[i] == '\t' {
						keyIndent += string(keyLine[i])
					} else {
						break
					}
				}
				break
			} else {
				break
			}
		}

		// The block indicator '|' should be on the same line as the key, after the colon
		colonPosInContent := keyLineStart + colonIdx
		// Find the start of the value (after colon and whitespace)
		valueStart := colonPosInContent + 1
		for valueStart < len(content) && (content[valueStart] == ' ' || content[valueStart] == '\t') {
			valueStart++
		}
		replacement := "|\n"
		contentIndent := keyIndent + "  "
		for _, line := range lines {
			replacement += contentIndent + line + "\n"
		}
		replacement = strings.TrimSuffix(replacement, "\n")
		result := content[:valueStart] + replacement + content[nodeInfo.EndPos:]
		return result, nil
	}

	// Special handling for flow sequence elements
	// If we're replacing an element in a flow sequence, we need to reconstruct the entire sequence
	if len(nodeInfo.Path) > 0 {
		// Check if this is an indexed element (e.g., branches.0)
		lastPart := nodeInfo.Path[len(nodeInfo.Path)-1]
		if idx, err := strconv.Atoi(lastPart); err == nil {
			// This is an indexed element, check if the parent is a flow sequence
			parentPath := strings.Join(nodeInfo.Path[:len(nodeInfo.Path)-1], ".")
			parentNodeInfo, err := findNodeByPathFromContent(content, parentPath)
			if err == nil && parentNodeInfo.Style == FlowSequence {
				// We're replacing an element in a flow sequence
				return applyFlowSequenceElementReplace(content, parentNodeInfo, idx, replacement)
			}
		}
	}

	// For block mappings, we need to handle indentation
	if nodeInfo.Style == BlockMapping {
		// Check if the replacement value is a mapping that should be formatted as a block mapping
		if isMappingValue(op.Value) {
			// Format the mapping as a proper block mapping
			replacement = formatBlockMappingValue(replacement, nodeInfo.Indentation)
		} else {
			replacement = formatBlockMappingReplacement(replacement, nodeInfo.Indentation)
		}
	}

	// Ensure positions are within bounds
	startPos := nodeInfo.StartPos
	endPos := nodeInfo.EndPos

	if startPos < 0 {
		startPos = 0
	}
	if endPos > len(content) {
		endPos = len(content)
	}
	if startPos >= endPos {
		startPos = 0
		endPos = len(content)
	}

	// Replace the content
	result := content[:startPos] + replacement + content[endPos:]
	return result, nil
}

// applyAdd applies an Add operation
func applyAdd(content string, nodeInfo *NodeInfo, op AddOp) (string, error) {
	// Disallow adding into multiline flow mappings for now – complex to keep
	// formatting.
	if nodeInfo.Style == MultilineFlowMapping {
		return "", NewError("add", "multiline flow mappings are not yet supported for add operations", strings.Join(nodeInfo.Path, "."))
	}

	// Handle single-line flow mapping `{ … }`.
	if nodeInfo.Style == FlowMapping {
		if keyExists(content, nodeInfo, op.Key) {
			return "", NewError("add", fmt.Sprintf("key '%s' already exists at path %s", op.Key, strings.Join(nodeInfo.Path, ".")), strings.Join(nodeInfo.Path, "."))
		}

		newContent, err := handleFlowMappingAddition(nodeInfo.Content, op.Key, op.Value)
		if err != nil {
			return "", err
		}

		// Replace the old flow mapping string with the new content.
		start := nodeInfo.StartPos
		end := nodeInfo.EndPos
		if start < 0 || end > len(content) || start >= end {
			return "", NewError("add", "invalid node position for flow mapping", strings.Join(nodeInfo.Path, "."))
		}
		return content[:start] + newContent + content[end:], nil
	}

	// Handle block mappings.
	if nodeInfo.Style == BlockMapping {
		if keyExists(content, nodeInfo, op.Key) {
			return "", NewError("add", fmt.Sprintf("key '%s' already exists at path %s", op.Key, strings.Join(nodeInfo.Path, ".")), strings.Join(nodeInfo.Path, "."))
		}

		valueStr, err := valueToYAMLString(op.Value)
		if err != nil {
			return "", NewError("serialization", fmt.Sprintf("failed to serialize value: %v", err), strings.Join(nodeInfo.Path, "."))
		}

		// Determine insertion point.
		var insertionPoint int
		if len(nodeInfo.Path) > 0 {
			if _, err := strconv.Atoi(nodeInfo.Path[len(nodeInfo.Path)-1]); err == nil {
				insertionPoint = findSequenceItemEndInContent(content, nodeInfo)
			} else {
				insertionPoint = findContentEndInContent(content, nodeInfo)
			}
		} else {
			insertionPoint = findContentEndInContent(content, nodeInfo)
		}

		if insertionPoint > len(content) {
			insertionPoint = len(content)
		}

		indentSpaces := extractLeadingIndentationForBlockItem(content, nodeInfo)
		addition := formatBlockMappingAddition(op.Key, valueStr, indentSpaces)

		// Avoid double newline.
		if insertionPoint > 0 && content[insertionPoint-1] == '\n' {
			addition = strings.TrimPrefix(addition, "\n")
		}

		return content[:insertionPoint] + addition + content[insertionPoint:], nil
	}

	return "", NewError("add", fmt.Sprintf("add operation is not permitted against style %s", nodeInfo.Style), strings.Join(nodeInfo.Path, "."))
}

// handleFlowMappingAddition inserts the key/value into an existing single-line
// flow mapping string ("{ a: 1 }") while preserving flow formatting.
func handleFlowMappingAddition(featureContent string, key string, value any) (string, error) {
	// We need to preserve the original ordering of keys in the mapping. Since
	// YAML maps are unordered after Unmarshal, we re-parse the original string
	// to obtain the existing pair order.

	trimmed := strings.TrimSpace(featureContent)
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "{"), "}"))

	var orderedPairs []string
	if inner != "" {
		segments := strings.Split(inner, ",")
		for _, seg := range segments {
			seg = strings.TrimSpace(seg)
			if seg != "" {
				orderedPairs = append(orderedPairs, seg)
			}
		}
	}

	// Append the new pair at the end.
	valueStr, err := valueToYAMLString(value)
	if err != nil {
		return "", err
	}
	orderedPairs = append(orderedPairs, fmt.Sprintf("%s: %s", key, valueStr))

	combined := strings.Join(orderedPairs, ", ")

	lead := ""
	trail := ""
	if len(featureContent) > 0 && featureContent[0] == ' ' {
		lead = " "
	}
	if len(featureContent) > 0 && featureContent[len(featureContent)-1] == ' ' {
		trail = " "
	}

	return lead + combined + " " + trail, nil
}

// applyMergeInto applies a MergeInto operation
func applyMergeInto(content string, nodeInfo *NodeInfo, op MergeIntoOp) (string, error) {
	// Build full path to the key we want to merge into.
	keyPath := append(nodeInfo.Path, op.Key)
	joinedKeyPath := strings.Join(keyPath, ".")

	existingNodeInfo, err := findNodeByPathFromContent(content, joinedKeyPath)

	if err == nil {
		// Key exists – decide whether to deep-merge or replace.
		var existingVal any
		if err := yaml.Unmarshal([]byte(existingNodeInfo.Content), &existingVal); err != nil {
			// Fallback to string content if unmarshal fails.
			existingVal = existingNodeInfo.Content
		}

		// Attempt deep merge when both sides are mappings.
		if isMappingValue(op.Value) && isMappingValue(existingVal) {
			merged, err := mergeMappings(existingVal, op.Value)
			if err != nil {
				return "", NewError("merge", fmt.Sprintf("failed to merge mappings: %v", err), joinedKeyPath)
			}

			// Calculate indentation units based on the key line.
			baseWS := extractLeadingWhitespace(content, existingNodeInfo.StartPos)
			parentUnits := len(baseWS) / 2

			mergedStr, err := valueToYAMLString(merged)
			if err != nil {
				return "", NewError("serialization", fmt.Sprintf("failed to serialize merged mapping: %v", err), joinedKeyPath)
			}

			formatted := formatBlockMappingValue(mergedStr, parentUnits)

			// Replace from beginning of the value line (indent start) to EndPos
			start := findLineStart(content, existingNodeInfo.StartPos)
			end := existingNodeInfo.EndPos
			newContent := content[:start] + formatted + content[end:]
			return newContent, nil
		}

		// Not both mappings – simple replacement.
		return applyReplace(content, existingNodeInfo, ReplaceOp{Value: op.Value})
	}

	// Key does not exist – fall back to Add.
	return applyAdd(content, nodeInfo, AddOp(op))
}

// applyRemove applies a Remove operation
func applyRemove(content string, nodeInfo *NodeInfo, _ RemoveOp) (string, error) {
	if len(nodeInfo.Path) == 0 {
		return "", NewError("remove", "cannot remove root document", "")
	}

	// For mapping nodes, we need to find the parent mapping and remove the entire key-value pair
	if nodeInfo.Style == BlockMapping || nodeInfo.Style == FlowMapping {
		// Find the parent mapping that contains this key
		if len(nodeInfo.Path) == 0 {
			return "", NewError("remove", "cannot remove root document", "")
		}

		parentPath := strings.Join(nodeInfo.Path[:len(nodeInfo.Path)-1], ".")
		keyToRemove := nodeInfo.Path[len(nodeInfo.Path)-1]

		// Find the parent mapping
		_, err := findNodeByPathFromContent(content, parentPath)
		if err != nil {
			return "", NewError("remove", fmt.Sprintf("could not find parent mapping: %v", err), parentPath)
		}

		// Find the line that contains the key we want to remove
		lines := strings.Split(content, "\n")
		keyLineIndex := -1
		keyPattern := fmt.Sprintf("%s:", keyToRemove)

		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == keyPattern {
				keyLineIndex = i
				break
			}
		}

		if keyLineIndex == -1 {
			return "", NewError("remove", fmt.Sprintf("could not find key '%s' in parent mapping", keyToRemove), parentPath)
		}

		// Find the start and end of the key-value block
		blockStart := keyLineIndex
		blockEnd := keyLineIndex + 1

		// Find the end of the block by looking for the next line with same or less indentation
		keyIndentation := extractIndentation(lines[keyLineIndex])

		for i := keyLineIndex + 1; i < len(lines); i++ {
			line := lines[i]
			trimmed := strings.TrimSpace(line)

			// Skip empty lines
			if trimmed == "" {
				continue
			}

			// Skip comment lines
			if strings.HasPrefix(trimmed, "#") {
				continue
			}

			// Check indentation
			lineIndentation := extractIndentation(line)
			if lineIndentation <= keyIndentation {
				// This line has same or less indentation, so it's not part of our block
				break
			}

			blockEnd = i + 1
		}

		// Calculate positions
		startPos := 0
		for i := 0; i < blockStart; i++ {
			startPos += len(lines[i]) + 1 // +1 for newline
		}

		endPos := startPos
		for i := blockStart; i < blockEnd; i++ {
			endPos += len(lines[i]) + 1 // +1 for newline
		}

		// Ensure positions are within bounds
		if startPos < 0 {
			startPos = 0
		}
		if endPos > len(content) {
			endPos = len(content)
		}
		if startPos >= endPos {
			return content, nil // Nothing to remove
		}

		result := content[:startPos] + content[endPos:]
		return result, nil
	}

	// For removal, we need to remove the entire line including leading whitespace
	startPos := findLineStart(content, nodeInfo.StartPos)
	endPos := findLineEnd(content, nodeInfo.EndPos)

	// Ensure positions are within bounds
	if startPos < 0 {
		startPos = 0
	}
	if endPos > len(content) {
		endPos = len(content)
	}
	if startPos >= endPos {
		return content, nil // Nothing to remove
	}

	result := content[:startPos] + content[endPos:]
	return result, nil
}

// findNodeByPathFromContent finds a node by path from a content string
func findNodeByPathFromContent(content string, path string) (*NodeInfo, error) {
	// Parse the content to create a file
	file, err := parser.ParseBytes([]byte(content), parser.ParseComments)
	if err != nil {
		return nil, NewError("parse", fmt.Sprintf("failed to parse content: %v", err), path)
	}

	// Use the existing findNodeByPath function
	return findNodeByPath(file, path)
}

// applyFlowSequenceElementReplace replaces an element in a flow sequence with proper comma formatting
func applyFlowSequenceElementReplace(content string, parentNodeInfo *NodeInfo, index int, replacement string) (string, error) {
	// Parse the parent sequence to get all elements
	parentContent := parentNodeInfo.Content
	trimmed := strings.TrimSpace(parentContent)

	// Extract the inner content without brackets
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return "", NewError("replace", "parent is not a flow sequence", "")
	}

	inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])

	// Split by commas and trim whitespace
	var elements []string
	if inner != "" {
		// Split by comma and trim each element
		parts := strings.Split(inner, ",")
		for _, part := range parts {
			elements = append(elements, strings.TrimSpace(part))
		}
	}

	// Check if index is valid
	if index < 0 || index >= len(elements) {
		return "", NewError("replace", fmt.Sprintf("index %d out of bounds for sequence with %d elements", index, len(elements)), "")
	}

	// Replace the element at the specified index
	elements[index] = replacement

	// Reconstruct the flow sequence with proper comma formatting
	newSequence := "[" + strings.Join(elements, ", ") + "]"

	// Find the position of the parent sequence in the content
	sequenceStart := strings.Index(content, parentContent)
	if sequenceStart == -1 {
		return "", NewError("replace", "could not find parent sequence in content", "")
	}

	sequenceEnd := sequenceStart + len(parentContent)

	// Replace the entire sequence
	result := content[:sequenceStart] + newSequence + content[sequenceEnd:]
	return result, nil
}

// findSequenceItemEndInContent finds the end position of a mapping within a sequence
// by analyzing the source content structure
func findSequenceItemEndInContent(content string, nodeInfo *NodeInfo) int {
	// Split content into lines
	lines := strings.Split(content, "\n")

	// Find the line that contains our start position
	currentPos := 0
	startLineIndex := -1
	for i, line := range lines {
		lineEnd := currentPos + len(line)
		if currentPos <= nodeInfo.StartPos && nodeInfo.StartPos <= lineEnd {
			startLineIndex = i
			break
		}
		currentPos = lineEnd + 1 // +1 for newline
	}

	if startLineIndex == -1 {
		// Fallback to original method
		return nodeInfo.EndPos
	}

	// Find the indentation of the line containing our mapping
	startLine := lines[startLineIndex]
	baseIndentation := extractIndentation(startLine)

	// Look for the next line that has the same or less indentation than the base
	// or starts with a dash (indicating next sequence item)
	endLineIndex := len(lines) - 1

	for i := startLineIndex + 1; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Skip empty lines and comments within the item
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		lineIndentation := extractIndentation(line)

		// If we find a line that starts with dash at same or lesser indentation
		// or any line with same or less indentation, this is where our item ends
		if strings.HasPrefix(trimmed, "-") && lineIndentation <= baseIndentation {
			endLineIndex = i - 1
			break
		} else if lineIndentation <= baseIndentation {
			endLineIndex = i - 1
			break
		}
	}

	// Now find the last non-empty line within our item to avoid including trailing blank lines
	lastContentLineIndex := endLineIndex
	for i := endLineIndex; i >= startLineIndex; i-- {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			lastContentLineIndex = i
			break
		}
	}

	// Calculate the position at the end of the last content line
	pos := 0
	for i := 0; i <= lastContentLineIndex && i < len(lines); i++ {
		if i < lastContentLineIndex {
			pos += len(lines[i]) + 1 // +1 for newline
		} else {
			pos += len(lines[i])
		}
	}

	return pos
}

// findFlexibleMatch finds a GitHub expression in text while handling whitespace variations
func findFlexibleMatch(text, pattern string) int {
	// First try exact match for performance
	if idx := strings.Index(text, pattern); idx != -1 {
		return idx
	}

	// Check if it's a GitHub expression pattern
	if strings.Contains(pattern, "${{") && strings.Contains(pattern, "}}") {
		// Extract the expression content between ${{ and }}
		start := strings.Index(pattern, "${{")
		end := strings.LastIndex(pattern, "}}")
		if start != -1 && end != -1 && end > start {
			innerPattern := pattern[start+3 : end]
			// Normalize whitespace in the pattern
			innerPattern = strings.TrimSpace(innerPattern)
			innerPattern = regexp.MustCompile(`\s+`).ReplaceAllString(innerPattern, `\s+`)

			// Create a regex that matches the expression with flexible whitespace
			regexPattern := regexp.QuoteMeta(pattern[:start]) +
				`\$\{\{\s*` +
				regexp.QuoteMeta(innerPattern) +
				`\s*\}\}` +
				regexp.QuoteMeta(pattern[end+2:])

			// Try to compile and match the regex
			if regex, err := regexp.Compile(regexPattern); err == nil {
				if match := regex.FindStringIndex(text); match != nil {
					return match[0]
				}
			}
		}
	}

	// Fallback to original exact match
	return strings.Index(text, pattern)
}
