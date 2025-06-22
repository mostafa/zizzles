package yaml_patch

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"
)

// applyRewriteFragment applies a RewriteFragment operation
func applyRewriteFragment(content string, nodeInfo *NodeInfo, op RewriteFragmentOp) (string, error) {
	extractedContent := nodeInfo.Content

	// Special handling for multiline literal and folded scalars
	if nodeInfo.Style == MultilineLiteralScalar || nodeInfo.Style == MultilineFoldedScalar {
		// In the original YAML, find the position of the indicator (|, |-, |+, >, >-, >+)
		indicatorStart := nodeInfo.StartPos
		indicatorEnd := indicatorStart
		for ; indicatorEnd < len(content); indicatorEnd++ {
			if content[indicatorEnd] == '\n' {
				break
			}
		}
		if indicatorEnd >= len(content) {
			return "", NewError("rewrite", "could not find end of multiline indicator line", strings.Join(nodeInfo.Path, "."))
		}
		// The header includes the indicator and the newline
		header := content[indicatorStart : indicatorEnd+1]
		bodyStart := indicatorEnd + 1
		bodyEnd := nodeInfo.EndPos
		if bodyEnd > len(content) {
			bodyEnd = len(content)
		}
		body := content[bodyStart:bodyEnd]

		// Find and replace in the body
		bias := 0
		if op.After != nil {
			bias = *op.After
		}
		if bias > len(body) {
			return "", NewError("rewrite", fmt.Sprintf("replacement scan index %d is out of bounds for feature", bias), strings.Join(nodeInfo.Path, "."))
		}
		slice := body[bias:]
		fromStart := strings.Index(slice, op.From)
		if fromStart == -1 {
			return "", NewError("rewrite", fmt.Sprintf("no match for '%s' in feature", op.From), strings.Join(nodeInfo.Path, "."))
		}
		fromStart += bias
		fromEnd := fromStart + len(op.From)
		patchedBody := body[:fromStart] + op.To + body[fromEnd:]

		// Reconstruct the full content
		patchedContent := header + patchedBody
		result := content[:indicatorStart] + patchedContent + content[bodyEnd:]
		return result, nil
	}

	bias := 0
	if op.After != nil {
		bias = *op.After
	}

	if bias > len(extractedContent) {
		return "", NewError("rewrite", fmt.Sprintf("replacement scan index %d is out of bounds for feature", bias), strings.Join(nodeInfo.Path, "."))
	}

	slice := extractedContent[bias:]
	fromStart := strings.Index(slice, op.From)
	if fromStart == -1 {
		return "", NewError("rewrite", fmt.Sprintf("no match for '%s' in feature", op.From), strings.Join(nodeInfo.Path, "."))
	}

	fromStart += bias
	fromEnd := fromStart + len(op.From)

	// Create the patched content
	patchedContent := extractedContent[:fromStart] + op.To + extractedContent[fromEnd:]

	// Check if the extracted content contains inner quotes that might cause issues
	// The issue is that the extracted content might be something like: echo 'foo: ...'
	// where the inner quotes are part of the content, not the outer quotes
	trimmedContent := strings.TrimSpace(extractedContent)
	if strings.Contains(trimmedContent, "'") || strings.Contains(trimmedContent, "\"") {
		// This content contains quotes, we need to be more careful about replacement
		// The issue is that the nodeInfo.EndPos might be pointing to the wrong position
		// Let's check if the after content starts with a quote
		if nodeInfo.EndPos < len(content) {
			afterChar := content[nodeInfo.EndPos]

			// If the character after our end position is a quote, we need to adjust
			if afterChar == '"' || afterChar == '\'' {
				// The end position is correct, but we need to be careful about the replacement
				// The extracted content is the value inside the outer quotes
				// We should replace the content as-is, but ensure we don't duplicate quotes

				// Check if the start position is also at a quote
				startChar := content[nodeInfo.StartPos]

				// Adjust positions to exclude the outer quotes
				actualStart := nodeInfo.StartPos
				actualEnd := nodeInfo.EndPos

				if startChar == '"' || startChar == '\'' {
					actualStart++ // Skip the opening quote
				}

				// Extract the content without the outer quotes
				innerContent := content[actualStart:actualEnd]

				// Do the replacement on the inner content
				innerSlice := innerContent[bias:]
				innerFromStart := strings.Index(innerSlice, op.From)
				if innerFromStart == -1 {
					return "", NewError("rewrite", fmt.Sprintf("no match for '%s' in inner content", op.From), strings.Join(nodeInfo.Path, "."))
				}

				innerFromStart += bias
				innerFromEnd := innerFromStart + len(op.From)

				// Create the patched inner content
				patchedInnerContent := innerContent[:innerFromStart] + op.To + innerContent[innerFromEnd:]

				// Replace the inner content while preserving the outer quotes
				result := content[:actualStart] + patchedInnerContent + content[actualEnd:]
				return result, nil
			}
		}
	}

	if (strings.HasPrefix(trimmedContent, "'") && strings.HasSuffix(trimmedContent, "'")) ||
		(strings.HasPrefix(trimmedContent, "\"") && strings.HasSuffix(trimmedContent, "\"")) {
		// This is a quoted string, we need to adjust the replacement
		// The extracted content includes the quotes, but we want to replace only the inner content
		quoteChar := trimmedContent[0]
		quoteLen := 1

		// Find the actual start and end of the quoted content
		actualStart := nodeInfo.StartPos
		actualEnd := nodeInfo.EndPos

		// Adjust for the opening quote
		if actualStart < len(content) && content[actualStart] == quoteChar {
			actualStart += quoteLen
		}

		// Adjust for the closing quote
		if actualEnd > 0 && actualEnd <= len(content) && content[actualEnd-1] == quoteChar {
			actualEnd -= quoteLen
		}

		// Extract the content without quotes
		innerContent := content[actualStart:actualEnd]

		// Do the replacement on the inner content
		innerSlice := innerContent[bias:]
		innerFromStart := strings.Index(innerSlice, op.From)
		if innerFromStart == -1 {
			return "", NewError("rewrite", fmt.Sprintf("no match for '%s' in inner content", op.From), strings.Join(nodeInfo.Path, "."))
		}

		innerFromStart += bias
		innerFromEnd := innerFromStart + len(op.From)

		// Create the patched inner content
		patchedInnerContent := innerContent[:innerFromStart] + op.To + innerContent[innerFromEnd:]

		// Replace the inner content while preserving the quotes
		result := content[:actualStart] + patchedInnerContent + content[actualEnd:]
		return result, nil
	}

	// Replace the content in the original string
	result := content[:nodeInfo.StartPos] + patchedContent + content[nodeInfo.EndPos:]
	return result, nil
}

// applyReplace applies a Replace operation
func applyReplace(content string, nodeInfo *NodeInfo, op ReplaceOp) (string, error) {
	// Convert the value to YAML string
	replacement, err := valueToYAMLString(op.Value)
	if err != nil {
		return "", NewError("serialization", fmt.Sprintf("failed to serialize value: %v", err), strings.Join(nodeInfo.Path, "."))
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
		start := strings.Index(content, nodeInfo.Content)
		if start == -1 {
			return "", NewError("add", "could not locate existing flow mapping in content", strings.Join(nodeInfo.Path, "."))
		}
		end := start + len(nodeInfo.Content)
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
	// Deserialize existing mapping.
	var existing map[string]any
	if err := yaml.Unmarshal([]byte(featureContent), &existing); err != nil {
		return "", NewError("serialization", fmt.Sprintf("failed to parse existing flow mapping: %v", err), "")
	}

	if _, exists := existing[key]; exists {
		return "", NewError("add", fmt.Sprintf("key '%s' already exists in flow mapping", key), "")
	}

	existing[key] = value

	// Create deterministic ordering (alphabetical).
	keys := make([]string, 0, len(existing))
	for k := range existing {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		v := existing[k]
		vs, err := valueToYAMLString(v)
		if err != nil {
			return "", NewError("serialization", fmt.Sprintf("failed to serialize value: %v", err), "")
		}
		pairs = append(pairs, fmt.Sprintf("%s: %s", k, vs))
	}

	return "{ " + strings.Join(pairs, ", ") + " }", nil
}

// applyMergeInto applies a MergeInto operation
func applyMergeInto(content string, nodeInfo *NodeInfo, op MergeIntoOp) (string, error) {
	// For MergeInto, we want to work with the parent mapping that contains the key
	// not the value of the key itself
	existingKeyPath := append(nodeInfo.Path, op.Key)
	existingNodeInfo, err := findNodeByPathFromContent(content, strings.Join(existingKeyPath, "."))

	if err == nil {
		if isMappingValue(op.Value) && isMappingValue(existingNodeInfo.Content) {
			mergedValue, err := mergeMappings(existingNodeInfo.Content, op.Value)
			if err != nil {
				return "", NewError("merge", fmt.Sprintf("failed to merge mappings: %v", err), strings.Join(existingKeyPath, "."))
			}

			// For env blocks, we need to replace the entire env key-value pair
			// Find the line that contains "env:" and replace from there
			lines := strings.Split(content, "\n")
			envLineIndex := -1
			for i, line := range lines {
				if strings.TrimSpace(line) == "env:" {
					envLineIndex = i
					break
				}
			}

			if envLineIndex == -1 {
				return "", NewError("merge", "could not find env: line", strings.Join(existingKeyPath, "."))
			}

			// Calculate the start position of the env: line
			startPos := 0
			for i := 0; i < envLineIndex; i++ {
				startPos += len(lines[i]) + 1 // +1 for newline
			}

			// Find the end position (end of the env block)
			endPos := startPos
			for i := envLineIndex; i < len(lines); i++ {
				endPos += len(lines[i]) + 1 // +1 for newline
				// Stop when we hit a line with same or less indentation that's not empty
				if i > envLineIndex {
					trimmed := strings.TrimSpace(lines[i])
					if trimmed != "" && !strings.HasPrefix(lines[i], "  ") {
						break
					}
				}
			}

			// Ensure bounds are valid
			if startPos >= len(content) {
				startPos = len(content) - 1
			}
			if endPos > len(content) {
				endPos = len(content)
			}
			if startPos >= endPos {
				endPos = startPos + 1
			}

			// Format the merged value as a proper env block
			mergedStr, err := valueToYAMLString(mergedValue)
			if err != nil {
				return "", NewError("serialization", fmt.Sprintf("failed to serialize merged value: %v", err), strings.Join(existingKeyPath, "."))
			}

			// Format as block mapping with correct indentation
			formattedValue := formatBlockMappingValue(mergedStr, 3) // 3 levels of indentation for env content

			// Create the replacement content with proper indentation
			replacement := "    env:\n" + formattedValue

			// Replace the content
			result := content[:startPos] + replacement + content[endPos:]
			return result, nil
		} else {
			replaceOp := ReplaceOp{Value: op.Value}
			return applyReplace(content, existingNodeInfo, replaceOp)
		}
	}

	// Fall back to adding the key since merge isn't possible (key doesn't exist or isn't a mapping)
	// Convert MergeIntoOp to AddOp using type conversion since they have identical field structures
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
