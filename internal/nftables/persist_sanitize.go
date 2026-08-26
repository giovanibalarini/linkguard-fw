package nftables

import "strings"

// sanitizeDynamicSetElements removes live elements from dynamic sets before a
// table snapshot is written to the boot ruleset. It deliberately preserves
// every byte outside those elements assignments.
func sanitizeDynamicSetElements(table string) string {
	var sanitized strings.Builder
	last := 0
	searchFrom := 0

	for {
		setStart, setOpen := nextSetDeclaration(table, searchFrom)
		if setStart < 0 {
			break
		}
		setClose := matchingBrace(table, setOpen)
		if setClose < 0 {
			break
		}

		setBlock := table[setStart : setClose+1]
		if hasDynamicFlag(setBlock) {
			sanitizedBlock := removeElementsAssignments(setBlock)
			if sanitizedBlock != setBlock {
				sanitized.WriteString(table[last:setStart])
				sanitized.WriteString(sanitizedBlock)
				last = setClose + 1
			}
		}
		searchFrom = setClose + 1
	}

	if last == 0 {
		return table
	}
	sanitized.WriteString(table[last:])
	return sanitized.String()
}

func nextSetDeclaration(table string, from int) (start, open int) {
	for lineStart := from; lineStart < len(table); {
		lineEnd := strings.IndexByte(table[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(table)
		} else {
			lineEnd += lineStart
		}
		line := table[lineStart:lineEnd]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "set ") || strings.HasPrefix(trimmed, "set\t") {
			brace := strings.IndexByte(line, '{')
			if brace >= 0 {
				return lineStart, lineStart + brace
			}
		}
		if lineEnd == len(table) {
			break
		}
		lineStart = lineEnd + 1
	}
	return -1, -1
}

func matchingBrace(text string, open int) int {
	depth := 0
	for i := open; i < len(text); i++ {
		switch text[i] {
		case '"':
			i = skipQuoted(text, i)
		case '#':
			i = skipComment(text, i)
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func hasDynamicFlag(setBlock string) bool {
	for _, line := range strings.Split(setBlock, "\n") {
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		for i, field := range fields {
			if field != "flags" {
				continue
			}
			for _, flagField := range fields[i+1:] {
				for _, flag := range strings.Split(strings.Trim(flagField, ","), ",") {
					if flag == "dynamic" {
						return true
					}
				}
			}
		}
	}
	return false
}

func removeElementsAssignments(setBlock string) string {
	var sanitized strings.Builder
	last := 0
	searchFrom := 0

	for {
		elementsStart, elementsOpen := nextElementsAssignment(setBlock, searchFrom)
		if elementsStart < 0 {
			break
		}
		elementsClose := matchingBrace(setBlock, elementsOpen)
		if elementsClose < 0 {
			break
		}
		sanitized.WriteString(setBlock[last:elementsStart])
		last = elementsClose + 1
		searchFrom = last
	}

	if last == 0 {
		return setBlock
	}
	sanitized.WriteString(setBlock[last:])
	return sanitized.String()
}

func nextElementsAssignment(setBlock string, from int) (start, open int) {
	const keyword = "elements"

	for i := from; i+len(keyword) <= len(setBlock); i++ {
		switch setBlock[i] {
		case '"':
			i = skipQuoted(setBlock, i)
		case '#':
			i = skipComment(setBlock, i)
		default:
			if setBlock[i:i+len(keyword)] != keyword || !tokenBoundary(setBlock, i-1) || !tokenBoundary(setBlock, i+len(keyword)) {
				continue
			}

			j := i + len(keyword)
			j = skipWhitespace(setBlock, j)
			if j >= len(setBlock) || setBlock[j] != '=' {
				continue
			}
			j = skipWhitespace(setBlock, j+1)
			if j < len(setBlock) && setBlock[j] == '{' {
				return i, j
			}
		}
	}
	return -1, -1
}

func tokenBoundary(text string, index int) bool {
	if index < 0 || index >= len(text) {
		return true
	}
	c := text[index]
	return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')
}

func skipWhitespace(text string, from int) int {
	for from < len(text) {
		switch text[from] {
		case ' ', '\t', '\r', '\n':
			from++
		default:
			return from
		}
	}
	return from
}

func skipQuoted(text string, from int) int {
	for i := from + 1; i < len(text); i++ {
		if text[i] == '\\' {
			i++
			continue
		}
		if text[i] == '"' {
			return i
		}
	}
	return len(text) - 1
}

func skipComment(text string, from int) int {
	if newline := strings.IndexByte(text[from:], '\n'); newline >= 0 {
		return from + newline
	}
	return len(text) - 1
}
