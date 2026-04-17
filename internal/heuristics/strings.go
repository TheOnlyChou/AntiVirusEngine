package heuristics

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// ExtractReadableStrings extracts ASCII-readable strings from a file.
// This is intentionally simple and educational: it extracts printable runs.
func ExtractReadableStrings(filePath string, minLength int) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	if minLength < 1 {
		minLength = 1
	}

	results := make([]string, 0)
	seen := make(map[string]struct{})
	buf := make([]rune, 0, 128)

	flush := func() {
		if len(buf) < minLength {
			buf = buf[:0]
			return
		}
		s := strings.TrimSpace(string(buf))
		buf = buf[:0]
		if len(s) < minLength {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		results = append(results, s)
	}

	for _, b := range data {
		r := rune(b)
		if isReadableASCII(r) {
			buf = append(buf, r)
		} else {
			flush()
		}
	}
	flush()

	return results, nil
}

func isReadableASCII(r rune) bool {
	if r < 32 || r > 126 {
		return false
	}
	if unicode.IsControl(r) {
		return false
	}
	return true
}
