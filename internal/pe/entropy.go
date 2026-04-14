package pe

import (
	"fmt"
	"math"
	"os"
)

// CalculateFileEntropy computes Shannon entropy for the entire file.
func CalculateFileEntropy(filePath string) (float64, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read file for entropy: %w", err)
	}
	if len(data) == 0 {
		return 0, nil
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	total := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	// TODO: Add section-level entropy for PE sections to reduce false positives.
	return entropy, nil
}
