package pe

import (
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/theonlychou/antivirusengine/internal/model"
)

// ImportSymbol represents one imported API symbol.
type ImportSymbol struct {
	DLL      string `json:"dll"`
	Function string `json:"function"`
}

// SuspiciousImportRule defines a suspicious import pattern and scoring metadata.
type SuspiciousImportRule struct {
	DLL      string  `json:"dll"`
	Function string  `json:"function"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	Reason   string  `json:"reason"`
}

type suspiciousImportDataset struct {
	Rules []SuspiciousImportRule `json:"rules"`
}

// ExtractImports reads imported symbols from a PE file.
func (pa *PEAnalyzer) ExtractImports(filePath string) ([]ImportSymbol, error) {
	f, err := pe.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("not a valid PE file: %w", err)
	}
	defer f.Close()

	rawSymbols, err := f.ImportedSymbols()
	if err != nil {
		return nil, fmt.Errorf("failed to read imported symbols: %w", err)
	}

	imports := make([]ImportSymbol, 0, len(rawSymbols))
	seen := make(map[string]struct{})
	for _, s := range rawSymbols {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) != 2 {
			continue
		}

		dll := strings.ToLower(strings.TrimSpace(parts[0]))
		fn := strings.TrimSpace(parts[1])
		if dll == "" || fn == "" {
			continue
		}

		key := dll + ":" + strings.ToLower(fn)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		imports = append(imports, ImportSymbol{DLL: dll, Function: fn})
	}

	return imports, nil
}

// LoadSuspiciousImports loads suspicious import rules from local JSON data.
func LoadSuspiciousImports(filePath string) ([]SuspiciousImportRule, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read suspicious imports file: %w", err)
	}

	var dataset suspiciousImportDataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return nil, fmt.Errorf("failed to parse suspicious imports JSON: %w", err)
	}

	return dataset.Rules, nil
}

// DetectSuspiciousImports matches imported APIs against local suspicious rules.
func DetectSuspiciousImports(imports []ImportSymbol, rules []SuspiciousImportRule) []model.Detection {
	detections := make([]model.Detection, 0)
	seen := make(map[string]struct{})

	for _, imp := range imports {
		importDLL := strings.ToLower(imp.DLL)
		importFn := strings.ToLower(imp.Function)

		for _, rule := range rules {
			ruleDLL := strings.ToLower(strings.TrimSpace(rule.DLL))
			ruleFn := strings.ToLower(strings.TrimSpace(rule.Function))

			dllMatches := ruleDLL == "*" || ruleDLL == importDLL
			fnMatches := ruleFn == "*" || ruleFn == importFn
			if !dllMatches || !fnMatches {
				continue
			}

			name := fmt.Sprintf("Suspicious Import: %s!%s", imp.DLL, imp.Function)
			key := name + ":" + strings.ToUpper(rule.Severity)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			score := rule.Score
			if score <= 0 {
				score = 0.35
			}
			reason := rule.Reason
			if reason == "" {
				reason = "Imported API is commonly observed in malware tradecraft"
			}

			detections = append(detections, model.Detection{
				Engine:    "PEImport",
				Name:      name,
				Severity:  strings.ToUpper(rule.Severity),
				Score:     score,
				Message:   reason,
				Type:      "suspicious_import",
				Timestamp: model.GetCurrentTime(),
			})
		}
	}

	return detections
}
