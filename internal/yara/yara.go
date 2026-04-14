package yara

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/theonlychou/antivirusengine/internal/model"
)

// YARAScanner handles YARA rule-based scanning.
type YARAScanner struct {
	rulesPath      string
	ruleFiles      []string
	loadedAt       time.Time
	yaraBinaryPath string
}

// NewYARAScanner creates a new YARAScanner instance.
func NewYARAScanner(rulesPath string) *YARAScanner {
	return &YARAScanner{
		rulesPath: rulesPath,
		ruleFiles: make([]string, 0),
	}
}

// LoadRules loads YARA rules from the specified path.
// This implementation discovers .yar/.yara files and validates that the yara
// binary exists. Rule syntax is validated when scanning each file.
func (ys *YARAScanner) LoadRules() error {
	binaryPath, err := exec.LookPath("yara")
	if err != nil {
		return fmt.Errorf("yara binary not found in PATH; install yara and try again")
	}
	ys.yaraBinaryPath = binaryPath

	rules := make([]string, 0)
	err = filepath.WalkDir(ys.rulesPath, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yar" || ext == ".yara" {
			rules = append(rules, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk rules directory: %w", err)
	}

	if len(rules) == 0 {
		return fmt.Errorf("no YARA rule files found in %s", ys.rulesPath)
	}

	sort.Strings(rules)
	ys.ruleFiles = rules
	ys.loadedAt = time.Now()

	// TODO: Phase 4 - Pre-compile rules and cache compiled artifacts for speed.
	return nil
}

// Scan scans a file against loaded YARA rules.
// This runs `yara <rule-file> <target-file>` for each discovered rule file and
// converts matches into Detection values.
func (ys *YARAScanner) Scan(filePath string) ([]model.Detection, error) {
	if ys.yaraBinaryPath == "" || len(ys.ruleFiles) == 0 {
		return nil, fmt.Errorf("YARA scanner is not initialized; call LoadRules first")
	}

	detections := make([]model.Detection, 0)
	seen := make(map[string]struct{})

	for _, ruleFile := range ys.ruleFiles {
		cmd := exec.Command(ys.yaraBinaryPath, ruleFile, filePath)
		output, err := cmd.CombinedOutput()
		trimmed := strings.TrimSpace(string(output))

		if err != nil {
			// YARA can return non-zero in some non-match cases depending on build.
			// If no output is produced, treat it as no match and continue.
			if trimmed == "" {
				continue
			}
			return nil, fmt.Errorf("yara execution failed for %s: %w: %s", ruleFile, err, trimmed)
		}

		if trimmed == "" {
			continue
		}

		lines := strings.Split(trimmed, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Typical YARA output line: "RuleName /path/to/file"
			fields := strings.Fields(line)
			if len(fields) < 1 {
				continue
			}
			ruleName := fields[0]

			// Deduplicate by rule name in case multiple rule files overlap.
			if _, ok := seen[ruleName]; ok {
				continue
			}
			seen[ruleName] = struct{}{}

			detections = append(detections, model.Detection{
				Engine:    "YARA",
				Name:      ruleName,
				Severity:  "HIGH",
				Score:     0.70,
				Message:   fmt.Sprintf("YARA rule matched: %s", ruleName),
				Type:      "yara_match",
				Timestamp: model.GetCurrentTime(),
			})
		}
	}

	// TODO: Phase 4 - Extract severity/tags from rule metadata instead of defaults.
	return detections, nil
}

// GetRuleStatistics returns information about loaded YARA rules.
func (ys *YARAScanner) GetRuleStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["rules_path"] = ys.rulesPath
	stats["rule_files_count"] = len(ys.ruleFiles)
	stats["loaded_at"] = ys.loadedAt
	stats["yara_binary"] = ys.yaraBinaryPath
	return stats
}

// RefreshRules reloads YARA rules from disk.
// Useful for hot-reloading updated rules.
func (ys *YARAScanner) RefreshRules() error {
	return ys.LoadRules()
}
