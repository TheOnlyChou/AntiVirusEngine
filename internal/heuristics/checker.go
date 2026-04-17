package heuristics

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/theonlychou/antivirusengine/internal/model"
)

// HeuristicChecker performs heuristic analysis to detect suspicious behavior.
type HeuristicChecker struct {
	patternsPath string
	patterns     []SuspiciousPattern
	loadErr      error
	loaded       bool
	mu           sync.Mutex
}

// NewHeuristicChecker creates a new HeuristicChecker instance.
func NewHeuristicChecker() *HeuristicChecker {
	return &HeuristicChecker{
		patternsPath: "data/heuristics/suspicious_strings.json",
		patterns:     make([]SuspiciousPattern, 0),
		loaded:       false,
	}
}

// CheckFile performs heuristic analysis on a file.
// Current implementation focuses on static string-based pattern checks.
func (hc *HeuristicChecker) CheckFile(filePath string, metadata map[string]interface{}) ([]model.Detection, error) {
	if err := hc.ensurePatternsLoaded(); err != nil {
		return nil, err
	}

	stringsFound, err := ExtractReadableStrings(filePath, 5)
	if err != nil {
		return nil, fmt.Errorf("failed to extract strings: %w", err)
	}

	detections := MatchPatterns(stringsFound, hc.patterns)
	detections = append(detections, DetectSuspiciousURLs(stringsFound)...)

	// Multiple matched patterns increase confidence but remain static-analysis only.
	combined := summarizeMatches(detections)
	if combined.count >= 3 {
		score := 0.45
		severity := "MEDIUM"
		if combined.count >= 5 {
			score = 0.60
			severity = "HIGH"
		}

		detections = append(detections, model.Detection{
			Engine:    "Heuristic",
			Name:      "Multiple Suspicious String Patterns",
			Severity:  severity,
			Score:     score,
			Message:   fmt.Sprintf("Detected %d suspicious patterns (%s)", combined.count, strings.Join(combined.names, ", ")),
			Type:      "heuristic_combo",
			Timestamp: model.GetCurrentTime(),
		})
	}

	// TODO: Add file-name and PE-context-aware heuristic correlation.
	// TODO: Add weighted grouping by behavior family (execution, persistence, C2).

	return detections, nil
}

// CheckFileSize checks if file size is suspicious.
// TODO: Implement file size heuristics.
func (hc *HeuristicChecker) CheckFileSize(fileSize int64) (float64, string) {
	// TODO: Return (suspicionScore, reason)
	// - Very small executable (< 1KB) with large virtual size = suspicious
	// - Unusually large file for expected type
	return 0.0, ""
}

// CheckEntropy checks if file entropy indicates compression or encryption.
// TODO: Implement entropy analysis.
func (hc *HeuristicChecker) CheckEntropy(filePath string) (float64, string, error) {
	// TODO: Calculate entropy and return (entropy, interpretation, error)
	return 0.0, "", nil
}

// CheckFileName checks if filename contains suspicious patterns.
// TODO: Implement filename heuristics.
func (hc *HeuristicChecker) CheckFileName(fileName string) (float64, string) {
	// TODO: Check for suspicious patterns (double extensions, Unicode tricks, etc.)
	return 0.0, ""
}

// GetHeuristicScore combines all heuristic checks into a single score.
// TODO: Implement score aggregation and weighting.
func (hc *HeuristicChecker) GetHeuristicScore(filePath string, metadata map[string]interface{}) (float64, error) {
	detections, err := hc.CheckFile(filePath, metadata)
	if err != nil {
		return 0.0, err
	}
	if len(detections) == 0 {
		return 0.0, nil
	}

	total := 0.0
	for _, d := range detections {
		total += d.Score
	}
	return total / float64(len(detections)), nil
}

func (hc *HeuristicChecker) ensurePatternsLoaded() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if hc.loaded {
		return hc.loadErr
	}

	hc.patterns, hc.loadErr = LoadSuspiciousPatterns(hc.patternsPath)
	hc.loaded = true
	return hc.loadErr
}

type matchSummary struct {
	count int
	names []string
}

func summarizeMatches(detections []model.Detection) matchSummary {
	uniq := make(map[string]struct{})
	names := make([]string, 0)

	for _, d := range detections {
		if d.Engine != "Heuristic" || d.Type == "heuristic_combo" {
			continue
		}
		if _, ok := uniq[d.Name]; ok {
			continue
		}
		uniq[d.Name] = struct{}{}
		names = append(names, d.Name)
	}

	sort.Strings(names)
	return matchSummary{count: len(names), names: names}
}
