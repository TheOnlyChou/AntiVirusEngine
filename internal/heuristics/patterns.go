package heuristics

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/theonlychou/antivirusengine/internal/model"
)

// SuspiciousPattern describes one suspicious string pattern.
type SuspiciousPattern struct {
	Name        string  `json:"name"`
	Pattern     string  `json:"pattern"`
	MatchType   string  `json:"match_type"` // contains | regex
	Severity    string  `json:"severity"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
}

type suspiciousPatternDataset struct {
	Patterns []SuspiciousPattern `json:"patterns"`
}

// LoadSuspiciousPatterns loads suspicious string patterns from JSON.
func LoadSuspiciousPatterns(filePath string) ([]SuspiciousPattern, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read suspicious pattern file: %w", err)
	}

	var dataset suspiciousPatternDataset
	if err := json.Unmarshal(data, &dataset); err != nil {
		return nil, fmt.Errorf("failed to parse suspicious pattern JSON: %w", err)
	}

	return dataset.Patterns, nil
}

// MatchPatterns applies configured patterns to extracted strings.
func MatchPatterns(extracted []string, patterns []SuspiciousPattern) []model.Detection {
	detections := make([]model.Detection, 0)
	seen := make(map[string]struct{})

	for _, p := range patterns {
		matched := false
		needle := strings.ToLower(p.Pattern)
		for _, s := range extracted {
			lower := strings.ToLower(s)

			switch strings.ToLower(p.MatchType) {
			case "regex":
				re, err := regexp.Compile(p.Pattern)
				if err != nil {
					continue
				}
				if re.MatchString(s) {
					matched = true
				}
			default:
				if strings.Contains(lower, needle) {
					matched = true
				}
			}

			if matched {
				break
			}
		}

		if !matched {
			continue
		}

		name := p.Name
		if name == "" {
			name = fmt.Sprintf("Suspicious Pattern: %s", p.Pattern)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}

		score := p.Score
		if score <= 0 {
			score = 0.20
		}
		severity := strings.ToUpper(strings.TrimSpace(p.Severity))
		if severity == "" {
			severity = "LOW"
		}
		message := p.Description
		if message == "" {
			message = "String pattern matched heuristic rule"
		}

		detections = append(detections, model.Detection{
			Engine:    "Heuristic",
			Name:      name,
			Severity:  severity,
			Score:     score,
			Message:   message,
			Type:      "suspicious_string",
			Timestamp: model.GetCurrentTime(),
		})
	}

	return detections
}

// DetectSuspiciousURLs flags URLs that look risky based on simple static rules.
func DetectSuspiciousURLs(extracted []string) []model.Detection {
	urlRE := regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	detections := make([]model.Detection, 0)
	seen := make(map[string]struct{})

	for _, s := range extracted {
		matches := urlRE.FindAllString(s, -1)
		for _, u := range matches {
			lower := strings.ToLower(u)
			if !looksSuspiciousURL(lower) {
				continue
			}
			if _, ok := seen[lower]; ok {
				continue
			}
			seen[lower] = struct{}{}

			detections = append(detections, model.Detection{
				Engine:    "Heuristic",
				Name:      "Suspicious URL Reference",
				Severity:  "MEDIUM",
				Score:     0.30,
				Message:   fmt.Sprintf("Embedded URL appears suspicious: %s", u),
				Type:      "suspicious_url",
				Timestamp: model.GetCurrentTime(),
			})
		}
	}

	return detections
}

func looksSuspiciousURL(url string) bool {
	keywords := []string{
		"pastebin", "raw.githubusercontent", "bit.ly", "tinyurl", "cdn.discordapp", "dropbox",
		"/payload", "/update", "/gate", "/shell", "download.php", "cmd=", "token=",
	}
	for _, k := range keywords {
		if strings.Contains(url, k) {
			return true
		}
	}

	ipLike := regexp.MustCompile(`https?://\d{1,3}(\.\d{1,3}){3}`)
	if ipLike.MatchString(url) {
		return true
	}

	return false
}
