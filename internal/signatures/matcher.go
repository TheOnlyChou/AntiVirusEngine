package signatures

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/theonlychou/antivirusengine/internal/model"
)

// Signature represents a single file signature.
type Signature struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"` // "hash" or "pattern"
	Value    string `json:"value"`
	Severity string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Category string `json:"category"` // e.g., "trojan", "adware", "suspicious"
}

// SignatureDatabase represents the loaded signature data.
type SignatureDatabase struct {
	Signatures []Signature `json:"signatures"`
}

// SignatureMatcher matches files against known malware signatures.
type SignatureMatcher struct {
	// Index hashes for fast O(1) lookup
	hashIndex map[string][]Signature // maps hash value to list of signatures
	count     int
}

// NewSignatureMatcher creates a new SignatureMatcher instance.
func NewSignatureMatcher() *SignatureMatcher {
	return &SignatureMatcher{
		hashIndex: make(map[string][]Signature),
		count:     0,
	}
}

// AddSignature adds a signature to the matcher's index.
func (sm *SignatureMatcher) AddSignature(sig Signature) {
	// Index by the signature value (hash)
	sm.hashIndex[strings.ToLower(sig.Value)] = append(sm.hashIndex[strings.ToLower(sig.Value)], sig)
	sm.count++
}

// MatchHash checks if any hash (MD5, SHA1, SHA256) matches known signatures.
// Returns detections for any matching signatures.
func (sm *SignatureMatcher) MatchHash(md5 string, sha1 string, sha256 string) []model.Detection {
	var detections []model.Detection

	// Check all three hash values
	hashValues := []string{
		strings.ToLower(md5),
		strings.ToLower(sha1),
		strings.ToLower(sha256),
	}

	for _, hash := range hashValues {
		if sigs, found := sm.hashIndex[hash]; found {
			for _, sig := range sigs {
				detection := model.Detection{
					Engine:    "HashSignature",
					Name:      sig.Name,
					Severity:  sig.Severity,
					Message:   fmt.Sprintf("File matches known malware signature: %s", sig.Name),
					Type:      sig.Category,
					Timestamp: model.GetCurrentTime(),
					Score:     sm.getSeverityScore(sig.Severity),
				}
				detections = append(detections, detection)
			}
		}
	}

	return detections
}

// LoadSignatures loads signatures from a JSON file.
func (sm *SignatureMatcher) LoadSignatures(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	var db SignatureDatabase
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("failed to parse signature file: %w", err)
	}

	sm.count = 0
	sm.hashIndex = make(map[string][]Signature)

	for _, sig := range db.Signatures {
		sm.AddSignature(sig)
	}

	return nil
}

// GetStatistics returns information about loaded signatures.
func (sm *SignatureMatcher) GetStatistics() map[string]int {
	stats := make(map[string]int)
	stats["total_signatures"] = sm.count

	// TODO: Phase 2 - Add more detailed statistics by category, severity
	return stats
}

// getSeverityScore converts severity level to numeric score (0.0 to 1.0).
func (sm *SignatureMatcher) getSeverityScore(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0.95
	case "HIGH":
		return 0.75
	case "MEDIUM":
		return 0.50
	case "LOW":
		return 0.25
	default:
		return 0.10
	}
}
