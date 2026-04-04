package model

import (
	"time"
)

// Verdict represents the detection result of a scan.
type Verdict string

const (
	VerdictClean      Verdict = "CLEAN"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictMalicious  Verdict = "MALICIOUS"
	VerdictUnknown    Verdict = "UNKNOWN"
)

// Detection represents a single detection in a file.
type Detection struct {
	Engine    string    `json:"engine"`   // e.g., "HashSignature", "YARA", "Heuristic"
	Name      string    `json:"name"`     // Detection name or signature ID
	Severity  string    `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Score     float64   `json:"score"`    // 0.0 to 1.0
	Message   string    `json:"message"`  // Human-readable description
	Type      string    `json:"type"`     // e.g., "trojan", "adware", "suspicious"
	Timestamp time.Time `json:"timestamp"`
}

// ScanResult represents the complete result of scanning a single file.
type ScanResult struct {
	FilePath     string        `json:"file_path"`
	FileName     string        `json:"file_name"`
	FileSize     int64         `json:"file_size"`
	LastModified time.Time     `json:"last_modified"`
	Hashes       *FileHashes   `json:"hashes"`
	Detections   []Detection   `json:"detections"`
	Verdict      Verdict       `json:"verdict"`
	TotalScore   float64       `json:"total_score"` // 0.0 to 1.0
	ScanDuration time.Duration `json:"scan_duration"`
	ScanTime     time.Time     `json:"scan_time"`
	// TODO: Add metadata for PE analysis, YARA matches, heuristic scores
}

// FileHashes represents various hash values of a file.
type FileHashes struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// Report represents a summary of multiple scan results.
type Report struct {
	ReportID        string        `json:"report_id"`
	GeneratedAt     time.Time     `json:"generated_at"`
	ScanResults     []ScanResult  `json:"scan_results"`
	TotalFiles      int           `json:"total_files"`
	CleanFiles      int           `json:"clean_files"`
	SuspiciousFiles int           `json:"suspicious_files"`
	MaliciousFiles  int           `json:"malicious_files"`
	TotalDuration   time.Duration `json:"total_duration"`
	// TODO: Add statistics and risk assessment
}

// ScanOptions holds configuration for a scan operation.
type ScanOptions struct {
	ScanHashes     bool
	ScanSignatures bool
	ScanYARA       bool
	ScanPE         bool
	ScanHeuristics bool
	EnableDeepScan bool
	// TODO: Add more options as the engine develops
}

// DefaultScanOptions returns sensible defaults.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		ScanHashes:     true,
		ScanSignatures: true,
		ScanYARA:       true,
		ScanPE:         false,
		ScanHeuristics: true,
		EnableDeepScan: false,
	}
}

// GetCurrentTime returns the current time.
func GetCurrentTime() time.Time {
	return time.Now()
}
