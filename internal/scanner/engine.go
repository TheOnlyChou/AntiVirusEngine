package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/theonlychou/antivirusengine/internal/hashing"
	"github.com/theonlychou/antivirusengine/internal/heuristics"
	"github.com/theonlychou/antivirusengine/internal/model"
	"github.com/theonlychou/antivirusengine/internal/pe"
	"github.com/theonlychou/antivirusengine/internal/signatures"
	"github.com/theonlychou/antivirusengine/internal/yara"
)

// Engine is the central scanning orchestrator.
type Engine struct {
	hasher           *hashing.Hasher
	signatureMatcher *signatures.SignatureMatcher
	yaraScanner      *yara.YARAScanner
	peAnalyzer       *pe.PEAnalyzer
	heuristicChecker *heuristics.HeuristicChecker
	initialized      bool
	yaraInitErr      error
	// TODO: Add configuration and logging
}

// NewEngine creates and initializes a new scanning engine.
func NewEngine() *Engine {
	return &Engine{
		hasher:           hashing.NewHasher(),
		signatureMatcher: signatures.NewSignatureMatcher(),
		yaraScanner:      yara.NewYARAScanner("./rules"),
		peAnalyzer:       pe.NewPEAnalyzer(),
		heuristicChecker: heuristics.NewHeuristicChecker(),
		initialized:      false,
		yaraInitErr:      nil,
	}
}

// Initialize sets up the engine (load rules, signatures, etc.).
// Loads signatures and YARA rule metadata.
func (e *Engine) Initialize() error {
	if e.initialized {
		return nil
	}

	// Phase 1: Load hash signatures
	sigPath := "rules/signatures.json"
	if err := e.signatureMatcher.LoadSignatures(sigPath); err != nil {
		return fmt.Errorf("failed to load signatures: %w", err)
	}

	// YARA initialization is captured and surfaced only when YARA scanning is enabled.
	e.yaraInitErr = e.yaraScanner.LoadRules()

	e.initialized = true
	return nil
}

// ScanFile performs a complete scan on a single file.
// Phase 1 implementation: Hash-based detection only
func (e *Engine) ScanFile(filePath string, opts model.ScanOptions) (*model.ScanResult, error) {
	startTime := time.Now()

	// Initialize engine if not already done
	if !e.initialized {
		if err := e.Initialize(); err != nil {
			return nil, err
		}
	}

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if fileInfo.IsDir() {
		return nil, fmt.Errorf("path is a directory, not a file")
	}

	// Phase 1: Compute file hashes
	hashes, err := e.hasher.ComputeHashes(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hashes: %w", err)
	}

	// Initialize detections
	var detections []model.Detection

	// Phase 1: Hash-based signature matching
	if opts.ScanHashes && opts.ScanSignatures {
		hashDetections := e.signatureMatcher.MatchHash(hashes.MD5, hashes.SHA1, hashes.SHA256)
		detections = append(detections, hashDetections...)
	}

	// Phase 2: YARA scanning
	if opts.ScanYARA {
		if e.yaraInitErr == nil {
			yaraDetections, scanErr := e.yaraScanner.Scan(filePath)
			if scanErr != nil {
				return nil, fmt.Errorf("YARA scan failed: %w", scanErr)
			}
			detections = append(detections, yaraDetections...)
		} else {
			// TODO: Add warning propagation in ScanResult to surface skipped YARA checks.
		}
	}

	var peMetadata map[string]interface{}

	// Phase 3: PE static analysis
	if opts.ScanPE {
		isPE, peCheckErr := e.peAnalyzer.IsExecutable(filePath)
		if peCheckErr != nil {
			return nil, fmt.Errorf("PE detection failed: %w", peCheckErr)
		}

		if isPE {
			metadata, metadataErr := e.peAnalyzer.ExtractMetadata(filePath)
			if metadataErr != nil {
				return nil, fmt.Errorf("PE metadata extraction failed: %w", metadataErr)
			}
			peMetadata = metadata

			peDetections, peAnalyzeErr := e.peAnalyzer.AnalyzeFile(filePath)
			if peAnalyzeErr != nil {
				return nil, fmt.Errorf("PE analysis failed: %w", peAnalyzeErr)
			}
			detections = append(detections, peDetections...)
		}
	}

	// TODO: Phase 4 - Deeper PE behavioral mapping and section heuristics.
	// TODO: Phase 5 - Heuristic checks

	totalScore := e.computeScore(detections)

	// Compute verdict based on detections
	verdict := e.computeVerdict(detections, totalScore)

	result := &model.ScanResult{
		FilePath:     filePath,
		FileName:     filepath.Base(filePath),
		FileSize:     fileInfo.Size(),
		LastModified: fileInfo.ModTime(),
		Hashes:       hashes,
		PEMetadata:   peMetadata,
		Detections:   detections,
		Verdict:      verdict,
		TotalScore:   totalScore,
		ScanDuration: time.Since(startTime),
		ScanTime:     startTime,
	}

	return result, nil
}

// ScanDirectory recursively scans all files in a directory.
// TODO: Phase 2 - Implement directory scanning with concurrent file processing.
func (e *Engine) ScanDirectory(dirPath string, opts model.ScanOptions) (*model.Report, error) {
	// TODO: Implement directory scan logic
	report := &model.Report{
		GeneratedAt: time.Now(),
		ScanResults: []model.ScanResult{},
	}
	return report, nil
}

// GetEngineStatistics returns information about the scanning engine state.
func (e *Engine) GetEngineStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["initialized"] = e.initialized
	stats["signatures"] = e.signatureMatcher.GetStatistics()
	stats["yara"] = e.yaraScanner.GetRuleStatistics()
	if e.yaraInitErr != nil {
		stats["yara_error"] = e.yaraInitErr.Error()
	}
	return stats
}

// computeScore calculates the average score across all detections.
func (e *Engine) computeScore(detections []model.Detection) float64 {
	if len(detections) == 0 {
		return 0.0
	}

	scoreSum := 0.0
	for _, det := range detections {
		scoreSum += det.Score
	}

	return scoreSum / float64(len(detections))
}

// computeVerdict determines the verdict based on detected threats and score.
// Phase 1 implementation: Simple threshold-based approach
func (e *Engine) computeVerdict(detections []model.Detection, totalScore float64) model.Verdict {
	// No detections = clean
	if len(detections) == 0 {
		return model.VerdictClean
	}

	// Use score thresholds
	if totalScore >= 0.75 {
		return model.VerdictMalicious
	} else if totalScore >= 0.50 {
		return model.VerdictSuspicious
	}

	// Low score detection = suspicious
	return model.VerdictSuspicious
}
